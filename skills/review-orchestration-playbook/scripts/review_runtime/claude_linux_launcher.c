#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) && !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif

#define PROXY_PORT 3128
#define LISTENER_ATTEMPTS 100
#define LISTENER_DELAY_NS 20000000L
#define PATH_BUFFER_SIZE 4096

static volatile sig_atomic_t forwarded_signal = 0;
static volatile sig_atomic_t proxy_pid = -1;
static volatile sig_atomic_t workload_pid = -1;
static const int forwarded_signals[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT};

static void handle_signal(int signum) {
    forwarded_signal = signum;
    if (workload_pid > 0) {
        (void)kill(-(pid_t)workload_pid, signum);
    }
    if (proxy_pid > 0) {
        (void)kill(-(pid_t)proxy_pid, signum);
    }
}

static int install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    for (size_t index = 0;
         index < sizeof(forwarded_signals) / sizeof(forwarded_signals[0]);
         ++index) {
        if (sigaction(forwarded_signals[index], &action, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int forwarded_signal_set(sigset_t *signals) {
    if (sigemptyset(signals) != 0) {
        return -1;
    }
    for (size_t index = 0;
         index < sizeof(forwarded_signals) / sizeof(forwarded_signals[0]);
         ++index) {
        if (sigaddset(signals, forwarded_signals[index]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int block_forwarded_signals(sigset_t *previous_mask) {
    sigset_t signals;
    if (forwarded_signal_set(&signals) != 0) {
        return -1;
    }
    return sigprocmask(SIG_BLOCK, &signals, previous_mask);
}

static int restore_signal_mask(const sigset_t *mask) {
    return sigprocmask(SIG_SETMASK, mask, NULL);
}

static int pending_forwarded_signal(void) {
    if (forwarded_signal != 0) {
        return (int)forwarded_signal;
    }
    sigset_t pending;
    if (sigpending(&pending) != 0) {
        return -1;
    }
    for (size_t index = 0;
         index < sizeof(forwarded_signals) / sizeof(forwarded_signals[0]);
         ++index) {
        int member = sigismember(&pending, forwarded_signals[index]);
        if (member < 0) {
            return -1;
        }
        if (member == 1) {
            return forwarded_signals[index];
        }
    }
    return 0;
}

static int prepare_child_signal_state(const sigset_t *restore_mask) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (size_t index = 0;
         index < sizeof(forwarded_signals) / sizeof(forwarded_signals[0]);
         ++index) {
        if (sigaction(forwarded_signals[index], &action, NULL) != 0) {
            return -1;
        }
    }
    if (raise(SIGSTOP) != 0) {
        return -1;
    }
    return restore_signal_mask(restore_mask);
}

static int establish_child_process_group(pid_t child) {
    for (;;) {
        if (setpgid(child, child) == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EACCES || errno == EPERM) {
            pid_t group = getpgid(child);
            if (group == child) {
                return 0;
            }
        }
        return -1;
    }
}

static int wait_for_child_launch_gate(pid_t child) {
    int status = 0;
    for (;;) {
        pid_t waited = waitpid(child, &status, WUNTRACED);
        if (waited == child) {
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                return 0;
            }
            errno = ECHILD;
            return -1;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
}

static int release_child_process_group(pid_t child) {
    return kill(-child, SIGCONT);
}

static bool is_absolute_path(const char *path) {
    return path != NULL && path[0] == '/' && strlen(path) < PATH_BUFFER_SIZE;
}

static int stream_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int descriptor_flags = fcntl(fd, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static void redirect_to_dev_null(void) {
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        _exit(125);
    }
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
        _exit(125);
    }
    if (fd > STDERR_FILENO) {
        close(fd);
    }
}

static int open_loopback(void) {
    int fd = stream_socket();
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(PROXY_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int connect_loopback(void) {
    int fd = open_loopback();
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int probe_proxy_relay(void) {
    static const char request[] =
        "CONNECT example.invalid:443 HTTP/1.1\r\n"
        "Host: example.invalid:443\r\n"
        "Connection: close\r\n\r\n";
    int fd = open_loopback();
    if (fd < 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < sizeof(request) - 1) {
        ssize_t written = write(fd, request + offset, sizeof(request) - 1 - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += (size_t)written;
    }
    char response[4097];
    size_t response_size = 0;
    for (int attempt = 0; attempt < 10 && response_size < sizeof(response) - 1;
         ++attempt) {
        struct pollfd poll_descriptor = {.fd = fd, .events = POLLIN, .revents = 0};
        int polled;
        do {
            polled = poll(&poll_descriptor, 1, 200);
        } while (polled < 0 && errno == EINTR);
        if (polled < 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (polled == 0) {
            continue;
        }
        ssize_t count;
        do {
            count = read(fd, response + response_size, sizeof(response) - 1 - response_size);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (count == 0) {
            break;
        }
        response_size += (size_t)count;
        response[response_size] = '\0';
        if (strstr(response, "\r\n") != NULL) {
            break;
        }
    }
    int saved_errno = errno;
    close(fd);
    if (response_size == 0) {
        errno = saved_errno == 0 ? ETIMEDOUT : saved_errno;
        return -1;
    }
    response[response_size] = '\0';
    if (strncmp(response, "HTTP/1.1 403 Forbidden\r\n", 24) != 0 &&
        strncmp(response, "HTTP/1.0 403 Forbidden\r\n", 24) != 0) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int wait_for_proxy_listener(pid_t child) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = LISTENER_DELAY_NS};
    for (int attempt = 0; attempt < LISTENER_ATTEMPTS; ++attempt) {
        if (forwarded_signal != 0) {
            errno = EINTR;
            return -1;
        }
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            errno = ECHILD;
            return -1;
        }
        if (waited < 0 && errno != EINTR) {
            return -1;
        }
        if (forwarded_signal != 0) {
            errno = EINTR;
            return -1;
        }
        if (connect_loopback() == 0) {
            if (forwarded_signal != 0) {
                errno = EINTR;
                return -1;
            }
            return 0;
        }
        (void)nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static pid_t start_proxy(
    const char *socat_path,
    const char *proxy_path,
    const sigset_t *restore_mask
) {
    char unix_argument[PATH_BUFFER_SIZE + 32];
    int length = snprintf(
        unix_argument,
        sizeof(unix_argument),
        "UNIX-CONNECT:%s",
        proxy_path
    );
    if (length <= 0 || (size_t)length >= sizeof(unix_argument)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    pid_t child = fork();
    if (child != 0) {
        if (child > 0 && establish_child_process_group(child) != 0) {
            int saved_errno = errno;
            (void)kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
            }
            errno = saved_errno;
            return -1;
        }
        if (child > 0 && wait_for_child_launch_gate(child) != 0) {
            int saved_errno = errno;
            (void)kill(-child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
            }
            errno = saved_errno;
            return -1;
        }
        return child;
    }
    if (setpgid(0, 0) != 0 || prepare_child_signal_state(restore_mask) != 0) {
        _exit(125);
    }
    redirect_to_dev_null();
    execl(
        socat_path,
        socat_path,
        "TCP4-LISTEN:3128,bind=127.0.0.1,reuseaddr,fork",
        unix_argument,
        (char *)NULL
    );
    _exit(127);
}

static pid_t start_workload(char *const argv[], const sigset_t *restore_mask) {
    pid_t child = fork();
    if (child != 0) {
        if (child > 0 && establish_child_process_group(child) != 0) {
            int saved_errno = errno;
            (void)kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
            }
            errno = saved_errno;
            return -1;
        }
        if (child > 0 && wait_for_child_launch_gate(child) != 0) {
            int saved_errno = errno;
            (void)kill(-child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
            }
            errno = saved_errno;
            return -1;
        }
        return child;
    }
    if (setpgid(0, 0) != 0 || prepare_child_signal_state(restore_mask) != 0) {
        _exit(125);
    }
    execv(argv[0], argv);
    _exit(127);
}

static void stop_process_group(pid_t pid) {
    if (pid <= 0) {
        return;
    }
    (void)kill(-pid, SIGTERM);
    (void)kill(-pid, SIGCONT);
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000L};
    for (int attempt = 0; attempt < 10; ++attempt) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid || (waited < 0 && errno == ECHILD)) {
            return;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        (void)nanosleep(&delay, NULL);
    }
    (void)kill(-pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
}

static int wait_for_workload(pid_t child) {
    int status = 0;
    for (;;) {
        pid_t waited = waitpid(child, &status, 0);
        if (waited == child) {
            break;
        }
        if (waited < 0 && errno == EINTR) {
            if (forwarded_signal != 0) {
                (void)kill(-child, forwarded_signal);
            }
            continue;
        }
        return 125;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 125;
}

static int read_workspace_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    char byte = 0;
    ssize_t count = read(fd, &byte, 1);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return count < 0 ? -1 : 0;
}

static int require_write_denied(const char *directory) {
    char path[PATH_BUFFER_SIZE];
    int length = snprintf(
        path,
        sizeof(path),
        "%s/.claude-linux-write-probe-%ld",
        directory,
        (long)getpid()
    );
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
        close(fd);
        (void)unlink(path);
        errno = EPERM;
        return -1;
    }
    if (errno != EROFS && errno != EACCES && errno != EPERM) {
        return -1;
    }
    return 0;
}

static int require_write_allowed(const char *directory) {
    char path[PATH_BUFFER_SIZE];
    int length = snprintf(
        path,
        sizeof(path),
        "%s/.claude-linux-write-probe-%ld",
        directory,
        (long)getpid()
    );
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    const char marker[] = "ok";
    ssize_t written = write(fd, marker, sizeof(marker) - 1);
    int saved_errno = errno;
    if (fsync(fd) != 0) {
        written = -1;
        saved_errno = errno;
    }
    close(fd);
    (void)unlink(path);
    errno = saved_errno;
    return written == (ssize_t)(sizeof(marker) - 1) ? 0 : -1;
}

static int require_hidden(const char *path) {
    struct stat metadata;
    if (lstat(path, &metadata) == 0) {
        errno = EPERM;
        return -1;
    }
    return errno == ENOENT ? 0 : -1;
}

static int require_direct_network_denied(void) {
    int fd = stream_socket();
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(443);
    if (inet_pton(AF_INET, "1.1.1.1", &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(fd);
    if (result == 0) {
        errno = EPERM;
        return -1;
    }
    if (saved_errno != ENETUNREACH && saved_errno != EHOSTUNREACH &&
        saved_errno != ENETDOWN) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int run_probe(int argc, char *argv[]) {
    if (argc != 7 || !is_absolute_path(argv[2]) || !is_absolute_path(argv[3]) ||
        !is_absolute_path(argv[4]) || !is_absolute_path(argv[5]) ||
        !is_absolute_path(argv[6])) {
        fprintf(stderr, "invalid isolation probe arguments\n");
        return 125;
    }
    if (read_workspace_file(argv[2]) != 0) {
        perror("workspace read probe");
        return 1;
    }
    if (require_write_denied(argv[3]) != 0) {
        perror("workspace write-denial probe");
        return 1;
    }
    if (require_write_allowed(argv[4]) != 0 || require_write_allowed(argv[5]) != 0) {
        perror("helper writable-directory probe");
        return 1;
    }
    if (require_hidden(argv[6]) != 0 || require_hidden("/mnt") != 0 ||
        require_hidden("/etc/claude-code") != 0) {
        perror("hidden host path probe");
        return 1;
    }
    if (probe_proxy_relay() != 0) {
        perror("proxy Unix-relay denial probe");
        return 1;
    }
    if (require_direct_network_denied() != 0) {
        perror("direct-network denial probe");
        return 1;
    }
    if (fputs("claude-linux-isolation-probe: ok\n", stdout) == EOF ||
        fflush(stdout) != 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    umask(077);
    if (argc >= 2 && strcmp(argv[1], "--probe") == 0) {
        return run_probe(argc, argv);
    }
    if (argc < 7 || strcmp(argv[1], "--proxy") != 0 ||
        strcmp(argv[3], "--socat") != 0 || strcmp(argv[5], "--") != 0 ||
        !is_absolute_path(argv[2]) || !is_absolute_path(argv[4]) ||
        !is_absolute_path(argv[6])) {
        fprintf(stderr, "invalid launcher arguments\n");
        return 125;
    }
    if (install_signal_handlers() != 0) {
        perror("signal setup");
        return 125;
    }
    sigset_t proxy_restore_mask;
    if (block_forwarded_signals(&proxy_restore_mask) != 0) {
        perror("signal block before proxy launch");
        return 125;
    }
    int pending_signal = pending_forwarded_signal();
    if (pending_signal < 0) {
        int saved_errno = errno;
        (void)restore_signal_mask(&proxy_restore_mask);
        errno = saved_errno;
        perror("pending signal inspection before proxy launch");
        return 125;
    }
    if (pending_signal != 0) {
        (void)restore_signal_mask(&proxy_restore_mask);
        return 128 + pending_signal;
    }
    pid_t proxy = start_proxy(argv[4], argv[2], &proxy_restore_mask);
    if (proxy < 0) {
        int saved_errno = errno;
        (void)restore_signal_mask(&proxy_restore_mask);
        errno = saved_errno;
        perror("proxy launch");
        return 125;
    }
    proxy_pid = proxy;
    if (restore_signal_mask(&proxy_restore_mask) != 0) {
        perror("signal restore after proxy launch");
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    if (forwarded_signal != 0) {
        int result = 128 + (int)forwarded_signal;
        stop_process_group(proxy);
        proxy_pid = -1;
        return result;
    }
    if (release_child_process_group(proxy) != 0) {
        perror("proxy launch gate release");
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    if (forwarded_signal != 0) {
        int result = 128 + (int)forwarded_signal;
        stop_process_group(proxy);
        proxy_pid = -1;
        return result;
    }
    if (wait_for_proxy_listener(proxy) != 0) {
        int signal_number = (int)forwarded_signal;
        if (signal_number == 0) {
            perror("proxy readiness");
        }
        stop_process_group(proxy);
        proxy_pid = -1;
        return signal_number == 0 ? 125 : 128 + signal_number;
    }
    sigset_t workload_restore_mask;
    if (block_forwarded_signals(&workload_restore_mask) != 0) {
        perror("signal block before workload launch");
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    pending_signal = pending_forwarded_signal();
    if (pending_signal < 0) {
        int saved_errno = errno;
        (void)restore_signal_mask(&workload_restore_mask);
        errno = saved_errno;
        perror("pending signal inspection before workload launch");
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    if (pending_signal != 0) {
        (void)restore_signal_mask(&workload_restore_mask);
        stop_process_group(proxy);
        proxy_pid = -1;
        return 128 + pending_signal;
    }
    pid_t workload = start_workload(&argv[6], &workload_restore_mask);
    if (workload < 0) {
        int saved_errno = errno;
        (void)restore_signal_mask(&workload_restore_mask);
        errno = saved_errno;
        perror("workload launch");
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    workload_pid = workload;
    if (restore_signal_mask(&workload_restore_mask) != 0) {
        perror("signal restore after workload launch");
        stop_process_group(workload);
        workload_pid = -1;
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    if (forwarded_signal != 0) {
        int result = 128 + (int)forwarded_signal;
        stop_process_group(workload);
        workload_pid = -1;
        stop_process_group(proxy);
        proxy_pid = -1;
        return result;
    }
    if (release_child_process_group(workload) != 0) {
        perror("workload launch gate release");
        stop_process_group(workload);
        workload_pid = -1;
        stop_process_group(proxy);
        proxy_pid = -1;
        return 125;
    }
    if (forwarded_signal != 0) {
        int result = 128 + (int)forwarded_signal;
        stop_process_group(workload);
        workload_pid = -1;
        stop_process_group(proxy);
        proxy_pid = -1;
        return result;
    }
    int result = wait_for_workload(workload);
    workload_pid = -1;
    stop_process_group(proxy);
    proxy_pid = -1;
    if (forwarded_signal != 0) {
        return 128 + (int)forwarded_signal;
    }
    return result;
}
