#define __STDC_WANT_LIB_EXT1__ 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// This executable is exposed to Claude Code as `security`, but it supports only
// the exact local-login lookup and stdin refresh-update forms used by supported
// Claude Code releases. The parent helper keeps credentials in memory during
// the review, validates refresh updates, and performs guarded post-review
// write-back to the selected host credential source. Other Keychain operations
// are rejected.
static const char *const kService = "Claude Code-credentials";
static const char *const kPortEnvironment = "CODEX_CLAUDE_KEYCHAIN_BROKER_PORT";
static const char *const kIdentitySocketEnvironment =
    "CODEX_CLAUDE_KEYCHAIN_BROKER_IDENTITY_SOCKET";
static const uint32_t kMaximumCredentialLength = 1024U * 1024U;
static const size_t kCapabilityLength = 32U;

static void clear_sensitive(void *buffer, size_t length) {
  if (length == 0U) {
    return;
  }
  if (buffer == NULL || memset_s(buffer, length, 0, length) != 0) {
    _exit(1);
  }
}

static int is_valid_account(const char *account) {
  if (account == NULL || *account == '\0') {
    return 0;
  }
  for (const unsigned char *cursor = (const unsigned char *)account;
       *cursor != '\0'; cursor++) {
    if (!((*cursor >= 'a' && *cursor <= 'z') ||
          (*cursor >= 'A' && *cursor <= 'Z') ||
          (*cursor >= '0' && *cursor <= '9') || *cursor == '.' ||
          *cursor == '_' || *cursor == '-')) {
      return 0;
    }
  }
  return 1;
}

static int write_all(int descriptor, const void *buffer, size_t length) {
  const unsigned char *cursor = buffer;
  while (length > 0) {
    ssize_t written = write(descriptor, cursor, length);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    cursor += (size_t)written;
    length -= (size_t)written;
  }
  return 0;
}

static int read_all(int descriptor, void *buffer, size_t length) {
  unsigned char *cursor = buffer;
  while (length > 0) {
    ssize_t received = read(descriptor, cursor, length);
    if (received <= 0) {
      if (received < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    cursor += (size_t)received;
    length -= (size_t)received;
  }
  return 0;
}

static int broker_port(void) {
  const char *raw = getenv(kPortEnvironment);
  if (raw == NULL || *raw == '\0') {
    return -1;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || value < 1 || value > 65535) {
    return -1;
  }
  return (int)value;
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

static int broker_capability(unsigned char output[32]) {
  const char *path = getenv(kIdentitySocketEnvironment);
  if (path == NULL || *path == '\0' ||
      strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
    return -1;
  }
  int client = socket(AF_UNIX, SOCK_STREAM, 0);
  if (client < 0) {
    return -1;
  }
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  memcpy(address.sun_path, path, strlen(path) + 1U);
  socklen_t length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1U);
  int result = connect(client, (struct sockaddr *)&address, length) == 0 &&
                       read_all(client, output, kCapabilityLength) == 0
                   ? 0
                   : -1;
  close(client);
  return result;
}

static int decode_hex(const char *hex, size_t hex_length,
                      unsigned char **credential, uint32_t *length) {
  if (hex_length == 0 || hex_length % 2U != 0 ||
      hex_length / 2U > kMaximumCredentialLength) {
    return -1;
  }
  size_t decoded_length = hex_length / 2U;
  unsigned char *decoded = malloc(decoded_length);
  if (decoded == NULL) {
    return -1;
  }
  for (size_t index = 0; index < decoded_length; index++) {
    int high = hex_nibble(hex[index * 2U]);
    int low = hex_nibble(hex[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      clear_sensitive(decoded, decoded_length);
      free(decoded);
      return -1;
    }
    decoded[index] = (unsigned char)((high << 4) | low);
  }
  *credential = decoded;
  *length = (uint32_t)decoded_length;
  return 0;
}

static int read_update_script(const char *account, unsigned char **credential,
                              uint32_t *length) {
  size_t maximum = (size_t)kMaximumCredentialLength * 2U + 512U;
  char *script = malloc(maximum + 1U);
  if (script == NULL) {
    return -1;
  }
  size_t used = 0;
  while (used < maximum) {
    ssize_t received = read(STDIN_FILENO, script + used, maximum - used);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      clear_sensitive(script, used);
      free(script);
      return -1;
    }
    if (received == 0) {
      break;
    }
    used += (size_t)received;
  }
  if (used == maximum) {
    char overflow = 0;
    ssize_t overflow_received = read(STDIN_FILENO, &overflow, 1);
    clear_sensitive(&overflow, sizeof(overflow));
    if (overflow_received != 0) {
      clear_sensitive(script, used);
      free(script);
      return -1;
    }
  }
  size_t sensitive_length = used;
  script[used] = '\0';
  char prefix[512] = {0};
  int prefix_length = snprintf(
      prefix, sizeof(prefix),
      "add-generic-password -U -a \"%s\" -s \"%s\" -X \"", account, kService);
  if (prefix_length < 0 || (size_t)prefix_length >= sizeof(prefix) ||
      used <= (size_t)prefix_length + 1U ||
      memcmp(script, prefix, (size_t)prefix_length) != 0) {
    clear_sensitive(script, sensitive_length);
    free(script);
    return -1;
  }
  if (script[used - 1U] == '\n') {
    used--;
  }
  if (used <= (size_t)prefix_length || script[used - 1U] != '"') {
    clear_sensitive(script, sensitive_length);
    free(script);
    return -1;
  }
  size_t hex_length = used - (size_t)prefix_length - 1U;
  int result =
      decode_hex(script + prefix_length, hex_length, credential, length);
  clear_sensitive(script, sensitive_length);
  free(script);
  return result;
}

static void clear_credential(unsigned char **credential, uint32_t length) {
  if (*credential != NULL) {
    clear_sensitive(*credential, length);
    free(*credential);
    *credential = NULL;
  }
}

int main(int argc, char *argv[]) {
  if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) {
    return 1;
  }
  struct passwd *user = getpwuid(getuid());
  if (user == NULL || user->pw_name == NULL) {
    return 1;
  }
  const char *account =
      is_valid_account(user->pw_name) ? user->pw_name : "claude-code-user";
  int is_read = argc == 7 && strcmp(argv[1], "find-generic-password") == 0 &&
                strcmp(argv[2], "-a") == 0 && strcmp(argv[3], account) == 0 &&
                strcmp(argv[4], "-w") == 0 && strcmp(argv[5], "-s") == 0 &&
                strcmp(argv[6], kService) == 0;
  unsigned char *updated_credential = NULL;
  uint32_t updated_length = 0;
  int is_update = argc == 2 && strcmp(argv[1], "-i") == 0;
  if (!is_read && !is_update) {
    return 64;
  }

  int port = broker_port();
  if (port < 0) {
    clear_credential(&updated_credential, updated_length);
    return 1;
  }
  int client = socket(AF_INET, SOCK_STREAM, 0);
  if (client < 0) {
    clear_credential(&updated_credential, updated_length);
    return 1;
  }
  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_port = htons((uint16_t)port),
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) {
    clear_credential(&updated_credential, updated_length);
    close(client);
    return 1;
  }

  unsigned char capability[32] = {0};
  if (broker_capability(capability) != 0 ||
      write_all(client, capability, sizeof(capability)) != 0) {
    clear_sensitive(capability, sizeof(capability));
    clear_credential(&updated_credential, updated_length);
    close(client);
    return 1;
  }
  clear_sensitive(capability, sizeof(capability));
  unsigned char authorization = 1;
  if (read_all(client, &authorization, 1) != 0 || authorization != 0) {
    clear_credential(&updated_credential, updated_length);
    close(client);
    return 1;
  }

  if (is_update) {
    if (read_update_script(account, &updated_credential, &updated_length) !=
        0) {
      close(client);
      return 64;
    }
    uint32_t network_length = htonl(updated_length);
    unsigned char status = 1;
    int sent =
        write_all(client, "W", 1) == 0 &&
        write_all(client, &network_length, sizeof(network_length)) == 0 &&
        write_all(client, updated_credential, updated_length) == 0;
    clear_credential(&updated_credential, updated_length);
    if (!sent || read_all(client, &status, 1) != 0) {
      close(client);
      return 1;
    }
    close(client);
    return status == 0 ? 0 : 1;
  }

  if (write_all(client, "R", 1) != 0) {
    close(client);
    return 1;
  }

  uint32_t network_length = 0;
  if (read_all(client, &network_length, sizeof(network_length)) != 0) {
    close(client);
    return 1;
  }
  uint32_t length = ntohl(network_length);
  if (length == 0) {
    close(client);
    return 44;
  }
  if (length > kMaximumCredentialLength) {
    close(client);
    return 1;
  }
  unsigned char *credential = malloc(length);
  if (credential == NULL) {
    close(client);
    return 1;
  }
  if (read_all(client, credential, length) != 0) {
    clear_sensitive(credential, length);
    free(credential);
    close(client);
    return 1;
  }
  close(client);

  int result = 0;
  if (write_all(STDOUT_FILENO, credential, length) != 0 ||
      write_all(STDOUT_FILENO, "\n", 1) != 0) {
    result = 1;
  }
  clear_sensitive(credential, length);
  free(credential);
  return result;
}
