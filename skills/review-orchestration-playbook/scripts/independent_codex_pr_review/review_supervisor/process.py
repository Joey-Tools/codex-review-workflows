from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import pathlib
import platform
import resource
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


PROCESS_GROUP_MEMBER_CAP = 262_144


@dataclass(frozen=True)
class SpawnedProcess:
    pid: int
    pgid: int
    acknowledgement_fd: int
    passed_fd_numbers: tuple[int, ...]
    start_identity: str | None = None


class ForkedProcessClosureUnproven(RuntimeError):
    def __init__(
        self,
        process: SpawnedProcess,
        identity_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        self.process = process
        super().__init__(
            "post-fork process closure is unproven: "
            f"pid={process.pid}, "
            f"identity_error={type(identity_error).__name__}, "
            f"cleanup_error={type(cleanup_error).__name__}"
        )


@dataclass(frozen=True)
class AuthenticatedNoChildProcessProfile:
    leader_pid: int
    leader_pgid: int
    leader_start_identity: str


@dataclass(frozen=True)
class TerminalStatus:
    code: int
    status: int

    @property
    def exit_code(self) -> int:
        if self.code == os.CLD_EXITED:
            return self.status
        return 128 + self.status


@dataclass
class TerminationSchedule:
    grace_seconds: float
    drain_seconds: float
    term_sent_at: float | None = None
    kill_sent_at: float | None = None

    def request_term(self, *, now: float) -> bool:
        if self.term_sent_at is not None:
            return False
        self.term_sent_at = now
        return True

    def request_kill_if_due(self, *, now: float) -> bool:
        if self.term_sent_at is None or self.kill_sent_at is not None:
            return False
        if now < self.term_sent_at + self.grace_seconds:
            return False
        self.kill_sent_at = now
        return True

    @property
    def grace_deadline(self) -> float | None:
        if self.term_sent_at is None:
            return None
        return self.term_sent_at + self.grace_seconds

    @property
    def drain_deadline(self) -> float | None:
        if self.kill_sent_at is None:
            return None
        return self.kill_sent_at + self.drain_seconds


def cloexec_pipe() -> tuple[int, int]:
    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, False)
    os.set_inheritable(write_fd, False)
    return read_fd, write_fd


def _maximum_fd() -> int:
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return 1_048_576
    return min(int(soft), 1_048_576)


def _safe_duplicates(fds: Sequence[int]) -> list[int]:
    duplicates: list[int] = []
    for fd in fds:
        duplicates.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64))
    return duplicates


def _settle_unidentified_fork(
    process: SpawnedProcess,
    *,
    own_process_group: bool,
    deadline: float,
) -> None:
    try:
        os.kill(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    wait_terminal(process.pid, deadline=deadline)
    if own_process_group:
        while True:
            members = process_group_members(process.pid, deadline=deadline)
            if not any(pid != process.pid for pid in members):
                break
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("post-fork process-group cleanup timed out")
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    reap(process.pid, deadline=deadline)


def fork_exec(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    pass_fds: Sequence[int] = (),
    own_process_group: bool,
    search_path: bool = False,
) -> SpawnedProcess:
    ack_read, ack_write = cloexec_pipe()
    passed_targets = tuple(range(3, 3 + len(pass_fds)))
    ack_target = 3 + len(pass_fds)
    pid = os.fork()
    if pid != 0:
        os.close(ack_write)
        try:
            start_identity = process_start_identity(pid)
        except BaseException as identity_error:
            os.close(ack_read)
            process = SpawnedProcess(
                pid=pid,
                pgid=pid if own_process_group else os.getpgrp(),
                acknowledgement_fd=-1,
                passed_fd_numbers=passed_targets,
                start_identity=None,
            )
            cleanup_error: BaseException | None = None
            cleanup_control_flow: BaseException | None = None
            for cleanup_seconds in (2.0, 5.0):
                try:
                    _settle_unidentified_fork(
                        process,
                        own_process_group=own_process_group,
                        deadline=time.monotonic() + cleanup_seconds,
                    )
                except BaseException as error:
                    cleanup_error = error
                    if not isinstance(error, Exception):
                        cleanup_control_flow = error
                    continue
                if cleanup_control_flow is not None:
                    raise cleanup_control_flow
                raise identity_error
            assert cleanup_error is not None
            raise ForkedProcessClosureUnproven(
                process,
                identity_error,
                cleanup_error,
            ) from cleanup_error
        return SpawnedProcess(
            pid=pid,
            pgid=pid if own_process_group else os.getpgrp(),
            acknowledgement_fd=ack_read,
            passed_fd_numbers=passed_targets,
            start_identity=start_identity,
        )

    try:
        os.close(ack_read)
        sources = [stdin_fd, stdout_fd, stderr_fd, *pass_fds, ack_write]
        safe = _safe_duplicates(sources)
        for target, source in zip((0, 1, 2), safe[:3], strict=True):
            os.dup2(source, target, inheritable=True)
        offset = 3
        for target, source in zip(
            passed_targets, safe[offset : offset + len(pass_fds)], strict=True
        ):
            os.dup2(source, target, inheritable=True)
        ack_safe = safe[-1]
        os.dup2(ack_safe, ack_target, inheritable=False)
        for fd in safe:
            if fd > ack_target:
                os.close(fd)
        os.closerange(ack_target + 1, _maximum_fd())
        if own_process_group:
            os.setpgid(0, 0)
        os.chdir(cwd)
        if search_path:
            os.execvp(argv[0], list(argv))
        else:
            os.execv(argv[0], list(argv))
    except BaseException as error:
        try:
            payload = f"{getattr(error, 'errno', errno.EIO)}:{type(error).__name__}:{error}".encode(
                "utf-8", "replace"
            )[:4096]
            os.write(ack_target, payload)
        except BaseException:
            pass
        os._exit(127)


def await_exec(process: SpawnedProcess, *, deadline: float) -> None:
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(process.acknowledgement_fd, False)
        selector.register(process.acknowledgement_fd, selectors.EVENT_READ)
        payload = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("child exec acknowledgement timed out")
            if not selector.select(min(remaining, 0.1)):
                status = os.waitid(
                    os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                )
                if status is not None:
                    raise ChildProcessError("child exited before exec acknowledgement")
                continue
            chunk = os.read(process.acknowledgement_fd, 4096 - len(payload))
            if chunk:
                payload.extend(chunk)
                if len(payload) >= 4096:
                    raise ChildProcessError("child exec failure record is oversized")
                continue
            if payload:
                raise ChildProcessError(
                    "child exec failed: " + payload.decode("utf-8", "replace")
                )
            status = os.waitid(
                os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
            )
            if status is not None:
                raise ChildProcessError(
                    "child died concurrently with exec acknowledgement"
                )
            if process.pgid == process.pid and os.getpgid(process.pid) != process.pid:
                raise ChildProcessError(
                    "child process-group identity is invalid after exec"
                )
            if (
                not process.start_identity
                or process_start_identity(process.pid) != process.start_identity
            ):
                raise ChildProcessError(
                    "child process-start identity changed after exec"
                )
            return
    finally:
        selector.close()
        os.close(process.acknowledgement_fd)


def process_start_identity(pid: int) -> str:
    proc_stat = pathlib.Path(f"/proc/{pid}/stat")
    if proc_stat.is_file():
        raw = proc_stat.read_bytes()
        if len(raw) > 4096:
            raise ValueError("process stat record is oversized")
        closing = raw.rfind(b")")
        fields = raw[closing + 2 :].split()
        if closing < 0 or len(fields) < 20:
            raise ValueError("process stat record is malformed")
        return f"linux-start-ticks:{fields[19].decode('ascii')}"
    if platform.system() == "Darwin":

        class ProcBsdInfo(ctypes.Structure):
            _fields_ = (
                ("pbi_flags", ctypes.c_uint32),
                ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32),
                ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32),
                ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32),
                ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16),
                ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32),
                ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32),
                ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64),
            )

        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_pidinfo
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        function.restype = ctypes.c_int
        value = ProcBsdInfo()
        result = function(
            pid,
            3,
            0,
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
        if (
            result != ctypes.sizeof(value)
            or value.pbi_pid != pid
            or value.pbi_start_tvsec == 0
            or value.pbi_start_tvusec >= 1_000_000
        ):
            error_number = ctypes.get_errno()
            raise ValueError(
                "cannot obtain Darwin process-start identity"
                + (f": {os.strerror(error_number)}" if error_number else "")
            )
        return f"darwin-proc-start:{value.pbi_start_tvsec}:{value.pbi_start_tvusec}"
    completed = subprocess.run(
        ("/bin/ps", "-o", "lstart=", "-p", str(pid)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=2,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if completed.returncode != 0 or not 1 <= len(completed.stdout) <= 256:
        raise ValueError("cannot obtain a bounded process-start identity")
    return "ps-lstart:" + completed.stdout.decode("ascii", "strict").strip()


def terminal_status(pid: int) -> TerminalStatus | None:
    value = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if value is None:
        return None
    return TerminalStatus(code=value.si_code, status=value.si_status)


def wait_terminal(pid: int, *, deadline: float) -> TerminalStatus:
    while True:
        status = terminal_status(pid)
        if status is not None:
            return status
        if time.monotonic() >= deadline:
            raise TimeoutError("process terminal-state deadline expired")
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def reap(pid: int, *, deadline: float | None = None) -> int:
    while True:
        waited, raw = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return os.waitstatus_to_exitcode(raw)
        if deadline is None or time.monotonic() >= deadline:
            raise TimeoutError("process reap deadline expired")
        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))


def require_authenticated_no_child_process_profile(
    state: Mapping[str, Any],
    *,
    process: SpawnedProcess | None = None,
) -> AuthenticatedNoChildProcessProfile:
    leader = state.get("leader")
    if (
        not isinstance(leader, dict)
        or set(leader) != {"pid", "pgid", "start_identity"}
        or type(leader.get("pid")) is not int
        or leader["pid"] <= 1
        or leader.get("pgid") != leader["pid"]
        or not isinstance(leader.get("start_identity"), str)
        or not leader["start_identity"]
    ):
        raise ChildProcessError("reviewer leader identity evidence is malformed")
    profile = state.get("no_child_process_profile")
    if (
        not isinstance(profile, dict)
        or set(profile)
        != {
            "version",
            "authenticated",
            "kernel_enforced",
            "child_process_limit",
            "leader",
        }
        or type(profile.get("version")) is not int
        or profile["version"] != 1
        or profile.get("authenticated") is not True
        or profile.get("kernel_enforced") is not True
        or type(profile.get("child_process_limit")) is not int
        or profile["child_process_limit"] != 0
        or profile.get("leader") != leader
    ):
        raise ChildProcessError(
            "authenticated kernel no-child-process profile evidence is required"
        )
    evidence = AuthenticatedNoChildProcessProfile(
        leader_pid=leader["pid"],
        leader_pgid=leader["pgid"],
        leader_start_identity=leader["start_identity"],
    )
    if process is not None and (
        process.pid != evidence.leader_pid
        or process.pgid != evidence.leader_pgid
        or process.start_identity != evidence.leader_start_identity
    ):
        raise ChildProcessError(
            "no-child-process profile is not bound to the spawned leader"
        )
    return evidence


def _require_live_group_anchor(process: SpawnedProcess) -> None:
    if process.pid <= 1 or process.pgid != process.pid or not process.start_identity:
        raise ChildProcessError("process is not an anchored process-group leader")
    try:
        terminal = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as error:
        raise ChildProcessError(
            "process-group leader no longer has an unreaped child anchor"
        ) from error
    if terminal is not None:
        return
    try:
        actual_identity = process_start_identity(process.pid)
        actual_pgid = os.getpgid(process.pid)
    except (OSError, ValueError) as error:
        try:
            became_terminal = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            became_terminal = None
        if became_terminal is not None:
            return
        raise ChildProcessError(
            "process-group leader identity is no longer live"
        ) from error
    if actual_identity != process.start_identity or actual_pgid != process.pgid:
        raise ChildProcessError("process-group leader identity changed")


def signal_anchored_group(
    process: SpawnedProcess,
    signal_value: signal.Signals,
) -> bool:
    _require_live_group_anchor(process)
    try:
        os.killpg(process.pgid, signal_value)
    except ProcessLookupError:
        return False
    except PermissionError:
        if terminal_status(process.pid) is not None:
            return False
        raise
    return True


def anchored_group_exists(process: SpawnedProcess) -> bool:
    _require_live_group_anchor(process)
    try:
        os.killpg(process.pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _linux_process_group_members(
    process_group: int,
    *,
    deadline: float,
) -> tuple[int, ...]:
    members: set[int] = set()
    inspected = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise TimeoutError("process-group inspection deadline expired")
            if not entry.name.isascii() or not entry.name.isdigit():
                continue
            inspected += 1
            if inspected > PROCESS_GROUP_MEMBER_CAP:
                raise ValueError("process table exceeds its inspection cap")
            pid = int(entry.name)
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    f"/proc/{pid}/stat",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                raw = os.read(descriptor, 4097)
            except (FileNotFoundError, ProcessLookupError):
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if len(raw) > 4096:
                raise ValueError("process stat record is oversized")
            closing = raw.rfind(b")")
            fields = raw[closing + 2 :].split() if closing >= 0 else ()
            if len(fields) < 3:
                raise ValueError("process stat record is malformed")
            try:
                observed_group = int(fields[2], 10)
            except ValueError as error:
                raise ValueError("process stat group is malformed") from error
            if observed_group == process_group:
                members.add(pid)
    return tuple(sorted(members))


def _darwin_process_group_members(
    process_group: int,
    *,
    deadline: float,
) -> tuple[int, ...]:
    if time.monotonic() >= deadline:
        raise TimeoutError("process-group inspection deadline expired")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_listpids
    function.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_int
    buffer = (ctypes.c_int * PROCESS_GROUP_MEMBER_CAP)()
    buffer_bytes = ctypes.sizeof(buffer)
    ctypes.set_errno(0)
    result = function(2, process_group, buffer, buffer_bytes)
    if time.monotonic() >= deadline:
        raise TimeoutError("process-group inspection deadline expired")
    if result < 0 or result % ctypes.sizeof(ctypes.c_int) != 0:
        error_number = ctypes.get_errno()
        raise ValueError(
            "cannot enumerate Darwin process-group members"
            + (f": {os.strerror(error_number)}" if error_number else "")
        )
    if result >= buffer_bytes:
        raise ValueError("process group exceeds its inspection cap")
    count = result // ctypes.sizeof(ctypes.c_int)
    return tuple(sorted({pid for pid in buffer[:count] if pid > 0}))


def process_group_members(
    process_group: int,
    *,
    deadline: float,
) -> tuple[int, ...]:
    if process_group <= 1:
        raise ValueError("process-group identity is unsafe")
    system = platform.system()
    if system == "Linux":
        return _linux_process_group_members(process_group, deadline=deadline)
    if system == "Darwin":
        return _darwin_process_group_members(process_group, deadline=deadline)
    raise ValueError("process-group enumeration is unsupported on this platform")


def anchored_group_members(
    process: SpawnedProcess,
    *,
    deadline: float,
) -> tuple[int, ...]:
    _require_live_group_anchor(process)
    return process_group_members(process.pgid, deadline=deadline)


def reap_anchored_group(
    process: SpawnedProcess,
    *,
    deadline: float,
    settlement_state: Mapping[str, Any] | None = None,
) -> int:
    if settlement_state is None:
        raise ChildProcessError(
            "exact process settlement requires authenticated profile state"
        )
    require_authenticated_no_child_process_profile(
        settlement_state,
        process=process,
    )
    _require_live_group_anchor(process)
    wait_terminal(process.pid, deadline=deadline)
    return reap(process.pid, deadline=deadline)


def terminate_anchored_group(
    process: SpawnedProcess,
    *,
    grace_seconds: float,
    deadline: float,
    term_sent_at: float | None = None,
    kill_sent_at: float | None = None,
    settlement_state: Mapping[str, Any] | None = None,
) -> int:
    now = time.monotonic()
    if now >= deadline:
        raise TimeoutError("anchored process-group termination deadline expired")
    if term_sent_at is None:
        signal_anchored_group(process, signal.SIGTERM)
        term_sent_at = now
    grace_deadline = min(deadline, term_sent_at + grace_seconds)
    while time.monotonic() < grace_deadline:
        time.sleep(min(0.02, max(0.0, grace_deadline - time.monotonic())))
    if kill_sent_at is None:
        signal_anchored_group(process, signal.SIGKILL)
    return reap_anchored_group(
        process,
        deadline=deadline,
        settlement_state=settlement_state,
    )


def terminate_direct_process(
    process: SpawnedProcess,
    *,
    grace_seconds: float,
    deadline: float,
) -> int:
    status = terminal_status(process.pid)
    if status is None:
        try:
            os.kill(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        grace_deadline = min(deadline, time.monotonic() + grace_seconds)
        try:
            wait_terminal(process.pid, deadline=grace_deadline)
        except TimeoutError:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    wait_terminal(process.pid, deadline=deadline)
    return reap(process.pid, deadline=deadline)


def close_quietly(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
