from __future__ import annotations

import enum
import errno
import json
import os
import pathlib
import re
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Iterable


class ReviewError(RuntimeError):
    """A user-facing review helper failure."""


class InvalidReviewerExecutable(ReviewError):
    """A candidate executable failed deterministic identity validation."""


class RejectedReviewerCandidates(ReviewError):
    """Automatic discovery found candidates, but all failed identity validation."""


class ReviewTimeoutError(ReviewError):
    """A bounded reviewer subprocess exceeded its deadline."""


class ReviewOutputLimitError(ReviewError):
    """A bounded reviewer subprocess exceeded its output allowance."""


class ReviewOutputDrainError(ReviewError):
    """A reviewer output stream could not be drained completely."""


class ReviewProcessLeakError(ReviewError):
    """A reviewer subprocess exited while descendants retained its process group."""


class ReviewProcessSecondaryFailureDiagnostic(Exception):
    """Python 3.10-visible diagnostic for a secondary process failure."""


class ForwardedSignal(RuntimeError):
    """A termination signal forwarded to the active reviewer process group."""

    def __init__(self, signum: signal.Signals, *, detail: str | None = None) -> None:
        self.signum = signum
        self.detail = detail
        message = f"review orchestration received signal {int(signum)}"
        if detail:
            message += f"; {detail}"
        super().__init__(message)


class ProcessStartState(enum.Enum):
    NOT_STARTED = "not-started"
    UNKNOWN = "unknown"
    CONFIRMED = "confirmed"


@dataclass
class ProcessStartOwner:
    """Publish monotonic process-start state across Popen handoff gaps."""

    _state: ProcessStartState = ProcessStartState.NOT_STARTED
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    @property
    def state(self) -> ProcessStartState:
        with self._lock:
            return self._state

    def publish_starting(self) -> None:
        with self._lock:
            if self._state is ProcessStartState.NOT_STARTED:
                self._state = ProcessStartState.UNKNOWN

    def publish_started(self) -> None:
        with self._lock:
            self._state = ProcessStartState.CONFIRMED

    def may_have_started(self) -> bool:
        return self.state is not ProcessStartState.NOT_STARTED

    def started(self) -> bool:
        return self.state is ProcessStartState.CONFIRMED


def _is_process_control_flow_error(error: BaseException) -> bool:
    return not isinstance(error, Exception) or isinstance(error, ForwardedSignal)


@dataclass(frozen=True)
class Completed:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class BoundedCapture:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytearray
    stderr: bytearray


class _BytearrayWriter:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, payload: bytes) -> int:
        self.data.extend(payload)
        return len(payload)

    def flush(self) -> None:
        return None


TRUSTED_PATH = os.pathsep.join(
    (
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    )
)

BASE_ENV_KEYS = (
    "ALL_PROXY",
    "COLORTERM",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TERM",
    "USER",
    "XDG_CONFIG_HOME",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)

PROCESS_GROUP_TERM_GRACE_SECONDS = 0.5
PROCESS_GROUP_EXIT_GRACE_SECONDS = 0.5
PROCESS_GROUP_POLL_SECONDS = 0.05
DESCRIPTOR_CWD_HANDOFF_TIMEOUT_SECONDS = 10.0
GATED_ENVIRONMENT_MAGIC = b"CGR1"
MAX_GATED_ENVIRONMENT_BYTES = 8 * 1024 * 1024
FD_EXEC_ERROR_PREFIX = b"fd_exec.py: launch-error:"
_PROCESS_SPAWN_THREAD = threading.Thread


def write_text_atomic(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary_path.unlink(missing_ok=True)


def write_bytes_atomic_at(directory_fd: int, name: str, payload: bytes) -> None:
    """Atomically persist a private file relative to an already-bound directory."""

    if not name or pathlib.PurePath(name).name != name or name in {".", ".."}:
        raise ReviewError("bound runtime artifact name is invalid")
    temporary_name = f".{name}.{os.urandom(12).hex()}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        raise ReviewError(
            f"cannot persist bound runtime artifact {name}: {error}"
        ) from error
    finally:
        if handle is not None:
            handle.close()
        elif descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def write_text_atomic_at(directory_fd: int, name: str, text: str) -> None:
    try:
        payload = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReviewError(
            f"cannot encode bound runtime artifact {name}: {error}"
        ) from error
    write_bytes_atomic_at(directory_fd, name, payload)


def write_json_atomic_at(directory_fd: int, name: str, value: Any) -> None:
    try:
        text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    except (TypeError, ValueError) as error:
        raise ReviewError(
            f"cannot encode bound runtime JSON artifact {name}: {error}"
        ) from error
    write_text_atomic_at(directory_fd, name, text)


def write_json(path: pathlib.Path, value: Any) -> None:
    write_text_atomic(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReviewError(f"cannot read review state {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"review state is not a JSON object: {path}")
    return value


def tail_text(
    path: pathlib.Path,
    *,
    line_count: int = 40,
    byte_count: int = 64 * 1024,
) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - byte_count)
            handle.seek(start)
            data = handle.read(byte_count)
    except OSError:
        return ""
    if start:
        _partial, separator, remainder = data.partition(b"\n")
        if separator:
            data = remainder
    lines = data.decode("utf-8", errors="replace").splitlines()
    return "\n".join(lines[-line_count:])


def run(
    argv: Iterable[str],
    *,
    cwd: pathlib.Path | None = None,
    cwd_fd: int | None = None,
    pass_fds: Iterable[int] = (),
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    check: bool = False,
    stdout_path: pathlib.Path | None = None,
    stderr_path: pathlib.Path | None = None,
    stdout_file: BinaryIO | None = None,
    stderr_file: BinaryIO | None = None,
    capture_limit_bytes: int = 4 * 1024 * 1024,
    timeout_seconds: float | None = None,
    output_file_limit_bytes: int | None = None,
    on_process_starting: Callable[[], None] | None = None,
    on_process_started: Callable[[], None] | None = None,
    on_process_quiescent: Callable[[], None] | None = None,
) -> Completed:
    command = tuple(str(item) for item in argv)
    if not command:
        raise ReviewError("command must not be empty")
    inherited_fds = _validate_pass_fds(pass_fds)
    if cwd is not None and cwd_fd is not None:
        raise ReviewError("cwd and cwd_fd are mutually exclusive")
    path_logging = stdout_path is not None or stderr_path is not None
    handle_logging = stdout_file is not None or stderr_file is not None
    if (stdout_path is None) != (stderr_path is None):
        raise ReviewError("stdout_path and stderr_path must be provided together")
    if (stdout_file is None) != (stderr_file is None):
        raise ReviewError("stdout_file and stderr_file must be provided together")
    if path_logging and handle_logging:
        raise ReviewError("logged output paths and files are mutually exclusive")
    logged_output = path_logging or handle_logging
    if output_file_limit_bytes is not None and (not logged_output):
        raise ReviewError("output_file_limit_bytes requires logged output paths")
    if output_file_limit_bytes is not None and timeout_seconds is None:
        raise ReviewError("output_file_limit_bytes requires timeout_seconds")
    if timeout_seconds is not None and not logged_output:
        raise ReviewError("timeout_seconds requires logged output paths")
    if on_process_starting is not None and not logged_output:
        raise ReviewError("on_process_starting requires logged output paths")
    if on_process_started is not None and not logged_output:
        raise ReviewError("on_process_started requires logged output paths")
    if on_process_quiescent is not None and not logged_output:
        raise ReviewError("on_process_quiescent requires logged output paths")
    if output_file_limit_bytes is not None and output_file_limit_bytes <= 0:
        raise ReviewError("output_file_limit_bytes must be positive")
    try:
        if not logged_output:
            spawn_command, cwd_pass_fds = _descriptor_cwd_command(
                command,
                cwd_fd,
            )
            completed = subprocess.run(
                spawn_command,
                cwd=cwd,
                env=env,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                pass_fds=_merge_pass_fds(inherited_fds, cwd_pass_fds),
            )
            result = Completed(
                command, completed.returncode, completed.stdout, completed.stderr
            )
            _raise_descriptor_exec_failure(result, enabled=cwd_fd is not None)
        elif path_logging:
            assert stdout_path is not None
            assert stderr_path is not None
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            with (
                stdout_path.open("w+b") as stdout_handle,
                stderr_path.open("w+b") as stderr_handle,
            ):
                returncode = _run_logged_process(
                    command,
                    cwd=cwd,
                    cwd_fd=cwd_fd,
                    pass_fds=inherited_fds,
                    env=env,
                    stdin=stdin,
                    stdout_handle=stdout_handle,
                    stderr_handle=stderr_handle,
                    timeout_seconds=timeout_seconds,
                    stdout_file_limit_bytes=output_file_limit_bytes,
                    stderr_file_limit_bytes=output_file_limit_bytes,
                    on_process_starting=on_process_starting,
                    on_process_started=on_process_started,
                    on_process_quiescent=on_process_quiescent,
                )
                result = Completed(
                    command,
                    returncode,
                    _read_bounded_handle(stdout_handle, capture_limit_bytes),
                    _read_bounded_handle(stderr_handle, capture_limit_bytes),
                )
        else:
            assert stdout_file is not None
            assert stderr_file is not None
            _prepare_capture_handle(stdout_file)
            _prepare_capture_handle(stderr_file)
            returncode = _run_logged_process(
                command,
                cwd=cwd,
                cwd_fd=cwd_fd,
                pass_fds=inherited_fds,
                env=env,
                stdin=stdin,
                stdout_handle=stdout_file,
                stderr_handle=stderr_file,
                timeout_seconds=timeout_seconds,
                stdout_file_limit_bytes=output_file_limit_bytes,
                stderr_file_limit_bytes=output_file_limit_bytes,
                on_process_starting=on_process_starting,
                on_process_started=on_process_started,
                on_process_quiescent=on_process_quiescent,
            )
            result = Completed(
                command,
                returncode,
                _read_bounded_handle(stdout_file, capture_limit_bytes),
                _read_bounded_handle(stderr_file, capture_limit_bytes),
            )
    except subprocess.TimeoutExpired as error:
        raise ReviewTimeoutError(
            f"command timed out after {timeout_seconds} seconds: {' '.join(command)}"
        ) from error
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise ReviewError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{detail}"
        )
    return result


def _prepare_capture_handle(handle: BinaryIO) -> None:
    try:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewError("logged output handle is not a regular file")
        handle.seek(0)
        handle.truncate(0)
        handle.flush()
    except OSError as error:
        raise ReviewError(f"cannot prepare logged output handle: {error}") from error


def _validate_pass_fds(descriptors: Iterable[int]) -> tuple[int, ...]:
    result: list[int] = []
    for descriptor in descriptors:
        if isinstance(descriptor, bool) or not isinstance(descriptor, int):
            raise ReviewError("inherited file descriptors must be integers")
        if descriptor < 0:
            raise ReviewError("inherited file descriptors must be non-negative")
        try:
            os.fstat(descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect inherited file descriptor {descriptor}: {error}"
            ) from error
        if descriptor not in result:
            result.append(descriptor)
    if result and os.name != "posix":
        raise ReviewError("inherited file descriptors require a POSIX runtime")
    return tuple(result)


def _merge_pass_fds(*groups: Iterable[int]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(descriptor for group in groups for descriptor in group))


@dataclass
class _FileDescriptorOwner:
    descriptor: int | None = None

    def close(self) -> None:
        if self.descriptor is None:
            return
        descriptor = self.descriptor
        self.descriptor = None
        os.close(descriptor)


def _pipe_above_standard_descriptors() -> tuple[int, int]:
    """Create a pipe whose ends cannot collide with child stdio remapping."""

    endpoints = [_FileDescriptorOwner(descriptor) for descriptor in os.pipe()]
    try:
        for index, source_owner in enumerate(tuple(endpoints)):
            descriptor = source_owner.descriptor
            assert descriptor is not None
            if descriptor >= 3:
                continue
            import fcntl

            duplicate_command = getattr(
                fcntl,
                "F_DUPFD_CLOEXEC",
                fcntl.F_DUPFD,
            )
            replacement_owner = _FileDescriptorOwner(
                int(fcntl.fcntl(descriptor, duplicate_command, 3))
            )
            try:
                if duplicate_command == fcntl.F_DUPFD:
                    assert replacement_owner.descriptor is not None
                    os.set_inheritable(replacement_owner.descriptor, False)
                source_owner.close()
                endpoints[index] = replacement_owner
            except BaseException:
                try:
                    replacement_owner.close()
                except OSError:
                    pass
                raise
        descriptors = tuple(owner.descriptor for owner in endpoints)
        assert all(descriptor is not None for descriptor in descriptors)
        for owner in endpoints:
            owner.descriptor = None
        return int(descriptors[0]), int(descriptors[1])
    except BaseException:
        for owner in endpoints:
            try:
                owner.close()
            except OSError:
                pass
        raise


def _encode_gated_environment(env: dict[str, str] | None) -> bytearray:
    source = os.environ if env is None else env
    try:
        items = tuple(source.items())
    except (AttributeError, RuntimeError) as error:
        raise ReviewError("cannot snapshot the supervised command environment") from error
    frame = bytearray(GATED_ENVIRONMENT_MAGIC + b"\x00\x00\x00\x00")
    encoded_keys: set[bytes] = set()
    payload_size = 0
    for key, value in items:
        if not isinstance(key, str) or not isinstance(value, str):
            raise ReviewError("supervised command environment entries must be strings")
        encoded_key = os.fsencode(key)
        encoded_value = os.fsencode(value)
        if not encoded_key or b"=" in encoded_key or b"\x00" in encoded_key:
            raise ReviewError("supervised command environment contains an invalid name")
        if b"\x00" in encoded_value:
            raise ReviewError("supervised command environment contains an invalid value")
        if encoded_key in encoded_keys:
            raise ReviewError(
                "supervised command environment contains duplicate encoded names"
            )
        encoded_keys.add(encoded_key)
        record = encoded_key + b"=" + encoded_value + b"\x00"
        payload_size += len(record)
        if payload_size > MAX_GATED_ENVIRONMENT_BYTES:
            raise ReviewError("supervised command environment exceeds the launch limit")
        frame.extend(record)
    frame[4:8] = payload_size.to_bytes(4, "big")
    return frame


def _wait_descriptor_ready(
    descriptor: int,
    *,
    writable: bool,
    timeout_seconds: float,
) -> bool:
    """Wait on a descriptor without select(2)'s FD_SETSIZE ceiling."""

    if os.name == "posix" and hasattr(select, "poll"):
        poller = select.poll()
        poller.register(descriptor, select.POLLOUT if writable else select.POLLIN)
        timeout_milliseconds = max(1, int(max(0.0, timeout_seconds) * 1000))
        return bool(poller.poll(timeout_milliseconds))
    if writable:
        _, ready, _ = select.select((), (descriptor,), (), timeout_seconds)
    else:
        ready, _, _ = select.select((descriptor,), (), (), timeout_seconds)
    return bool(ready)


def _read_bounded_handle(handle: BinaryIO, limit: int) -> bytes:
    if limit <= 0:
        raise ReviewError("capture_limit_bytes must be positive")
    try:
        handle.flush()
        size = os.fstat(handle.fileno()).st_size
        handle.seek(0)
        if size <= limit:
            return handle.read()
        head_size = limit // 2
        tail_size = limit - head_size
        head = handle.read(head_size)
        handle.seek(size - tail_size)
        tail = handle.read(tail_size)
    except OSError as error:
        raise ReviewError(f"cannot read bounded command output: {error}") from error
    return head + b"\n... bounded capture omitted middle bytes ...\n" + tail


def _descriptor_cwd_command(
    command: tuple[str, ...],
    cwd_fd: int | None,
    *,
    status_fd: int | None = None,
    gate_fd: int | None = None,
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    if cwd_fd is None and gate_fd is None:
        return command, ()
    if os.name != "posix":
        raise ReviewError("descriptor-backed launch requires a POSIX runtime")
    if cwd_fd is not None:
        try:
            metadata = os.fstat(cwd_fd)
        except OSError as error:
            raise ReviewError(
                f"cannot inspect descriptor-backed cwd: {error}"
            ) from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReviewError("descriptor-backed cwd is not a directory")
    launcher = pathlib.Path(__file__).with_name("fd_exec.py")
    if not launcher.is_file():
        raise ReviewError("descriptor-backed cwd launcher is unavailable")
    inherited_descriptors = tuple(
        descriptor
        for descriptor in (cwd_fd, status_fd, gate_fd)
        if descriptor is not None
    )
    if gate_fd is None:
        launcher_arguments = (
            str(cwd_fd),
            str(status_fd) if status_fd is not None else "-",
        )
    else:
        launcher_arguments = (
            "--gated",
            str(cwd_fd) if cwd_fd is not None else "-",
            str(status_fd) if status_fd is not None else "-",
            str(gate_fd),
        )
    return (
        (
            sys.executable,
            "-I",
            "-S",
            str(launcher),
            *launcher_arguments,
            *command,
        ),
        inherited_descriptors,
    )


def _descriptor_exec_error(payload: bytes, command: tuple[str, ...]) -> OSError:
    encoded_errno, separator, encoded_detail = payload.partition(b"\n")
    try:
        error_number = int(encoded_errno.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        error_number = errno.EIO
        encoded_detail = payload
    detail = encoded_detail.decode("utf-8", errors="replace").strip()
    if not separator or not detail:
        detail = "descriptor-backed reviewer launch failed"
    if error_number == errno.ENOENT:
        return FileNotFoundError(error_number, detail, command[0])
    return OSError(error_number, detail, command[0])


def _raise_descriptor_exec_failure(result: Completed, *, enabled: bool) -> None:
    if not enabled or result.returncode != 126:
        return
    if not result.stderr.startswith(FD_EXEC_ERROR_PREFIX):
        return
    payload = result.stderr[len(FD_EXEC_ERROR_PREFIX) :].lstrip()
    raise _descriptor_exec_error(payload, result.argv)


def run_bounded_capture(
    argv: Iterable[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    pass_fds: Iterable[int] = (),
    stdin: bytes | bytearray | None = None,
    timeout_seconds: float,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
) -> BoundedCapture:
    command = tuple(str(item) for item in argv)
    if not command:
        raise ReviewError("command must not be empty")
    inherited_fds = _validate_pass_fds(pass_fds)
    if stdout_limit_bytes <= 0 or stderr_limit_bytes <= 0:
        raise ReviewError("bounded capture limits must be positive")
    stdout = _BytearrayWriter()
    stderr = _BytearrayWriter()
    try:
        returncode = _run_logged_process(
            command,
            cwd=cwd,
            pass_fds=inherited_fds,
            env=env,
            stdin=stdin,
            stdout_handle=stdout,
            stderr_handle=stderr,
            timeout_seconds=timeout_seconds,
            stdout_file_limit_bytes=stdout_limit_bytes,
            stderr_file_limit_bytes=stderr_limit_bytes,
        )
    except subprocess.TimeoutExpired as error:
        stdout.data[:] = b"\x00" * len(stdout.data)
        stderr.data[:] = b"\x00" * len(stderr.data)
        raise ReviewTimeoutError(
            f"command timed out after {timeout_seconds} seconds: {' '.join(command)}"
        ) from error
    except Exception:
        stdout.data[:] = b"\x00" * len(stdout.data)
        stderr.data[:] = b"\x00" * len(stderr.data)
        raise
    return BoundedCapture(command, returncode, stdout.data, stderr.data)


def forwarded_signals() -> tuple[signal.Signals, ...]:
    forwarded = [signal.SIGTERM, signal.SIGINT]
    for name in ("SIGHUP", "SIGQUIT"):
        candidate = getattr(signal, name, None)
        if candidate is not None and candidate not in forwarded:
            forwarded.append(candidate)
    return tuple(forwarded)


@dataclass
class ForwardedSignalMaskOwner:
    """Retain mask ownership across a callee-return assignment boundary."""

    previous_mask: set[signal.Signals] | None = None
    active: bool = False
    restore_attempted: bool = False

    def publish(self, previous_mask: set[signal.Signals] | None) -> None:
        self.previous_mask = previous_mask
        self.active = True

    def owns(self, previous_mask: set[signal.Signals] | None) -> bool:
        return self.active and self.previous_mask is previous_mask

    def restore(
        self,
        restore: Callable[[set[signal.Signals] | None], None] | None = None,
    ) -> None:
        if not self.active:
            return
        if restore is None:
            restore = restore_signal_mask
        self.restore_attempted = True
        restore(self.previous_mask)
        self.active = False


def block_forwarded_signals(
    *,
    signal_mask_owner: ForwardedSignalMaskOwner | None = None,
) -> set[signal.Signals] | None:
    if (
        os.name != "posix"
        or threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "pthread_sigmask")
    ):
        return None
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    try:
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            forwarded_signals(),
        )
        if signal_mask_owner is not None:
            signal_mask_owner.publish(previous_mask)
    except BaseException as block_error:
        if (
            signal_mask_owner is None
            or not signal_mask_owner.owns(previous_mask)
        ):
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as restore_error:
                _attach_process_secondary_failure(
                    block_error,
                    restore_error,
                    context=(
                        "restoring the forwarded-signal mask after interrupted "
                        "mask acquisition"
                    ),
                )
        raise
    return previous_mask


def restore_signal_mask(previous: set[signal.Signals] | None) -> None:
    if previous is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _restore_forwarded_signal_mask_owner_bounded(
    signal_mask_owner: ForwardedSignalMaskOwner,
    *,
    restore: Callable[[set[signal.Signals] | None], None] | None = None,
) -> tuple[BaseException, ...]:
    failures: list[BaseException] = []
    for _attempt in range(2):
        if not signal_mask_owner.active:
            break
        try:
            signal_mask_owner.restore(restore)
        except BaseException as error:
            failures.append(error)
    return tuple(failures)


def _propagate_signal_mask_restore_failures(
    primary_error: BaseException | None,
    failures: tuple[BaseException, ...],
) -> None:
    if not failures:
        return
    candidates = (
        ((primary_error,) if primary_error is not None else ()) + failures
    )
    selected = next(
        (error for error in candidates if _is_process_control_flow_error(error)),
        primary_error if primary_error is not None else failures[0],
    )
    for error in candidates:
        if error is selected:
            continue
        context = "restoring the forwarded-signal mask"
        if error is primary_error:
            context = "process operation failed before mask restoration"
        _attach_process_secondary_failure(selected, error, context=context)
    if selected is not primary_error:
        raise selected


def unblock_forwarded_signals() -> None:
    if os.name == "posix" and hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, forwarded_signals())


def consume_pending_forwarded_signal() -> signal.Signals | None:
    if not hasattr(signal, "sigpending") or not hasattr(signal, "sigwait"):
        return None
    pending = set(signal.sigpending()).intersection(forwarded_signals())
    if not pending:
        return None
    ordered = sorted(pending, key=int)
    for pending_signal in ordered:
        signal.sigwait({pending_signal})
    return ordered[0]


def _process_group_exists(process_pid: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if sys.platform.startswith("linux"):
        live_members = _linux_process_group_has_live_members(process_pid)
        if live_members is not None:
            return live_members
    return True


def _linux_process_group_has_live_members(process_group: int) -> bool | None:
    try:
        entries = os.scandir("/proc")
    except OSError:
        return None
    try:
        with entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                try:
                    with open(
                        f"/proc/{entry.name}/stat",
                        "r",
                        encoding="utf-8",
                    ) as handle:
                        stat = handle.read(4096)
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
                try:
                    fields = stat.rsplit(") ", 1)[1].split()
                    state = fields[0]
                    member_group = int(fields[2])
                except (IndexError, ValueError):
                    return None
                if member_group == process_group and state not in {"X", "Z"}:
                    return True
    except OSError:
        return None
    return False


def signal_process_group(
    process: subprocess.Popen[bytes], signum: signal.Signals
) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signum)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            pass
    try:
        process.send_signal(signum)
    except ProcessLookupError:
        pass


def terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    initial_signal: signal.Signals = signal.SIGTERM,
    signal_already_sent: bool = False,
    grace_seconds: float = PROCESS_GROUP_TERM_GRACE_SECONDS,
) -> None:
    if os.name != "posix":
        if process.poll() is None:
            if not signal_already_sent:
                signal_process_group(process, initial_signal)
            try:
                process.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return
    if not _process_group_exists(process.pid):
        return
    if not signal_already_sent:
        signal_process_group(process, initial_signal)
    deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(PROCESS_GROUP_POLL_SECONDS)
    if _process_group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass


def _await_descriptor_exec_handoff(
    process: subprocess.Popen[bytes],
    descriptor: int,
    *,
    command: tuple[str, ...],
    operation_deadline: float | None = None,
    timeout_seconds: float | None = None,
) -> None:
    handoff_deadline = time.monotonic() + DESCRIPTOR_CWD_HANDOFF_TIMEOUT_SECONDS
    deadline = handoff_deadline
    if operation_deadline is not None:
        deadline = min(deadline, operation_deadline)
    payload = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if (
                operation_deadline is not None
                and operation_deadline <= handoff_deadline
            ):
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            raise ReviewTimeoutError(
                "descriptor-backed reviewer exec handoff timed out: "
                f"{' '.join(command)}"
            )
        try:
            readable = _wait_descriptor_ready(
                descriptor,
                writable=False,
                timeout_seconds=remaining,
            )
        except InterruptedError:
            continue
        if not readable:
            continue
        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > 4096:
            raise ReviewError("descriptor-backed reviewer exec handoff overflowed")
    if payload:
        try:
            process.wait(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        raise _descriptor_exec_error(bytes(payload), command)


@dataclass
class _ProcessSpawnOwner:
    """Retain or quiesce a Popen handle across the worker handoff."""

    process: subprocess.Popen[bytes] | None = None
    error: BaseException | None = None
    completed: threading.Event = field(default_factory=threading.Event)
    cleanup_completed: threading.Event = field(default_factory=threading.Event)
    cleanup_failures: list[BaseException] = field(default_factory=list)
    worker_cleaned_process: bool = False
    cleanup_signal: signal.Signals = signal.SIGTERM
    _claimed: bool = False
    _claimed_event: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def claimed(self) -> bool:
        with self._lock:
            return self._claimed

    def cancel(
        self,
        cancelled: threading.Event,
        cleanup_signal: signal.Signals,
    ) -> None:
        with self._lock:
            self.cleanup_signal = cleanup_signal
            cancelled.set()

    def claim(self, cancelled: threading.Event) -> subprocess.Popen[bytes]:
        with self._lock:
            if self.error is not None:
                raise self.error
            if cancelled.is_set():
                raise ReviewError("reviewer process spawn was cancelled")
            if self.process is None:
                raise ReviewError("reviewer process spawn completed without a handle")
            self._claimed = True
            self._claimed_event.set()
            return self.process

    def spawn(
        self,
        factory: Callable[[], subprocess.Popen[bytes]],
        ready: threading.Event,
        requested: threading.Event,
        cancelled: threading.Event,
        inherited_owners: tuple[_FileDescriptorOwner, ...],
    ) -> None:
        candidate: subprocess.Popen[bytes] | None = None
        worker_owns_candidate = False
        try:
            ready.set()
            requested.wait()
            if cancelled.is_set():
                self.cleanup_completed.set()
                return
            candidate = factory()
            with self._lock:
                self.process = candidate
                worker_owns_candidate = cancelled.is_set()
        except BaseException as error:
            with self._lock:
                self.error = error
        finally:
            for owner in inherited_owners:
                try:
                    owner.close()
                except BaseException as error:
                    self.cleanup_failures.append(error)
            self.completed.set()
        if candidate is None:
            self.cleanup_completed.set()
            return
        while not worker_owns_candidate:
            if self._claimed_event.wait(PROCESS_GROUP_POLL_SECONDS):
                self.cleanup_completed.set()
                return
            with self._lock:
                worker_owns_candidate = cancelled.is_set() and not self._claimed
        try:
            terminate_process_group(
                candidate,
                initial_signal=self.cleanup_signal,
                signal_already_sent=False,
            )
        except BaseException as error:
            self.cleanup_failures.append(error)
        for stream in (candidate.stdin, candidate.stdout, candidate.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except BaseException as error:
                self.cleanup_failures.append(error)
        self.worker_cleaned_process = not self.cleanup_failures
        self.cleanup_completed.set()


def _await_owned_process_spawn(
    owner: _ProcessSpawnOwner,
    thread: threading.Thread,
    cancelled: threading.Event,
    *,
    check_interruption: Callable[[], None],
    operation_deadline: float | None,
    command: tuple[str, ...],
    timeout_seconds: float | None,
) -> subprocess.Popen[bytes]:
    while not owner.completed.wait(PROCESS_GROUP_POLL_SECONDS):
        check_interruption()
        if operation_deadline is not None and time.monotonic() >= operation_deadline:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
    if owner.error is not None:
        raise owner.error
    check_interruption()
    process = owner.claim(cancelled)
    thread.join(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
    if thread.is_alive():
        raise ReviewProcessLeakError("reviewer process spawn worker did not quiesce")
    return process


def _write_exec_control(
    descriptor: int,
    payload: bytes | bytearray,
    *,
    deadline: float,
) -> None:
    view = memoryview(payload)
    offset = 0
    try:
        os.set_blocking(descriptor, False)
        while offset < len(view):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReviewTimeoutError("reviewer launch control write timed out")
            try:
                ready = _wait_descriptor_ready(
                    descriptor,
                    writable=True,
                    timeout_seconds=min(PROCESS_GROUP_POLL_SECONDS, remaining),
                )
            except InterruptedError:
                continue
            if not ready:
                continue
            try:
                written = os.write(descriptor, view[offset:])
            except BlockingIOError:
                continue
            except BrokenPipeError as error:
                raise ReviewError("reviewer launch gate closed before commit") from error
            if written <= 0:
                raise ReviewError("reviewer launch control write made no progress")
            offset += written
    finally:
        view.release()


def _release_exec_gate(
    descriptor: int,
    environment_frame: bytes | bytearray,
    *,
    deadline: float,
    before_commit: Callable[[], None],
) -> None:
    _write_exec_control(descriptor, environment_frame, deadline=deadline)
    before_commit()
    _write_exec_control(descriptor, b"G", deadline=deadline)


def _run_logged_process(
    command: tuple[str, ...],
    *,
    cwd: pathlib.Path | None,
    cwd_fd: int | None = None,
    pass_fds: tuple[int, ...] = (),
    env: dict[str, str] | None,
    stdin: bytes | bytearray | None,
    stdout_handle: BinaryIO,
    stderr_handle: BinaryIO,
    timeout_seconds: float | None = None,
    stdout_file_limit_bytes: int | None = None,
    stderr_file_limit_bytes: int | None = None,
    on_process_starting: Callable[[], None] | None = None,
    on_process_started: Callable[[], None] | None = None,
    on_process_quiescent: Callable[[], None] | None = None,
) -> int:
    if not command:
        raise ReviewError("command must not be empty")
    operation_deadline = (
        time.monotonic() + timeout_seconds if timeout_seconds is not None else None
    )
    process: subprocess.Popen[bytes] | None = None
    spawn_owner: _ProcessSpawnOwner | None = None
    spawn_thread: threading.Thread | None = None
    spawn_worker_ready: threading.Event | None = None
    spawn_requested: threading.Event | None = None
    spawn_cancelled: threading.Event | None = None
    spawn_thread_start_attempted = False
    spawn_thread_start_confirmed = False
    pending_signal: signal.Signals | None = None
    forwarded_signal_sent = False
    signal_deferral_active = False
    io_threads: list[threading.Thread] = []
    stop_io = threading.Event()
    drain_errors: list[Exception] = []
    process_cleanup_inconclusive = False
    primary_error: BaseException | None = None
    cleanup_failures: list[tuple[str, BaseException]] = []
    handoff_read = _FileDescriptorOwner()
    handoff_write = _FileDescriptorOwner()
    gate_read = _FileDescriptorOwner()
    gate_write = _FileDescriptorOwner()
    gated_environment = bytearray()

    def forward_signal(signum: int, _frame: object) -> None:
        nonlocal forwarded_signal_sent, pending_signal
        forwarded = signal.Signals(signum)
        pending_signal = forwarded
        active_process = process
        if (
            active_process is None
            and spawn_owner is not None
            and spawn_owner._claimed_event.is_set()
        ):
            active_process = spawn_owner.process
        if active_process is None:
            return
        if signal_deferral_active:
            return
        signal_process_group(active_process, forwarded)
        forwarded_signal_sent = True
        raise ForwardedSignal(forwarded)

    def close_launch_descriptor(owner: _FileDescriptorOwner) -> None:
        nonlocal signal_deferral_active
        previous_deferral = signal_deferral_active
        signal_deferral_active = True
        try:
            owner.close()
        finally:
            signal_deferral_active = previous_deferral

    def raise_pending_process_signal() -> None:
        nonlocal forwarded_signal_sent
        if pending_signal is None:
            return
        active_process = process
        if active_process is None:
            raise ForwardedSignal(pending_signal)
        signal_process_group(active_process, pending_signal)
        forwarded_signal_sent = True
        raise ForwardedSignal(pending_signal)

    def raise_if_operation_timed_out() -> None:
        if operation_deadline is not None and time.monotonic() >= operation_deadline:
            raise subprocess.TimeoutExpired(command, timeout_seconds)

    previous_handlers: dict[signal.Signals, object] = {}
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for forwarded in forwarded_signals():
            previous_handlers[forwarded] = signal.getsignal(forwarded)
            signal.signal(forwarded, forward_signal)

    cleanup_signal = signal.SIGTERM
    try:
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        gated_exec = os.name == "posix"
        owned_spawn = True
        if gated_exec:
            gated_environment = _encode_gated_environment(env)
        previous_deferral = signal_deferral_active
        signal_deferral_active = True
        try:
            if cwd_fd is not None or gated_exec:
                (
                    handoff_read.descriptor,
                    handoff_write.descriptor,
                ) = _pipe_above_standard_descriptors()
            if gated_exec:
                (
                    gate_read.descriptor,
                    gate_write.descriptor,
                ) = _pipe_above_standard_descriptors()
        finally:
            signal_deferral_active = previous_deferral
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        spawn_command, cwd_pass_fds = _descriptor_cwd_command(
            command,
            cwd_fd,
            status_fd=handoff_write.descriptor,
            gate_fd=gate_read.descriptor,
        )
        spawn_pass_fds = _merge_pass_fds(pass_fds, cwd_pass_fds)
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()

        def spawn_process() -> subprocess.Popen[bytes]:
            return subprocess.Popen(
                spawn_command,
                cwd=cwd,
                pass_fds=spawn_pass_fds,
                env={} if gated_exec else env,
                stdin=(subprocess.PIPE if stdin is not None else subprocess.DEVNULL),
                stdout=(
                    subprocess.PIPE
                    if stdout_file_limit_bytes is not None
                    else stdout_handle
                ),
                stderr=(
                    subprocess.PIPE
                    if stderr_file_limit_bytes is not None
                    else stderr_handle
                ),
                start_new_session=os.name == "posix",
            )

        if owned_spawn:
            spawn_owner = _ProcessSpawnOwner()
            spawn_worker_ready = threading.Event()
            spawn_requested = threading.Event()
            spawn_cancelled = threading.Event()
            spawn_thread = _PROCESS_SPAWN_THREAD(
                target=spawn_owner.spawn,
                args=(
                    spawn_process,
                    spawn_worker_ready,
                    spawn_requested,
                    spawn_cancelled,
                    (handoff_write, gate_read),
                ),
                name="review-process-spawn",
                daemon=True,
            )
            spawn_thread_start_attempted = True
            spawn_thread.start()
            spawn_thread_start_confirmed = True
            while not spawn_worker_ready.wait(PROCESS_GROUP_POLL_SECONDS):
                raise_pending_process_signal()
                raise_if_operation_timed_out()
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()
        if on_process_starting is not None:
            # The callback conservatively publishes UNKNOWN after all
            # no-process preparation, but before the trusted launcher or the
            # target process is authorized to start.
            on_process_starting()
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()
        if owned_spawn:
            assert spawn_owner is not None
            assert spawn_thread is not None
            assert spawn_requested is not None
            # Python dispatches forwarded-signal handlers on the main thread.
            # The worker owns Popen's result before this frame can unwind. On
            # POSIX, fd_exec.py additionally waits behind the GO descriptor.
            spawn_requested.set()
            process = _await_owned_process_spawn(
                spawn_owner,
                spawn_thread,
                spawn_cancelled,
                check_interruption=raise_pending_process_signal,
                operation_deadline=operation_deadline,
                command=command,
                timeout_seconds=timeout_seconds,
            )
        else:
            process = spawn_process()
        close_launch_descriptor(handoff_write)
        close_launch_descriptor(gate_read)
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            forwarded_signal_sent = True
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()
        if gate_write.descriptor is not None:
            launch_control_deadline = (
                time.monotonic() + DESCRIPTOR_CWD_HANDOFF_TIMEOUT_SECONDS
            )
            if operation_deadline is not None:
                launch_control_deadline = min(
                    launch_control_deadline,
                    operation_deadline,
                )
            try:
                _release_exec_gate(
                    gate_write.descriptor,
                    gated_environment,
                    deadline=launch_control_deadline,
                    before_commit=raise_pending_process_signal,
                )
            except ReviewTimeoutError as error:
                if (
                    operation_deadline is not None
                    and time.monotonic() >= operation_deadline
                ):
                    raise subprocess.TimeoutExpired(
                        command,
                        timeout_seconds,
                    ) from error
                raise
            gated_environment[:] = b"\x00" * len(gated_environment)
            close_launch_descriptor(gate_write)
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            forwarded_signal_sent = True
            raise ForwardedSignal(pending_signal)
        if handoff_read.descriptor is not None:
            _await_descriptor_exec_handoff(
                process,
                handoff_read.descriptor,
                command=command,
                operation_deadline=operation_deadline,
                timeout_seconds=timeout_seconds,
            )
            close_launch_descriptor(handoff_read)
        if pending_signal is not None:
            signal_process_group(process, pending_signal)
            forwarded_signal_sent = True
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()
        if on_process_started is not None:
            previous_deferral = signal_deferral_active
            signal_deferral_active = True
            try:
                on_process_started()
            finally:
                signal_deferral_active = previous_deferral
        if pending_signal is not None:
            if not forwarded_signal_sent:
                signal_process_group(process, pending_signal)
                forwarded_signal_sent = True
            raise ForwardedSignal(pending_signal)
        raise_if_operation_timed_out()
        if stdout_file_limit_bytes is None or stderr_file_limit_bytes is None:
            if timeout_seconds is None:
                process.communicate(input=stdin)
            else:
                assert operation_deadline is not None
                remaining = operation_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                process.communicate(input=stdin, timeout=remaining)
            return int(process.returncode)

        assert process.stdout is not None
        assert process.stderr is not None
        output_overflow = threading.Event()

        def drain_bounded(
            stream: BinaryIO,
            destination: BinaryIO,
            limit_bytes: int,
        ) -> None:
            try:
                written = 0
                descriptor = stream.fileno()
                os.set_blocking(descriptor, False)
                while not stop_io.is_set():
                    readable = _wait_descriptor_ready(
                        descriptor,
                        writable=False,
                        timeout_seconds=PROCESS_GROUP_POLL_SECONDS,
                    )
                    if not readable:
                        continue
                    try:
                        chunk = os.read(descriptor, 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        return
                    remaining = limit_bytes - written
                    if remaining > 0:
                        destination.write(chunk[:remaining])
                        destination.flush()
                        written += min(len(chunk), remaining)
                    if len(chunk) > remaining and not output_overflow.is_set():
                        output_overflow.set()
                        signal_process_group(process, signal.SIGTERM)
            except Exception as error:
                drain_errors.append(error)
                signal_process_group(process, signal.SIGTERM)

        def write_stdin_bounded(
            stream: BinaryIO,
            payload: bytes | bytearray,
        ) -> None:
            view = memoryview(payload)
            try:
                descriptor = stream.fileno()
                os.set_blocking(descriptor, False)
                offset = 0
                while offset < len(payload) and not stop_io.is_set():
                    writable = _wait_descriptor_ready(
                        descriptor,
                        writable=True,
                        timeout_seconds=PROCESS_GROUP_POLL_SECONDS,
                    )
                    if not writable:
                        continue
                    try:
                        written = os.write(descriptor, view[offset:])
                    except BlockingIOError:
                        continue
                    offset += written
                if offset == len(payload):
                    stream.close()
            except BrokenPipeError:
                return
            except Exception as error:
                drain_errors.append(error)
                signal_process_group(process, signal.SIGTERM)
            finally:
                view.release()

        thread_start_mask_owner = ForwardedSignalMaskOwner()
        thread_start_error: BaseException | None = None
        try:
            try:
                thread_start_mask = block_forwarded_signals(
                    signal_mask_owner=thread_start_mask_owner,
                )
                if (
                    not thread_start_mask_owner.active
                    and thread_start_mask is not None
                ):
                    thread_start_mask_owner.publish(thread_start_mask)
                for stream, destination, limit_bytes in (
                    (process.stdout, stdout_handle, stdout_file_limit_bytes),
                    (process.stderr, stderr_handle, stderr_file_limit_bytes),
                ):
                    thread = threading.Thread(
                        target=drain_bounded,
                        args=(stream, destination, limit_bytes),
                        daemon=True,
                    )
                    try:
                        thread.start()
                    except BaseException:
                        process_cleanup_inconclusive = True
                        raise
                    io_threads.append(thread)
                if stdin is not None:
                    assert process.stdin is not None
                    thread = threading.Thread(
                        target=write_stdin_bounded,
                        args=(process.stdin, stdin),
                        daemon=True,
                    )
                    try:
                        thread.start()
                    except BaseException:
                        process_cleanup_inconclusive = True
                        raise
                    io_threads.append(thread)
            except BaseException as error:
                thread_start_error = error
                raise
        finally:
            thread_start_restore_failures = (
                _restore_forwarded_signal_mask_owner_bounded(
                    thread_start_mask_owner,
                )
            )
            _propagate_signal_mask_restore_failures(
                thread_start_error,
                thread_start_restore_failures,
            )
        assert timeout_seconds is not None
        assert operation_deadline is not None
        deadline = operation_deadline
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            try:
                process.wait(timeout=min(PROCESS_GROUP_POLL_SECONDS, remaining))
                break
            except subprocess.TimeoutExpired:
                if output_overflow.is_set() or drain_errors:
                    try:
                        terminate_process_group(process)
                    except BaseException as error:
                        if isinstance(error, ForwardedSignal) or not isinstance(
                            error, Exception
                        ):
                            raise
                        cleanup_failures.append(
                            ("terminating the supervised process group", error)
                        )
                    break
        leftover_process_group = _process_group_exists(process.pid)
        if leftover_process_group:
            exit_deadline = time.monotonic() + PROCESS_GROUP_EXIT_GRACE_SECONDS
            while (
                _process_group_exists(process.pid) and time.monotonic() < exit_deadline
            ):
                time.sleep(PROCESS_GROUP_POLL_SECONDS)
            leftover_process_group = _process_group_exists(process.pid)
        if leftover_process_group:
            process_cleanup_inconclusive = True
            terminate_process_group(process)
        for thread in io_threads:
            thread.join(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
        if any(thread.is_alive() for thread in io_threads):
            process_cleanup_inconclusive = True
            stop_io.set()
            for thread in io_threads:
                thread.join(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
            raise ReviewProcessLeakError(
                "command I/O streams remained open after bounded cleanup: "
                f"{' '.join(command)}"
            )
        if drain_errors:
            process_cleanup_inconclusive = True
            raise ReviewOutputDrainError(
                f"command output drain failed: {' '.join(command)}"
            ) from drain_errors[0]
        if output_overflow.is_set():
            raise ReviewOutputLimitError(
                f"command output exceeded its bounded stream limit: {' '.join(command)}"
            )
        if leftover_process_group:
            process_cleanup_inconclusive = True
            raise ReviewProcessLeakError(
                f"command left descendant processes after exit: {' '.join(command)}"
            )
        return int(process.returncode)
    except BaseException as error:
        primary_error = error
        if isinstance(error, ForwardedSignal):
            cleanup_signal = error.signum
        elif pending_signal is not None:
            cleanup_signal = pending_signal
        raise
    finally:
        cleanup_signal_mask_owner = ForwardedSignalMaskOwner()
        pending_cleanup_signal: signal.Signals | None = None
        try:
            try:
                previous_mask = block_forwarded_signals(
                    signal_mask_owner=cleanup_signal_mask_owner,
                )
                if (
                    not cleanup_signal_mask_owner.active
                    and previous_mask is not None
                ):
                    cleanup_signal_mask_owner.publish(previous_mask)
            except BaseException as error:
                cleanup_failures.append(
                    ("blocking forwarded signals during process cleanup", error)
                )
            if spawn_cancelled is not None:
                try:
                    if spawn_owner is not None:
                        spawn_owner.cancel(spawn_cancelled, cleanup_signal)
                    else:
                        spawn_cancelled.set()
                except BaseException as error:
                    cleanup_failures.append(
                        ("cancelling the reviewer spawn worker", error)
                    )
            if spawn_requested is not None:
                try:
                    spawn_requested.set()
                except BaseException as error:
                    cleanup_failures.append(
                        ("releasing the reviewer spawn worker", error)
                    )
            for context, owner in (
                ("closing the reviewer launch gate", gate_write),
                ("closing the reviewer exec-status reader", handoff_read),
            ):
                try:
                    owner.close()
                except BaseException as error:
                    cleanup_failures.append((context, error))
            worker_started = False
            worker_alive = False
            if spawn_thread is not None and spawn_thread_start_attempted:
                worker_started = spawn_thread_start_confirmed
                started_event = getattr(spawn_thread, "_started", None)
                if isinstance(started_event, threading.Event):
                    if not worker_started and not started_event.is_set():
                        try:
                            started_event.wait(
                                timeout=PROCESS_GROUP_TERM_GRACE_SECONDS
                            )
                        except BaseException as error:
                            cleanup_failures.append(
                                ("observing reviewer spawn-worker startup", error)
                            )
                    worker_started = worker_started or started_event.is_set()
                else:
                    try:
                        worker_started = worker_started or spawn_thread.ident is not None
                    except BaseException as error:
                        cleanup_failures.append(
                            ("observing reviewer spawn-worker identity", error)
                        )
                if worker_started:
                    try:
                        spawn_thread.join(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
                    except BaseException as error:
                        process_cleanup_inconclusive = True
                        cleanup_failures.append(
                            ("joining the reviewer process spawn worker", error)
                        )
                    try:
                        worker_alive = spawn_thread.is_alive()
                    except BaseException as error:
                        worker_alive = True
                        cleanup_failures.append(
                            ("verifying reviewer spawn-worker shutdown", error)
                        )
                    if worker_alive:
                        process_cleanup_inconclusive = True
                        cleanup_failures.append(
                            (
                                "joining the reviewer process spawn worker",
                                ReviewProcessLeakError(
                                    "reviewer spawn worker remains active after "
                                    "bounded cancellation"
                                ),
                            )
                        )
            if (
                process is None
                and spawn_owner is not None
                and (
                    spawn_owner._claimed_event.is_set()
                    or (
                        spawn_owner.cleanup_completed.is_set()
                        and not worker_alive
                    )
                )
            ):
                process = spawn_owner.process
            if (
                spawn_owner is not None
                and spawn_owner.error is not None
                and spawn_owner.error is not primary_error
            ):
                cleanup_failures.append(
                    ("spawning the supervised process", spawn_owner.error)
                )
            if spawn_owner is not None:
                for error in tuple(spawn_owner.cleanup_failures):
                    cleanup_failures.append(
                        ("cleaning the reviewer spawn worker", error)
                    )
            if not worker_started or not worker_alive:
                for owner in (gate_read, handoff_write):
                    try:
                        owner.close()
                    except BaseException as error:
                        cleanup_failures.append(
                            ("closing reviewer exec handoff", error)
                        )
            gated_environment[:] = b"\x00" * len(gated_environment)
            process_already_cleaned = (
                spawn_owner is not None
                and spawn_owner.process is process
                and spawn_owner.worker_cleaned_process
            )
            if process is not None and not process_already_cleaned:
                try:
                    terminate_process_group(
                        process,
                        initial_signal=cleanup_signal,
                        signal_already_sent=forwarded_signal_sent,
                    )
                except BaseException as error:
                    cleanup_failures.append(
                        ("terminating the supervised process group", error)
                    )
            try:
                stop_io.set()
            except BaseException as error:
                process_cleanup_inconclusive = True
                cleanup_failures.append(("stopping command I/O workers", error))
            for thread in io_threads:
                try:
                    thread.join(timeout=PROCESS_GROUP_TERM_GRACE_SECONDS)
                except BaseException as error:
                    cleanup_failures.append(("joining a command I/O worker", error))
            io_worker_alive = False
            for thread in io_threads:
                try:
                    io_worker_alive = thread.is_alive() or io_worker_alive
                except BaseException as error:
                    io_worker_alive = True
                    cleanup_failures.append(
                        ("verifying command I/O worker shutdown", error)
                    )
            if io_worker_alive:
                process_cleanup_inconclusive = True
                if not isinstance(primary_error, ReviewProcessLeakError):
                    cleanup_failures.append(
                        (
                            "quiescing command I/O workers",
                            ReviewProcessLeakError(
                                "command I/O streams remained open after bounded "
                                f"cleanup: {' '.join(command)}"
                            ),
                        )
                    )
            if drain_errors:
                process_cleanup_inconclusive = True
                if not isinstance(primary_error, ReviewOutputDrainError):
                    drain_failure = ReviewOutputDrainError(
                        f"command output drain failed: {' '.join(command)}"
                    )
                    drain_failure.__cause__ = drain_errors[0]
                    cleanup_failures.append(("draining command output", drain_failure))
            if process is not None:
                owned_streams = [("stdin", process.stdin)]
                if stdout_file_limit_bytes is not None:
                    owned_streams.append(("stdout", process.stdout))
                if stderr_file_limit_bytes is not None:
                    owned_streams.append(("stderr", process.stderr))
                for stream_name, stream in owned_streams:
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException as error:
                            cleanup_failures.append(
                                (f"closing command {stream_name}", error)
                            )
            for forwarded, previous in previous_handlers.items():
                try:
                    signal.signal(forwarded, previous)
                except BaseException as error:
                    cleanup_failures.append(
                        (f"restoring the {forwarded.name} signal handler", error)
                    )
            if cleanup_signal_mask_owner.active:
                try:
                    pending_cleanup_signal = consume_pending_forwarded_signal()
                except BaseException as error:
                    cleanup_failures.append(
                        ("consuming forwarded signals pending during cleanup", error)
                    )
            if process is not None and on_process_quiescent is not None:
                try:
                    process_reaped = process.poll() is not None
                    process_group_absent = (
                        os.name != "posix" or not _process_group_exists(process.pid)
                    )
                except BaseException as error:
                    if isinstance(error, ForwardedSignal) or not isinstance(
                        error, Exception
                    ):
                        cleanup_failures.append(
                            ("proving supervised process-group quiescence", error)
                        )
                    else:
                        proof_failure = ReviewProcessLeakError(
                            "command process quiescence proof failed: "
                            f"{' '.join(command)}"
                        )
                        proof_failure.__cause__ = error
                        cleanup_failures.append(
                            (
                                "proving supervised process-group quiescence",
                                proof_failure,
                            )
                        )
                else:
                    quiescence_proven = (
                        process_reaped
                        and process_group_absent
                        and not process_cleanup_inconclusive
                    )
                    if quiescence_proven:
                        try:
                            on_process_quiescent()
                        except BaseException as error:
                            cleanup_failures.append(
                                ("running the process quiescence callback", error)
                            )
                    else:
                        cleanup_failures.append(
                            (
                                "proving supervised process-group quiescence",
                                ReviewProcessLeakError(
                                    "command process quiescence could not be proven: "
                                    f"{' '.join(command)}"
                                ),
                            )
                        )
        finally:
            for error in _restore_forwarded_signal_mask_owner_bounded(
                cleanup_signal_mask_owner,
            ):
                cleanup_failures.append(
                    ("restoring the forwarded-signal mask", error)
                )

        effective_pending_signal = pending_cleanup_signal or pending_signal
        signal_error: ForwardedSignal | None = None
        if effective_pending_signal is not None:
            if (
                isinstance(primary_error, ForwardedSignal)
                and primary_error.signum == effective_pending_signal
            ):
                signal_error = primary_error
            else:
                signal_error = ForwardedSignal(effective_pending_signal)

        cleanup_control_flow = next(
            (
                error
                for _, error in cleanup_failures
                if _is_process_control_flow_error(error)
            ),
            None,
        )
        primary_context: str | None = None
        if signal_error is not None:
            selected_error: BaseException | None = signal_error
            primary_context = "process operation failed after a signal became pending"
        elif primary_error is not None and _is_process_control_flow_error(
            primary_error
        ):
            selected_error = primary_error
        elif cleanup_control_flow is not None:
            selected_error = cleanup_control_flow
            primary_context = "process operation failed before cleanup control flow"
        elif primary_error is not None:
            selected_error = primary_error
        elif cleanup_failures:
            _, selected_error = cleanup_failures[0]
        else:
            selected_error = None

        if selected_error is not None:
            if primary_error is not None and primary_error is not selected_error:
                assert primary_context is not None
                _attach_process_secondary_failure(
                    selected_error,
                    primary_error,
                    context=primary_context,
                )
            for context, error in cleanup_failures:
                _attach_process_secondary_failure(
                    selected_error,
                    error,
                    context=context,
                )
            if selected_error is not primary_error:
                if selected_error.__cause__ is not None:
                    raise selected_error from selected_error.__cause__
                raise selected_error from None


def _attach_process_secondary_failure(
    primary: BaseException,
    secondary: BaseException,
    *,
    context: str,
) -> None:
    if primary is secondary:
        return
    detail = str(secondary).strip()
    diagnostic = f"{context} ({type(secondary).__name__})"
    if detail:
        diagnostic += f": {detail}"
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        add_note(diagnostic)
        return
    node = ReviewProcessSecondaryFailureDiagnostic(diagnostic)
    if primary.__cause__ is not None:
        node.__cause__ = primary.__cause__
    elif not primary.__suppress_context__ and primary.__context__ is not None:
        node.__context__ = primary.__context__
    primary.__cause__ = node


def _read_bounded_bytes(path: pathlib.Path, limit: int) -> bytes:
    if limit <= 0:
        raise ReviewError("capture_limit_bytes must be positive")
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size <= limit:
                return handle.read()
            head_size = limit // 2
            tail_size = limit - head_size
            head = handle.read(head_size)
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
    except OSError as error:
        raise ReviewError(
            f"cannot read bounded command output {path}: {error}"
        ) from error
    return head + b"\n... bounded capture omitted middle bytes ...\n" + tail


def resolve_executable(
    name: str, preferred_paths: Iterable[str]
) -> pathlib.Path | None:
    for candidate in preferred_paths:
        path = pathlib.Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    discovered = shutil.which(name, path=TRUSTED_PATH)
    if discovered is None:
        return None
    path = pathlib.Path(discovered).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path


def _nvm_version_key(path: pathlib.Path) -> tuple[int, ...]:
    try:
        version = path.parents[1].name.removeprefix("v")
    except IndexError:
        return ()
    parts: list[int] = []
    for value in version.split("."):
        if not value.isdigit():
            return ()
        parts.append(int(value))
    return tuple(parts)


def _user_executable_candidates(name: str) -> list[pathlib.Path]:
    home_value = os.environ.get("HOME")
    if not home_value:
        return []
    home = pathlib.Path(home_value).expanduser().absolute()
    candidates: list[pathlib.Path] = []
    nvm_bin = os.environ.get("NVM_BIN")
    if nvm_bin:
        nvm_path = pathlib.Path(nvm_bin).expanduser().absolute()
        if is_relative_to(nvm_path, home):
            candidates.append(nvm_path / name)
    candidates.append(home / ".nvm/current/bin" / name)
    nvm_candidates = list((home / ".nvm/versions/node").glob(f"*/bin/{name}"))
    candidates.extend(sorted(nvm_candidates, key=_nvm_version_key, reverse=True))
    candidates.extend(
        (
            home / ".local/bin" / name,
            home / ".volta/bin" / name,
            home / ".asdf/shims" / name,
            home / ".bun/bin" / name,
            home / ".npm-global/bin" / name,
            home / "bin" / name,
        )
    )
    return candidates


ENV_SHEBANG = re.compile(
    rb"^#![ \t]*/usr/bin/env(?:[ \t]+-S)?[ \t]+([A-Za-z0-9_.+-]+)(?:[ \t]|$)"
)
DIRECT_SHEBANG = re.compile(rb"^#![ \t]*(/[^ \t\r\n]+)")


def _env_shebang_runtime(path: pathlib.Path) -> pathlib.Path | None:
    try:
        with path.open("rb") as handle:
            first_line = handle.readline(512)
    except OSError:
        return None
    match = ENV_SHEBANG.match(first_line.rstrip(b"\r\n"))
    if match is None:
        return None
    interpreter = match.group(1).decode("ascii")
    candidates = _user_executable_candidates(interpreter)
    discovered = shutil.which(interpreter, path=TRUSTED_PATH)
    if discovered:
        candidates.append(pathlib.Path(discovered))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.absolute()
    return None


def reviewer_executable_path(
    path: pathlib.Path,
    *,
    base_path: str = TRUSTED_PATH,
) -> str:
    entries = [str(path.parent)]
    runtime = _env_shebang_runtime(path)
    if runtime is not None and str(runtime.parent) not in entries:
        entries.append(str(runtime.parent))
    for entry in base_path.split(os.pathsep):
        if entry and entry not in entries:
            entries.append(entry)
    return os.pathsep.join(entries)


def reviewer_executable_dependencies(path: pathlib.Path) -> tuple[pathlib.Path, ...]:
    """Return exact files required to exec a reviewer entrypoint."""
    candidates = [path.absolute(), path.resolve()]
    try:
        with path.open("rb") as handle:
            first_line = handle.readline(512).rstrip(b"\r\n")
    except OSError:
        first_line = b""
    direct_match = DIRECT_SHEBANG.match(first_line)
    if direct_match is not None:
        try:
            direct = pathlib.Path(direct_match.group(1).decode("utf-8"))
        except UnicodeDecodeError:
            direct = None
        if direct is not None and direct.is_file() and os.access(direct, os.X_OK):
            candidates.extend((direct.absolute(), direct.resolve()))
    env_runtime = _env_shebang_runtime(path)
    if env_runtime is not None:
        candidates.extend((env_runtime.absolute(), env_runtime.resolve()))
    result: list[pathlib.Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            result.append(candidate)
    return tuple(result)


def _executable_identity_matches(
    path: pathlib.Path,
    markers: Iterable[str],
) -> bool:
    marker_values = tuple(markers)
    env = {
        "HOME": os.environ.get("HOME", str(pathlib.Path.home())),
        "NO_COLOR": "1",
        "PATH": reviewer_executable_path(path),
    }
    try:
        completed = subprocess.run(
            (str(path), "--version"),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    output = f"{completed.stdout.decode(errors='replace')}\n{completed.stderr.decode(errors='replace')}".lower()
    return all(marker.lower() in output for marker in marker_values)


def resolve_reviewer_executable(
    name: str,
    *,
    candidate_validator: Callable[[pathlib.Path], None] | None = None,
) -> pathlib.Path | None:
    specs = {
        "codex": (
            "CODEX_REVIEW_CODEX_PATH",
            ("/opt/homebrew/bin/codex", "/usr/local/bin/codex"),
            ("codex-cli",),
            False,
        ),
        "claude": (
            "CODEX_REVIEW_CLAUDE_PATH",
            (
                "/opt/homebrew/bin/claude",
                "/usr/local/bin/claude",
                "/usr/bin/claude",
            ),
            ("claude code",),
            True,
        ),
        "copilot": (
            "CODEX_REVIEW_COPILOT_PATH",
            ("/opt/homebrew/bin/copilot", "/usr/local/bin/copilot"),
            ("github copilot cli",),
            False,
        ),
    }
    if name not in specs:
        raise ReviewError(f"unknown review executable: {name}")
    override_key, system_paths, markers, defer_identity = specs[name]
    override_value = os.environ.get(override_key)
    if override_value:
        override = pathlib.Path(override_value).expanduser()
        if not override.is_absolute():
            raise ReviewError(f"{override_key} must be an absolute executable path")
        if not override.is_file() or not os.access(override, os.X_OK):
            raise ReviewError(f"{override_key} is not executable: {override}")
        if defer_identity and candidate_validator is not None:
            try:
                candidate_validator(override.absolute())
            except InvalidReviewerExecutable as error:
                raise ReviewError(
                    f"{override_key} did not pass sandboxed {name} validation: "
                    f"{override}"
                ) from error
        elif not defer_identity and not _executable_identity_matches(override, markers):
            raise ReviewError(
                f"{override_key} did not identify as the expected {name} CLI: {override}"
            )
        return override.absolute()

    candidates = [
        *(pathlib.Path(value) for value in system_paths),
        *_user_executable_candidates(name),
    ]
    discovered = shutil.which(name, path=TRUSTED_PATH)
    if discovered:
        candidates.append(pathlib.Path(discovered))
    seen: set[str] = set()
    rejected: list[pathlib.Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        absolute = candidate.absolute()
        if defer_identity:
            if candidate_validator is None:
                return absolute
            try:
                candidate_validator(absolute)
            except InvalidReviewerExecutable:
                rejected.append(absolute)
                continue
            return absolute
        if _executable_identity_matches(candidate, markers):
            return absolute
        rejected.append(candidate.absolute())
    if rejected:
        paths = ", ".join(str(path) for path in rejected)
        raise RejectedReviewerCandidates(
            f"found {name} CLI candidate(s), but executable identity validation "
            f"failed or timed out: {paths}"
        )
    return None


def resolve_git() -> pathlib.Path:
    path = resolve_executable(
        "git",
        ("/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"),
    )
    if path is None:
        raise ReviewError("git is not available in a trusted executable path")
    return path


def is_relative_to(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def child_environment(
    *,
    container_dir: pathlib.Path,
    passthrough_keys: Iterable[str] = (),
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    allowed_keys = {*BASE_ENV_KEYS, *passthrough_keys}
    env = {key: os.environ[key] for key in allowed_keys if key in os.environ}
    env.update(
        {
            "PATH": TRUSTED_PATH,
            "TMPDIR": str(container_dir / "tmp"),
            "TMP": str(container_dir / "tmp"),
            "TEMP": str(container_dir / "tmp"),
        }
    )
    (container_dir / "tmp").mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env
