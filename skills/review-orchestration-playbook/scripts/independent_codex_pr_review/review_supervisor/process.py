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
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


PROCESS_GROUP_MEMBER_CAP = 262_144
_LINUX_TERMINAL_PROCESS_STATES = frozenset({b"Z", b"X", b"x"})
_FORK_PID_RECEIPT = struct.Struct("!8sQ")
_FORK_PID_RECEIPT_MAGIC = b"FXPIDv1\0"
_FORK_PID_RECEIPT_SECONDS = 2.0


@dataclass(slots=True)
class ForkExecReceipt:
    """Caller-owned proof of child and acknowledgement descriptor custody.

    The protected property is child-process ownership and termination
    convergence. Descriptor metadata records cleanup obligations, but an
    ambiguous close outcome is never promoted to known closure.
    """

    creator_pid: int
    own_process_group: bool
    acknowledgement_read_fd: int
    acknowledgement_write_fd: int
    passed_fd_numbers: tuple[int, ...] = ()
    fork_call_started: bool = False
    fork_call_completed: bool = False
    fork_failure_proven: bool = False
    returned_pid: int | None = None
    child_pid: int | None = None
    child_pid_receipt_attempted: bool = False
    child_pid_receipt_published: bool = False
    child_pid_receipt_received: bool = False
    child_pid_receipt_error: BaseException | None = None
    acknowledgement_read_close_outcome: str = "owned"
    acknowledgement_write_close_outcome: str = "owned"
    descriptor_close_errors: dict[str, BaseException] = field(default_factory=dict)

    @property
    def in_child_process(self) -> bool:
        return os.getpid() != self.creator_pid

    @property
    def acknowledgement_descriptors_closed(self) -> bool:
        closed_outcomes = {"closed", "missing"}
        return (
            self.acknowledgement_read_fd < 0
            and self.acknowledgement_write_fd < 0
            and self.acknowledgement_read_close_outcome in closed_outcomes
            and self.acknowledgement_write_close_outcome in closed_outcomes
        )

    def publish_returned_pid(self, pid: int) -> None:
        if pid <= 0:
            raise ValueError("fork returned an invalid process identifier")
        if self.returned_pid is not None and self.returned_pid != pid:
            raise ValueError("fork return receipt was rebound")
        self.returned_pid = pid

    def publish_child_pid(self, pid: int, *, received: bool) -> None:
        if pid <= 0:
            raise ValueError("child PID receipt is invalid")
        if self.child_pid is not None and self.child_pid != pid:
            raise ValueError("child PID receipt was rebound")
        self.child_pid = pid
        if received:
            self.child_pid_receipt_received = True
        else:
            self.child_pid_receipt_published = True

    def close_acknowledgement_read(
        self,
        failures: list[BaseException] | None = None,
    ) -> bool:
        return self._close_descriptor(
            descriptor_attribute="acknowledgement_read_fd",
            outcome_attribute="acknowledgement_read_close_outcome",
            role="acknowledgement-read",
            failures=failures,
        )

    def close_acknowledgement_write(
        self,
        failures: list[BaseException] | None = None,
    ) -> bool:
        return self._close_descriptor(
            descriptor_attribute="acknowledgement_write_fd",
            outcome_attribute="acknowledgement_write_close_outcome",
            role="acknowledgement-write",
            failures=failures,
        )

    def _close_descriptor(
        self,
        *,
        descriptor_attribute: str,
        outcome_attribute: str,
        role: str,
        failures: list[BaseException] | None,
    ) -> bool:
        descriptor = getattr(self, descriptor_attribute)
        outcome = getattr(self, outcome_attribute)
        if descriptor < 0:
            return outcome in {"closed", "missing"}
        if outcome in {"closed", "missing"}:
            setattr(self, descriptor_attribute, -1)
            return True
        if outcome == "close-outcome-unproven":
            return False
        if outcome != "owned":
            error = ChildProcessError(
                f"{role} descriptor has invalid close state: {outcome}"
            )
            self.descriptor_close_errors[role] = error
            if failures is None:
                raise error
            failures.append(error)
            return False

        # Publish uncertainty before the syscall. If delivery is interrupted
        # after close, retrying this integer could close a reused descriptor.
        setattr(self, outcome_attribute, "close-outcome-unproven")
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                setattr(self, outcome_attribute, "missing")
                setattr(self, descriptor_attribute, -1)
                self.descriptor_close_errors.pop(role, None)
                return True
            self.descriptor_close_errors[role] = error
            try:
                setattr(error, "fork_exec_receipt", self)
            except BaseException:
                pass
            if failures is None:
                raise
            failures.append(error)
            return False
        except BaseException as error:
            self.descriptor_close_errors[role] = error
            try:
                setattr(error, "fork_exec_receipt", self)
            except BaseException:
                pass
            if failures is None:
                raise
            failures.append(error)
            return False
        setattr(self, outcome_attribute, "closed")
        setattr(self, descriptor_attribute, -1)
        self.descriptor_close_errors.pop(role, None)
        return True


@dataclass(frozen=True)
class SpawnedProcess:
    pid: int
    pgid: int
    acknowledgement_fd: int
    passed_fd_numbers: tuple[int, ...]
    start_identity: str | None = None
    fork_exec_receipt: ForkExecReceipt | None = field(
        default=None,
        compare=False,
        repr=False,
    )


@dataclass(slots=True)
class ForkExecResultOwner:
    """Caller-visible owner for one fork result until explicit transfer."""

    receipt: ForkExecReceipt | None = None
    process: SpawnedProcess | None = None
    transferred: bool = False
    termination_proven: bool = False

    def publish_receipt(self, receipt: ForkExecReceipt) -> None:
        if self.receipt is None:
            self.receipt = receipt
        elif self.receipt is not receipt:
            raise ValueError("fork-exec receipt owner was rebound")

    def owns_receipt(self, receipt: ForkExecReceipt) -> bool:
        return self.receipt is receipt

    def publish(self, process: SpawnedProcess) -> None:
        receipt = self.receipt
        if receipt is None or process.fork_exec_receipt is not receipt:
            raise ValueError("fork-exec process is not bound to the owned receipt")
        if self.process is None:
            self.process = process
        elif self.process is not process:
            raise ValueError("fork-exec process owner was rebound")

    def owns(self, process: SpawnedProcess) -> bool:
        return self.process is process

    def transfer(self, process: SpawnedProcess) -> SpawnedProcess:
        if self.process is not process or self.termination_proven:
            raise ValueError("fork-exec process transfer is inconsistent")
        self.transferred = True
        return process

    def mark_termination_proven(self, process: SpawnedProcess) -> None:
        if self.process is None:
            self.process = process
        elif self.process is not process:
            raise ValueError("fork-exec settlement process was rebound")
        self.termination_proven = True

    def __enter__(self) -> ForkExecResultOwner:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> bool:
        del exception_type, traceback
        if self.transferred or self.termination_proven:
            return False
        source = exception
        while source is not None:
            if (
                isinstance(
                    source,
                    (ForkedProcessClosureUnproven, ForkedProcessOwnershipUnproven),
                )
                and source.result_owner is self
            ):
                return False
            source = source.__cause__
        trigger = exception or RuntimeError(
            "fork-exec result owner exited without transferring the process"
        )
        settle_untransferred_fork_exec(self, trigger=trigger)
        if exception is None:
            raise trigger
        return False


class ForkedProcessClosureUnproven(RuntimeError):
    def __init__(
        self,
        process: SpawnedProcess,
        identity_error: BaseException,
        cleanup_error: BaseException,
        *,
        result_owner: ForkExecResultOwner | None = None,
    ) -> None:
        self.process = process
        self.result_owner = result_owner
        self.receipt = result_owner.receipt if result_owner is not None else None
        super().__init__(
            "post-fork process closure is unproven: "
            f"pid={process.pid}, "
            f"identity_error={type(identity_error).__name__}, "
            f"cleanup_error={type(cleanup_error).__name__}"
        )


class ForkedProcessOwnershipUnproven(RuntimeError):
    def __init__(
        self,
        result_owner: ForkExecResultOwner,
        trigger: BaseException,
        recovery_error: BaseException,
    ) -> None:
        self.result_owner = result_owner
        self.receipt = result_owner.receipt
        super().__init__(
            "post-fork child ownership is unproven: "
            f"trigger={type(trigger).__name__}, "
            f"recovery_error={type(recovery_error).__name__}"
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


_FORK_EXEC_RECEIPT_CONTEXT = threading.local()
_FORK_EXEC_HOOK_LOCK = threading.Lock()
_FORK_EXEC_HOOK_REGISTERED = False


def _active_fork_exec_receipt() -> ForkExecReceipt | None:
    receipt = getattr(_FORK_EXEC_RECEIPT_CONTEXT, "receipt", None)
    return receipt if isinstance(receipt, ForkExecReceipt) else None


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "fork PID receipt write made no progress")
        offset += written


def _publish_child_pid_receipt(receipt: ForkExecReceipt) -> None:
    child_pid = os.getpid()
    _write_all(
        receipt.acknowledgement_write_fd,
        _FORK_PID_RECEIPT.pack(_FORK_PID_RECEIPT_MAGIC, child_pid),
    )
    receipt.publish_child_pid(child_pid, received=False)


def _after_fork_exec_in_parent() -> None:
    receipt = _active_fork_exec_receipt()
    if receipt is not None:
        receipt.fork_call_completed = True


def _after_fork_exec_in_child() -> None:
    receipt = _active_fork_exec_receipt()
    if receipt is None:
        return
    receipt.fork_call_completed = True
    if receipt.child_pid_receipt_attempted:
        return
    receipt.child_pid_receipt_attempted = True
    try:
        _publish_child_pid_receipt(receipt)
    except BaseException as error:
        receipt.child_pid_receipt_error = error


def _ensure_fork_exec_hooks() -> None:
    global _FORK_EXEC_HOOK_REGISTERED

    if _FORK_EXEC_HOOK_REGISTERED:
        return
    with _FORK_EXEC_HOOK_LOCK:
        if _FORK_EXEC_HOOK_REGISTERED:
            return
        os.register_at_fork(
            after_in_parent=_after_fork_exec_in_parent,
            after_in_child=_after_fork_exec_in_child,
        )
        _FORK_EXEC_HOOK_REGISTERED = True


def _clear_active_fork_exec_receipt(receipt: ForkExecReceipt) -> None:
    if _active_fork_exec_receipt() is receipt:
        del _FORK_EXEC_RECEIPT_CONTEXT.receipt


def _read_child_pid_receipt(
    receipt: ForkExecReceipt,
    *,
    deadline: float,
) -> int:
    if receipt.child_pid_receipt_received and receipt.child_pid is not None:
        return receipt.child_pid
    descriptor = receipt.acknowledgement_read_fd
    if descriptor < 0 or receipt.acknowledgement_read_close_outcome != "owned":
        raise ChildProcessError("fork PID receipt descriptor is unavailable")

    selector = selectors.DefaultSelector()
    payload = bytearray()
    try:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        while len(payload) < _FORK_PID_RECEIPT.size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fork PID receipt deadline expired")
            if not selector.select(min(remaining, 0.1)):
                continue
            try:
                chunk = os.read(descriptor, _FORK_PID_RECEIPT.size - len(payload))
            except BlockingIOError:
                continue
            if not chunk:
                raise ChildProcessError("fork PID receipt pipe closed early")
            payload.extend(chunk)
    finally:
        selector.close()

    magic, child_pid = _FORK_PID_RECEIPT.unpack(payload)
    if magic != _FORK_PID_RECEIPT_MAGIC or child_pid <= 0:
        raise ChildProcessError("fork PID receipt is invalid")
    receipt.publish_child_pid(child_pid, received=True)
    return child_pid


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


def _receipt_process(
    result_owner: ForkExecResultOwner,
    *,
    trigger: BaseException,
) -> SpawnedProcess:
    if result_owner.process is not None:
        return result_owner.process
    receipt = result_owner.receipt
    if receipt is None:
        raise ForkedProcessOwnershipUnproven(
            result_owner,
            trigger,
            ChildProcessError("fork-exec receipt was not published"),
        )

    pid = receipt.returned_pid
    if pid is None:
        close_failures: list[BaseException] = []
        receipt.close_acknowledgement_write(close_failures)
        try:
            pid = _read_child_pid_receipt(
                receipt,
                deadline=time.monotonic() + _FORK_PID_RECEIPT_SECONDS,
            )
        except BaseException as recovery_error:
            raise ForkedProcessOwnershipUnproven(
                result_owner,
                trigger,
                recovery_error,
            ) from recovery_error
    process = SpawnedProcess(
        pid=pid,
        pgid=pid if receipt.own_process_group else os.getpgrp(),
        acknowledgement_fd=-1,
        passed_fd_numbers=receipt.passed_fd_numbers,
        start_identity=None,
        fork_exec_receipt=receipt,
    )
    result_owner.publish(process)
    return process


def settle_untransferred_fork_exec(
    result_owner: ForkExecResultOwner,
    *,
    trigger: BaseException,
) -> None:
    """Converge a child that was created before result transfer completed."""

    try:
        setattr(trigger, "fork_exec_result_owner", result_owner)
    except BaseException:
        pass
    if result_owner.transferred or result_owner.termination_proven:
        return
    receipt = result_owner.receipt
    if receipt is None:
        return

    may_have_child = receipt.fork_call_started and not receipt.fork_failure_proven
    descriptor_failures: list[BaseException] = []
    if not may_have_child:
        receipt.close_acknowledgement_write(descriptor_failures)
        receipt.close_acknowledgement_read(descriptor_failures)
        result_owner.termination_proven = True
        return

    process = _receipt_process(result_owner, trigger=trigger)
    receipt.close_acknowledgement_write(descriptor_failures)
    receipt.close_acknowledgement_read(descriptor_failures)

    cleanup_error: BaseException | None = None
    cleanup_control_flow: BaseException | None = None
    for cleanup_seconds in (2.0, 5.0):
        try:
            _settle_unidentified_fork(
                process,
                own_process_group=receipt.own_process_group,
                deadline=time.monotonic() + cleanup_seconds,
            )
        except BaseException as error:
            cleanup_error = error
            if not isinstance(error, Exception):
                cleanup_control_flow = error
            continue
        result_owner.mark_termination_proven(process)
        if cleanup_control_flow is not None:
            raise cleanup_control_flow
        return
    assert cleanup_error is not None
    raise ForkedProcessClosureUnproven(
        process,
        trigger,
        cleanup_error,
        result_owner=result_owner,
    ) from cleanup_error


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
    result_owner: ForkExecResultOwner,
) -> SpawnedProcess:
    ack_read, ack_write = cloexec_pipe()
    passed_targets = tuple(range(3, 3 + len(pass_fds)))
    receipt = ForkExecReceipt(
        creator_pid=os.getpid(),
        own_process_group=own_process_group,
        acknowledgement_read_fd=ack_read,
        acknowledgement_write_fd=ack_write,
        passed_fd_numbers=passed_targets,
    )
    result_owner.publish_receipt(receipt)
    if not result_owner.owns_receipt(receipt):
        raise ChildProcessError("fork-exec receipt owner did not retain the receipt")
    ack_target = 3 + len(pass_fds)
    try:
        _ensure_fork_exec_hooks()
        try:
            _FORK_EXEC_RECEIPT_CONTEXT.receipt = receipt
            receipt.fork_call_started = True
            try:
                pid = os.fork()
            except OSError:
                if not receipt.fork_call_completed:
                    receipt.fork_failure_proven = True
                raise
        finally:
            _clear_active_fork_exec_receipt(receipt)

        receipt.fork_call_completed = True
        if pid != 0:
            receipt.publish_returned_pid(pid)
            receipt.close_acknowledgement_write()
            child_pid = _read_child_pid_receipt(
                receipt,
                deadline=time.monotonic() + _FORK_PID_RECEIPT_SECONDS,
            )
            if child_pid != pid:
                raise ChildProcessError(
                    "fork return does not match the child PID receipt"
                )
            start_identity = process_start_identity(pid)
            process = SpawnedProcess(
                pid=pid,
                pgid=pid if own_process_group else os.getpgrp(),
                acknowledgement_fd=receipt.acknowledgement_read_fd,
                passed_fd_numbers=passed_targets,
                start_identity=start_identity,
                fork_exec_receipt=receipt,
            )
            result_owner.publish(process)
            if not result_owner.owns(process):
                raise ChildProcessError(
                    "fork-exec result owner did not retain the spawned process"
                )
            return process

        if receipt.child_pid_receipt_error is not None:
            raise receipt.child_pid_receipt_error
        if not receipt.child_pid_receipt_published:
            receipt.child_pid_receipt_attempted = True
            _publish_child_pid_receipt(receipt)
        receipt.close_acknowledgement_read()
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
        if not receipt.in_child_process:
            settle_untransferred_fork_exec(result_owner, trigger=error)
            raise
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
        try:
            selector.close()
        finally:
            receipt = process.fork_exec_receipt
            if receipt is None:
                os.close(process.acknowledgement_fd)
            else:
                receipt.close_acknowledgement_read()


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
            if error_number == errno.ESRCH:
                raise ProcessLookupError(
                    error_number,
                    os.strerror(error_number),
                    pid,
                )
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
            process_state = fields[0]
            if len(process_state) != 1:
                raise ValueError("process stat state is malformed")
            try:
                observed_group = int(fields[2], 10)
            except ValueError as error:
                raise ValueError("process stat group is malformed") from error
            # Zombies and dead tasks cannot execute or retain inherited streams.
            # Their parent owns eventual reaping, so they do not block group closure.
            if (
                observed_group == process_group
                and process_state not in _LINUX_TERMINAL_PROCESS_STATES
            ):
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
    error_number = ctypes.get_errno()
    if time.monotonic() >= deadline:
        raise TimeoutError("process-group inspection deadline expired")
    if (
        result < 0
        or (result == 0 and error_number != 0)
        or result % ctypes.sizeof(ctypes.c_int) != 0
    ):
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
