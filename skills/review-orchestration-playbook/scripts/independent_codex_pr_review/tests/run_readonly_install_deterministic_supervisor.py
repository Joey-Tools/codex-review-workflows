from __future__ import annotations

import ctypes
import errno
import grp
import hashlib
import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from types import CodeType, FrameType, TracebackType
from typing import Any

from review_supervisor.gitraw import GitProcessClosureUnproven, run_bounded
from review_supervisor.models import Identity
from review_supervisor.recovery_cleanup import (
    CustodiedDeletionResultOwner,
    CustodiedManifestResultOwner,
    RootSpec,
    build_custodied_manifest,
    delete_custodied_roots,
    quarantine_and_remove_empty_root,
    quarantined_root_recovery_evidence,
    remove_published_manifest,
)
from review_supervisor.secureio import (
    directory_identities_match,
    identity_from_stat,
)
from review_supervisor.signal_relay import (
    DeferredSignalInterrupt,
    activate_deferred_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)

from .async_fd_custody import (
    FdCloseSettlement,
    RawFdCustody,
    acquire_raw_fd,
    supported_async_publication,
)
from .support import (
    _create_bound_owned_private_directory,
    _DirectoryParentBinding,
    _DirectoryParentBindingResultOwner,
    _open_directory_parent,
    _private_runtime_parent,
    _PrivateDirectoryCreationResultOwner,
    _PrivateDirectoryCreationRetentionRequired,
    _settle_directory_parent_binding_result_preserving_trigger,
)

EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
CHILD_TIMEOUT_SECONDS = 600.0
CHILD_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
CHILD_STDERR_LIMIT_BYTES = 8 * 1024 * 1024
ACL_LISTING_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
XATTR_NOFOLLOW = 0x0001
XATTR_NAMES_LIMIT_BYTES = 64 * 1024
XATTR_VALUE_LIMIT_BYTES = 16 * 1024 * 1024
XATTR_AGGREGATE_LIMIT_BYTES = 64 * 1024 * 1024
DARWIN_PROC_UID_ONLY = 4
DARWIN_PROC_RUID_ONLY = 5
DARWIN_CTL_KERN = 1
DARWIN_KERN_PROC = 14
DARWIN_KERN_PROC_PID = 1
DARWIN_KINFO_PROC_BYTES = 648
DARWIN_PROCESS_CENSUS_CAP = 4096
DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS = 5.0
DARWIN_PROCESS_ABSENCE_STABILITY_SECONDS = 0.25
SANDBOX_FILTER_NONE = 0
CHILD_ACCOUNT_PROBE_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
CHILD_ACCOUNT_PROBE_TIMEOUT_SECONDS = 5.0
BOUND_CLEANUP_ENTRY_CAP = 8192
BOUND_CLEANUP_MANIFEST_BYTES = 4 * 1024 * 1024
BOUND_CLEANUP_TIMEOUT_SECONDS = 60.0
_CLEANUP_BODY_CONTEXT_SCAN_LIMIT = 64
_CLEANUP_BODY_TRACEBACK_SCAN_LIMIT = 256
_CLEANUP_RECOVERY_EVIDENCE_ATTR = "_readonly_cleanup_recovery_evidence"


@dataclass(frozen=True)
class TreeEntrySnapshot:
    kind: str
    device: int
    inode: int
    generation: int
    uid: int
    gid: int
    mode: int
    flags: int
    link_count: int | None
    digest: str | None
    xattrs: tuple[tuple[bytes, str], ...]
    acl_entries: tuple[bytes, ...]

    def protected_key(self) -> tuple[object, ...]:
        return (
            self.kind,
            self.device,
            self.inode,
            self.generation,
            self.uid,
            self.gid,
            self.mode,
            self.flags,
            self.link_count,
            self.digest,
            self.xattrs,
            self.acl_entries,
        )


@dataclass(frozen=True)
class CleanupFailure:
    path: str
    error_kind: str
    error_errno: int | None
    retained: bool | None
    restore_error_kind: str | None
    restore_error_errno: int | None
    original_path: str | None = None
    path_status: str = "lexical"
    replacement_path: str | None = None
    held_identity: dict[str, int] | None = None
    original_path_status: str | None = None
    access_policy_status: str | None = None
    recovery_evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class PrimaryFailure:
    stage: str
    error_kind: str
    error_errno: int | None
    message: str


@dataclass(frozen=True)
class SecondaryFailure:
    operation: str
    error_kind: str
    error_errno: int | None
    message: str


class ChildRunInterrupted(RuntimeError):
    def __init__(self, signal_number: int) -> None:
        self.signal_number = signal_number
        super().__init__(f"child run interrupted by signal {signal_number}")


class ChildSignalTeardownError(RuntimeError):
    def __init__(self, failures: tuple[SecondaryFailure, ...]) -> None:
        self.failures = failures
        operations = ",".join(failure.operation for failure in failures)
        super().__init__(f"child signal teardown failed: {operations}")


@dataclass(frozen=True)
class ChildSignalGuard:
    signals: tuple[signal.Signals, ...]
    previous_handlers: tuple[Any, ...]
    previous_mask: set[signal.Signals]
    interrupt: DeferredSignalInterrupt


@dataclass
class ChildProcessClosureProof:
    # Protected property: same-UID process-tree closure. Only this proof may
    # authorize destructive cleanup; a returned child outcome is not closure
    # evidence and is deliberately carried by a separate caller-owned receipt.
    started: bool = False
    proven: bool = False
    destructive_cleanup_authorized: bool = True


@dataclass
class ChildRunOutcomeReceipt:
    """Caller-owned receipt for a bounded child's returned process outcome.

    The protected property is diagnostic stability of the return code and
    byte-bounded output after ``run_bounded`` returns. Publication proves
    neither same-UID process-tree closure nor permission to delete retained
    directories; those responsibilities remain with ``ChildProcessClosureProof``.
    """

    completed: subprocess.CompletedProcess[str] | None = None

    def publish(self, completed: subprocess.CompletedProcess[str]) -> None:
        if self.completed is not None:
            raise RuntimeError("bounded child outcome receipt was already published")
        self.completed = completed


def _child_process_closure_status(proof: ChildProcessClosureProof) -> str:
    if proof.proven:
        return "proven"
    return "unproven" if proof.started else "not-started"


@dataclass(frozen=True)
class BoundPathEvidence:
    path: pathlib.Path
    retained: bool | None
    path_status: str
    replacement_path: pathlib.Path | None
    original_path_status: str
    access_policy_status: str


@dataclass(frozen=True, order=True)
class DarwinProcessIdentity:
    # Protected property: process-object identity. PID selects the process
    # table slot but can be recycled; the exact kernel start timeval
    # distinguishes successive occupants. State and credential metadata are
    # deliberately excluded because they can change without object replacement.
    pid: int
    start_seconds: int
    start_microseconds: int
    # Process state is diagnostic/scope evidence, not object identity. A live
    # process can become terminal without occupying a new process-table slot.
    process_state: bytes = field(default=b"?", compare=False)


class ChildProcessTreeClosureUnproven(RuntimeError):
    def __init__(
        self,
        processes: tuple[DarwinProcessIdentity, ...],
        cause: BaseException | None = None,
    ) -> None:
        self.processes = processes
        self.cause = cause
        identities = ",".join(
            f"{item.pid}:{item.start_seconds}.{item.start_microseconds:06d}"
            f"/state={item.process_state[0] if len(item.process_state) == 1 else -1}"
            for item in processes[:16]
        )
        if len(processes) > 16:
            identities += f",...(+{len(processes) - 16})"
        detail = (
            identities
            if identities
            else type(cause).__name__
            if cause is not None
            else "unknown"
        )
        super().__init__(f"same-UID child process-tree closure is unproven: {detail}")


class _DarwinTimeval(ctypes.Structure):
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_int),
    )


class _DarwinKinfoProcPrefix(ctypes.Structure):
    # SDK-declared 64-bit Darwin layout prefix of kinfo_proc.kp_proc
    # (extern_proc). The initial union has the same layout as timeval.
    _fields_ = (
        ("p_starttime", _DarwinTimeval),
        ("p_vmspace", ctypes.c_void_p),
        ("p_sigacts", ctypes.c_void_p),
        ("p_flag", ctypes.c_int),
        ("p_stat", ctypes.c_char),
        ("p_pid", ctypes.c_int),
    )


class _DarwinKinfoProcScope(ctypes.Structure):
    # SDK-declared 64-bit Darwin kinfo_proc offsets through the real/effective
    # UID fields. These are census-scope signals, not process-object identity.
    _fields_ = (
        ("identity", _DarwinKinfoProcPrefix),
        (
            "_through_real_uid",
            ctypes.c_uint8 * (392 - ctypes.sizeof(_DarwinKinfoProcPrefix)),
        ),
        ("real_uid", ctypes.c_uint32),
        ("_through_effective_uid", ctypes.c_uint8 * (420 - 392 - 4)),
        ("effective_uid", ctypes.c_uint32),
    )


def _install_child_signal_guard() -> ChildSignalGuard:
    handled = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
    previous_handlers: list[Any] = []
    interrupt = DeferredSignalInterrupt(ChildRunInterrupted)

    def interrupt_child_run(
        signal_number: int,
        _frame: FrameType | None,
    ) -> None:
        interrupt.request(signal_number)

    try:
        for signal_number in handled:
            previous_handlers.append(signal.signal(signal_number, interrupt_child_run))
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, handled)
        for signal_number, previous in zip(
            handled[: len(previous_handlers)],
            previous_handlers,
            strict=True,
        ):
            signal.signal(signal_number, previous)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    return ChildSignalGuard(
        signals=handled,
        previous_handlers=tuple(previous_handlers),
        previous_mask=previous_mask,
        interrupt=interrupt,
    )


def _restore_child_signal_guard(guard: ChildSignalGuard) -> None:
    signal.pthread_sigmask(signal.SIG_BLOCK, guard.signals)
    try:
        for signal_number, previous in zip(
            guard.signals,
            guard.previous_handlers,
            strict=True,
        ):
            signal.signal(signal_number, previous)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, guard.previous_mask)


def _secondary_failure(
    operation: str,
    error: BaseException,
) -> SecondaryFailure:
    try:
        error_errno = getattr(error, "errno", None)
    except BaseException:
        error_errno = None
    try:
        message = str(error)
    except BaseException as formatting_error:
        message = (
            "<secondary failure message unavailable: "
            f"{type(formatting_error).__name__}>"
        )
    if len(message) > 2_048:
        message = message[-2_048:]
    return SecondaryFailure(
        operation=operation,
        error_kind=type(error).__name__,
        error_errno=error_errno if isinstance(error_errno, int) else None,
        message=message,
    )


def _prefer_control_flow_error(
    earlier: BaseException,
    later: BaseException,
) -> tuple[BaseException, BaseException]:
    if isinstance(earlier, Exception) and not isinstance(later, Exception):
        return later, earlier
    return earlier, later


@contextmanager
def _bound_child_signals(
    secondary_failures: list[SecondaryFailure],
) -> Iterator[None]:
    guard = _install_child_signal_guard()
    binding: Any | None = None
    primary_error: BaseException | None = None
    try:
        binding = activate_deferred_signal_interrupt(guard.interrupt)
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        teardown_errors: list[BaseException] = []
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, guard.signals)
        except BaseException as error:
            secondary_failures.append(_secondary_failure("block-child-signals", error))
            teardown_errors.append(error)
        else:
            if binding is not None:
                try:
                    deactivate_deferred_signal_interrupt(binding)
                except BaseException as error:
                    secondary_failures.append(
                        _secondary_failure(
                            "deactivate-deferred-signal-interrupt",
                            error,
                        )
                    )
                    teardown_errors.append(error)
            try:
                _restore_child_signal_guard(guard)
            except BaseException as error:
                secondary_failures.append(
                    _secondary_failure("restore-child-signal-guard", error)
                )
                teardown_errors.append(error)
        if teardown_errors and primary_error is None:
            control_flow = next(
                (
                    error
                    for error in teardown_errors
                    if not isinstance(error, Exception)
                ),
                None,
            )
            if control_flow is not None:
                raise control_flow
            raise ChildSignalTeardownError(tuple(secondary_failures))


def _process_census_deadline(deadline: float | None = None) -> float:
    return (
        time.monotonic() + DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS
        if deadline is None
        else deadline
    )


def _require_process_census_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("same-UID Darwin process census deadline expired")


def _darwin_same_uid_processes(
    *,
    deadline: float | None = None,
) -> tuple[DarwinProcessIdentity, ...]:
    operation_deadline = _process_census_deadline(deadline)
    _require_process_census_time(operation_deadline)
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Darwin process census is unavailable")
    if (
        ctypes.sizeof(_DarwinTimeval) != 16
        or _DarwinTimeval.tv_usec.offset != 8
        or _DarwinKinfoProcPrefix.p_pid.offset != 40
        or ctypes.sizeof(_DarwinKinfoProcPrefix) != 48
        or _DarwinKinfoProcScope.real_uid.offset != 392
        or _DarwinKinfoProcScope.effective_uid.offset != 420
        or ctypes.sizeof(_DarwinKinfoProcScope) != 424
    ):
        raise OSError(errno.ENOTSUP, "unsupported Darwin kinfo_proc ABI")
    user_id = os.getuid()
    process_library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    system_library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    _require_process_census_time(operation_deadline)
    list_pids = process_library.proc_listpids
    list_pids.argtypes = (
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    )
    list_pids.restype = ctypes.c_int
    inspect_pid = system_library.sysctl
    inspect_pid.argtypes = (
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    )
    inspect_pid.restype = ctypes.c_int

    while True:
        process_ids: set[int] = set()
        for process_type in (DARWIN_PROC_UID_ONLY, DARWIN_PROC_RUID_ONLY):
            _require_process_census_time(operation_deadline)
            buffer = (ctypes.c_int * DARWIN_PROCESS_CENSUS_CAP)()
            buffer_bytes = ctypes.sizeof(buffer)
            ctypes.set_errno(0)
            result = list_pids(
                process_type,
                user_id,
                buffer,
                buffer_bytes,
            )
            _require_process_census_time(operation_deadline)
            error_number = ctypes.get_errno()
            if (
                result < 0
                or (result == 0 and error_number != 0)
                or result % ctypes.sizeof(ctypes.c_int) != 0
            ):
                raise OSError(
                    error_number or errno.EIO,
                    "cannot enumerate same-UID Darwin processes",
                )
            if result >= buffer_bytes:
                raise OverflowError("same-UID Darwin process census exceeds its cap")
            count = result // ctypes.sizeof(ctypes.c_int)
            process_ids.update(item for item in buffer[:count] if item > 0)

        processes: list[DarwinProcessIdentity] = []
        retry_census = False
        for pid in sorted(process_ids):
            _require_process_census_time(operation_deadline)
            mib = (ctypes.c_int * 4)(
                DARWIN_CTL_KERN,
                DARWIN_KERN_PROC,
                DARWIN_KERN_PROC_PID,
                pid,
            )
            buffer = (ctypes.c_uint8 * DARWIN_KINFO_PROC_BYTES)()
            buffer_size = ctypes.c_size_t(ctypes.sizeof(buffer))
            ctypes.set_errno(0)
            info_result = inspect_pid(
                mib,
                len(mib),
                buffer,
                ctypes.byref(buffer_size),
                None,
                0,
            )
            _require_process_census_time(operation_deadline)
            error_number = ctypes.get_errno()
            if info_result != 0:
                if error_number == errno.ESRCH:
                    # The enumerated process exited before its start identity
                    # could be bound. Restart the complete census under the
                    # shared deadline so PID reuse is rebound rather than
                    # skipped under the old object's numeric PID.
                    retry_census = True
                    break
                raise OSError(
                    error_number or errno.EIO,
                    f"cannot bind same-UID Darwin process identity: {pid}",
                )
            if buffer_size.value == 0:
                # KERN_PROC_PID reports an exited process as a successful,
                # empty result on current Darwin releases.
                retry_census = True
                break
            if buffer_size.value != DARWIN_KINFO_PROC_BYTES:
                raise OSError(
                    errno.EIO,
                    f"cannot bind same-UID Darwin process identity: {pid}",
                )
            value = ctypes.cast(
                buffer,
                ctypes.POINTER(_DarwinKinfoProcScope),
            ).contents
            if (
                value.identity.p_pid != pid
                or value.identity.p_starttime.tv_sec <= 0
                or not 0 <= value.identity.p_starttime.tv_usec < 1_000_000
            ):
                raise OSError(
                    errno.EIO,
                    f"cannot bind same-UID Darwin process identity: {pid}",
                )
            if value.effective_uid != user_id and value.real_uid != user_id:
                # UID is the census scope, not object identity. A credential
                # transition or cross-UID PID reuse between enumeration and
                # binding restarts the complete snapshot rather than being
                # mislabeled as object replacement or silently skipped.
                retry_census = True
                break
            processes.append(
                DarwinProcessIdentity(
                    pid=pid,
                    start_seconds=value.identity.p_starttime.tv_sec,
                    start_microseconds=value.identity.p_starttime.tv_usec,
                    process_state=bytes(value.identity.p_stat),
                )
            )
        if not retry_census:
            return tuple(processes)


def _stable_same_uid_processes(
    *,
    deadline: float | None = None,
) -> tuple[DarwinProcessIdentity, ...]:
    operation_deadline = _process_census_deadline(deadline)
    first = _darwin_same_uid_processes(deadline=operation_deadline)
    remaining = operation_deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("same-UID Darwin process census deadline expired")
    time.sleep(min(0.01, remaining))
    _require_process_census_time(operation_deadline)
    second = _darwin_same_uid_processes(deadline=operation_deadline)
    # Both scans finish before the supervised child can start. Exact
    # (pid, start_seconds, start_microseconds) identities from either scan are
    # therefore valid
    # baseline objects, while PID reuse after either scan produces a distinct
    # identity. Taking their union tolerates unrelated same-UID process churn
    # without allowing a post-baseline process to hide behind a recycled PID.
    return tuple(sorted(set(first) | set(second)))


def _require_no_new_same_uid_processes(
    baseline: tuple[DarwinProcessIdentity, ...],
    *,
    deadline: float | None = None,
) -> None:
    operation_deadline = _process_census_deadline(deadline)
    baseline_set = set(baseline)
    last_escaped: tuple[DarwinProcessIdentity, ...] = ()
    absent_since: float | None = None
    while True:
        if time.monotonic() >= operation_deadline:
            if last_escaped:
                raise ChildProcessTreeClosureUnproven(last_escaped)
            raise ChildProcessTreeClosureUnproven(
                (),
                TimeoutError("same-UID Darwin process census deadline expired"),
            )
        observed = _darwin_same_uid_processes(deadline=operation_deadline)
        escaped = tuple(item for item in observed if item not in baseline_set)
        if escaped:
            last_escaped = escaped
            absent_since = None
            _reap_terminal_same_uid_children(
                escaped,
                deadline=operation_deadline,
            )
        else:
            now = time.monotonic()
            if absent_since is None:
                absent_since = now
            elif now - absent_since >= DARWIN_PROCESS_ABSENCE_STABILITY_SECONDS:
                return
        if not any(item.pid == os.getpid() for item in observed):
            raise ChildProcessTreeClosureUnproven(
                (),
                OSError(errno.ESTALE, "process census omitted the supervisor"),
            )
        remaining = operation_deadline - time.monotonic()
        if remaining <= 0:
            continue
        time.sleep(min(0.01, remaining))


def _reap_terminal_same_uid_children(
    processes: tuple[DarwinProcessIdentity, ...],
    *,
    deadline: float,
) -> None:
    for process in processes:
        try:
            _require_process_census_time(deadline)
        except TimeoutError as error:
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        try:
            terminal = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            # A same-UID process that is not our child remains census-visible
            # and therefore cannot be promoted to proven closure here.
            continue
        except ProcessLookupError:
            continue
        if terminal is None:
            continue
        if terminal.si_pid != process.pid:
            error = ChildProcessError("terminal child status returned a different PID")
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        # WNOWAIT keeps this terminal process-table object present. Rebind its
        # exact start timeval before the numeric-PID reap: PID selects the slot,
        # while the start timeval proves that the slot still contains the
        # census object. Mutable state remains diagnostic and is not compared.
        try:
            _require_process_census_time(deadline)
            rebound = tuple(
                candidate
                for candidate in _darwin_same_uid_processes(deadline=deadline)
                if candidate.pid == process.pid
            )
            _require_process_census_time(deadline)
        except Exception as error:
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        if not rebound:
            error = ProcessLookupError(
                errno.ESRCH,
                "terminal child identity disappeared before reap",
                process.pid,
            )
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        if len(rebound) != 1:
            error = OSError(
                errno.EIO,
                "terminal child PID has ambiguous process identities",
                process.pid,
            )
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        if rebound[0] != process:
            error = OSError(
                errno.ESTALE,
                "terminal child identity changed before reap",
                process.pid,
            )
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        try:
            _require_process_census_time(deadline)
            waited, _ = os.waitpid(process.pid, os.WNOHANG)
            _require_process_census_time(deadline)
        except Exception as error:
            raise ChildProcessTreeClosureUnproven((process,), error) from error
        if waited not in (0, process.pid):
            error = ChildProcessError("terminal child reap returned a different PID")
            raise ChildProcessTreeClosureUnproven((process,), error) from error


def _require_process_identities_absent(
    processes: tuple[DarwinProcessIdentity, ...],
    *,
    deadline: float | None = None,
) -> None:
    operation_deadline = _process_census_deadline(deadline)
    required_absent = set(processes)
    absent_since: float | None = None
    last_present = processes
    while True:
        if time.monotonic() >= operation_deadline:
            raise ChildProcessTreeClosureUnproven(last_present)
        observed = set(_darwin_same_uid_processes(deadline=operation_deadline))
        present = tuple(sorted(required_absent & observed))
        if present:
            last_present = present
            absent_since = None
            _reap_terminal_same_uid_children(
                present,
                deadline=operation_deadline,
            )
        else:
            now = time.monotonic()
            if absent_since is None:
                absent_since = now
            elif now - absent_since >= DARWIN_PROCESS_ABSENCE_STABILITY_SECONDS:
                return
        remaining = operation_deadline - time.monotonic()
        if remaining <= 0:
            continue
        time.sleep(min(0.01, remaining))


def _require_sudo_exec_denied() -> None:
    try:
        subprocess.run(
            ("/usr/bin/sudo", "-n", "-l"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=CHILD_ACCOUNT_PROBE_TIMEOUT_SECONDS,
            env=CHILD_ACCOUNT_PROBE_ENVIRONMENT,
        )
    except PermissionError as error:
        if error.errno == errno.EPERM:
            return
        raise RuntimeError(
            "cannot prove the inherited sandbox denies sudo execution"
        ) from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(
            "cannot prove the inherited sandbox denies sudo execution"
        ) from error
    raise RuntimeError("sudo execution was not denied by the inherited sandbox")


def _require_job_creation_denied() -> None:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Darwin Seatbelt inspection is unavailable")
    library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
    sandbox_check = library.sandbox_check
    sandbox_check.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    sandbox_check.restype = ctypes.c_int
    result = sandbox_check(
        os.getpid(),
        b"job-creation",
        SANDBOX_FILTER_NONE,
    )
    if result != 1:
        raise RuntimeError(
            "cannot prove the inherited sandbox denies launchd job creation"
        )


def _require_isolated_child_account() -> tuple[DarwinProcessIdentity, ...]:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise PermissionError(errno.EPERM, "read-only child account UID is privileged")
    try:
        admin_group = grp.getgrnam("admin").gr_gid
    except KeyError as error:
        raise RuntimeError("cannot resolve the Darwin admin group") from error
    if admin_group in os.getgroups():
        raise PermissionError(
            errno.EPERM,
            "read-only child account is a member of the admin group",
        )
    _require_job_creation_denied()
    _require_sudo_exec_denied()
    baseline = _stable_same_uid_processes()
    if len(baseline) != 1 or baseline[0].pid != os.getpid():
        raise ChildProcessTreeClosureUnproven(
            baseline,
            OSError(errno.EBUSY, "read-only child account is not process-isolated"),
        )
    return baseline


def _run_bounded_child(
    argv: tuple[str, ...],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    timeout: float = CHILD_TIMEOUT_SECONDS,
    stdout_limit: int = CHILD_STDOUT_LIMIT_BYTES,
    stderr_limit: int = CHILD_STDERR_LIMIT_BYTES,
    secondary_failures: list[SecondaryFailure] | None = None,
    closure_proof: ChildProcessClosureProof | None = None,
    outcome_receipt: ChildRunOutcomeReceipt | None = None,
    require_isolated_account: bool = False,
) -> subprocess.CompletedProcess[str]:
    diagnostics = secondary_failures if secondary_failures is not None else []
    proof = closure_proof if closure_proof is not None else ChildProcessClosureProof()
    proof.destructive_cleanup_authorized = False
    with _bound_child_signals(diagnostics):
        baseline = (
            _require_isolated_child_account()
            if require_isolated_account
            else _stable_same_uid_processes()
        )
        result: tuple[int, bytes, bytes] | None = None
        pending_error: BaseException | None = None
        proof.started = True
        try:
            result = run_bounded(
                argv,
                cwd=cwd,
                environment=environment,
                timeout=timeout,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
            )
        except GitProcessClosureUnproven as error:
            try:
                error.finish_signal_deferral(deliver=False)
            except BaseException as teardown_error:
                diagnostics.append(
                    _secondary_failure(
                        "finish-closure-signal-deferral",
                        teardown_error,
                    )
                )
            pending_error = error
        except BaseException as error:
            pending_error = error
        completed: subprocess.CompletedProcess[str] | None = None
        if result is not None:
            try:
                returncode, stdout, stderr = result
                completed = subprocess.CompletedProcess(
                    args=argv,
                    returncode=returncode,
                    stdout=stdout.decode("utf-8", "replace"),
                    stderr=stderr.decode("utf-8", "replace"),
                )
                if outcome_receipt is not None:
                    # Publish the diagnostic outcome before closure can fail. This
                    # receipt is intentionally incapable of changing cleanup authority.
                    outcome_receipt.publish(completed)
            except BaseException as error:
                # Receipt construction/publication is diagnostic custody, not
                # closure. Preserve its failure without skipping the mandatory
                # same-UID closure check below.
                pending_error = error
        try:
            _require_no_new_same_uid_processes(baseline)
        except ChildProcessTreeClosureUnproven as error:
            raise error from pending_error
        except BaseException as error:
            raise ChildProcessTreeClosureUnproven((), error) from pending_error
        if isinstance(pending_error, GitProcessClosureUnproven):
            raise pending_error
        proof.proven = True
        proof.destructive_cleanup_authorized = True
        if pending_error is not None:
            raise pending_error
        assert completed is not None
    return completed


def _acl_entries(path: pathlib.Path) -> tuple[bytes, ...]:
    completed = subprocess.run(
        ("/bin/ls", "-lde", str(path)),
        env=ACL_LISTING_ENVIRONMENT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )
    if completed.returncode != 0:
        raise RuntimeError("failed to snapshot extended ACL")
    return tuple(completed.stdout.splitlines()[1:])


def _xattr_snapshot(path: pathlib.Path) -> tuple[tuple[bytes, str], ...]:
    libc = ctypes.CDLL(None, use_errno=True)
    listxattr = libc.listxattr
    listxattr.argtypes = (
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    )
    listxattr.restype = ctypes.c_ssize_t
    getxattr = libc.getxattr
    getxattr.argtypes = (
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    getxattr.restype = ctypes.c_ssize_t
    raw_path = os.fsencode(path)

    def read_names() -> bytes:
        ctypes.set_errno(0)
        size = listxattr(raw_path, None, 0, XATTR_NOFOLLOW)
        if size < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot size extended attribute names",
            )
        if size > XATTR_NAMES_LIMIT_BYTES:
            raise ValueError("extended attribute names exceed their byte bound")
        if size == 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        ctypes.set_errno(0)
        actual = listxattr(raw_path, buffer, size, XATTR_NOFOLLOW)
        if actual < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot read extended attribute names",
            )
        if actual != size:
            raise OSError(errno.ESTALE, "extended attributes changed during snapshot")
        return bytes(buffer.raw[:size])

    first_names = read_names()
    second_names = read_names()
    if first_names != second_names:
        raise OSError(errno.ESTALE, "extended attributes changed during snapshot")
    if not first_names:
        return ()
    if not first_names.endswith(b"\0"):
        raise ValueError("extended attribute name list is malformed")
    names = tuple(sorted(first_names[:-1].split(b"\0")))
    if (
        any(not name for name in names)
        or len(names) > 128
        or len(set(names)) != len(names)
    ):
        raise ValueError("extended attribute name list is malformed")

    aggregate_size = 0
    snapshot: list[tuple[bytes, str]] = []
    for name in names:

        def read_value() -> bytes:
            ctypes.set_errno(0)
            size = getxattr(raw_path, name, None, 0, 0, XATTR_NOFOLLOW)
            if size < 0:
                raise OSError(
                    ctypes.get_errno() or errno.EIO,
                    "cannot size extended attribute value",
                )
            if size > XATTR_VALUE_LIMIT_BYTES:
                raise ValueError("extended attribute value exceeds its byte bound")
            if size == 0:
                return b""
            buffer = ctypes.create_string_buffer(size)
            ctypes.set_errno(0)
            actual = getxattr(
                raw_path,
                name,
                buffer,
                size,
                0,
                XATTR_NOFOLLOW,
            )
            if actual < 0:
                raise OSError(
                    ctypes.get_errno() or errno.EIO,
                    "cannot read extended attribute value",
                )
            if actual != size:
                raise OSError(
                    errno.ESTALE,
                    "extended attribute changed during snapshot",
                )
            return bytes(buffer.raw[:size])

        first_value = read_value()
        second_value = read_value()
        if first_value != second_value:
            raise OSError(errno.ESTALE, "extended attribute changed during snapshot")
        aggregate_size += len(first_value)
        if aggregate_size > XATTR_AGGREGATE_LIMIT_BYTES:
            raise ValueError("extended attributes exceed their aggregate byte bound")
        snapshot.append((name, hashlib.sha256(first_value).hexdigest()))
    return tuple(snapshot)


def _tree_snapshot(root: pathlib.Path) -> dict[str, TreeEntrySnapshot]:
    snapshot: dict[str, TreeEntrySnapshot] = {}
    paths = (root, *sorted(root.rglob("*")))
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise RuntimeError(
                    f"regular file has an external hardlink alias: {relative}"
                )
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            kind = "file"
            link_count = metadata.st_nlink
        elif stat.S_ISDIR(metadata.st_mode):
            digest = None
            kind = "directory"
            link_count = None
        elif stat.S_ISLNK(metadata.st_mode):
            digest = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
            kind = "symlink"
            link_count = None
        else:
            digest = None
            kind = "other"
            link_count = None
        snapshot[relative] = TreeEntrySnapshot(
            kind=kind,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            generation=getattr(metadata, "st_gen", 0),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=mode,
            flags=getattr(metadata, "st_flags", 0),
            link_count=link_count,
            digest=digest,
            xattrs=_xattr_snapshot(path),
            acl_entries=_acl_entries(path),
        )
    return snapshot


def _tree_property_unchanged(
    before: dict[str, TreeEntrySnapshot],
    after: dict[str, TreeEntrySnapshot],
) -> bool:
    if before.keys() != after.keys():
        return False
    return all(
        before[path].protected_key() == after[path].protected_key() for path in before
    )


def _set_tree_read_only(root: pathlib.Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _restore_owner_write(root: pathlib.Path) -> None:
    for path in sorted(
        (root, *root.rglob("*")),
        key=lambda item: len(item.parts),
    ):
        if path.is_symlink():
            continue
        try:
            mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
            path.chmod(mode | stat.S_IWUSR)
        except FileNotFoundError:
            continue


def _filesystem_object_key(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
    )


def _settle_bound_cleanup_child(
    child_owner: RawFdCustody,
    close_settlement: FdCloseSettlement,
) -> None:
    while child_owner.state in {"empty", "owned"}:
        try:
            close_settlement.settle()
        except BaseException as close_boundary_error:
            close_settlement.capture(
                close_boundary_error,
                "bound cleanup child close caller boundary",
            )
    while True:
        try:
            close_settlement.raise_first()
        except BaseException as raise_boundary_error:
            if raise_boundary_error is close_settlement.first_error:
                raise
            close_settlement.capture(
                raise_boundary_error,
                "bound cleanup final raise caller boundary",
            )
        else:
            break


def _restore_owner_write_below_bound_root(root_fd: int) -> None:
    deadline = time.monotonic() + BOUND_CLEANUP_TIMEOUT_SECONDS
    remaining = BOUND_CLEANUP_ENTRY_CAP

    def visit(directory_fd: int, depth: int) -> None:
        nonlocal remaining
        if depth > 512:
            raise ValueError("bound cleanup tree exceeds its depth cap")
        if time.monotonic() >= deadline:
            raise TimeoutError("bound cleanup write restoration timed out")
        with os.scandir(directory_fd) as entries:
            names = tuple(os.fsencode(entry.name) for entry in entries)
        for name in names:
            if remaining <= 0:
                raise ValueError("bound cleanup tree exceeds its entry cap")
            remaining -= 1
            if time.monotonic() >= deadline:
                raise TimeoutError("bound cleanup write restoration timed out")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            # Identity alone is insufficient: a local path may re-raise the
            # exact exception already handled by this function's caller.
            invocation_ambient_error = sys.exception()
            invocation_ambient_traceback = (
                invocation_ambient_error.__traceback__
                if invocation_ambient_error is not None
                else None
            )
            child_owner = RawFdCustody()
            close_settlement = FdCloseSettlement(child_owner)

            def process_child() -> None:
                try:
                    child_fd = acquire_raw_fd(
                        child_owner,
                        lambda: os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_fd,
                        ),
                    )
                    before = os.fstat(child_fd)
                    if _filesystem_object_key(before) != _filesystem_object_key(
                        metadata
                    ):
                        raise OSError(
                            errno.ESTALE,
                            "bound cleanup directory changed before write restoration",
                        )
                    visit(child_fd, depth + 1)
                    os.fchmod(
                        child_fd,
                        stat.S_IMODE(before.st_mode) | stat.S_IWUSR | stat.S_IXUSR,
                    )
                    if _filesystem_object_key(
                        os.fstat(child_fd)
                    ) != _filesystem_object_key(before):
                        raise OSError(
                            errno.ESTALE,
                            "bound cleanup directory changed during write restoration",
                        )
                except BaseException as error:
                    capture_boundary_errors: tuple[BaseException, ...] = ()
                    while True:
                        try:
                            if close_settlement.first_error is not None:
                                break
                            close_settlement.capture(
                                error,
                                "bound cleanup child traversal",
                            )
                        except BaseException as capture_boundary_error:
                            capture_boundary_errors = (
                                *capture_boundary_errors,
                                capture_boundary_error,
                            )
                    for capture_boundary_error in capture_boundary_errors:
                        primary, secondary = _prefer_control_flow_error(
                            close_settlement.first_error,
                            capture_boundary_error,
                        )
                        if primary is close_settlement.first_error:
                            close_settlement.secondary_errors = (
                                *close_settlement.secondary_errors,
                                (
                                    "bound cleanup child traversal caller boundary",
                                    secondary,
                                ),
                            )
                        else:
                            close_settlement.secondary_errors = (
                                *close_settlement.secondary_errors,
                                ("bound cleanup child traversal", secondary),
                            )
                            close_settlement.first_error = primary
                    raise
                finally:
                    _settle_bound_cleanup_child(child_owner, close_settlement)

            try:
                process_child()
            except BaseException as boundary_error:
                if close_settlement.first_error is None:
                    earlier_error = boundary_error.__context__
                    if earlier_error is invocation_ambient_error and (
                        earlier_error is None
                        or earlier_error.__traceback__ is invocation_ambient_traceback
                    ):
                        earlier_error = None
                    if earlier_error is None:
                        close_settlement.first_error = boundary_error
                    else:
                        primary, secondary = _prefer_control_flow_error(
                            earlier_error,
                            boundary_error,
                        )
                        close_settlement.first_error = primary
                        close_settlement.secondary_errors = (
                            *close_settlement.secondary_errors,
                            (
                                "bound cleanup child traversal caller boundary",
                                secondary,
                            ),
                        )
                elif boundary_error is not close_settlement.first_error:
                    primary, secondary = _prefer_control_flow_error(
                        close_settlement.first_error,
                        boundary_error,
                    )
                    close_settlement.first_error = primary
                    close_settlement.secondary_errors = (
                        *close_settlement.secondary_errors,
                        ("bound cleanup child outer caller boundary", secondary),
                    )
                _settle_bound_cleanup_child(child_owner, close_settlement)
                raise AssertionError("bound cleanup child settlement returned")

    visit(root_fd, 1)


def _bounded_failure_text(value: str, *, limit: int = 16_384) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]


def _primary_failure(stage: str, error: BaseException) -> PrimaryFailure:
    error_errno = getattr(error, "errno", None)
    return PrimaryFailure(
        stage=stage,
        error_kind=type(error).__name__,
        error_errno=error_errno if isinstance(error_errno, int) else None,
        message=_bounded_failure_text(str(error), limit=2_048),
    )


def _cleanup_tree(
    path: pathlib.Path | None,
    *,
    restore_owner_write: bool,
) -> CleanupFailure | None:
    if path is None or not os.path.lexists(path):
        return None
    restore_error: BaseException | None = None
    if restore_owner_write:
        try:
            _restore_owner_write(path)
        except Exception as error:
            restore_error = error
    try:
        shutil.rmtree(path)
    except Exception as error:
        error_errno = getattr(error, "errno", None)
        restore_error_errno = getattr(restore_error, "errno", None)
        return CleanupFailure(
            path=str(path),
            error_kind=type(error).__name__,
            error_errno=error_errno if isinstance(error_errno, int) else None,
            retained=os.path.lexists(path),
            restore_error_kind=(
                type(restore_error).__name__ if restore_error is not None else None
            ),
            restore_error_errno=(
                restore_error_errno if isinstance(restore_error_errno, int) else None
            ),
        )
    if os.path.lexists(path):
        return CleanupFailure(
            path=str(path),
            error_kind="PathRetainedAfterRmtree",
            error_errno=None,
            retained=True,
            restore_error_kind=(
                type(restore_error).__name__ if restore_error is not None else None
            ),
            restore_error_errno=(
                restore_error.errno if restore_error is not None else None
            ),
        )
    return None


def _cleanup_failure_from_error(
    path: pathlib.Path,
    error: BaseException,
    *,
    retained: bool | None,
    original_path: pathlib.Path | None = None,
    path_status: str = "lexical",
    replacement_path: pathlib.Path | None = None,
    held_identity: dict[str, int] | None = None,
    original_path_status: str | None = None,
    access_policy_status: str | None = None,
    recovery_evidence: dict[str, Any] | None = None,
) -> CleanupFailure:
    error_errno = getattr(error, "errno", None)
    return CleanupFailure(
        path=str(path),
        error_kind=type(error).__name__,
        error_errno=error_errno if isinstance(error_errno, int) else None,
        retained=retained,
        restore_error_kind=None,
        restore_error_errno=None,
        original_path=str(original_path) if original_path is not None else None,
        path_status=path_status,
        replacement_path=(
            str(replacement_path) if replacement_path is not None else None
        ),
        held_identity=held_identity,
        original_path_status=original_path_status,
        access_policy_status=access_policy_status,
        recovery_evidence=recovery_evidence,
    )


def _list_bound_directory(
    binding: _DirectoryParentBinding,
) -> tuple[str, ...]:
    binding.revalidate()
    entries = tuple(sorted(os.listdir(binding.fd)))
    binding.revalidate()
    return entries


def _bound_path_evidence(binding: _DirectoryParentBinding) -> BoundPathEvidence:
    original_status = binding.original_path_identity_status()
    access_policy_status = binding.access_policy_status()
    try:
        current = binding.current_path()
    except (OSError, ValueError):
        return BoundPathEvidence(
            path=binding.path,
            retained=_held_object_namespace_retention(binding),
            path_status="bound-unresolved",
            replacement_path=(binding.path if original_status == "replaced" else None),
            original_path_status=original_status,
            access_policy_status=access_policy_status,
        )
    if current == binding.path and original_status != "same":
        original_status = "unstable"
    return BoundPathEvidence(
        path=current,
        retained=True,
        path_status="bound-original" if current == binding.path else "bound-moved",
        replacement_path=(
            binding.path
            if current != binding.path and original_status == "replaced"
            else None
        ),
        original_path_status=original_status,
        access_policy_status=access_policy_status,
    )


def _held_object_namespace_retention(
    binding: _DirectoryParentBinding,
) -> bool | None:
    """Classify namespace retention of the exact descriptor-bound directory."""
    try:
        held_metadata = os.fstat(binding.fd)
    except OSError:
        return None
    if _stat_object_locator(held_metadata) != binding.object_locator():
        return None
    # A positive link count cannot distinguish a non-ASCII move, a transient
    # reopen failure, or another unresolved location. Zero alone proves that
    # this exact held directory object is no longer linked into the namespace.
    return False if held_metadata.st_nlink == 0 else None


def _bound_cleanup_failure(
    binding: _DirectoryParentBinding,
    error: BaseException,
) -> CleanupFailure:
    evidence = _bound_path_evidence(binding)
    recovery_evidence = getattr(error, _CLEANUP_RECOVERY_EVIDENCE_ATTR, None)
    if not isinstance(recovery_evidence, dict):
        recovery_evidence = {}
    else:
        recovery_evidence = dict(recovery_evidence)
    removal_evidence = getattr(
        error,
        "_readonly_manifest_removal_evidence",
        None,
    )
    if isinstance(removal_evidence, dict):
        recovery_evidence["manifest_removal"] = dict(removal_evidence)
    if not recovery_evidence:
        recovery_evidence = None
    return _cleanup_failure_from_error(
        evidence.path,
        error,
        retained=evidence.retained,
        original_path=binding.path,
        path_status=evidence.path_status,
        replacement_path=evidence.replacement_path,
        held_identity=binding.object_locator(),
        original_path_status=evidence.original_path_status,
        access_policy_status=evidence.access_policy_status,
        recovery_evidence=recovery_evidence,
    )


def _stat_object_locator(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "file_type": stat.S_IFMT(value.st_mode),
        "generation": getattr(value, "st_gen", 0),
    }


def _creation_object_locator(value: tuple[int, ...] | None) -> dict[str, int] | None:
    if value is None:
        return None
    device, inode, file_type, generation = value
    return {
        "device": device,
        "inode": inode,
        "file_type": file_type,
        "generation": generation,
    }


def _private_directory_creation_source_evidence(
    error: _PrivateDirectoryCreationRetentionRequired,
) -> dict[str, Any]:
    evidence = error.evidence
    return {
        "stage": evidence.stage,
        "parent_path": evidence.parent_path,
        "entry_name": evidence.entry_name,
        "parent_fd": evidence.parent_fd,
        "directory_fd": evidence.directory_fd,
        "parent_identity": evidence.parent_identity.to_json(),
        "directory_identity": (
            evidence.directory_identity.to_json()
            if evidence.directory_identity is not None
            else None
        ),
        "directory_object_identity": _creation_object_locator(
            evidence.directory_object_identity
        ),
        "observed_identity": (
            evidence.observed_identity.to_json()
            if evidence.observed_identity is not None
            else None
        ),
        "entry_state": evidence.entry_state,
        "trigger_kind": evidence.trigger_kind,
        "trigger_message": _bounded_failure_text(
            evidence.trigger_message,
            limit=2_048,
        ),
        "observation_kind": evidence.observation_kind,
        "observation_message": (
            _bounded_failure_text(evidence.observation_message, limit=2_048)
            if evidence.observation_message is not None
            else None
        ),
        "rollback_kind": evidence.rollback_kind,
        "rollback_message": (
            _bounded_failure_text(evidence.rollback_message, limit=2_048)
            if evidence.rollback_message is not None
            else None
        ),
        "protected_property": evidence.protected_property,
        "access_policy_gate": evidence.access_policy_gate,
    }


def _private_directory_creation_entry_evidence(
    *,
    parent_fd: int,
    name: bytes,
    expected_object: tuple[int, ...] | None,
    expected_unbound_identity: Identity | None,
) -> dict[str, Any]:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {"status": "missing", "identity": None}
    except OSError as error:
        return {
            "status": "unreadable",
            "identity": None,
            "error_kind": type(error).__name__,
            "error_errno": error.errno,
        }
    observed_object = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
    )
    if expected_object is None:
        expected_unbound_object = (
            (
                expected_unbound_identity.device,
                expected_unbound_identity.inode,
                stat.S_IFMT(expected_unbound_identity.mode),
            )
            if expected_unbound_identity is not None
            else None
        )
        observed_unbound_object = observed_object[:3]
        status = (
            "present-unbound"
            if expected_unbound_object is None
            or observed_unbound_object == expected_unbound_object
            else "different-object"
        )
    elif observed_object == expected_object:
        status = "expected-object"
    else:
        status = "different-object"
    return {
        "status": status,
        "identity": _stat_object_locator(metadata),
    }


def _private_directory_creation_lexical_evidence(
    path: pathlib.Path,
    *,
    expected_object: tuple[int, ...] | None,
    expected_unbound_identity: Identity | None,
) -> dict[str, Any]:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return {"status": "missing", "identity": None}
    except OSError as error:
        return {
            "status": "unreadable",
            "identity": None,
            "error_kind": type(error).__name__,
            "error_errno": error.errno,
        }
    observed_object = (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
    )
    if expected_object is not None:
        status = (
            "expected-object"
            if observed_object == expected_object
            else "different-object"
        )
    elif expected_unbound_identity is None:
        status = "present-unbound"
    else:
        expected_unbound_object = (
            expected_unbound_identity.device,
            expected_unbound_identity.inode,
            stat.S_IFMT(expected_unbound_identity.mode),
        )
        status = (
            "present-unbound"
            if observed_object[:3] == expected_unbound_object
            else "different-object"
        )
    return {"status": status, "identity": _stat_object_locator(metadata)}


def _private_directory_creation_quarantine_evidence(
    error: _PrivateDirectoryCreationRetentionRequired,
    *,
    parent_path: pathlib.Path,
    expected_object: tuple[int, ...] | None,
) -> list[dict[str, Any]]:
    quarantined: list[dict[str, Any]] = []
    for evidence in error.quarantined_root_recovery_evidence:
        try:
            observed_metadata = os.stat(
                evidence.quarantine_name,
                dir_fd=evidence.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            quarantine_status = "missing"
            observed_identity = None
        except OSError as observation_error:
            quarantine_status = "unreadable"
            observed_identity = None
            observation_kind: str | None = type(observation_error).__name__
            observation_errno: int | None = observation_error.errno
        else:
            observed_identity = _stat_object_locator(observed_metadata)
            observed_object = (
                observed_metadata.st_dev,
                observed_metadata.st_ino,
                stat.S_IFMT(observed_metadata.st_mode),
                getattr(observed_metadata, "st_gen", 0),
            )
            quarantine_status = (
                "present-unbound"
                if expected_object is None
                else "expected-object"
                if observed_object == expected_object
                else "different-object"
            )
            observation_kind = None
            observation_errno = None
        try:
            held_identity = _stat_object_locator(os.fstat(evidence.root_fd))
        except OSError:
            held_identity = None
        record: dict[str, Any] = {
            "label": evidence.label,
            "stage": evidence.stage,
            "protected_property": evidence.protected_property,
            "original_name_hex": evidence.original_name.hex(),
            "quarantine_name_hex": evidence.quarantine_name.hex(),
            "original_path": str(parent_path / os.fsdecode(evidence.original_name)),
            "quarantine_path": str(parent_path / os.fsdecode(evidence.quarantine_name)),
            "parent_identity": evidence.parent_identity.to_json(),
            "expected_root_identity": evidence.expected_identity.to_json(),
            "held_root_identity": held_identity,
            "observed_quarantine_identity": observed_identity,
            "quarantine_status": quarantine_status,
            "access_policy_status": "unproven",
        }
        if quarantine_status == "unreadable":
            record["observation_kind"] = observation_kind
            record["observation_errno"] = observation_errno
        quarantined.append(record)
    return quarantined


def _snapshot_private_directory_creation_recovery(
    error: _PrivateDirectoryCreationRetentionRequired,
) -> CleanupFailure:
    recovery = error.recovery
    expected_object = recovery.directory_object_identity
    bound_parent_entry = _private_directory_creation_entry_evidence(
        parent_fd=recovery.parent_fd,
        name=recovery.name,
        expected_object=expected_object,
        expected_unbound_identity=recovery.observed_identity,
    )
    original_lexical_entry = _private_directory_creation_lexical_evidence(
        recovery.path,
        expected_object=expected_object,
        expected_unbound_identity=recovery.observed_identity,
    )
    try:
        current_parent = recovery.parent_binding.current_path()
    except (OSError, ValueError):
        current_parent = recovery.parent_binding.path
        parent_path_status = "bound-unresolved"
    else:
        parent_path_status = (
            "bound-original"
            if current_parent == recovery.parent_binding.path
            else "bound-moved"
        )

    selected_path = recovery.path
    path_status = "unbound-original"
    retained: bool | None
    held_identity: dict[str, int] | None = None
    held_link_count: int | None = None
    current_path_error: dict[str, Any] | None = None
    if recovery.directory_fd is None or expected_object is None:
        if parent_path_status != "bound-unresolved":
            selected_path = current_parent / os.fsdecode(recovery.name)
        retained = {
            # A missing original name is not proof that an unbound object was
            # never created or was not moved elsewhere before this snapshot.
            "missing": None,
            "present-unbound": True,
        }.get(bound_parent_entry["status"])
        path_status = (
            "unbound-parent-unresolved"
            if parent_path_status == "bound-unresolved"
            else "unbound-missing"
            if bound_parent_entry["status"] == "missing"
            else (
                "unbound-parent-moved"
                if parent_path_status == "bound-moved"
                else "unbound-original"
            )
            if bound_parent_entry["status"] == "present-unbound"
            else "unbound-unresolved"
        )
    else:
        held_metadata = os.fstat(recovery.directory_fd)
        held_identity = _stat_object_locator(held_metadata)
        held_link_count = held_metadata.st_nlink
        held_object = (
            held_metadata.st_dev,
            held_metadata.st_ino,
            stat.S_IFMT(held_metadata.st_mode),
            getattr(held_metadata, "st_gen", 0),
        )
        if held_object != expected_object:
            retained = None
            path_status = "bound-identity-mismatch"
        elif held_metadata.st_nlink == 0:
            retained = False
            path_status = "bound-unlinked"
        else:
            try:
                selected_path = recovery.current_directory_path()
            except (OSError, ValueError) as path_error:
                retained = None
                path_status = "bound-unresolved"
                current_path_error = {
                    "error_kind": type(path_error).__name__,
                    "error_errno": (
                        path_error.errno if isinstance(path_error, OSError) else None
                    ),
                    "message": _bounded_failure_text(str(path_error), limit=2_048),
                }
            else:
                retained = True
                path_status = (
                    "bound-original"
                    if selected_path == recovery.path
                    else "bound-moved"
                )

    original_status = str(original_lexical_entry["status"])
    bound_entry_status = str(bound_parent_entry["status"])
    replacement_path = (
        recovery.path
        if original_status == "different-object"
        else selected_path
        if bound_entry_status == "different-object"
        else None
    )
    cleanup_error = error.rollback_error if error.rollback_error is not None else error
    recovery_evidence = {
        "protected_property": "object-identity",
        "access_policy_gate": "private-fail-closed",
        "creation": _private_directory_creation_source_evidence(error),
        "parent_current_path": str(current_parent),
        "parent_path_status": parent_path_status,
        "held_directory_identity": held_identity,
        "held_directory_link_count": held_link_count,
        "current_path_error": current_path_error,
        "bound_parent_entry": bound_parent_entry,
        "original_lexical_entry": original_lexical_entry,
        "quarantined_roots": _private_directory_creation_quarantine_evidence(
            error,
            parent_path=current_parent,
            expected_object=expected_object,
        ),
    }
    return _cleanup_failure_from_error(
        selected_path,
        cleanup_error,
        retained=retained,
        original_path=recovery.path,
        path_status=path_status,
        replacement_path=replacement_path,
        held_identity=held_identity,
        original_path_status=original_status,
        access_policy_status="unproven",
        recovery_evidence=recovery_evidence,
    )


def _private_directory_creation_control_flow_error(
    error: _PrivateDirectoryCreationRetentionRequired,
) -> BaseException | None:
    for candidate in (
        error.trigger_error,
        error.observation_error,
        error.rollback_error,
    ):
        if candidate is not None and not isinstance(candidate, Exception):
            return candidate
    return None


def _fail_closed_deferred_control_flow(error: BaseException) -> BaseException:
    if isinstance(error, SystemExit) and (
        error.code is None or (isinstance(error.code, int) and error.code == 0)
    ):
        hardened = SystemExit(1)
        hardened.add_note(
            "a successful SystemExit was converted to status 1 because "
            "private-directory recovery remained incomplete"
        )
        return hardened
    return error


def _consume_private_directory_creation_retention(
    error: _PrivateDirectoryCreationRetentionRequired,
    *,
    secondary_failures: list[SecondaryFailure],
) -> tuple[CleanupFailure, BaseException | None]:
    deferred = _private_directory_creation_control_flow_error(error)
    if error.observation_error is not None:
        secondary_failures.append(
            _secondary_failure(
                "observe-private-directory-creation-result",
                error.observation_error,
            )
        )
    try:
        failure = _snapshot_private_directory_creation_recovery(error)
    except BaseException as snapshot_error:
        secondary_failures.append(
            _secondary_failure(
                "snapshot-private-directory-creation-recovery",
                snapshot_error,
            )
        )
        if deferred is None and not isinstance(snapshot_error, Exception):
            deferred = snapshot_error
        failure = _cleanup_failure_from_error(
            error.retained_path,
            error.rollback_error if error.rollback_error is not None else error,
            retained=None,
            original_path=error.retained_path,
            path_status="creation-recovery-unresolved",
            original_path_status=error.evidence.entry_state,
            access_policy_status="unproven",
            recovery_evidence={
                "protected_property": "object-identity",
                "access_policy_gate": "private-fail-closed",
                "creation": _private_directory_creation_source_evidence(error),
                "snapshot_error": {
                    "error_kind": type(snapshot_error).__name__,
                    "message": _bounded_failure_text(
                        str(snapshot_error),
                        limit=2_048,
                    ),
                },
            },
        )
    try:
        error.close_descriptors_for_recovery()
    except BaseException as close_error:
        secondary_failures.append(
            _secondary_failure(
                "close-private-directory-creation-recovery",
                close_error,
            )
        )
        if deferred is None and not isinstance(close_error, Exception):
            deferred = close_error
    return failure, deferred


def _claim_private_directory_creation_result(
    owner: _PrivateDirectoryCreationResultOwner,
    binding: _DirectoryParentBinding | None,
) -> _DirectoryParentBinding | None:
    published = owner.binding
    if published is None:
        return binding
    if binding is not None and binding is not published:
        raise RuntimeError("private-directory creation result owner is inconsistent")
    if not owner.transferred:
        owner.transfer(published)
    return published


def _retained_private_directory_creation_from_owner(
    owner: _PrivateDirectoryCreationResultOwner,
    trigger_error: BaseException,
) -> _PrivateDirectoryCreationRetentionRequired | None:
    if owner.retention is not None:
        return owner.retention
    return owner.retained_creation_for(trigger_error)


def _snapshot_bound_cleanup_recovery(
    error: BaseException,
    *,
    parent_binding: _DirectoryParentBinding,
    manifest_path: pathlib.Path,
    manifest_seal: dict[str, Any] | None,
    manifest_result_owner: CustodiedManifestResultOwner,
    deletion_owner: CustodiedDeletionResultOwner,
) -> None:
    try:
        parent_path = parent_binding.current_path()
        parent_path_status = (
            "bound-original" if parent_path == parent_binding.path else "bound-moved"
        )
    except (OSError, ValueError):
        parent_path = parent_binding.path
        parent_path_status = "bound-unresolved"

    deletion_recovery = deletion_owner.recovery_evidence(expected_root_count=1)
    root_states = {
        item["quarantine_name_hex"]: item["state"]
        for item in deletion_recovery["roots"]
    }
    quarantined_roots: list[dict[str, Any]] = []
    for evidence in quarantined_root_recovery_evidence(error):
        quarantine_name = os.fsdecode(evidence.quarantine_name)
        quarantine_path = parent_path / quarantine_name
        observed_identity: dict[str, int] | None = None
        observed_locator: dict[str, int] | None = None
        try:
            observed_stat = os.stat(
                evidence.quarantine_name,
                dir_fd=evidence.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            quarantine_status = "missing"
            retained: bool | None = False
        except OSError:
            quarantine_status = "unreadable"
            retained = None
        else:
            observed = identity_from_stat(observed_stat)
            observed_identity = observed.to_json()
            observed_locator = _stat_object_locator(observed_stat)
            quarantine_status = (
                "expected-object"
                if directory_identities_match(observed, evidence.expected_identity)
                else "different-object"
            )
            retained = True
        try:
            held_root_locator = _stat_object_locator(os.fstat(evidence.root_fd))
        except OSError:
            held_root_locator = None
        quarantined_roots.append(
            {
                "label": evidence.label,
                "stage": evidence.stage,
                "protected_property": evidence.protected_property,
                "original_name_hex": evidence.original_name.hex(),
                "quarantine_name_hex": evidence.quarantine_name.hex(),
                "original_path": str(parent_path / os.fsdecode(evidence.original_name)),
                "quarantine_path": str(quarantine_path),
                "parent_path_status": parent_path_status,
                "parent_identity": evidence.parent_identity.to_json(),
                "parent_held_identity": parent_binding.object_locator(),
                "parent_access_policy_status": (parent_binding.access_policy_status()),
                "expected_root_identity": evidence.expected_identity.to_json(),
                "held_root_identity": held_root_locator,
                "observed_quarantine_identity": observed_identity,
                "observed_quarantine_locator": observed_locator,
                "quarantine_status": quarantine_status,
                "retained": retained,
                "deletion_state": root_states.get(
                    evidence.quarantine_name.hex(),
                    "not-published",
                ),
            }
        )

    published_manifest = manifest_result_owner.manifest
    published_seal = (
        published_manifest.seal if published_manifest is not None else manifest_seal
    )
    manifest_evidence = {
        "path": str(manifest_path),
        "state": "published" if published_manifest is not None else "not-published",
        "result_owner_transferred": manifest_result_owner.transferred,
        "sha256": (
            published_seal.get("sha256") if published_seal is not None else None
        ),
        "record_count": (
            published_seal.get("record_count") if published_seal is not None else None
        ),
    }
    setattr(
        error,
        _CLEANUP_RECOVERY_EVIDENCE_ATTR,
        {
            "protected_property": (
                "recovery-object-identity-and-deletion-result-ownership"
            ),
            "manifest": manifest_evidence,
            "deletion_result": deletion_recovery,
            "quarantined_roots": quarantined_roots,
        },
    )


@dataclass(slots=True)
class _CleanupBodyErrorSettlement:
    """Publish one local body error across supported async handler gaps."""

    invocation_ambient_error: BaseException | None
    invocation_ambient_traceback: TracebackType | None
    invocation_ambient_context: BaseException | None = None
    invocation_ambient_context_traceback: TracebackType | None = None
    invocation_code: CodeType | None = None
    active_error: BaseException | None = None
    active_error_replaced: bool = False
    publication_error: BaseException | None = None
    publication_observations: list[tuple[str, BaseException]] = field(
        default_factory=list
    )
    publication_observation_ids: set[int] = field(default_factory=set)

    def _is_invocation_ambient(self, error: BaseException) -> bool:
        return (
            error is self.invocation_ambient_error
            and error.__traceback__ is self.invocation_ambient_traceback
        )

    def _traceback_belongs_to_invocation(self, error: BaseException) -> bool:
        invocation_code = self.invocation_code
        if invocation_code is None:
            return False
        seen: set[int] = set()
        cursor = error.__traceback__
        for _ in range(_CLEANUP_BODY_TRACEBACK_SCAN_LIMIT):
            if not isinstance(cursor, TracebackType):
                return False
            cursor_id = id(cursor)
            if cursor_id in seen:
                return False
            seen.add(cursor_id)
            frame = cursor.tb_frame
            if frame.f_code is invocation_code:
                try:
                    settlement = frame.f_locals.get("body_error_settlement")
                except BaseException:  # noqa: BLE001 - fail closed
                    return False
                if settlement is self:
                    return True
            cursor = cursor.tb_next
        return False

    def _capture_publication_error(
        self,
        error: BaseException,
        operation: str,
    ) -> None:
        error_id = id(error)
        secondary: BaseException | None = None
        with supported_async_publication():
            if (
                error is self.active_error
                or error_id in self.publication_observation_ids
            ):
                return
            # The id, strong observation reference, and selected publication
            # primary are one transaction. A restored hook can observe all of
            # them or none of them, never a seen-but-unpublished error.
            self.publication_observation_ids.add(error_id)
            self.publication_observations.append((operation, error))
            if self.publication_error is None:
                self.publication_error = error
            else:
                primary, secondary = _prefer_control_flow_error(
                    self.publication_error,
                    error,
                )
                self.publication_error = primary
        if secondary is None:
            return
        try:
            primary.add_note(
                f"{operation} also failed: {type(secondary).__name__}: {secondary}"
            )
        except BaseException:  # noqa: BLE001, S110 - notes are best effort
            pass

    def publish_local_active_error(self, error: BaseException) -> None:
        with supported_async_publication():
            self.active_error = error

    def recover_current_exception(self) -> None:
        """Recover a bounded, invocation-local body error after replacement."""

        with supported_async_publication():
            current_error = sys.exception()
            if (
                not isinstance(current_error, BaseException)
                or self._is_invocation_ambient(current_error)
                or current_error is self.active_error
            ):
                return

            if self.active_error is not None:
                active_error = self.active_error
                invocation_candidates: list[BaseException] = []
                seen: set[int] = set()
                cursor: BaseException | None = current_error
                scan_complete = False
                for _ in range(_CLEANUP_BODY_CONTEXT_SCAN_LIMIT):
                    if not isinstance(cursor, BaseException):
                        scan_complete = True
                        break
                    cursor_id = id(cursor)
                    if cursor_id in seen:
                        break
                    seen.add(cursor_id)
                    if cursor is active_error or self._is_invocation_ambient(cursor):
                        scan_complete = True
                        break
                    if self._traceback_belongs_to_invocation(cursor):
                        invocation_candidates.append(cursor)
                    try:
                        context = cursor.__context__
                    except BaseException:  # noqa: BLE001 - fail closed
                        break
                    if not isinstance(context, BaseException):
                        scan_complete = True
                        break
                    cursor = context

                if scan_complete:
                    for candidate in reversed(invocation_candidates):
                        active_error, _secondary = _prefer_control_flow_error(
                            active_error,
                            candidate,
                        )
                    self.active_error = active_error
                self.active_error_replaced = current_error is not self.active_error
                if current_error is not self.active_error:
                    self._capture_publication_error(
                        current_error,
                        "cleanup body publication boundary",
                    )
                return

            seen: set[int] = set()
            candidate: BaseException | None = None
            cursor: BaseException | None = current_error
            scan_complete = False
            for _ in range(_CLEANUP_BODY_CONTEXT_SCAN_LIMIT):
                if not isinstance(cursor, BaseException):
                    scan_complete = True
                    break
                cursor_id = id(cursor)
                if cursor_id in seen:
                    break
                seen.add(cursor_id)

                if cursor is self.invocation_ambient_error:
                    if cursor.__traceback__ is self.invocation_ambient_traceback:
                        scan_complete = True
                        break
                    if self._traceback_belongs_to_invocation(cursor):
                        candidate = cursor
                        scan_complete = True
                        break
                    try:
                        context = cursor.__context__
                    except BaseException:  # noqa: BLE001 - fail closed
                        break
                    if cursor is current_error:
                        candidate = cursor
                        scan_complete = True
                        break
                    if context is self.invocation_ambient_context:
                        if (
                            not isinstance(context, BaseException)
                            or context.__traceback__
                            is self.invocation_ambient_context_traceback
                        ):
                            # The body locally reraised the ambient object and
                            # retained its exact pre-invocation context.
                            candidate = cursor
                            scan_complete = True
                        # A mutated pre-invocation context is ambiguous. Do not
                        # enter it or select the ambient control-flow object.
                        break
                    if not isinstance(context, BaseException):
                        break
                    # A changed context proves that this ambient object is an
                    # intermediate callback error. Skip it and continue toward
                    # the invocation-local cleanup body.
                    cursor = context
                    continue

                candidate = cursor
                try:
                    context = cursor.__context__
                except BaseException:  # noqa: BLE001 - fail closed on hostile errors
                    break
                if not isinstance(context, BaseException):
                    scan_complete = True
                    break
                cursor = context

            if not scan_complete or candidate is None:
                self._capture_publication_error(
                    current_error,
                    "cleanup body publication boundary",
                )
                return

            self.active_error = candidate
            self.active_error_replaced = current_error is not candidate
            if current_error is not candidate:
                # Intermediate context nodes may be callback-internal errors
                # that were already caught. Only the uncaught outer boundary
                # is a settlement observation.
                self._capture_publication_error(
                    current_error,
                    "cleanup body publication boundary",
                )

    def capture_recovery_boundary(self, error: BaseException) -> None:
        self._capture_publication_error(
            error,
            "cleanup body publication recovery boundary",
        )

    def capture_delivery_boundary(
        self,
        error: BaseException,
        operation: str,
    ) -> None:
        """Publish one owner-bound settlement or delivery failure."""

        self._capture_publication_error(error, operation)

    def settle_current_exception(self) -> None:
        """Retry restoration deliveries until recovery returns from its try."""

        while True:
            try:
                self.recover_current_exception()
                return
            except BaseException as recovery_boundary_error:  # noqa: BLE001
                self.capture_recovery_boundary(recovery_boundary_error)

    def attach_publication_notes(self, primary: BaseException) -> None:
        for operation, observed in self.publication_observations:
            if observed is primary:
                continue
            try:
                primary.add_note(
                    f"{operation} also failed: {type(observed).__name__}: {observed}"
                )
            except BaseException:  # noqa: BLE001, S110 - notes are best effort
                pass


@dataclass(slots=True)
class _PublishedManifestRemovalOwner:
    """Own one non-repeatable published-manifest removal outcome.

    The protected property is the exact manifest object's validated content
    and durable name absence. Once removal is armed, an interruption may have
    occurred before or after ``unlink`` and the operation is never retried.
    """

    state: str = "unstarted"
    seal: dict[str, Any] | None = None
    proof: dict[str, Any] | None = None

    def remove(self, seal: dict[str, Any]) -> None:
        if self.state == "complete":
            if self.seal is not seal:
                raise ValueError("published manifest removal owner was rebound")
            return
        if self.state == "remove-outcome-unproven":
            raise RuntimeError("published manifest removal outcome is unproven")
        if self.state != "unstarted" or self.seal is not None:
            raise RuntimeError("published manifest removal owner is invalid")

        # Publish ambiguity before entering a helper that may already have
        # completed unlink and parent fsync when a caller boundary interrupts.
        with supported_async_publication():
            self.seal = seal
            self.state = "remove-outcome-unproven"
        remove_published_manifest(seal)
        proof = {
            "protected_property": (
                "manifest-object-identity-content-and-durable-name-absence"
            ),
            "state": "complete",
            "path": seal.get("path"),
            "identity": seal.get("identity"),
            "sha256": seal.get("sha256"),
            "length": seal.get("length"),
            "remove_returned": True,
            "parent_fsync_complete": True,
            "exact_name_absent": True,
        }
        with supported_async_publication():
            self.proof = proof
            self.state = "complete"

    def attach_evidence(self, error: BaseException) -> None:
        try:
            setattr(
                error,
                "_readonly_manifest_removal_evidence",
                {
                    "protected_property": (
                        "manifest-object-identity-content-and-durable-name-absence"
                    ),
                    "state": self.state,
                    "proof": self.proof,
                },
            )
        except BaseException:  # noqa: BLE001, S110 - evidence is best effort
            pass


class _BoundCleanupDeliveryOwner:
    """Long-lived owner for terminal custody and exact error delivery.

    Resource progress is derived only from the manifest and parent owners. A
    restored supported hook becomes pending delivery state; it cannot skip
    descriptor settlement, repeat an ambiguous unlink, or replace the selected
    invocation-local body/control-flow object.
    """

    __slots__ = (
        "_armed_error",
        "_complete",
        "_manifest_close_complete",
        "_pending_errors",
        "_raise_in_progress",
        "body_error_settlement",
        "manifest",
        "manifest_result_owner",
        "manifest_removal_owner",
        "parent_result_owner",
        "remove_manifest_on_success",
        "seal",
        "settlement_note",
    )

    def __init__(
        self,
        *,
        remove_manifest_on_success: bool,
        settlement_note: str,
    ) -> None:
        self.body_error_settlement: _CleanupBodyErrorSettlement | None = None
        self.parent_result_owner: _DirectoryParentBindingResultOwner | None = None
        self.manifest_result_owner: CustodiedManifestResultOwner | None = None
        self.manifest: Any = None
        self.seal: dict[str, Any] | None = None
        self.remove_manifest_on_success = remove_manifest_on_success
        self.settlement_note = settlement_note
        self.manifest_removal_owner = _PublishedManifestRemovalOwner()
        self._manifest_close_complete = False
        self._pending_errors: tuple[tuple[str, BaseException], ...] = ()
        self._armed_error: BaseException | None = None
        self._raise_in_progress = False
        self._complete = False

    @property
    def complete(self) -> bool:
        return self._complete

    @property
    def bound(self) -> bool:
        """Report whether the complete pre-resource settlement tuple is live."""

        return (
            self.body_error_settlement is not None
            and self.parent_result_owner is not None
        )

    @property
    def authoritative_error(self) -> BaseException | None:
        settlement = self.body_error_settlement
        if settlement is None:
            return None
        active_error = settlement.active_error
        publication_error = settlement.publication_error
        if active_error is None:
            return publication_error
        if publication_error is None:
            return active_error
        primary, _secondary = _prefer_control_flow_error(
            active_error,
            publication_error,
        )
        return primary

    def bind(
        self,
        *,
        body_error_settlement: _CleanupBodyErrorSettlement,
        parent_result_owner: _DirectoryParentBindingResultOwner,
        manifest_result_owner: CustodiedManifestResultOwner | None = None,
    ) -> None:
        if (
            self.body_error_settlement is not None
            or self.parent_result_owner is not None
        ):
            raise ValueError("bound cleanup delivery owner was rebound")
        with supported_async_publication():
            self.body_error_settlement = body_error_settlement
            self.parent_result_owner = parent_result_owner
            self.manifest_result_owner = manifest_result_owner

    def publish_manifest(
        self,
        manifest: Any,
        seal: dict[str, Any] | None,
    ) -> None:
        result_owner = self.manifest_result_owner
        if result_owner is not None:
            published_manifest = result_owner.manifest
            if manifest is None:
                manifest = published_manifest
            elif published_manifest is not None and published_manifest is not manifest:
                raise ValueError("bound cleanup manifest result owner is inconsistent")
            if seal is None and published_manifest is not None:
                seal = published_manifest.seal
        with supported_async_publication():
            self.manifest = manifest
            self.seal = seal

    def enqueue(self, operation: str, error: BaseException) -> None:
        if not isinstance(operation, str) or not operation:
            raise ValueError("bound cleanup delivery operation is invalid")
        if not isinstance(error, BaseException):
            raise TypeError("bound cleanup delivery error is invalid")
        with supported_async_publication():
            self._pending_errors = (*self._pending_errors, (operation, error))
            self._armed_error = None
            self._raise_in_progress = False
            self._complete = False
        self.manifest_removal_owner.attach_evidence(error)

    def _manifest_close_is_terminal(self) -> bool:
        if self.manifest is None or self._manifest_close_complete:
            return True
        closed = getattr(self.manifest, "_closed", None)
        blocked = getattr(self.manifest, "_close_blocked", None)
        return closed is True or blocked is True

    def observe_manifest_close_boundary(self) -> None:
        if self._manifest_close_is_terminal():
            with supported_async_publication():
                self._manifest_close_complete = True

    def _capture_next_pending(self) -> bool:
        if not self._pending_errors:
            return False
        settlement = self.body_error_settlement
        if settlement is None:
            raise RuntimeError("bound cleanup delivery owner is unbound")
        operation, pending_error = self._pending_errors[0]
        settlement.capture_delivery_boundary(pending_error, operation)
        with supported_async_publication():
            if (
                self._pending_errors
                and self._pending_errors[0][0] == operation
                and self._pending_errors[0][1] is pending_error
            ):
                self._pending_errors = self._pending_errors[1:]
        return True

    def _prepare_authoritative_error(self) -> BaseException | None:
        settlement = self.body_error_settlement
        if settlement is None:
            raise RuntimeError("bound cleanup delivery owner is unbound")
        active_error = settlement.active_error
        publication_error = settlement.publication_error
        if publication_error is None:
            authoritative = active_error
        elif active_error is None:
            authoritative = publication_error
        else:
            authoritative, secondary = _prefer_control_flow_error(
                active_error,
                publication_error,
            )
            try:
                authoritative.add_note(
                    f"{self.settlement_note} also failed: "
                    f"{type(secondary).__name__}: {secondary}"
                )
            except BaseException:  # noqa: BLE001, S110 - notes are best effort
                pass
        if authoritative is not None:
            settlement.attach_publication_notes(authoritative)
            self.manifest_removal_owner.attach_evidence(authoritative)
        return authoritative

    def step(self) -> None:
        # This loop-head local is deliberately inside a callee whose complete
        # boundary is consumed by _drive_bound_cleanup_delivery's caller.
        authoritative: BaseException | None = None
        self._armed_error = None
        self._raise_in_progress = False
        settlement = self.body_error_settlement
        parent_result_owner = self.parent_result_owner
        if settlement is None or parent_result_owner is None:
            raise RuntimeError("bound cleanup delivery owner is unbound")

        settlement.settle_current_exception()

        if not self._manifest_close_is_terminal():
            self.manifest.close()
            with supported_async_publication():
                self._manifest_close_complete = True
            return
        if not self._manifest_close_complete:
            with supported_async_publication():
                self._manifest_close_complete = True
            return

        if not parent_result_owner.settled:
            parent_result_owner.close()
            return

        if self._capture_next_pending():
            return

        authoritative = self._prepare_authoritative_error()
        if authoritative is not None:
            with supported_async_publication():
                self._armed_error = authoritative
                self._raise_in_progress = True
            raise authoritative

        if self.remove_manifest_on_success:
            seal = self.seal
            if seal is None:
                raise RuntimeError("published cleanup manifest seal is unavailable")
            if self.manifest_removal_owner.state != "complete":
                self.manifest_removal_owner.remove(seal)
                return

        with supported_async_publication():
            self._complete = True


def _drive_bound_cleanup_delivery(owner: _BoundCleanupDeliveryOwner) -> None:
    """Drive owner state under a separate caller-owned delivery boundary."""

    while not owner.complete:
        try:
            owner.step()
        except BaseException as delivery_error:  # noqa: BLE001 - owner boundary
            if owner._raise_in_progress and delivery_error is owner._armed_error:
                # The caller owns this exact armed raise. A hook at this bare
                # raise is therefore reconciled against the same live owner.
                raise
            owner.observe_manifest_close_boundary()
            owner.enqueue(
                "bound cleanup owner delivery boundary",
                delivery_error,
            )


def _reconcile_bound_cleanup_delivery(
    owner: _BoundCleanupDeliveryOwner,
    boundary_error: BaseException,
) -> BaseException:
    """Consume a function boundary without losing the authoritative identity."""

    # bind() is the first operation in either cleanup body. An interruption at
    # its caller-side CALL opcode therefore precedes every resource acquisition
    # and leaves no owner state to settle. Preserve that exact boundary object
    # instead of feeding an unbound owner into the delivery loop indefinitely.
    if not owner.bound:
        return boundary_error

    owner.enqueue("bound cleanup function caller boundary", boundary_error)
    while True:
        try:
            _drive_bound_cleanup_delivery(owner)
        except BaseException as delivery_error:  # noqa: BLE001 - caller handoff
            if owner._raise_in_progress and delivery_error is owner._armed_error:
                return delivery_error
            owner.enqueue(
                "bound cleanup caller reconciliation boundary",
                delivery_error,
            )
        else:
            authoritative = owner.authoritative_error
            return boundary_error if authoritative is None else authoritative


def _delete_bound_tree(
    binding: _DirectoryParentBinding,
    *,
    restore_owner_write: bool,
    manifest_path: pathlib.Path,
    _delivery_owner: _BoundCleanupDeliveryOwner | None = None,
) -> None:
    invocation_ambient_error = sys.exception()
    invocation_ambient_context = (
        invocation_ambient_error.__context__
        if isinstance(invocation_ambient_error, BaseException)
        else None
    )
    body_error_settlement = _CleanupBodyErrorSettlement(
        invocation_ambient_error=invocation_ambient_error,
        invocation_ambient_traceback=(
            invocation_ambient_error.__traceback__
            if isinstance(invocation_ambient_error, BaseException)
            else None
        ),
        invocation_ambient_context=invocation_ambient_context,
        invocation_ambient_context_traceback=(
            invocation_ambient_context.__traceback__
            if isinstance(invocation_ambient_context, BaseException)
            else None
        ),
        invocation_code=_delete_bound_tree.__code__,
    )
    delivery_owner = _delivery_owner or _BoundCleanupDeliveryOwner(
        remove_manifest_on_success=True,
        settlement_note="bound-tree cleanup settlement",
    )
    parent_result_owner = _DirectoryParentBindingResultOwner()
    manifest_result_owner = CustodiedManifestResultOwner()
    delivery_owner.bind(
        body_error_settlement=body_error_settlement,
        parent_result_owner=parent_result_owner,
        manifest_result_owner=manifest_result_owner,
    )
    binding.revalidate()
    if restore_owner_write:
        _restore_owner_write_below_bound_root(binding.fd)
        binding.revalidate()
    try:
        parent_binding = _open_directory_parent(
            binding.path.parent,
            require_owned_private_parent=binding.require_owned_private_parent,
            result_owner=parent_result_owner,
        )
        parent_result_owner.transfer(parent_binding)
    except BaseException as error:
        preserved = _settle_directory_parent_binding_result_preserving_trigger(
            parent_result_owner,
            error,
        )
        if preserved is error:
            raise
        raise preserved
    manifest = None
    seal: dict[str, Any] | None = None
    deletion_owner = CustodiedDeletionResultOwner()
    # sys.exception() in the finally block would expose a caller's ambient
    # handler even when this invocation completed its body successfully.
    local_active_error: BaseException | None = None
    try:
        try:
            deadline = time.monotonic() + BOUND_CLEANUP_TIMEOUT_SECONDS
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label="read-only-installed-test-tree",
                        parent_fd=parent_binding.fd,
                        parent_identity=parent_binding.identity,
                        name=os.fsencode(binding.path.name),
                        expected_identity=binding.identity,
                        private_metadata=True,
                    ),
                ),
                manifest_path=manifest_path,
                entry_cap=BOUND_CLEANUP_ENTRY_CAP,
                payload_cap=BOUND_CLEANUP_MANIFEST_BYTES,
                deadline=deadline,
                result_owner=manifest_result_owner,
            )
            if manifest_result_owner.manifest is None:
                manifest_result_owner.publish(manifest)
            manifest_result_owner.transfer(manifest)
            seal = manifest.seal
            delete_custodied_roots(
                manifest,
                deadline=deadline,
                result_owner=deletion_owner,
            )
        except BaseException as error:
            body_error_settlement.publish_local_active_error(error)
            attached_owner = getattr(
                error,
                "custodied_deletion_result_owner",
                deletion_owner,
            )
            if not isinstance(attached_owner, CustodiedDeletionResultOwner):
                attached_owner = deletion_owner
            try:
                _snapshot_bound_cleanup_recovery(
                    error,
                    parent_binding=parent_binding,
                    manifest_path=manifest_path,
                    manifest_seal=seal,
                    manifest_result_owner=manifest_result_owner,
                    deletion_owner=attached_owner,
                )
            except BaseException as recovery_error:
                primary, secondary = _prefer_control_flow_error(
                    error,
                    recovery_error,
                )
                try:
                    primary.add_note(
                        "cleanup recovery evidence capture also observed: "
                        f"{type(secondary).__name__}: {secondary}"
                    )
                except BaseException:
                    pass
                body_error_settlement.publish_local_active_error(primary)
                if primary is recovery_error:
                    raise recovery_error from error
            body_error_settlement.publish_local_active_error(error)
            raise
    except BaseException as error:
        local_active_error = error
        assert local_active_error is error
        body_error_settlement.recover_current_exception()
        raise
    finally:
        while True:
            try:
                delivery_owner.publish_manifest(manifest, seal)
                _drive_bound_cleanup_delivery(delivery_owner)
            except BaseException as caller_error:  # noqa: BLE001 - owner handoff
                if (
                    delivery_owner._raise_in_progress
                    and caller_error is delivery_owner._armed_error
                ):
                    # _cleanup_bound_tree owns the next boundary when this
                    # function is used through its production caller.
                    raise
                delivery_owner.enqueue(
                    "bound-tree cleanup recursive-caller boundary",
                    caller_error,
                )
            else:
                break


def _cleanup_bound_tree_operation(
    binding: _DirectoryParentBinding | None,
    *,
    restore_owner_write: bool,
    delivery_owner: _BoundCleanupDeliveryOwner,
    manifest_path: pathlib.Path | None = None,
) -> CleanupFailure | None:
    if binding is None:
        return None
    try:
        binding.revalidate()
    except Exception as error:
        return _bound_cleanup_failure(binding, error)
    if manifest_path is None:
        return _bound_cleanup_failure(
            binding,
            RuntimeError("descriptor-bound cleanup control is unavailable"),
        )
    try:
        _delete_bound_tree(
            binding,
            restore_owner_write=restore_owner_write,
            manifest_path=manifest_path,
            _delivery_owner=delivery_owner,
        )
    except BaseException as error:  # noqa: BLE001 - owner handoff
        selected = _reconcile_bound_cleanup_delivery(delivery_owner, error)
        if isinstance(selected, Exception):
            return _bound_cleanup_failure(binding, selected)
        if selected is error:
            raise
        raise selected
    return None


def _cleanup_bound_tree(
    binding: _DirectoryParentBinding | None,
    *,
    restore_owner_write: bool,
    manifest_path: pathlib.Path | None = None,
    _delivery_owner: _BoundCleanupDeliveryOwner | None = None,
) -> CleanupFailure | None:
    delivery_owner = _delivery_owner or _BoundCleanupDeliveryOwner(
        remove_manifest_on_success=True,
        settlement_note="bound-tree cleanup settlement",
    )
    try:
        return _cleanup_bound_tree_operation(
            binding,
            restore_owner_write=restore_owner_write,
            delivery_owner=delivery_owner,
            manifest_path=manifest_path,
        )
    except BaseException as boundary_error:  # noqa: BLE001 - public handoff
        selected = _reconcile_bound_cleanup_delivery(
            delivery_owner,
            boundary_error,
        )
        if isinstance(selected, Exception):
            assert binding is not None
            return _bound_cleanup_failure(binding, selected)
        if selected is boundary_error:
            raise
        raise selected


def _consume_cleanup_bound_tree_endpoint(
    binding: _DirectoryParentBinding | None,
    *,
    restore_owner_write: bool,
    manifest_path: pathlib.Path | None = None,
    _delivery_owner: _BoundCleanupDeliveryOwner | None = None,
) -> CleanupFailure | None:
    """Own one explicit caller handoff across the public cleanup endpoint.

    The public endpoint's terminal return and raise opcodes are inside this
    finite boundary. This caller's own terminal opcodes are the next contract
    boundary; the handoff is deliberately not a transparent self-contained
    guarantee across an unbounded stack of Python frames.
    """

    delivery_owner = _delivery_owner or _BoundCleanupDeliveryOwner(
        remove_manifest_on_success=True,
        settlement_note="bound-tree cleanup settlement",
    )
    try:
        return _cleanup_bound_tree(
            binding,
            restore_owner_write=restore_owner_write,
            manifest_path=manifest_path,
            _delivery_owner=delivery_owner,
        )
    except BaseException as boundary_error:  # noqa: BLE001 - one-caller handoff
        if delivery_owner.body_error_settlement is None:
            raise
        selected = _reconcile_bound_cleanup_delivery(
            delivery_owner,
            boundary_error,
        )
        if isinstance(selected, Exception):
            assert binding is not None
            return _bound_cleanup_failure(binding, selected)
        if selected is boundary_error:
            raise
        raise selected


def _cleanup_empty_bound_control_operation(
    binding: _DirectoryParentBinding,
    *,
    delivery_owner: _BoundCleanupDeliveryOwner,
) -> CleanupFailure | None:
    invocation_ambient_error = sys.exception()
    invocation_ambient_context = (
        invocation_ambient_error.__context__
        if isinstance(invocation_ambient_error, BaseException)
        else None
    )
    body_error_settlement = _CleanupBodyErrorSettlement(
        invocation_ambient_error=invocation_ambient_error,
        invocation_ambient_traceback=(
            invocation_ambient_error.__traceback__
            if isinstance(invocation_ambient_error, BaseException)
            else None
        ),
        invocation_ambient_context=invocation_ambient_context,
        invocation_ambient_context_traceback=(
            invocation_ambient_context.__traceback__
            if isinstance(invocation_ambient_context, BaseException)
            else None
        ),
        invocation_code=_cleanup_empty_bound_control_operation.__code__,
    )
    parent_result_owner = _DirectoryParentBindingResultOwner()
    delivery_owner.bind(
        body_error_settlement=body_error_settlement,
        parent_result_owner=parent_result_owner,
    )
    try:
        binding.revalidate()
        try:
            parent_binding = _open_directory_parent(
                binding.path.parent,
                require_owned_private_parent=binding.require_owned_private_parent,
                result_owner=parent_result_owner,
            )
            parent_result_owner.transfer(parent_binding)
        except BaseException as error:
            preserved = _settle_directory_parent_binding_result_preserving_trigger(
                parent_result_owner,
                error,
            )
            if preserved is error:
                raise
            raise preserved
        # Bind only an exception propagating out of this local body; the
        # caller's ambient handler must not participate in close precedence.
        local_active_error: BaseException | None = None
        try:
            try:
                quarantine_and_remove_empty_root(
                    RootSpec(
                        label="read-only-cleanup-control",
                        parent_fd=parent_binding.fd,
                        parent_identity=parent_binding.identity,
                        name=os.fsencode(binding.path.name),
                        expected_identity=binding.identity,
                        private_metadata=True,
                    ),
                    binding.fd,
                    deadline=time.monotonic() + BOUND_CLEANUP_TIMEOUT_SECONDS,
                )
            except BaseException as error:
                local_active_error = error
                body_error_settlement.publish_local_active_error(local_active_error)
                raise
        finally:
            while True:
                try:
                    _drive_bound_cleanup_delivery(delivery_owner)
                except BaseException as caller_error:  # noqa: BLE001 - handoff
                    if (
                        delivery_owner._raise_in_progress
                        and caller_error is delivery_owner._armed_error
                    ):
                        raise
                    delivery_owner.enqueue(
                        "cleanup-control recursive-caller boundary",
                        caller_error,
                    )
                else:
                    break
    except BaseException as error:  # noqa: BLE001 - final owner consumer
        selected = _reconcile_bound_cleanup_delivery(delivery_owner, error)
        if isinstance(selected, Exception):
            return _bound_cleanup_failure(binding, selected)
        if selected is error:
            raise
        raise selected
    return None


def _cleanup_empty_bound_control(
    binding: _DirectoryParentBinding,
    *,
    _delivery_owner: _BoundCleanupDeliveryOwner | None = None,
) -> CleanupFailure | None:
    delivery_owner = _delivery_owner or _BoundCleanupDeliveryOwner(
        remove_manifest_on_success=False,
        settlement_note="cleanup-control parent settlement",
    )
    try:
        return _cleanup_empty_bound_control_operation(
            binding,
            delivery_owner=delivery_owner,
        )
    except BaseException as boundary_error:  # noqa: BLE001 - public handoff
        selected = _reconcile_bound_cleanup_delivery(
            delivery_owner,
            boundary_error,
        )
        if isinstance(selected, Exception):
            return _bound_cleanup_failure(binding, selected)
        if selected is boundary_error:
            raise
        raise selected


def _consume_cleanup_empty_bound_control_endpoint(
    binding: _DirectoryParentBinding,
    *,
    _delivery_owner: _BoundCleanupDeliveryOwner | None = None,
) -> CleanupFailure | None:
    """Own one explicit caller handoff across the public control endpoint.

    This consumes the public endpoint's terminal return and raise opcodes. Its
    own terminal opcodes remain the documented finite contract boundary.
    """

    delivery_owner = _delivery_owner or _BoundCleanupDeliveryOwner(
        remove_manifest_on_success=False,
        settlement_note="cleanup-control parent settlement",
    )
    try:
        return _cleanup_empty_bound_control(
            binding,
            _delivery_owner=delivery_owner,
        )
    except BaseException as boundary_error:  # noqa: BLE001 - one-caller handoff
        if delivery_owner.body_error_settlement is None:
            raise
        selected = _reconcile_bound_cleanup_delivery(
            delivery_owner,
            boundary_error,
        )
        if isinstance(selected, Exception):
            return _bound_cleanup_failure(binding, selected)
        if selected is boundary_error:
            raise
        raise selected


def _retained_bound_for_unproven_child_closure(
    binding: _DirectoryParentBinding | None,
    fallback: pathlib.Path | None,
) -> CleanupFailure | None:
    if binding is None:
        return _retained_for_unproven_child_closure(fallback)
    evidence = _bound_path_evidence(binding)
    return CleanupFailure(
        path=str(evidence.path),
        error_kind="ChildProcessClosureUnproven",
        error_errno=None,
        retained=evidence.retained,
        restore_error_kind=None,
        restore_error_errno=None,
        original_path=str(binding.path),
        path_status=evidence.path_status,
        replacement_path=(
            str(evidence.replacement_path)
            if evidence.replacement_path is not None
            else None
        ),
        held_identity=binding.object_locator(),
        original_path_status=evidence.original_path_status,
        access_policy_status=evidence.access_policy_status,
    )


def _retained_for_unproven_child_closure(
    path: pathlib.Path | None,
) -> CleanupFailure | None:
    if path is None or not os.path.lexists(path):
        return None
    return CleanupFailure(
        path=str(path),
        error_kind="ChildProcessClosureUnproven",
        error_errno=None,
        retained=True,
        restore_error_kind=None,
        restore_error_errno=None,
    )


def main() -> int:
    if sys.platform != "darwin":
        print(
            "read-only installed supervisor regression requires Darwin", file=sys.stderr
        )
        return 2
    parent_metadata = READONLY_INSTALL_PARENT.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or not parent_metadata.st_mode & stat.S_ISVTX
        or not parent_metadata.st_mode & stat.S_IWOTH
    ):
        print("/private/tmp is not the expected 01777-style parent", file=sys.stderr)
        return 2

    source_root = pathlib.Path(__file__).resolve().parents[1]
    install_container: pathlib.Path | None = None
    install_container_binding: _DirectoryParentBinding | None = None
    install_container_owner = _PrivateDirectoryCreationResultOwner()
    runtime_parent: pathlib.Path | None = None
    runtime_parent_binding: _DirectoryParentBinding | None = None
    runtime_parent_owner = _PrivateDirectoryCreationResultOwner()
    cleanup_control_binding: _DirectoryParentBinding | None = None
    cleanup_control_owner = _PrivateDirectoryCreationResultOwner()
    installed_root: pathlib.Path | None = None
    completed: subprocess.CompletedProcess[str] | None = None
    child_outcome_receipt = ChildRunOutcomeReceipt()
    before: dict[str, TreeEntrySnapshot] | None = None
    after: dict[str, TreeEntrySnapshot] | None = None
    runtime_residue: tuple[str, ...] = ()
    timeout_error: TimeoutError | None = None
    output_limit_error: OverflowError | None = None
    signal_error: ChildRunInterrupted | None = None
    closure_error: GitProcessClosureUnproven | None = None
    child_process_closure = "not-started"
    primary_failure: PrimaryFailure | None = None
    secondary_failures: list[SecondaryFailure] = []
    closure_proof = ChildProcessClosureProof()
    cleanup_failures: tuple[CleanupFailure, ...] = ()
    creation_cleanup_failures: list[CleanupFailure] = []
    deferred_control_flow_error: BaseException | None = None
    stage = "install-container"
    try:
        install_container_binding = _create_bound_owned_private_directory(
            READONLY_INSTALL_PARENT,
            ".codex-review-readonly-install-",
            result_owner=install_container_owner,
            require_owned_private_parent=False,
        )
        install_container_binding = install_container_owner.transfer(
            install_container_binding
        )
        install_container = install_container_binding.path
        stage = "runtime-parent"
        runtime_parent_binding = _create_bound_owned_private_directory(
            _private_runtime_parent(),
            ".codex-review-readonly-runtime-",
            result_owner=runtime_parent_owner,
        )
        runtime_parent_binding = runtime_parent_owner.transfer(runtime_parent_binding)
        runtime_parent = runtime_parent_binding.path
        stage = "permissions"
        installed_root = install_container / "independent_codex_pr_review"
        stage = "install-copy"
        shutil.copytree(
            source_root,
            installed_root,
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        stage = "install-read-only"
        _set_tree_read_only(installed_root)
        stage = "snapshot-before"
        before = _tree_snapshot(installed_root)
        stage = "access-policy"
        if any(entry.acl_entries for entry in before.values()):
            raise RuntimeError("read-only installed tree has an extended ACL")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                EXPLICIT_RUNTIME_PARENT_ENV: str(runtime_parent),
                "TMPDIR": str(runtime_parent),
            }
        )
        stage = "child-run"
        completed = _run_bounded_child(
            (
                sys.executable,
                "-B",
                "-m",
                "tests.run_required_deterministic_supervisor",
            ),
            cwd=installed_root,
            environment=environment,
            secondary_failures=secondary_failures,
            closure_proof=closure_proof,
            outcome_receipt=child_outcome_receipt,
            require_isolated_account=True,
        )
        child_process_closure = "proven"
        stage = "install-container-revalidation"
        install_container_binding.revalidate()
        stage = "snapshot-after"
        after = _tree_snapshot(installed_root)
        stage = "runtime-residue"
        runtime_residue = _list_bound_directory(runtime_parent_binding)
        stage = "complete"
    except _PrivateDirectoryCreationRetentionRequired as error:
        child_process_closure = _child_process_closure_status(closure_proof)
        primary_failure = _primary_failure(stage, error.trigger_error)
        creation_failure, deferred_control_flow_error = (
            _consume_private_directory_creation_retention(
                error,
                secondary_failures=secondary_failures,
            )
        )
        creation_cleanup_failures.append(creation_failure)
    except GitProcessClosureUnproven as error:
        closure_error = error
        child_process_closure = "unproven"
        primary_failure = _primary_failure(stage, error)
    except TimeoutError as error:
        timeout_error = error
        child_process_closure = _child_process_closure_status(closure_proof)
        primary_failure = _primary_failure(stage, error)
    except OverflowError as error:
        output_limit_error = error
        child_process_closure = _child_process_closure_status(closure_proof)
        primary_failure = _primary_failure(stage, error)
    except ChildRunInterrupted as error:
        signal_error = error
        child_process_closure = _child_process_closure_status(closure_proof)
        primary_failure = _primary_failure(stage, error)
    except Exception as error:
        child_process_closure = _child_process_closure_status(closure_proof)
        creation_owner = (
            install_container_owner
            if stage == "install-container"
            else runtime_parent_owner
            if stage == "runtime-parent"
            else None
        )
        retained = (
            _retained_private_directory_creation_from_owner(
                creation_owner,
                error,
            )
            if creation_owner is not None
            else None
        )
        if retained is None:
            primary_failure = _primary_failure(stage, error)
        else:
            primary_failure = _primary_failure(stage, retained.trigger_error)
            creation_failure, control_flow_error = (
                _consume_private_directory_creation_retention(
                    retained,
                    secondary_failures=secondary_failures,
                )
            )
            creation_cleanup_failures.append(creation_failure)
            deferred_control_flow_error = control_flow_error
    except BaseException as error:
        child_process_closure = _child_process_closure_status(closure_proof)
        creation_owner = (
            install_container_owner
            if stage == "install-container"
            else runtime_parent_owner
            if stage == "runtime-parent"
            else None
        )
        retained = (
            _retained_private_directory_creation_from_owner(
                creation_owner,
                error,
            )
            if creation_owner is not None
            else None
        )
        primary_failure = _primary_failure(
            stage,
            retained.trigger_error if retained is not None else error,
        )
        retained_control_flow_error: BaseException | None = None
        if retained is not None:
            creation_failure, retained_control_flow_error = (
                _consume_private_directory_creation_retention(
                    retained,
                    secondary_failures=secondary_failures,
                )
            )
            creation_cleanup_failures.append(creation_failure)
        deferred_control_flow_error = retained_control_flow_error or error
    finally:
        if completed is None:
            # Recover diagnostics published before a later closure failure.
            # This does not alter closure proof or destructive-cleanup authority.
            completed = child_outcome_receipt.completed
        try:
            install_container_binding = _claim_private_directory_creation_result(
                install_container_owner,
                install_container_binding,
            )
        except BaseException as claim_error:
            secondary_failures.append(
                _secondary_failure(
                    "claim-install-container-creation-result",
                    claim_error,
                )
            )
            if deferred_control_flow_error is None and not isinstance(
                claim_error, Exception
            ):
                deferred_control_flow_error = claim_error
            if install_container_binding is None:
                install_container_binding = install_container_owner.binding
        try:
            runtime_parent_binding = _claim_private_directory_creation_result(
                runtime_parent_owner,
                runtime_parent_binding,
            )
        except BaseException as claim_error:
            secondary_failures.append(
                _secondary_failure(
                    "claim-runtime-parent-creation-result",
                    claim_error,
                )
            )
            if deferred_control_flow_error is None and not isinstance(
                claim_error, Exception
            ):
                deferred_control_flow_error = claim_error
            if runtime_parent_binding is None:
                runtime_parent_binding = runtime_parent_owner.binding

        cleanup_results: list[CleanupFailure | None] = list(creation_cleanup_failures)
        cleanup_phase_operation = "prepare-private-directory-cleanup"
        cleanup_phase_path: pathlib.Path | None = None
        try:
            if not closure_proof.destructive_cleanup_authorized:
                cleanup_phase_operation = "retain-install-container-after-child-closure"
                cleanup_phase_path = install_container
                cleanup_results.append(
                    _retained_bound_for_unproven_child_closure(
                        install_container_binding,
                        install_container,
                    )
                )
                cleanup_phase_operation = "retain-runtime-parent-after-child-closure"
                cleanup_phase_path = runtime_parent
                cleanup_results.append(
                    _retained_bound_for_unproven_child_closure(
                        runtime_parent_binding,
                        runtime_parent,
                    )
                )
            else:
                cleanup_phase_operation = "create-bound-cleanup-control"
                cleanup_phase_path = (
                    runtime_parent or install_container or READONLY_INSTALL_PARENT
                )
                try:
                    cleanup_control_binding = _create_bound_owned_private_directory(
                        _private_runtime_parent(),
                        ".codex-review-readonly-cleanup-",
                        result_owner=cleanup_control_owner,
                    )
                    cleanup_control_binding = cleanup_control_owner.transfer(
                        cleanup_control_binding
                    )
                except _PrivateDirectoryCreationRetentionRequired as error:
                    secondary_failures.append(
                        _secondary_failure(
                            "create-bound-cleanup-control",
                            error.trigger_error,
                        )
                    )
                    creation_failure, control_flow_error = (
                        _consume_private_directory_creation_retention(
                            error,
                            secondary_failures=secondary_failures,
                        )
                    )
                    cleanup_results.append(creation_failure)
                    if deferred_control_flow_error is None:
                        deferred_control_flow_error = control_flow_error
                except Exception as error:
                    retained = _retained_private_directory_creation_from_owner(
                        cleanup_control_owner,
                        error,
                    )
                    if retained is None:
                        secondary_failures.append(
                            _secondary_failure("create-bound-cleanup-control", error)
                        )
                    else:
                        secondary_failures.append(
                            _secondary_failure(
                                "create-bound-cleanup-control",
                                retained.trigger_error,
                            )
                        )
                        creation_failure, control_flow_error = (
                            _consume_private_directory_creation_retention(
                                retained,
                                secondary_failures=secondary_failures,
                            )
                        )
                        cleanup_results.append(creation_failure)
                        if deferred_control_flow_error is None:
                            deferred_control_flow_error = control_flow_error
                except BaseException as error:
                    retained = _retained_private_directory_creation_from_owner(
                        cleanup_control_owner,
                        error,
                    )
                    secondary_failures.append(
                        _secondary_failure(
                            "create-bound-cleanup-control",
                            retained.trigger_error if retained is not None else error,
                        )
                    )
                    retained_control_flow_error: BaseException | None = None
                    if retained is not None:
                        creation_failure, retained_control_flow_error = (
                            _consume_private_directory_creation_retention(
                                retained,
                                secondary_failures=secondary_failures,
                            )
                        )
                        cleanup_results.append(creation_failure)
                    if deferred_control_flow_error is None:
                        deferred_control_flow_error = (
                            retained_control_flow_error
                            if retained is not None
                            and retained_control_flow_error is not None
                            else error
                        )
                try:
                    cleanup_control_binding = _claim_private_directory_creation_result(
                        cleanup_control_owner,
                        cleanup_control_binding,
                    )
                except BaseException as claim_error:
                    secondary_failures.append(
                        _secondary_failure(
                            "claim-cleanup-control-creation-result",
                            claim_error,
                        )
                    )
                    if deferred_control_flow_error is None and not isinstance(
                        claim_error, Exception
                    ):
                        deferred_control_flow_error = claim_error
                    if cleanup_control_binding is None:
                        cleanup_control_binding = cleanup_control_owner.binding

                cleanup_phase_operation = "cleanup-install-container"
                cleanup_phase_path = install_container
                cleanup_results.append(
                    _consume_cleanup_bound_tree_endpoint(
                        install_container_binding,
                        restore_owner_write=True,
                        manifest_path=(
                            cleanup_control_binding.path / "install.manifest"
                            if cleanup_control_binding is not None
                            else None
                        ),
                    )
                )
                cleanup_phase_operation = "cleanup-runtime-parent"
                cleanup_phase_path = runtime_parent
                cleanup_results.append(
                    _consume_cleanup_bound_tree_endpoint(
                        runtime_parent_binding,
                        restore_owner_write=False,
                        manifest_path=(
                            cleanup_control_binding.path / "runtime.manifest"
                            if cleanup_control_binding is not None
                            else None
                        ),
                    )
                )
                if install_container_binding is None:
                    cleanup_phase_operation = "cleanup-install-container-fallback"
                    cleanup_phase_path = install_container
                    cleanup_results.append(
                        _cleanup_tree(install_container, restore_owner_write=True)
                    )
                if runtime_parent_binding is None:
                    cleanup_phase_operation = "cleanup-runtime-parent-fallback"
                    cleanup_phase_path = runtime_parent
                    cleanup_results.append(
                        _cleanup_tree(runtime_parent, restore_owner_write=False)
                    )
                if cleanup_control_binding is not None:
                    cleanup_phase_operation = "inspect-cleanup-control"
                    cleanup_phase_path = cleanup_control_binding.path
                    try:
                        cleanup_control_entries = _list_bound_directory(
                            cleanup_control_binding
                        )
                    except Exception:
                        cleanup_control_entries = ("<unreadable>",)
                    if cleanup_control_entries:
                        evidence = _bound_path_evidence(cleanup_control_binding)
                        cleanup_results.append(
                            CleanupFailure(
                                path=str(evidence.path),
                                error_kind="CleanupControlRetained",
                                error_errno=None,
                                retained=evidence.retained,
                                restore_error_kind=None,
                                restore_error_errno=None,
                                original_path=str(cleanup_control_binding.path),
                                path_status=evidence.path_status,
                                replacement_path=(
                                    str(evidence.replacement_path)
                                    if evidence.replacement_path is not None
                                    else None
                                ),
                                held_identity=cleanup_control_binding.object_locator(),
                                original_path_status=evidence.original_path_status,
                                access_policy_status=evidence.access_policy_status,
                            )
                        )
                    else:
                        cleanup_phase_operation = "cleanup-empty-bound-control"
                        cleanup_results.append(
                            _consume_cleanup_empty_bound_control_endpoint(
                                cleanup_control_binding
                            )
                        )
        except BaseException as cleanup_error:
            secondary_failures.append(
                _secondary_failure(cleanup_phase_operation, cleanup_error)
            )
            cleanup_recovery_evidence = getattr(
                cleanup_error,
                _CLEANUP_RECOVERY_EVIDENCE_ATTR,
                None,
            )
            if not isinstance(cleanup_recovery_evidence, dict):
                cleanup_recovery_evidence = None
            if deferred_control_flow_error is None and not isinstance(
                cleanup_error, Exception
            ):
                deferred_control_flow_error = cleanup_error
            if cleanup_phase_path is not None:
                try:
                    cleanup_results.append(
                        _cleanup_failure_from_error(
                            cleanup_phase_path,
                            cleanup_error,
                            retained=None,
                            original_path=cleanup_phase_path,
                            path_status="cleanup-control-flow-unresolved",
                            replacement_path=(
                                cleanup_phase_path
                                if os.path.lexists(cleanup_phase_path)
                                else None
                            ),
                            recovery_evidence=cleanup_recovery_evidence,
                        )
                    )
                except BaseException as evidence_error:
                    secondary_failures.append(
                        _secondary_failure(
                            f"record-{cleanup_phase_operation}-failure",
                            evidence_error,
                        )
                    )
                    if deferred_control_flow_error is None and not isinstance(
                        evidence_error, Exception
                    ):
                        deferred_control_flow_error = evidence_error
            if cleanup_control_binding is not None:
                try:
                    cleanup_control_entries = _list_bound_directory(
                        cleanup_control_binding
                    )
                    control_evidence = _bound_path_evidence(cleanup_control_binding)
                    cleanup_results.append(
                        CleanupFailure(
                            path=str(control_evidence.path),
                            error_kind="CleanupControlRetained",
                            error_errno=None,
                            retained=control_evidence.retained,
                            restore_error_kind=None,
                            restore_error_errno=None,
                            original_path=str(cleanup_control_binding.path),
                            path_status=control_evidence.path_status,
                            replacement_path=(
                                str(control_evidence.replacement_path)
                                if control_evidence.replacement_path is not None
                                else None
                            ),
                            held_identity=cleanup_control_binding.object_locator(),
                            original_path_status=(
                                control_evidence.original_path_status
                            ),
                            access_policy_status=(
                                control_evidence.access_policy_status
                            ),
                            recovery_evidence={
                                "protected_property": (
                                    "cleanup-control-object-identity"
                                ),
                                "reason": (
                                    "cleanup-control-retained-after-control-flow"
                                ),
                                "entries": list(cleanup_control_entries),
                            },
                        )
                    )
                except BaseException as inspection_error:
                    secondary_failures.append(
                        _secondary_failure(
                            "inspect-cleanup-control-after-control-flow",
                            inspection_error,
                        )
                    )
                    if deferred_control_flow_error is None and not isinstance(
                        inspection_error, Exception
                    ):
                        deferred_control_flow_error = inspection_error
        finally:
            for binding_role, binding, include_held_identity in (
                ("install-container", install_container_binding, False),
                ("runtime-parent", runtime_parent_binding, False),
                ("cleanup-control", cleanup_control_binding, True),
            ):
                if binding is None:
                    continue
                try:
                    binding.close()
                except BaseException as close_error:
                    if binding.fd_close_outcome == "owned":
                        try:
                            binding.close()
                        except BaseException as retry_error:
                            try:
                                close_error.add_note(
                                    "binding close caller-boundary retry also failed: "
                                    f"{type(retry_error).__name__}: {retry_error}"
                                )
                            except BaseException:
                                pass
                    if deferred_control_flow_error is None and not isinstance(
                        close_error, Exception
                    ):
                        deferred_control_flow_error = close_error
                    try:
                        cleanup_results.append(
                            _cleanup_failure_from_error(
                                binding.path,
                                close_error,
                                retained=None,
                                original_path=binding.path,
                                path_status="close-unresolved",
                                replacement_path=(
                                    binding.path
                                    if os.path.lexists(binding.path)
                                    else None
                                ),
                                held_identity=(
                                    binding.object_locator()
                                    if include_held_identity
                                    else None
                                ),
                            )
                        )
                    except BaseException as evidence_error:
                        secondary_failures.append(
                            _secondary_failure(
                                f"record-{binding_role}-binding-close-failure",
                                evidence_error,
                            )
                        )
                        if deferred_control_flow_error is None and not isinstance(
                            evidence_error, Exception
                        ):
                            deferred_control_flow_error = evidence_error
            for operation, owner in (
                ("close-install-container-result-owner", install_container_owner),
                ("close-runtime-parent-result-owner", runtime_parent_owner),
                ("close-cleanup-control-result-owner", cleanup_control_owner),
            ):
                try:
                    owner.close_descriptors_for_recovery()
                except BaseException as close_error:
                    if not owner.settled:
                        try:
                            owner.close_descriptors_for_recovery()
                        except BaseException as retry_error:
                            try:
                                close_error.add_note(
                                    "result-owner close caller-boundary retry also "
                                    "failed: "
                                    f"{type(retry_error).__name__}: {retry_error}"
                                )
                            except BaseException:
                                pass
                    secondary_failures.append(
                        _secondary_failure(operation, close_error)
                    )
                    if deferred_control_flow_error is None and not isinstance(
                        close_error, Exception
                    ):
                        deferred_control_flow_error = close_error
        cleanup_failures = tuple(
            failure for failure in cleanup_results if failure is not None
        )

    if deferred_control_flow_error is not None:
        propagated_control_flow = (
            _fail_closed_deferred_control_flow(deferred_control_flow_error)
            if cleanup_failures
            else deferred_control_flow_error
        )
        try:
            setattr(
                propagated_control_flow,
                "readonly_cleanup_failures",
                tuple(asdict(failure) for failure in cleanup_failures),
            )
            setattr(
                propagated_control_flow,
                "readonly_secondary_failures",
                tuple(asdict(failure) for failure in secondary_failures),
            )
        except BaseException:
            pass
        raise propagated_control_flow

    release_tree_immutable = (
        before is not None
        and after is not None
        and _tree_property_unchanged(before, after)
    )
    retained_paths = [
        failure.path for failure in cleanup_failures if failure.retained is not False
    ]
    if primary_failure is not None:
        if timeout_error is not None:
            primary_status = "timed-out"
        elif output_limit_error is not None:
            primary_status = "output-limit"
        elif signal_error is not None:
            primary_status = "interrupted"
        elif (
            closure_error is not None
            or not closure_proof.destructive_cleanup_authorized
        ):
            primary_status = "closure-unproven"
        else:
            primary_status = "failed"
    elif completed is None:
        primary_status = "not-completed"
    elif completed.returncode != 0:
        primary_status = "child-failed"
    elif not release_tree_immutable:
        primary_status = "property-mismatch"
    elif runtime_residue:
        primary_status = "runtime-residue"
    else:
        primary_status = "complete"
    summary = {
        "child_process_closure": child_process_closure,
        "cleanup_failures": [asdict(failure) for failure in cleanup_failures],
        "cleanup_status": "incomplete" if cleanup_failures else "complete",
        "install_parent_is_sticky_world_writable": True,
        "primary_failure": (
            asdict(primary_failure) if primary_failure is not None else None
        ),
        "primary_status": primary_status,
        "release_tree_immutable": release_tree_immutable,
        "release_tree_property": "object-identity-content-access-policy",
        "retained_paths": retained_paths,
        "returncode": completed.returncode if completed is not None else None,
        "runtime_residue": list(runtime_residue),
        "secondary_failures": [asdict(failure) for failure in secondary_failures],
        "signal_number": (
            signal_error.signal_number if signal_error is not None else None
        ),
        "timed_out": timeout_error is not None,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))

    primary_failed = primary_status != "complete"
    if primary_failure is not None:
        print(
            "read-only installed supervisor primary failure: "
            + json.dumps(
                asdict(primary_failure),
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
    if secondary_failures:
        print(
            "read-only installed supervisor secondary failures: "
            + json.dumps(
                [asdict(failure) for failure in secondary_failures],
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
    if completed is not None and primary_failed:
        if completed.stdout:
            print(_bounded_failure_text(completed.stdout), file=sys.stderr)
        if completed.stderr:
            print(_bounded_failure_text(completed.stderr), file=sys.stderr)
    if timeout_error is not None:
        print("read-only installed supervisor regression timed out", file=sys.stderr)
    if cleanup_failures:
        print(
            "read-only installed supervisor cleanup incomplete: "
            + json.dumps(
                [asdict(failure) for failure in cleanup_failures],
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
    if signal_error is not None:
        return 128 + signal_error.signal_number
    return 1 if primary_failed or cleanup_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
