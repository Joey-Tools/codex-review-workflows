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
from dataclasses import asdict, dataclass
from types import FrameType
from typing import Any

from review_supervisor.gitraw import GitProcessClosureUnproven, run_bounded
from review_supervisor.recovery_cleanup import (
    CustodiedDeletionResultOwner,
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

from .support import (
    _create_bound_owned_private_directory,
    _DirectoryParentBinding,
    _open_directory_parent,
    _private_runtime_parent,
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
    started: bool = False
    proven: bool = False


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
    for pause in (0.0, 0.01):
        if pause:
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("same-UID Darwin process census deadline expired")
            time.sleep(min(pause, remaining))
            _require_process_census_time(operation_deadline)
        observed = _darwin_same_uid_processes(deadline=operation_deadline)
        escaped = tuple(item for item in observed if item not in baseline_set)
        if escaped:
            raise ChildProcessTreeClosureUnproven(escaped)
        if not any(item.pid == os.getpid() for item in observed):
            raise ChildProcessTreeClosureUnproven(
                (),
                OSError(errno.ESTALE, "process census omitted the supervisor"),
            )


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
    require_isolated_account: bool = False,
) -> subprocess.CompletedProcess[str]:
    diagnostics = secondary_failures if secondary_failures is not None else []
    proof = closure_proof if closure_proof is not None else ChildProcessClosureProof()
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
        try:
            _require_no_new_same_uid_processes(baseline)
        except ChildProcessTreeClosureUnproven as error:
            raise error from pending_error
        except BaseException as error:
            raise ChildProcessTreeClosureUnproven((), error) from pending_error
        if isinstance(pending_error, GitProcessClosureUnproven):
            raise pending_error
        proof.proven = True
        if pending_error is not None:
            raise pending_error
        assert result is not None
        returncode, stdout, stderr = result
    return subprocess.CompletedProcess(
        args=argv,
        returncode=returncode,
        stdout=stdout.decode("utf-8", "replace"),
        stderr=stderr.decode("utf-8", "replace"),
    )


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
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                before = os.fstat(child_fd)
                if _filesystem_object_key(before) != _filesystem_object_key(metadata):
                    raise OSError(
                        errno.ESTALE,
                        "bound cleanup directory changed before write restoration",
                    )
                visit(child_fd, depth + 1)
                os.fchmod(
                    child_fd,
                    stat.S_IMODE(before.st_mode) | stat.S_IWUSR | stat.S_IXUSR,
                )
                if _filesystem_object_key(os.fstat(child_fd)) != _filesystem_object_key(
                    before
                ):
                    raise OSError(
                        errno.ESTALE,
                        "bound cleanup directory changed during write restoration",
                    )
            finally:
                os.close(child_fd)

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


def _snapshot_bound_cleanup_recovery(
    error: BaseException,
    *,
    parent_binding: _DirectoryParentBinding,
    manifest_path: pathlib.Path,
    manifest_seal: dict[str, Any] | None,
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

    manifest_evidence = {
        "path": str(manifest_path),
        "state": "published" if manifest_seal is not None else "not-published",
        "sha256": (manifest_seal.get("sha256") if manifest_seal is not None else None),
        "record_count": (
            manifest_seal.get("record_count") if manifest_seal is not None else None
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


def _delete_bound_tree(
    binding: _DirectoryParentBinding,
    *,
    restore_owner_write: bool,
    manifest_path: pathlib.Path,
) -> None:
    binding.revalidate()
    if restore_owner_write:
        _restore_owner_write_below_bound_root(binding.fd)
        binding.revalidate()
    parent_binding = _open_directory_parent(
        binding.path.parent,
        require_owned_private_parent=binding.require_owned_private_parent,
    )
    manifest = None
    seal: dict[str, Any] | None = None
    deletion_owner = CustodiedDeletionResultOwner()
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
        )
        seal = manifest.seal
        delete_custodied_roots(
            manifest,
            deadline=deadline,
            result_owner=deletion_owner,
        )
    except BaseException as error:
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
                deletion_owner=attached_owner,
            )
        except BaseException as recovery_error:
            error.add_note(
                "cleanup recovery evidence capture failed: "
                f"{type(recovery_error).__name__}: {recovery_error}"
            )
        raise
    finally:
        try:
            if manifest is not None:
                manifest.close()
        finally:
            parent_binding.close()
    assert seal is not None
    remove_published_manifest(seal)


def _cleanup_bound_tree(
    binding: _DirectoryParentBinding | None,
    *,
    restore_owner_write: bool,
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
        )
    except Exception as error:
        return _bound_cleanup_failure(binding, error)
    return None


def _cleanup_empty_bound_control(
    binding: _DirectoryParentBinding,
) -> CleanupFailure | None:
    try:
        binding.revalidate()
        parent_binding = _open_directory_parent(
            binding.path.parent,
            require_owned_private_parent=binding.require_owned_private_parent,
        )
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
        finally:
            parent_binding.close()
    except Exception as error:
        return _bound_cleanup_failure(binding, error)
    return None


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
    runtime_parent: pathlib.Path | None = None
    runtime_parent_binding: _DirectoryParentBinding | None = None
    cleanup_control_binding: _DirectoryParentBinding | None = None
    installed_root: pathlib.Path | None = None
    completed: subprocess.CompletedProcess[str] | None = None
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
    stage = "install-container"
    try:
        install_container_binding = _create_bound_owned_private_directory(
            READONLY_INSTALL_PARENT,
            ".codex-review-readonly-install-",
            require_owned_private_parent=False,
        )
        install_container = install_container_binding.path
        stage = "runtime-parent"
        runtime_parent_binding = _create_bound_owned_private_directory(
            _private_runtime_parent(),
            ".codex-review-readonly-runtime-",
        )
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
    except GitProcessClosureUnproven as error:
        closure_error = error
        child_process_closure = "unproven"
        primary_failure = _primary_failure(stage, error)
    except TimeoutError as error:
        timeout_error = error
        child_process_closure = (
            "proven"
            if closure_proof.proven
            else "unproven"
            if closure_proof.started
            else "not-started"
        )
        primary_failure = _primary_failure(stage, error)
    except OverflowError as error:
        output_limit_error = error
        child_process_closure = (
            "proven"
            if closure_proof.proven
            else "unproven"
            if closure_proof.started
            else "not-started"
        )
        primary_failure = _primary_failure(stage, error)
    except ChildRunInterrupted as error:
        signal_error = error
        child_process_closure = (
            "proven"
            if closure_proof.proven
            else "unproven"
            if closure_proof.started
            else "not-started"
        )
        primary_failure = _primary_failure(stage, error)
    except Exception as error:
        child_process_closure = (
            "proven"
            if closure_proof.proven
            else "unproven"
            if closure_proof.started
            else "not-started"
        )
        primary_failure = _primary_failure(stage, error)
    finally:
        cleanup_results: list[CleanupFailure | None]
        if child_process_closure == "unproven":
            cleanup_results = [
                _retained_bound_for_unproven_child_closure(
                    install_container_binding,
                    install_container,
                ),
                _retained_bound_for_unproven_child_closure(
                    runtime_parent_binding,
                    runtime_parent,
                ),
            ]
        else:
            try:
                cleanup_control_binding = _create_bound_owned_private_directory(
                    _private_runtime_parent(),
                    ".codex-review-readonly-cleanup-",
                )
            except Exception as error:
                secondary_failures.append(
                    _secondary_failure("create-bound-cleanup-control", error)
                )
            cleanup_results = [
                _cleanup_bound_tree(
                    install_container_binding,
                    restore_owner_write=True,
                    manifest_path=(
                        cleanup_control_binding.path / "install.manifest"
                        if cleanup_control_binding is not None
                        else None
                    ),
                ),
                _cleanup_bound_tree(
                    runtime_parent_binding,
                    restore_owner_write=False,
                    manifest_path=(
                        cleanup_control_binding.path / "runtime.manifest"
                        if cleanup_control_binding is not None
                        else None
                    ),
                ),
            ]
            if install_container_binding is None:
                cleanup_results.append(
                    _cleanup_tree(install_container, restore_owner_write=True)
                )
            if runtime_parent_binding is None:
                cleanup_results.append(
                    _cleanup_tree(runtime_parent, restore_owner_write=False)
                )
            if cleanup_control_binding is not None:
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
                    cleanup_results.append(
                        _cleanup_empty_bound_control(cleanup_control_binding)
                    )
        if install_container_binding is not None:
            try:
                install_container_binding.close()
            except Exception as error:
                cleanup_results.append(
                    _cleanup_failure_from_error(
                        install_container_binding.path,
                        error,
                        retained=None,
                        original_path=install_container_binding.path,
                        path_status="close-unresolved",
                        replacement_path=(
                            install_container_binding.path
                            if os.path.lexists(install_container_binding.path)
                            else None
                        ),
                    )
                )
        if runtime_parent_binding is not None:
            try:
                runtime_parent_binding.close()
            except Exception as error:
                cleanup_results.append(
                    _cleanup_failure_from_error(
                        runtime_parent_binding.path,
                        error,
                        retained=None,
                        original_path=runtime_parent_binding.path,
                        path_status="close-unresolved",
                        replacement_path=(
                            runtime_parent_binding.path
                            if os.path.lexists(runtime_parent_binding.path)
                            else None
                        ),
                    )
                )
        if cleanup_control_binding is not None:
            try:
                cleanup_control_binding.close()
            except Exception as error:
                cleanup_results.append(
                    _cleanup_failure_from_error(
                        cleanup_control_binding.path,
                        error,
                        retained=None,
                        original_path=cleanup_control_binding.path,
                        path_status="close-unresolved",
                        replacement_path=(
                            cleanup_control_binding.path
                            if os.path.lexists(cleanup_control_binding.path)
                            else None
                        ),
                        held_identity=cleanup_control_binding.object_locator(),
                    )
                )
        cleanup_failures = tuple(
            failure for failure in cleanup_results if failure is not None
        )

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
        elif closure_error is not None or child_process_closure == "unproven":
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
