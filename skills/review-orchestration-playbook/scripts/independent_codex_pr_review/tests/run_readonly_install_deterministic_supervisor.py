from __future__ import annotations

import ctypes
import errno
import grp
import hashlib
import json
import os
import pathlib
import pwd
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

from review_supervisor.gitraw import (
    CatFileBatch,
    GitProcessClosureUnproven,
    bound_git_environment,
    enumerate_tree,
    inspect_repository,
    run_bounded,
    selected_git_executable,
)
from review_supervisor.models import Identity
from review_supervisor import no_child_profile
from review_supervisor.codex_executable import (
    BoundedCommandOutputLimitExceeded,
    _macos_acl_entries,
    bounded_command_process_closure,
    run_bounded_command,
)
from review_supervisor.no_child_profile import (
    attest_writable_root,
    prepare_sandboxed_python_no_child_profile,
)
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
    begin_bound_signal_deferral,
    checkpoint_bound_signal_interrupt,
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
    _runtime_parent_creation_allows_sticky_writable_ancestors,
    _settle_directory_parent_binding_result_preserving_trigger,
)
from .readonly_no_child_contract import SUCCESS_RECORD as NO_CHILD_SUCCESS_RECORD

EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
RUNNER_ENVIRONMENT_ENV = "CODEX_REVIEW_RUNNER_ENVIRONMENT"
RUNNER_ARCH_ENV = "CODEX_REVIEW_RUNNER_ARCH"
EXPECTED_HEAD_ENV = "CODEX_REVIEW_EXPECTED_HEAD_SHA"
DEDICATED_ACCOUNT_CUSTODY_ENV = "CODEX_REVIEW_DEDICATED_ACCOUNT_CUSTODY_SHA256"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
CHILD_TIMEOUT_SECONDS = 600.0
CHILD_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
CHILD_STDERR_LIMIT_BYTES = 8 * 1024 * 1024


def _create_bound_owned_private_runtime_directory(
    prefix: str,
    *,
    result_owner: _PrivateDirectoryCreationResultOwner,
) -> _DirectoryParentBinding:
    """Preserve runner-local parent and creation injection seams."""

    explicit_parent = os.environ.get(EXPLICIT_RUNTIME_PARENT_ENV)
    parent = _private_runtime_parent()
    allow_sticky_writable_ancestors = (
        _runtime_parent_creation_allows_sticky_writable_ancestors(
            explicit_parent,
            parent,
        )
    )
    if allow_sticky_writable_ancestors:
        return _create_bound_owned_private_directory(
            parent,
            prefix,
            result_owner=result_owner,
            allow_sticky_writable_ancestors=True,
        )
    return _create_bound_owned_private_directory(
        parent,
        prefix,
        result_owner=result_owner,
    )


NO_CHILD_SUITE_CODE = (
    "import errno,os,pathlib,runpy,sys,tempfile\n"
    "if not sys.flags.isolated or not sys.flags.no_site:\n"
    " raise RuntimeError('read-only test child requires isolated no-site startup')\n"
    "root=pathlib.Path(sys.argv[1])\n"
    "runtime=pathlib.Path(sys.argv[2])\n"
    f"os.environ[{EXPLICIT_RUNTIME_PARENT_ENV!r}]=sys.argv[2]\n"
    "os.environ['TMPDIR']=sys.argv[2]\n"
    "tempfile.tempdir=sys.argv[2]\n"
    "def require_denied(action,label):\n"
    " try:\n"
    "  result=action()\n"
    " except OSError as error:\n"
    "  if error.errno in {errno.EACCES,errno.EPERM}:\n"
    "   return\n"
    "  raise\n"
    " if isinstance(result,int):\n"
    "  os.close(result)\n"
    " raise RuntimeError(f'read-only install policy allowed {label}')\n"
    "probe=root/'tests'/'__init__.py'\n"
    "require_denied(lambda:os.chmod(root,0o700),'root chmod')\n"
    "require_denied(lambda:os.chmod(probe,0o600),'file chmod')\n"
    "require_denied(lambda:os.open(probe,os.O_WRONLY),'file write-open')\n"
    "hardlink_probe=runtime/'release-hardlink-probe'\n"
    "try:\n"
    " require_denied(lambda:os.link(probe,hardlink_probe),"
    "'release hard link into runtime')\n"
    "finally:\n"
    " try:\n"
    "  os.unlink(hardlink_probe)\n"
    " except FileNotFoundError:\n"
    "  pass\n"
    "parent_probe=root.parent/'seatbelt-parent-write-probe'\n"
    "require_denied(lambda:os.open(parent_probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL,"
    "0o600),'install-parent create')\n"
    "runtime_probe=runtime/'seatbelt-write-probe'\n"
    "try:\n"
    " fd=os.open(runtime_probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
    " try:\n"
    "  os.write(fd,b'allowed runtime write\\n')\n"
    " finally:\n"
    "  os.close(fd)\n"
    "finally:\n"
    " try:\n"
    "  os.unlink(runtime_probe)\n"
    " except FileNotFoundError:\n"
    "  pass\n"
    "os.chdir(root)\n"
    "sys.path.insert(0,str(root))\n"
    "runpy.run_module('tests.run_readonly_no_child_supervisor',run_name='__main__')\n"
)
CREATION_ORIGIN_GUARANTEE = (
    "best-effort-128-bit-leaf-immediate-nofollow-open-same-uid-host-tcb"
)
CLEANUP_GUARANTEE = (
    "custodied-manifest-quarantine-descriptor-revalidation-"
    "same-uid-final-rename-unlink-host-tcb"
)
ACL_LISTING_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
XATTR_NOFOLLOW = 0x0001
XATTR_NAMES_LIMIT_BYTES = 64 * 1024
XATTR_VALUE_LIMIT_BYTES = 16 * 1024 * 1024
XATTR_AGGREGATE_LIMIT_BYTES = 64 * 1024 * 1024
# This counts listing, capture, and revalidation observations, not unique paths.
TREE_SNAPSHOT_ENTRY_OBSERVATION_LIMIT = 32 * 1024
TREE_SNAPSHOT_FILE_READ_LIMIT_BYTES = 512 * 1024 * 1024
TREE_SNAPSHOT_ACCESS_POLICY_READ_LIMIT_BYTES = 128 * 1024 * 1024
TREE_SNAPSHOT_PATH_READ_LIMIT_BYTES = 16 * 1024 * 1024
TREE_SNAPSHOT_MAX_DEPTH = 64
TREE_SNAPSHOT_TIMEOUT_SECONDS = 60.0
DARWIN_PROC_UID_ONLY = 4
DARWIN_PROC_RUID_ONLY = 5
DARWIN_CTL_KERN = 1
DARWIN_KERN_PROC = 14
DARWIN_KERN_PROC_PID = 1
DARWIN_KINFO_PROC_BYTES = 648
DARWIN_PROCESS_CENSUS_CAP = 4096
DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS = 5.0
DARWIN_PROCESS_ABSENCE_STABILITY_SECONDS = 0.25
DARWIN_DEDICATED_PROCESS_TERMINATE_GRACE_SECONDS = 0.1
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
    size: int | None
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
            self.size,
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
class SourceTreeBinding:
    source_manifest_sha256: str
    source_root_gid: int
    source_entries: tuple[tuple[str, TreeEntrySnapshot], ...]


@dataclass(frozen=True)
class SourceCheckoutBinding:
    repo_root: pathlib.Path
    head_sha: str
    source_relative_path: str
    source_manifest_sha256: str
    head_subtree_manifest_sha256: str
    source_root_gid: int
    source_entries: tuple[tuple[str, TreeEntrySnapshot], ...]


@dataclass
class TreeSnapshotBudget:
    entry_observations_remaining: int
    file_read_bytes_remaining: int
    access_policy_read_bytes_remaining: int
    path_read_bytes_remaining: int
    max_depth: int

    @classmethod
    def create(cls) -> TreeSnapshotBudget:
        return cls(
            entry_observations_remaining=TREE_SNAPSHOT_ENTRY_OBSERVATION_LIMIT,
            file_read_bytes_remaining=TREE_SNAPSHOT_FILE_READ_LIMIT_BYTES,
            access_policy_read_bytes_remaining=(
                TREE_SNAPSHOT_ACCESS_POLICY_READ_LIMIT_BYTES
            ),
            path_read_bytes_remaining=TREE_SNAPSHOT_PATH_READ_LIMIT_BYTES,
            max_depth=TREE_SNAPSHOT_MAX_DEPTH,
        )

    def start_scan(self) -> TreeSnapshotScan:
        return TreeSnapshotScan(
            budget=self,
            deadline=time.monotonic() + TREE_SNAPSHOT_TIMEOUT_SECONDS,
        )


@dataclass
class TreeSnapshotScan:
    budget: TreeSnapshotBudget
    deadline: float

    def checkpoint(self) -> None:
        if time.monotonic() >= self.deadline:
            raise RuntimeError("tree snapshot exceeded its total deadline")

    def observe_entry(self, *, depth: int, path_bytes: int) -> None:
        self.checkpoint()
        if depth > self.budget.max_depth:
            raise RuntimeError("tree snapshot exceeds its depth bound")
        if self.budget.entry_observations_remaining <= 0:
            raise RuntimeError("tree snapshot exceeds its entry-observation bound")
        if path_bytes < 0 or path_bytes > self.budget.path_read_bytes_remaining:
            raise RuntimeError("tree snapshot exceeds its cumulative path byte bound")
        self.budget.entry_observations_remaining -= 1
        self.budget.path_read_bytes_remaining -= path_bytes

    def consume_file_read(self, size: int) -> None:
        self.checkpoint()
        if size < 0 or size > self.budget.file_read_bytes_remaining:
            raise RuntimeError("tree snapshot exceeds its cumulative file byte bound")
        self.budget.file_read_bytes_remaining -= size

    def consume_access_policy_read(self, size: int) -> None:
        self.checkpoint()
        if size < 0 or size > self.budget.access_policy_read_bytes_remaining:
            raise RuntimeError(
                "tree snapshot exceeds its cumulative access-policy byte bound"
            )
        self.budget.access_policy_read_bytes_remaining -= size


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


class TerminalPublicationError(RuntimeError):
    def __init__(self, operation: str, error: BaseException) -> None:
        self.operation = operation
        self.error = error
        super().__init__(
            f"terminal publication {operation} failed: {type(error).__name__}: {error}"
        )


@dataclass(frozen=True)
class ChildSignalGuard:
    signals: tuple[signal.Signals, ...]
    previous_handlers: tuple[Any, ...]
    previous_mask: set[signal.Signals]
    interrupt: DeferredSignalInterrupt


@dataclass
class LifecycleSignalFence:
    signals: tuple[signal.Signals, ...]
    previous_handlers: tuple[Any, ...]
    previous_mask: set[signal.Signals]
    received_signal: int | None = None
    terminal_signal: int | None = None
    terminal_selected_signal: int | None = None
    terminal_exit_code: int | None = None
    terminal_decision_frozen: bool = False
    terminal_output_committed: bool = False


@dataclass
class ChildProcessClosureProof:
    # Protected property: same-UID process-tree closure. Only this proof may
    # authorize destructive cleanup; a returned child outcome is not closure
    # evidence and is deliberately carried by a separate caller-owned receipt.
    started: bool = False
    proven: bool = False
    destructive_cleanup_authorized: bool = True
    runtime_profile: str | None = None


class ChildOutputLimitExceeded(OverflowError):
    def __init__(self, *, scope: str, limit: int) -> None:
        self.scope = scope
        self.limit = limit
        super().__init__(
            f"bounded no-child test {scope} output exceeded its {limit}-byte cap"
        )


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


def _select_no_child_runtime_profile() -> tuple[str, no_child_profile.RuntimePin]:
    if os.environ.get("GITHUB_ACTIONS") == "true" or any(
        os.environ.get(name) is not None
        for name in (RUNNER_ENVIRONMENT_ENV, RUNNER_ARCH_ENV)
    ):
        raise RuntimeError(
            "read-only installed supervisor is forbidden under GitHub Actions "
            "and hosted runner profiles"
        )
    return "production-current", no_child_profile.PINNED_RUNTIME


def _authenticated_no_child_closure(
    closure: object | None,
    *,
    require_stdio_closed: bool,
) -> bool:
    return bool(
        closure is not None
        and getattr(closure, "authenticated_no_child_profile", False) is True
        and getattr(closure, "permitted_process_closure_proven", False) is True
        and getattr(closure, "leader_reaped", False) is True
        and (
            not require_stdio_closed or getattr(closure, "stdio_closed", False) is True
        )
        and getattr(
            closure,
            "process_group_emptiness_used_as_descendant_proof",
            True,
        )
        is False
    )


def _install_lifecycle_signal_fence() -> LifecycleSignalFence:
    handled = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled)
    previous_handlers: list[Any] = []
    fence = LifecycleSignalFence(
        signals=handled,
        previous_handlers=(),
        previous_mask=previous_mask,
    )

    def retain_lifecycle_signal(
        signal_number: int,
        _frame: FrameType | None,
    ) -> None:
        if fence.received_signal is None:
            fence.received_signal = signal_number

    try:
        for signal_number in handled:
            previous_handlers.append(
                signal.signal(signal_number, retain_lifecycle_signal)
            )
        fence.previous_handlers = tuple(previous_handlers)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, handled)
        for signal_number, previous in zip(
            handled,
            previous_handlers,
            strict=False,
        ):
            signal.signal(signal_number, previous)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    return fence


def _restore_lifecycle_signal_fence(fence: LifecycleSignalFence) -> int | None:
    signal.pthread_sigmask(signal.SIG_BLOCK, fence.signals)
    pending = signal.sigpending()
    selected = fence.received_signal
    if selected is None:
        selected = next(
            (int(item) for item in fence.signals if item in pending),
            None,
        )
    for signal_number, previous in zip(
        fence.signals,
        fence.previous_handlers,
        strict=True,
    ):
        signal.signal(signal_number, previous)
    signal.pthread_sigmask(signal.SIG_SETMASK, fence.previous_mask)
    return selected


def _freeze_lifecycle_terminal_signal(
    fence: LifecycleSignalFence,
) -> int | None:
    if fence.terminal_decision_frozen:
        return fence.terminal_signal
    signal.pthread_sigmask(signal.SIG_BLOCK, fence.signals)
    pending = signal.sigpending()
    selected = fence.received_signal
    if selected is None:
        selected = next(
            (int(item) for item in fence.signals if item in pending),
            None,
        )
    fence.terminal_signal = selected
    fence.terminal_decision_frozen = True
    return selected


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


@dataclass(frozen=True)
class DedicatedUidScope:
    # This capability is valid only while the ephemeral account remains the
    # caller's real/effective UID and its prelaunch census contains this
    # supervisor alone. Signals are still ordinary same-UID kill(2) calls;
    # Darwin provides no pidfd-style atomic revalidate-and-signal primitive.
    uid: int
    account_name: str
    receipt_sha256: str
    baseline: tuple[DarwinProcessIdentity, ...]


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


def _run_no_child_test_suite(
    *,
    installed_root: pathlib.Path,
    install_container_binding: _DirectoryParentBinding,
    runtime_parent_binding: _DirectoryParentBinding,
    timeout: float = CHILD_TIMEOUT_SECONDS,
    stdout_limit: int = CHILD_STDOUT_LIMIT_BYTES,
    stderr_limit: int = CHILD_STDERR_LIMIT_BYTES,
    secondary_failures: list[SecondaryFailure] | None = None,
    closure_proof: ChildProcessClosureProof | None = None,
    lifecycle_fence: LifecycleSignalFence | None = None,
) -> subprocess.CompletedProcess[str]:
    diagnostics = secondary_failures if secondary_failures is not None else []
    proof = closure_proof if closure_proof is not None else ChildProcessClosureProof()
    runtime_parent = runtime_parent_binding.path
    if installed_root.parent != install_container_binding.path:
        raise RuntimeError(
            "read-only installed root is outside its bound install container"
        )
    install_container_binding.revalidate()
    runtime_parent_binding.revalidate()
    if directory_identities_match(
        install_container_binding.identity,
        runtime_parent_binding.identity,
    ):
        raise RuntimeError("runtime root aliases the read-only install container")
    install_container = str(install_container_binding.path)
    runtime_root = str(runtime_parent)
    common = os.path.commonpath((install_container, runtime_root))
    if common in {install_container, runtime_root}:
        raise RuntimeError("runtime root overlaps the read-only install container")
    writable_runtime = attest_writable_root(
        runtime_parent,
        directory_fd=runtime_parent_binding.fd,
    )
    with _bound_child_signals(diagnostics):
        if lifecycle_fence is not None and lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        runtime_profile, runtime_pin = _select_no_child_runtime_profile()
        proof.runtime_profile = runtime_profile
        prepared = prepare_sandboxed_python_no_child_profile(
            additional_seatbelt_rules="(deny file-write*)",
            runtime_pin=runtime_pin,
            writable_roots=(writable_runtime,),
        )
        if lifecycle_fence is not None and lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        target = prepared.sandboxed_target
        if target is None:
            raise RuntimeError(
                "read-only installed test profile lacks a bound Python target"
            )
        argv = (
            target.path,
            "-I",
            "-S",
            "-B",
            "-c",
            NO_CHILD_SUITE_CODE,
            str(installed_root),
            str(runtime_parent),
        )
        install_container_binding.revalidate()
        runtime_parent_binding.revalidate()
        proof_scope = begin_bound_signal_deferral()
        try:
            checkpoint_bound_signal_interrupt(force=True)
            proof.started = True
            proof.destructive_cleanup_authorized = False
            try:
                result = run_bounded_command(
                    argv,
                    timeout_seconds=timeout,
                    max_output_bytes=stdout_limit + stderr_limit,
                    max_stdout_bytes=stdout_limit,
                    max_stderr_bytes=stderr_limit,
                    _prepared_no_child_profile=prepared,
                )
            except BaseException as error:
                closure = bounded_command_process_closure(error)
                if _authenticated_no_child_closure(
                    closure,
                    require_stdio_closed=False,
                ):
                    proof.proven = True
                    proof.destructive_cleanup_authorized = True
                if isinstance(error, BoundedCommandOutputLimitExceeded):
                    raise ChildOutputLimitExceeded(
                        scope=error.scope,
                        limit=error.limit,
                    ) from error
                raise
            closure = result.process_closure
            if not _authenticated_no_child_closure(
                closure,
                require_stdio_closed=True,
            ):
                raise RuntimeError(
                    "read-only installed test process closure lacks an authenticated "
                    "no-child proof"
                )
            proof.proven = True
            proof.destructive_cleanup_authorized = True
            if len(result.stdout) > stdout_limit:
                raise ChildOutputLimitExceeded(scope="stdout", limit=stdout_limit)
            if len(result.stderr) > stderr_limit:
                raise ChildOutputLimitExceeded(scope="stderr", limit=stderr_limit)
            if result.returncode == 0 and result.stdout != (
                NO_CHILD_SUCCESS_RECORD + "\n"
            ).encode("ascii"):
                raise RuntimeError(
                    "read-only installed test child lacks its exact completion record"
                )
        finally:
            if proof_scope is not None:
                proof_scope.finish(deliver=proof.proven or not proof.started)
    return subprocess.CompletedProcess(
        args=argv,
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", "replace"),
        stderr=result.stderr.decode("utf-8", "replace"),
    )


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
    dedicated_scope: DedicatedUidScope | None = None,
) -> None:
    operation_deadline = _process_census_deadline(deadline)
    baseline_set = set(baseline)
    last_escaped: tuple[DarwinProcessIdentity, ...] = ()
    absent_since: float | None = None
    terminate_sent_at: dict[DarwinProcessIdentity, float] = {}
    kill_sent: set[DarwinProcessIdentity] = set()
    if dedicated_scope is not None and dedicated_scope.baseline != baseline:
        raise ChildProcessTreeClosureUnproven(
            (),
            OSError(errno.EPERM, "dedicated UID scope does not match the baseline"),
        )
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
            if dedicated_scope is not None:
                _require_dedicated_uid_scope_current(dedicated_scope)
                now = time.monotonic()
                for process in escaped:
                    first_signal = terminate_sent_at.get(process)
                    if first_signal is None:
                        if _signal_dedicated_uid_process(
                            process,
                            signal.SIGTERM,
                            deadline=operation_deadline,
                        ):
                            terminate_sent_at[process] = now
                    elif (
                        process not in kill_sent
                        and now - first_signal
                        >= DARWIN_DEDICATED_PROCESS_TERMINATE_GRACE_SECONDS
                    ):
                        if _signal_dedicated_uid_process(
                            process,
                            signal.SIGKILL,
                            deadline=operation_deadline,
                        ):
                            kill_sent.add(process)
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


def _require_dedicated_uid_scope_current(scope: DedicatedUidScope) -> None:
    if os.getuid() != scope.uid or os.geteuid() != scope.uid:
        raise ChildProcessTreeClosureUnproven(
            (),
            PermissionError(errno.EPERM, "dedicated UID custody changed"),
        )
    try:
        account = pwd.getpwuid(scope.uid)
    except KeyError as error:
        raise ChildProcessTreeClosureUnproven((), error) from error
    if (
        account.pw_name != scope.account_name
        or account.pw_uid != scope.uid
        or account.pw_gid != scope.uid
        or account.pw_dir != "/var/empty"
        or account.pw_shell != "/usr/bin/false"
    ):
        raise ChildProcessTreeClosureUnproven(
            (),
            OSError(errno.ESTALE, "dedicated UID account identity or policy changed"),
        )


def _signal_dedicated_uid_process(
    process: DarwinProcessIdentity,
    signal_number: int,
    *,
    deadline: float,
) -> bool:
    _require_process_census_time(deadline)
    rebound = tuple(
        candidate
        for candidate in _darwin_same_uid_processes(deadline=deadline)
        if candidate.pid == process.pid
    )
    if not rebound:
        return False
    if len(rebound) != 1 or rebound[0] != process:
        raise ChildProcessTreeClosureUnproven(
            (process,),
            OSError(
                errno.ESTALE, "dedicated UID process identity changed before signal"
            ),
        )
    try:
        os.kill(process.pid, signal_number)
    except ProcessLookupError:
        return False
    except OSError as error:
        raise ChildProcessTreeClosureUnproven((process,), error) from error
    return True


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


def _dedicated_uid_scope(
    baseline: tuple[DarwinProcessIdentity, ...],
) -> DedicatedUidScope | None:
    receipt = os.environ.get(DEDICATED_ACCOUNT_CUSTODY_ENV)
    if receipt is None:
        return None
    if len(receipt) != 64 or any(
        character not in "0123456789abcdef" for character in receipt
    ):
        raise PermissionError(errno.EPERM, "dedicated UID receipt is malformed")
    uid = os.getuid()
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise PermissionError(
            errno.EPERM,
            "dedicated UID account identity is unavailable",
        ) from error
    suffix = account.pw_name.removeprefix("codexreview")
    if (
        not 50000 <= uid <= 59999
        or account.pw_uid != uid
        or account.pw_gid != uid
        or len(suffix) != 12
        or any(character not in "0123456789abcdef" for character in suffix)
        or account.pw_dir != "/var/empty"
        or account.pw_shell != "/usr/bin/false"
        or len(baseline) != 1
        or baseline[0].pid != os.getpid()
    ):
        raise PermissionError(
            errno.EPERM,
            "dedicated UID account custody is not proven",
        )
    return DedicatedUidScope(
        uid=uid,
        account_name=account.pw_name,
        receipt_sha256=receipt,
        baseline=baseline,
    )


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
        dedicated_scope = (
            _dedicated_uid_scope(baseline) if require_isolated_account else None
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
            _require_no_new_same_uid_processes(
                baseline,
                dedicated_scope=dedicated_scope,
            )
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


def _acl_entries(descriptor: int) -> tuple[bytes, ...]:
    return tuple(
        entry.encode("ascii", "strict") for entry in _macos_acl_entries(descriptor)
    )


def _xattr_snapshot(
    descriptor: int,
    *,
    budget: TreeSnapshotScan | None = None,
) -> tuple[tuple[bytes, str], ...]:
    libc = ctypes.CDLL(None, use_errno=True)
    listxattr = libc.flistxattr
    listxattr.argtypes = (
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    )
    listxattr.restype = ctypes.c_ssize_t
    getxattr = libc.fgetxattr
    getxattr.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    getxattr.restype = ctypes.c_ssize_t

    def read_names() -> bytes:
        ctypes.set_errno(0)
        size = listxattr(descriptor, None, 0, 0)
        if size < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot size extended attribute names",
            )
        if size > XATTR_NAMES_LIMIT_BYTES:
            raise ValueError("extended attribute names exceed their byte bound")
        if budget is not None:
            budget.consume_access_policy_read(size)
        if size == 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        ctypes.set_errno(0)
        actual = listxattr(descriptor, buffer, size, 0)
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
            size = getxattr(descriptor, name, None, 0, 0, 0)
            if size < 0:
                raise OSError(
                    ctypes.get_errno() or errno.EIO,
                    "cannot size extended attribute value",
                )
            if size > XATTR_VALUE_LIMIT_BYTES:
                raise ValueError("extended attribute value exceeds its byte bound")
            if budget is not None:
                budget.consume_access_policy_read(size)
            if size == 0:
                return b""
            buffer = ctypes.create_string_buffer(size)
            ctypes.set_errno(0)
            actual = getxattr(descriptor, name, buffer, size, 0, 0)
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


def _snapshot_binding_key(metadata: os.stat_result) -> tuple[object, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
        metadata.st_nlink if stat.S_ISREG(metadata.st_mode) else None,
    )


def _open_snapshot_entry(
    parent_descriptor: int,
    name: str,
) -> tuple[int, os.stat_result]:
    if not name or name in {".", ".."} or "/" in name or "\0" in name:
        raise ValueError("snapshot entry name is malformed")
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    common_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if stat.S_ISREG(initial.st_mode):
        flags = common_flags | os.O_NOFOLLOW
    elif stat.S_ISDIR(initial.st_mode):
        flags = common_flags | os.O_DIRECTORY | os.O_NOFOLLOW
    elif stat.S_ISLNK(initial.st_mode):
        raise OSError(
            errno.EPERM,
            "symlinks are unsupported in immutable install snapshots",
        )
    else:
        raise OSError(errno.EPERM, "unsupported entry in read-only install tree")
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        if _snapshot_binding_key(initial) != _snapshot_binding_key(opened):
            raise OSError(errno.ESTALE, "snapshot entry changed while opening")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_snapshot_root(root: pathlib.Path) -> tuple[int, os.stat_result]:
    initial = root.lstat()
    if not stat.S_ISDIR(initial.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, "snapshot root is not a directory")
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        opened = os.fstat(descriptor)
        if _snapshot_binding_key(initial) != _snapshot_binding_key(opened):
            raise OSError(errno.ESTALE, "snapshot root changed while opening")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _descriptor_digest(
    descriptor: int,
    *,
    budget: TreeSnapshotScan,
) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "snapshot digest requires a regular file")
    budget.consume_file_read(before.st_size + 1)
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
        budget.checkpoint()
    extra = os.pread(descriptor, 1, offset)
    after = os.fstat(descriptor)
    if (
        _snapshot_binding_key(before) != _snapshot_binding_key(after)
        or before.st_size != after.st_size
        or offset != after.st_size
        or extra
    ):
        raise OSError(errno.ESTALE, "regular file changed during snapshot")
    return digest.hexdigest()


def _access_policy_snapshot(
    descriptor: int,
    *,
    budget: TreeSnapshotScan,
) -> tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]]:
    xattrs = _xattr_snapshot(descriptor, budget=budget)
    acl_entries = _acl_entries(descriptor)
    budget.consume_access_policy_read(sum(len(entry) for entry in acl_entries))
    return xattrs, acl_entries


def _stable_access_policy_snapshot(
    descriptor: int,
    *,
    budget: TreeSnapshotScan,
) -> tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]]:
    first = _access_policy_snapshot(descriptor, budget=budget)
    second = _access_policy_snapshot(descriptor, budget=budget)
    if first != second:
        raise OSError(errno.ESTALE, "access policy changed during snapshot")
    return second


def _regular_entry_sample(
    descriptor: int,
    *,
    budget: TreeSnapshotScan,
) -> tuple[
    str,
    tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
]:
    digest_before = _descriptor_digest(descriptor, budget=budget)
    access_policy = _stable_access_policy_snapshot(descriptor, budget=budget)
    digest_after = _descriptor_digest(descriptor, budget=budget)
    if digest_before != digest_after:
        raise OSError(errno.ESTALE, "regular file changed during snapshot")
    return digest_after, access_policy


def _stable_regular_entry_sample(
    descriptor: int,
    *,
    budget: TreeSnapshotScan,
) -> tuple[
    str,
    tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
]:
    first = _regular_entry_sample(descriptor, budget=budget)
    second = _regular_entry_sample(descriptor, budget=budget)
    if first != second:
        raise OSError(
            errno.ESTALE,
            "regular file content or access policy changed during snapshot",
        )
    return second


def _snapshot_opened_entry(
    descriptor: int,
    initial: os.stat_result,
    *,
    relative: str,
    snapshot: dict[str, TreeEntrySnapshot],
    scan: TreeSnapshotScan,
    depth: int,
    expected_kinds: dict[bytes, str] | None,
) -> TreeEntrySnapshot:
    relative_bytes = os.fsencode(relative)
    scan.observe_entry(depth=depth, path_bytes=len(relative_bytes))
    if stat.S_ISREG(initial.st_mode):
        kind = "file"
    elif stat.S_ISDIR(initial.st_mode):
        kind = "directory"
    else:
        raise OSError(errno.EPERM, "unsupported entry in read-only install tree")
    if expected_kinds is not None and expected_kinds.get(relative_bytes) != kind:
        raise RuntimeError("source checkout subtree does not match the exact HEAD tree")

    if kind == "file":
        if initial.st_nlink != 1:
            raise RuntimeError(
                f"regular file has an external hardlink alias: {relative}"
            )
        digest, access_policy = _stable_regular_entry_sample(
            descriptor,
            budget=scan,
        )
        link_count = initial.st_nlink
    else:
        digest = None
        link_count = None
        access_before = _stable_access_policy_snapshot(
            descriptor,
            budget=scan,
        )
        names = _bounded_snapshot_directory_names(
            descriptor,
            scan=scan,
            child_depth=depth + 1,
        )
        for name in names:
            child_relative = name if relative == "." else f"{relative}/{name}"
            child_descriptor, child_initial = _open_snapshot_entry(descriptor, name)
            try:
                child_snapshot = _snapshot_opened_entry(
                    child_descriptor,
                    child_initial,
                    relative=child_relative,
                    snapshot=snapshot,
                    scan=scan,
                    depth=depth + 1,
                    expected_kinds=expected_kinds,
                )
                final_child = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if _snapshot_binding_key(child_initial) != _snapshot_binding_key(
                    final_child
                ):
                    raise OSError(
                        errno.ESTALE,
                        "snapshot path no longer names the bound object: "
                        f"{child_relative}",
                    )
                snapshot[child_relative] = child_snapshot
            finally:
                os.close(child_descriptor)
        if names != _bounded_snapshot_directory_names(
            descriptor,
            scan=scan,
            child_depth=depth + 1,
        ):
            raise OSError(
                errno.ESTALE,
                f"directory changed during snapshot: {relative}",
            )
        access_policy = _stable_access_policy_snapshot(
            descriptor,
            budget=scan,
        )
        if access_before != access_policy:
            raise OSError(errno.ESTALE, "access policy changed during snapshot")
    final_descriptor = os.fstat(descriptor)
    if _snapshot_binding_key(initial) != _snapshot_binding_key(final_descriptor):
        raise OSError(
            errno.ESTALE,
            f"snapshot object changed during capture: {relative}",
        )
    if stat.S_ISREG(initial.st_mode) and initial.st_size != final_descriptor.st_size:
        raise OSError(errno.ESTALE, f"regular file changed during snapshot: {relative}")
    xattrs, acl_entries = access_policy
    return TreeEntrySnapshot(
        kind=kind,
        size=final_descriptor.st_size if kind == "file" else None,
        device=final_descriptor.st_dev,
        inode=final_descriptor.st_ino,
        generation=getattr(final_descriptor, "st_gen", 0),
        uid=final_descriptor.st_uid,
        gid=final_descriptor.st_gid,
        mode=stat.S_IMODE(final_descriptor.st_mode),
        flags=getattr(final_descriptor, "st_flags", 0),
        link_count=link_count,
        digest=digest,
        xattrs=xattrs,
        acl_entries=acl_entries,
    )


def _bounded_snapshot_directory_names(
    descriptor: int,
    *,
    scan: TreeSnapshotScan,
    child_depth: int,
) -> tuple[str, ...]:
    names = []
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            encoded = os.fsencode(entry.name)
            scan.observe_entry(depth=child_depth, path_bytes=len(encoded))
            names.append(entry.name)
    scan.checkpoint()
    return tuple(sorted(names))


def _tree_snapshot_once(
    root: pathlib.Path,
    *,
    scan: TreeSnapshotScan,
    expected_kinds: dict[bytes, str] | None = None,
) -> dict[str, TreeEntrySnapshot]:
    snapshot: dict[str, TreeEntrySnapshot] = {}
    scan.checkpoint()
    descriptor, initial = _open_snapshot_root(root)
    try:
        root_snapshot = _snapshot_opened_entry(
            descriptor,
            initial,
            relative=".",
            snapshot=snapshot,
            scan=scan,
            depth=0,
            expected_kinds=expected_kinds,
        )
        final_descriptor = os.fstat(descriptor)
        final_path = root.lstat()
        if _snapshot_binding_key(final_descriptor) != _snapshot_binding_key(final_path):
            raise OSError(
                errno.ESTALE,
                "snapshot root path no longer names the bound object",
            )
        snapshot["."] = root_snapshot
        if (
            expected_kinds is not None
            and {os.fsencode(path): entry.kind for path, entry in snapshot.items()}
            != expected_kinds
        ):
            raise RuntimeError(
                "source checkout subtree does not match the exact HEAD tree"
            )
        return snapshot
    finally:
        os.close(descriptor)


def _tree_snapshot(
    root: pathlib.Path,
    *,
    budget: TreeSnapshotBudget | None = None,
    expected_kinds: dict[bytes, str] | None = None,
) -> dict[str, TreeEntrySnapshot]:
    scan = (budget or TreeSnapshotBudget.create()).start_scan()
    first = _tree_snapshot_once(
        root,
        scan=scan,
        expected_kinds=expected_kinds,
    )
    second = _tree_snapshot_once(
        root,
        scan=scan,
        expected_kinds=expected_kinds,
    )
    if not _tree_property_unchanged(first, second):
        raise OSError(errno.ESTALE, "install tree changed during snapshot")
    return second


def _tree_property_unchanged(
    before: dict[str, TreeEntrySnapshot],
    after: dict[str, TreeEntrySnapshot],
) -> bool:
    if before.keys() != after.keys():
        return False
    return all(
        before[path].protected_key() == after[path].protected_key() for path in before
    )


def _snapshot_manifest_sha256(
    snapshot: dict[str, TreeEntrySnapshot],
    *,
    owner_uid_override: int | None,
    group_gid_override: int | None,
) -> str:
    records = []
    for path, entry in sorted(snapshot.items()):
        records.append(
            (
                path,
                entry.kind,
                entry.size,
                entry.uid if owner_uid_override is None else owner_uid_override,
                entry.gid if group_gid_override is None else group_gid_override,
                entry.mode,
                entry.flags,
                entry.digest,
                tuple((name.hex(), digest) for name, digest in entry.xattrs),
                tuple(value.hex() for value in entry.acl_entries),
            )
        )
    encoded = json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def _source_snapshot_manifest_sha256(
    snapshot: dict[str, TreeEntrySnapshot],
) -> str:
    return _snapshot_manifest_sha256(
        snapshot,
        owner_uid_override=None,
        group_gid_override=None,
    )


def _destination_snapshot_manifest_sha256(
    source_entries: tuple[tuple[str, TreeEntrySnapshot], ...],
    *,
    destination_owner_uid: int,
    destination_group_gid: int,
) -> str:
    return _snapshot_manifest_sha256(
        dict(source_entries),
        owner_uid_override=destination_owner_uid,
        group_gid_override=destination_group_gid,
    )


def _source_manifest_sha256(
    root: pathlib.Path,
    *,
    budget: TreeSnapshotBudget | None = None,
) -> str:
    return _source_snapshot_manifest_sha256(_tree_snapshot(root, budget=budget))


def _source_git_output(source_root: pathlib.Path, *arguments: str) -> bytes:
    command = (
        selected_git_executable(),
        "--no-pager",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "color.ui=false",
        "-C",
        str(source_root),
        *arguments,
    )
    returncode, stdout, stderr = run_bounded(
        command,
        cwd=source_root,
        environment=bound_git_environment(
            {
                "GIT_ASKPASS": "/usr/bin/false",
                "GIT_PAGER": "cat",
                "PAGER": "cat",
            }
        ),
        timeout=30,
        stdout_limit=1024 * 1024,
        stderr_limit=64 * 1024,
    )
    if returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()[:512]
        raise RuntimeError(f"source checkout Git validation failed: {detail}")
    return stdout


def _validate_source_git_configuration(source_root: pathlib.Path) -> None:
    payload = _source_git_output(
        source_root,
        "config",
        "--no-includes",
        "--null",
        "--list",
    )
    if payload and not payload.endswith(b"\0"):
        raise RuntimeError("source checkout Git config output is malformed")
    for record in payload[:-1].split(b"\0") if payload else ():
        key, separator, value = record.partition(b"\n")
        if not key or not separator:
            raise RuntimeError("source checkout Git config output is malformed")
        lower_key = key.lower()
        lower_value = value.strip().lower()
        if lower_key == b"include.path" or (
            lower_key.startswith(b"includeif.") and lower_key.endswith(b".path")
        ):
            raise RuntimeError("source checkout Git config contains an include")
        if lower_key.startswith(b"alias."):
            raise RuntimeError("source checkout Git config contains an alias")
        if lower_key == b"core.filemode" and lower_value not in {
            b"true",
            b"yes",
            b"on",
            b"1",
        }:
            raise RuntimeError("source checkout Git config disables core.fileMode")
        if lower_key == b"core.fsmonitor" and lower_value not in {
            b"false",
            b"no",
            b"off",
            b"0",
        }:
            raise RuntimeError("source checkout Git config enables core.fsmonitor")
        filter_key = lower_key.startswith(b"filter.") and lower_key.rsplit(b".", 1)[
            -1
        ] in {b"clean", b"process", b"smudge"}
        diff_key = lower_key == b"diff.external" or (
            lower_key.startswith(b"diff.")
            and lower_key.rsplit(b".", 1)[-1] in {b"command", b"textconv"}
        )
        if (filter_key or diff_key) and lower_value:
            raise RuntimeError(
                "source checkout Git config contains an executable filter or diff"
            )


def _validate_source_index_flags(
    repo_root: pathlib.Path,
    source_relative_path: str,
) -> None:
    payload = _source_git_output(
        repo_root,
        "ls-files",
        "--cached",
        "--full-name",
        "-v",
        "-z",
        "--",
        source_relative_path,
    )
    if payload and not payload.endswith(b"\0"):
        raise RuntimeError("source checkout index flag output is malformed")
    valid_tags = frozenset(b"HSMRCK?hsmrck")
    for record in payload[:-1].split(b"\0") if payload else ():
        if len(record) < 3 or record[1:2] != b" " or record[0] not in valid_tags:
            raise RuntimeError("source checkout index flag output is malformed")
        tag = record[0:1]
        if tag == b"S" or tag.islower():
            raise RuntimeError(
                "source checkout contains assume-unchanged or skip-worktree flags"
            )


def _source_head_subtree(
    *,
    repo_root: pathlib.Path,
    source_relative_path: str,
    head_sha: str,
    budget: TreeSnapshotBudget,
) -> tuple[Any, tuple[tuple[bytes, Any], ...], dict[bytes, str]]:
    repository = inspect_repository(
        repo=repo_root,
        base_sha=head_sha,
        head_sha=head_sha,
        git_executable=selected_git_executable(),
    )
    tree = enumerate_tree(repository, head_sha)
    prefix = os.fsencode(source_relative_path)
    prefix_with_separator = b"" if prefix == b"." else prefix + b"/"
    selected = []
    expansion_scan = budget.start_scan()
    for entry in tree.entries:
        expansion_scan.checkpoint()
        if prefix_with_separator:
            if not entry.path.startswith(prefix_with_separator):
                continue
            relative_path = entry.path[len(prefix_with_separator) :]
        else:
            relative_path = entry.path
        if not relative_path or not entry.is_regular:
            raise RuntimeError(
                "source checkout exact-head subtree contains an unsupported entry"
            )
        selected.append((relative_path, entry))
    if not selected:
        raise RuntimeError("source checkout exact-head subtree is empty")
    expected_kinds = {b".": "directory"}
    expansion_scan.observe_entry(depth=0, path_bytes=1)
    for relative_path, _entry in selected:
        components = relative_path.split(b"/")
        if any(not component or component in {b".", b".."} for component in components):
            raise RuntimeError("source checkout exact-head path is malformed")
        for index in range(1, len(components)):
            directory = b"/".join(components[:index])
            if directory not in expected_kinds:
                expansion_scan.observe_entry(
                    depth=index,
                    path_bytes=len(directory),
                )
                expected_kinds[directory] = "directory"
        expansion_scan.observe_entry(
            depth=len(components),
            path_bytes=len(relative_path),
        )
        expected_kinds[relative_path] = "file"
    return repository, tuple(selected), expected_kinds


def _bind_source_tree(
    source_root: pathlib.Path,
    *,
    budget: TreeSnapshotBudget,
) -> SourceTreeBinding:
    source_snapshot = _tree_snapshot(source_root, budget=budget)
    return SourceTreeBinding(
        source_manifest_sha256=_source_snapshot_manifest_sha256(source_snapshot),
        source_root_gid=source_snapshot["."].gid,
        source_entries=tuple(sorted(source_snapshot.items())),
    )


def _verify_source_snapshot_matches_head(
    *,
    source_snapshot: dict[str, TreeEntrySnapshot],
    repository: Any,
    selected: tuple[tuple[bytes, Any], ...],
) -> str:
    actual_files = {
        os.fsencode(path): entry
        for path, entry in source_snapshot.items()
        if entry.kind == "file"
    }
    actual_directories = {
        os.fsencode(path)
        for path, entry in source_snapshot.items()
        if entry.kind == "directory"
    }
    expected_directories = {b"."}
    for relative_path, _entry in selected:
        components = relative_path.split(b"/")
        expected_directories.update(
            b"/".join(components[:index]) for index in range(1, len(components))
        )
    expected_paths = {relative_path for relative_path, _entry in selected}
    if (
        actual_files.keys() != expected_paths
        or actual_directories != expected_directories
    ):
        raise RuntimeError("source checkout subtree does not match the exact HEAD tree")

    manifest_digest = hashlib.sha256()
    with CatFileBatch(repository) as batch:
        for relative_path, entry in selected:
            local_entry = actual_files[relative_path]
            if entry.mode != (stat.S_IFREG | local_entry.mode):
                raise RuntimeError(
                    "source checkout file mode does not match the exact HEAD tree"
                )
            blob_digest = hashlib.sha256()
            batch.read_blob(entry, consumer=blob_digest.update)
            observed_digest = blob_digest.hexdigest()
            if local_entry.digest != observed_digest:
                raise RuntimeError(
                    "source checkout file content does not match the exact HEAD blob"
                )
            manifest_digest.update(f"{entry.mode:06o} ".encode("ascii"))
            manifest_digest.update(observed_digest.encode("ascii"))
            manifest_digest.update(b"\t")
            manifest_digest.update(relative_path)
            manifest_digest.update(b"\0")
    return manifest_digest.hexdigest()


def _bind_source_checkout(
    source_root: pathlib.Path,
    *,
    budget: TreeSnapshotBudget | None = None,
) -> SourceCheckoutBinding:
    active_budget = budget or TreeSnapshotBudget.create()
    expected_head = os.environ.get(EXPECTED_HEAD_ENV, "")
    if len(expected_head) != 40 or any(
        character not in "0123456789abcdef" for character in expected_head
    ):
        raise RuntimeError(f"{EXPECTED_HEAD_ENV} must be one full lowercase SHA-1")
    _validate_source_git_configuration(source_root)
    repo_root = pathlib.Path(
        os.fsdecode(
            _source_git_output(source_root, "rev-parse", "--show-toplevel").strip()
        )
    ).resolve(strict=True)
    resolved_source = source_root.resolve(strict=True)
    try:
        relative = resolved_source.relative_to(repo_root)
    except ValueError as error:
        raise RuntimeError(
            "runner source is outside its reported Git worktree"
        ) from error
    observed_head = os.fsdecode(
        _source_git_output(source_root, "rev-parse", "HEAD").strip()
    )
    if observed_head != expected_head:
        raise RuntimeError(
            "source checkout HEAD does not match the expected exact head"
        )
    relative_path = relative.as_posix()
    _validate_source_index_flags(repo_root, relative_path)
    repository, selected, expected_kinds = _source_head_subtree(
        repo_root=repo_root,
        source_relative_path=relative_path,
        head_sha=expected_head,
        budget=active_budget,
    )
    source_snapshot = _tree_snapshot(
        source_root,
        budget=active_budget,
        expected_kinds=expected_kinds,
    )
    head_subtree_manifest_sha256 = _verify_source_snapshot_matches_head(
        source_snapshot=source_snapshot,
        repository=repository,
        selected=selected,
    )
    _validate_source_git_configuration(source_root)
    _validate_source_index_flags(repo_root, relative_path)
    return SourceCheckoutBinding(
        repo_root=repo_root,
        head_sha=observed_head,
        source_relative_path=relative_path,
        source_manifest_sha256=_source_snapshot_manifest_sha256(source_snapshot),
        head_subtree_manifest_sha256=head_subtree_manifest_sha256,
        source_root_gid=source_snapshot["."].gid,
        source_entries=tuple(sorted(source_snapshot.items())),
    )


def _snapshot_entry_matches_metadata(
    entry: TreeEntrySnapshot,
    metadata: os.stat_result,
) -> bool:
    return (
        entry.device == metadata.st_dev
        and entry.inode == metadata.st_ino
        and entry.generation == getattr(metadata, "st_gen", 0)
        and entry.uid == metadata.st_uid
        and entry.gid == metadata.st_gid
        and entry.mode == stat.S_IMODE(metadata.st_mode)
        and entry.flags == getattr(metadata, "st_flags", 0)
        and entry.link_count
        == (metadata.st_nlink if stat.S_ISREG(metadata.st_mode) else None)
        and entry.size == (metadata.st_size if stat.S_ISREG(metadata.st_mode) else None)
    )


@contextmanager
def _open_relative_source_entry(
    root_descriptor: int,
    relative: str,
) -> Iterator[tuple[int, os.stat_result]]:
    if relative == ".":
        descriptor = os.dup(root_descriptor)
        try:
            yield descriptor, os.fstat(descriptor)
        finally:
            os.close(descriptor)
        return
    components = pathlib.PurePosixPath(relative).parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise RuntimeError("bound source path is malformed")
    parent_descriptor = os.dup(root_descriptor)
    try:
        metadata: os.stat_result | None = None
        for component in components:
            child_descriptor, metadata = _open_snapshot_entry(
                parent_descriptor,
                component,
            )
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        assert metadata is not None
        yield parent_descriptor, metadata
    finally:
        os.close(parent_descriptor)


def _copy_bound_xattrs(
    source_descriptor: int,
    destination_descriptor: int,
    expected: TreeEntrySnapshot,
    *,
    scan: TreeSnapshotScan,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    listxattr = libc.flistxattr
    listxattr.argtypes = (
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    )
    listxattr.restype = ctypes.c_ssize_t
    getxattr = libc.fgetxattr
    getxattr.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    getxattr.restype = ctypes.c_ssize_t
    setxattr = libc.fsetxattr
    setxattr.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    setxattr.restype = ctypes.c_int

    ctypes.set_errno(0)
    names_size = listxattr(source_descriptor, None, 0, 0)
    if names_size < 0:
        raise OSError(
            ctypes.get_errno() or errno.EIO,
            "cannot size source extended attribute names during bounded copy",
        )
    if names_size > XATTR_NAMES_LIMIT_BYTES:
        raise ValueError("source extended attribute names exceed their byte bound")
    scan.consume_access_policy_read(names_size)
    if names_size:
        names_buffer = ctypes.create_string_buffer(names_size)
        ctypes.set_errno(0)
        actual_names_size = listxattr(
            source_descriptor,
            names_buffer,
            names_size,
            0,
        )
        if actual_names_size < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot read source extended attribute names during bounded copy",
            )
        if actual_names_size != names_size:
            raise OSError(
                errno.ESTALE,
                "source extended attributes changed during bounded copy",
            )
        raw_names = bytes(names_buffer.raw[:names_size])
        if not raw_names.endswith(b"\0"):
            raise ValueError("source extended attribute name list is malformed")
        observed_names = tuple(sorted(raw_names[:-1].split(b"\0")))
    else:
        observed_names = ()
    if (
        any(not name for name in observed_names)
        or len(observed_names) > 128
        or len(set(observed_names)) != len(observed_names)
    ):
        raise ValueError("source extended attribute name list is malformed")
    expected_names = tuple(name for name, _digest in expected.xattrs)
    if observed_names != expected_names:
        raise OSError(errno.ESTALE, "source xattrs changed during bounded copy")
    for name, expected_digest in expected.xattrs:
        ctypes.set_errno(0)
        value_size = getxattr(source_descriptor, name, None, 0, 0, 0)
        if value_size < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot size source extended attribute during bounded copy",
            )
        if value_size > XATTR_VALUE_LIMIT_BYTES:
            raise ValueError("source extended attribute exceeds its byte bound")
        scan.consume_access_policy_read(value_size)
        value_buffer = ctypes.create_string_buffer(max(1, value_size))
        ctypes.set_errno(0)
        actual_value_size = getxattr(
            source_descriptor,
            name,
            value_buffer,
            value_size,
            0,
            0,
        )
        if actual_value_size < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot read source extended attribute during bounded copy",
            )
        if actual_value_size != value_size:
            raise OSError(
                errno.ESTALE,
                "source extended attribute changed during bounded copy",
            )
        value = bytes(value_buffer.raw[:value_size])
        if hashlib.sha256(value).hexdigest() != expected_digest:
            raise OSError(errno.ESTALE, "source xattr changed during bounded copy")
        ctypes.set_errno(0)
        if (
            setxattr(
                destination_descriptor,
                name,
                value_buffer,
                value_size,
                0,
                0,
            )
            != 0
        ):
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot copy source extended attribute to installed tree",
            )


def _require_copied_destination_owner(
    destination_descriptor: int,
    *,
    destination_owner_uid: int,
) -> os.stat_result:
    destination_metadata = os.fstat(destination_descriptor)
    if destination_metadata.st_uid != destination_owner_uid:
        raise RuntimeError("bounded source copy changed the expected destination owner")
    return destination_metadata


def _require_copied_destination_identity(
    destination_descriptor: int,
    *,
    destination_owner_uid: int,
    destination_group_gid: int,
) -> os.stat_result:
    destination_metadata = _require_copied_destination_owner(
        destination_descriptor,
        destination_owner_uid=destination_owner_uid,
    )
    if destination_metadata.st_gid != destination_group_gid:
        raise RuntimeError("bounded source copy changed the expected destination group")
    return destination_metadata


def _apply_copied_entry_policy(
    source_descriptor: int,
    destination_descriptor: int,
    expected: TreeEntrySnapshot,
    *,
    scan: TreeSnapshotScan,
    destination_owner_uid: int,
    destination_group_gid: int,
) -> None:
    source_policy = _stable_access_policy_snapshot(
        source_descriptor,
        budget=scan,
    )
    if source_policy != (expected.xattrs, expected.acl_entries):
        raise OSError(errno.ESTALE, "source access policy changed during bounded copy")
    if expected.acl_entries:
        raise RuntimeError("bounded source copy does not admit extended ACLs")
    destination_metadata = _require_copied_destination_owner(
        destination_descriptor,
        destination_owner_uid=destination_owner_uid,
    )
    _copy_bound_xattrs(
        source_descriptor,
        destination_descriptor,
        expected,
        scan=scan,
    )
    destination_metadata = _require_copied_destination_owner(
        destination_descriptor,
        destination_owner_uid=destination_owner_uid,
    )
    if destination_metadata.st_gid != destination_group_gid:
        os.fchown(destination_descriptor, -1, destination_group_gid)
    os.fchmod(destination_descriptor, expected.mode)
    if expected.flags:
        if not hasattr(os, "fchflags"):
            raise RuntimeError("bounded source copy cannot apply file flags")
        os.fchflags(destination_descriptor, expected.flags)
    _require_copied_destination_identity(
        destination_descriptor,
        destination_owner_uid=destination_owner_uid,
        destination_group_gid=destination_group_gid,
    )


def _copy_bound_regular_file(
    source_descriptor: int,
    destination: pathlib.Path,
    expected: TreeEntrySnapshot,
    *,
    scan: TreeSnapshotScan,
    destination_owner_uid: int,
    destination_group_gid: int,
) -> None:
    if expected.kind != "file" or expected.size is None or expected.digest is None:
        raise RuntimeError("bounded source file receipt is malformed")
    initial = os.fstat(source_descriptor)
    if not _snapshot_entry_matches_metadata(expected, initial):
        raise OSError(errno.ESTALE, "bound source file identity changed before copy")
    scan.consume_file_read(expected.size + 1)
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        digest = hashlib.sha256()
        offset = 0
        while offset < expected.size:
            chunk = os.pread(
                source_descriptor,
                min(1024 * 1024, expected.size - offset),
                offset,
            )
            if not chunk:
                break
            digest.update(chunk)
            written = 0
            while written < len(chunk):
                count = os.write(destination_descriptor, chunk[written:])
                if count <= 0:
                    raise OSError(errno.EIO, "bounded source copy made no progress")
                written += count
            offset += len(chunk)
            scan.checkpoint()
        extra = os.pread(source_descriptor, 1, offset)
        final = os.fstat(source_descriptor)
        if (
            offset != expected.size
            or extra
            or not _snapshot_entry_matches_metadata(expected, final)
            or digest.hexdigest() != expected.digest
        ):
            raise OSError(errno.ESTALE, "bound source file changed during copy")
        _apply_copied_entry_policy(
            source_descriptor,
            destination_descriptor,
            expected,
            scan=scan,
            destination_owner_uid=destination_owner_uid,
            destination_group_gid=destination_group_gid,
        )
    finally:
        os.close(destination_descriptor)


def _copy_bound_source_tree(
    source_root: pathlib.Path,
    installed_root: pathlib.Path,
    source_binding: SourceCheckoutBinding | SourceTreeBinding,
    *,
    budget: TreeSnapshotBudget,
    destination_owner_uid: int,
    destination_group_gid: int,
) -> None:
    entries = dict(source_binding.source_entries)
    root_entry = entries.get(".")
    if root_entry is None or root_entry.kind != "directory":
        raise RuntimeError("bound source root receipt is malformed")
    scan = budget.start_scan()
    source_descriptor, source_metadata = _open_snapshot_root(source_root)
    try:
        scan.observe_entry(depth=0, path_bytes=1)
        if not _snapshot_entry_matches_metadata(root_entry, source_metadata):
            raise OSError(
                errno.ESTALE, "bound source root identity changed before copy"
            )
        installed_root.mkdir(mode=0o700)
        installed_root_descriptor = os.open(
            installed_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            _require_copied_destination_owner(
                installed_root_descriptor,
                destination_owner_uid=destination_owner_uid,
            )
        finally:
            os.close(installed_root_descriptor)
        directories = sorted(
            (
                (path, entry)
                for path, entry in entries.items()
                if path != "." and entry.kind == "directory"
            ),
            key=lambda item: (len(pathlib.PurePosixPath(item[0]).parts), item[0]),
        )
        files = sorted(
            (item for item in entries.items() if item[1].kind == "file"),
            key=lambda item: item[0],
        )
        if len(directories) + len(files) + 1 != len(entries):
            raise RuntimeError("bound source receipt contains an unsupported entry")
        for relative, _entry in directories:
            scan.observe_entry(
                depth=len(pathlib.PurePosixPath(relative).parts),
                path_bytes=len(os.fsencode(relative)),
            )
            (installed_root / relative).mkdir(mode=0o700)
        for relative, entry in files:
            scan.observe_entry(
                depth=len(pathlib.PurePosixPath(relative).parts),
                path_bytes=len(os.fsencode(relative)),
            )
            with _open_relative_source_entry(
                source_descriptor,
                relative,
            ) as (entry_descriptor, metadata):
                if not _snapshot_entry_matches_metadata(entry, metadata):
                    raise OSError(
                        errno.ESTALE,
                        "bound source file identity changed before copy",
                    )
                _copy_bound_regular_file(
                    entry_descriptor,
                    installed_root / relative,
                    entry,
                    scan=scan,
                    destination_owner_uid=destination_owner_uid,
                    destination_group_gid=destination_group_gid,
                )
        for relative, entry in sorted(
            ((".", root_entry), *directories),
            key=lambda item: (len(pathlib.PurePosixPath(item[0]).parts), item[0]),
            reverse=True,
        ):
            scan.observe_entry(
                depth=(
                    0 if relative == "." else len(pathlib.PurePosixPath(relative).parts)
                ),
                path_bytes=len(os.fsencode(relative)),
            )
            with _open_relative_source_entry(
                source_descriptor,
                relative,
            ) as (entry_descriptor, metadata):
                if not _snapshot_entry_matches_metadata(entry, metadata):
                    raise OSError(
                        errno.ESTALE,
                        "bound source directory identity changed during copy",
                    )
                destination_descriptor = os.open(
                    installed_root if relative == "." else installed_root / relative,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_NONBLOCK
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW,
                )
                try:
                    _apply_copied_entry_policy(
                        entry_descriptor,
                        destination_descriptor,
                        entry,
                        scan=scan,
                        destination_owner_uid=destination_owner_uid,
                        destination_group_gid=destination_group_gid,
                    )
                finally:
                    os.close(destination_descriptor)
    finally:
        os.close(source_descriptor)


def _copy_bound_tree(
    source_root: pathlib.Path,
    installed_root: pathlib.Path,
    source_binding: SourceTreeBinding,
    *,
    budget: TreeSnapshotBudget,
    destination_owner_uid: int | None = None,
    destination_group_gid: int | None = None,
) -> str:
    destination_owner_uid = (
        os.geteuid() if destination_owner_uid is None else destination_owner_uid
    )
    destination_group_gid = (
        os.getegid() if destination_group_gid is None else destination_group_gid
    )
    _copy_bound_source_tree(
        source_root,
        installed_root,
        source_binding,
        budget=budget,
        destination_owner_uid=destination_owner_uid,
        destination_group_gid=destination_group_gid,
    )
    installed_manifest = _source_manifest_sha256(
        installed_root,
        budget=budget,
    )
    source_binding_after = _bind_source_tree(
        source_root,
        budget=budget,
    )
    if (
        source_binding_after != source_binding
        or installed_manifest
        != _destination_snapshot_manifest_sha256(
            source_binding.source_entries,
            destination_owner_uid=destination_owner_uid,
            destination_group_gid=destination_group_gid,
        )
    ):
        raise RuntimeError(
            "installed test input does not match the stable bounded source"
        )
    return source_binding.source_manifest_sha256


def _copy_bound_source(
    source_root: pathlib.Path,
    installed_root: pathlib.Path,
    source_binding: SourceCheckoutBinding,
    source_manifest_before: str,
    *,
    budget: TreeSnapshotBudget | None = None,
    destination_owner_uid: int | None = None,
    destination_group_gid: int | None = None,
) -> str:
    active_budget = budget or TreeSnapshotBudget.create()
    destination_owner_uid = (
        os.geteuid() if destination_owner_uid is None else destination_owner_uid
    )
    destination_group_gid = (
        os.getegid() if destination_group_gid is None else destination_group_gid
    )
    _copy_bound_source_tree(
        source_root,
        installed_root,
        source_binding,
        budget=active_budget,
        destination_owner_uid=destination_owner_uid,
        destination_group_gid=destination_group_gid,
    )
    installed_manifest = _source_manifest_sha256(
        installed_root,
        budget=active_budget,
    )
    source_binding_after = _bind_source_checkout(
        source_root,
        budget=active_budget,
    )
    source_manifest_after = source_binding_after.source_manifest_sha256
    if (
        source_binding_after != source_binding
        or source_manifest_after != source_manifest_before
        or installed_manifest
        != _destination_snapshot_manifest_sha256(
            source_binding.source_entries,
            destination_owner_uid=destination_owner_uid,
            destination_group_gid=destination_group_gid,
        )
    ):
        raise RuntimeError(
            "installed test input does not match the stable exact-head source"
        )
    return source_manifest_before


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


def _serialize_terminal_json(value: object, *, operation: str) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except BaseException as error:
        raise TerminalPublicationError(operation, error) from error


def _write_terminal_stdout(payload: bytes) -> None:
    try:
        descriptor = sys.stdout.fileno()
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "terminal stdout write made no progress")
            remaining = remaining[written:]
    except BaseException as error:
        raise TerminalPublicationError("stdout-write", error) from error
    try:
        written = os.write(descriptor, b"\n")
        if written != 1:
            raise OSError(
                errno.EIO,
                "terminal stdout newline write made no progress",
            )
    except BaseException as error:
        _report_terminal_publication_failure(
            TerminalPublicationError("stdout-newline", error)
        )


def _publish_terminal_output(
    summary: dict[str, object],
    diagnostics: str,
    *,
    terminal_process: bool,
) -> None:
    summary_text = _serialize_terminal_json(
        summary,
        operation="summary-serialization",
    )
    try:
        sys.stdout.flush()
    except BaseException as error:
        raise TerminalPublicationError("stdout-flush", error) from error
    try:
        if diagnostics:
            sys.stderr.write(diagnostics)
    except BaseException as error:
        raise TerminalPublicationError("stderr-write", error) from error
    try:
        sys.stderr.flush()
    except BaseException as error:
        raise TerminalPublicationError("stderr-flush", error) from error

    payload = summary_text.encode("utf-8")
    if terminal_process:
        _write_terminal_stdout(payload)
        return
    try:
        sys.stdout.write(payload.decode("utf-8") + "\n")
        sys.stdout.flush()
    except BaseException as error:
        raise TerminalPublicationError("stdout-write", error) from error


def _report_terminal_publication_failure(error: TerminalPublicationError) -> None:
    message = (
        "read-only installed supervisor terminal publication failed: "
        f"operation={error.operation}; "
        f"error={type(error.error).__name__}: "
        f"{_bounded_failure_text(str(error.error), limit=1_024)}\n"
    )
    try:
        os.write(2, message.encode("utf-8", errors="backslashreplace"))
    except BaseException:
        pass


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
    path: pathlib.Path | str,
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


def _bound_close_failure(
    binding: _DirectoryParentBinding,
    error: BaseException,
    *,
    evidence: BoundPathEvidence | None,
    evidence_error: BaseException | None,
) -> CleanupFailure:
    """Report the held object, never a replacement at its lexical path."""

    held_identity = binding.object_locator()
    if evidence_error is not None:
        try:
            error.add_note(
                "pre-close retention evidence failed: "
                f"{type(evidence_error).__name__}: {evidence_error}"
            )
        except BaseException:
            pass
    if evidence is None or evidence.path_status == "bound-unresolved":
        path: pathlib.Path | str = (
            f"descriptor-object://{held_identity['device']}/{held_identity['inode']}"
        )
        retained = evidence.retained if evidence is not None else None
        replacement_path = evidence.replacement_path if evidence is not None else None
        original_path_status = (
            evidence.original_path_status if evidence is not None else "unreadable"
        )
        access_policy_status = (
            evidence.access_policy_status if evidence is not None else "unreadable"
        )
        path_status = "descriptor-object"
    else:
        path = evidence.path
        retained = evidence.retained
        replacement_path = evidence.replacement_path
        original_path_status = evidence.original_path_status
        access_policy_status = evidence.access_policy_status
        path_status = evidence.path_status
    return _cleanup_failure_from_error(
        path,
        error,
        retained=retained,
        original_path=binding.path,
        path_status=path_status,
        replacement_path=replacement_path,
        held_identity=held_identity,
        original_path_status=original_path_status,
        access_policy_status=access_policy_status,
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


def _run_main(
    lifecycle_fence: LifecycleSignalFence,
    *,
    terminal_process: bool,
) -> int:
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
    signal_is_primary = False
    closure_error: GitProcessClosureUnproven | None = None
    child_process_closure = "not-started"
    primary_failure: PrimaryFailure | None = None
    secondary_failures: list[SecondaryFailure] = []
    closure_proof = ChildProcessClosureProof()
    cleanup_failures: tuple[CleanupFailure, ...] = ()
    creation_cleanup_failures: list[CleanupFailure] = []
    deferred_control_flow_error: BaseException | None = None
    source_binding: SourceCheckoutBinding | None = None
    source_tree_binding: SourceTreeBinding | SourceCheckoutBinding | None = None
    source_head_bound = False
    source_manifest_sha256: str | None = None
    trusted_source_requested = bool(os.environ.get(EXPECTED_HEAD_ENV))
    source_manifest_before: str | None = None
    snapshot_budget = TreeSnapshotBudget.create()
    stage = "source-head-binding" if trusted_source_requested else "install-container"
    try:
        if trusted_source_requested:
            source_binding = _bind_source_checkout(
                source_root,
                budget=snapshot_budget,
            )
            source_tree_binding = source_binding
        else:
            source_tree_binding = _bind_source_tree(
                source_root,
                budget=snapshot_budget,
            )
        source_manifest_before = source_tree_binding.source_manifest_sha256
        stage = "install-container"
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
        destination_owner_uid = install_container_binding.policy.uid
        destination_group_gid = install_container_binding.policy.gid
        stage = "runtime-parent"
        runtime_parent_binding = _create_bound_owned_private_runtime_directory(
            ".codex-review-readonly-runtime-",
            result_owner=runtime_parent_owner,
        )
        runtime_parent_binding = runtime_parent_owner.transfer(runtime_parent_binding)
        runtime_parent = runtime_parent_binding.path
        stage = "permissions"
        installed_root = install_container / "independent_codex_pr_review"
        stage = "install-copy"
        install_container_binding.revalidate()
        if source_binding is not None:
            source_manifest_sha256 = _copy_bound_source(
                source_root,
                installed_root,
                source_binding,
                source_manifest_before,
                budget=snapshot_budget,
                destination_owner_uid=destination_owner_uid,
                destination_group_gid=destination_group_gid,
            )
        else:
            assert isinstance(source_tree_binding, SourceTreeBinding)
            source_manifest_sha256 = _copy_bound_tree(
                source_root,
                installed_root,
                source_tree_binding,
                budget=snapshot_budget,
                destination_owner_uid=destination_owner_uid,
                destination_group_gid=destination_group_gid,
            )
        install_container_binding.revalidate()
        source_head_bound = source_binding is not None
        stage = "install-read-only"
        _set_tree_read_only(installed_root)
        stage = "snapshot-before"
        install_container_binding.revalidate()
        before = _tree_snapshot(installed_root, budget=snapshot_budget)
        stage = "access-policy"
        if any(entry.acl_entries for entry in before.values()):
            raise RuntimeError("read-only installed tree has an extended ACL")
        if lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        stage = "child-run"
        if trusted_source_requested:
            child_process_closure = "pending"
            completed = _run_no_child_test_suite(
                installed_root=installed_root,
                install_container_binding=install_container_binding,
                runtime_parent_binding=runtime_parent_binding,
                secondary_failures=secondary_failures,
                closure_proof=closure_proof,
                lifecycle_fence=lifecycle_fence,
            )
        else:
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
        if lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        stage = "install-container-revalidation"
        install_container_binding.revalidate()
        stage = "snapshot-after"
        after = _tree_snapshot(installed_root, budget=snapshot_budget)
        install_container_binding.revalidate()
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
        signal_is_primary = True
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
                    cleanup_control_binding = (
                        _create_bound_owned_private_runtime_directory(
                            ".codex-review-readonly-cleanup-",
                            result_owner=cleanup_control_owner,
                        )
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
            for binding_role, binding in (
                ("install-container", install_container_binding),
                ("runtime-parent", runtime_parent_binding),
                ("cleanup-control", cleanup_control_binding),
            ):
                if binding is None:
                    continue
                close_evidence: BoundPathEvidence | None = None
                close_evidence_error: BaseException | None = None
                try:
                    close_evidence = _bound_path_evidence(binding)
                except BaseException as evidence_error:
                    close_evidence_error = evidence_error
                    if deferred_control_flow_error is None and not isinstance(
                        evidence_error, Exception
                    ):
                        deferred_control_flow_error = evidence_error
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
                            _bound_close_failure(
                                binding,
                                close_error,
                                evidence=close_evidence,
                                evidence_error=close_evidence_error,
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

    terminal_signal = _freeze_lifecycle_terminal_signal(lifecycle_fence)
    if terminal_signal is not None and signal_error is None:
        signal_error = ChildRunInterrupted(terminal_signal)
        if primary_failure is None:
            signal_is_primary = True
            primary_failure = _primary_failure(stage, signal_error)
    lifecycle_fence.terminal_selected_signal = (
        signal_error.signal_number if signal_error is not None else terminal_signal
    )
    try:
        release_tree_immutable = (
            before is not None
            and after is not None
            and _tree_property_unchanged(before, after)
        )
        retained_paths = list(
            dict.fromkeys(
                failure.path
                for failure in cleanup_failures
                if failure.retained is not False
            )
        )
        if primary_failure is not None:
            if timeout_error is not None:
                primary_status = "timed-out"
            elif output_limit_error is not None:
                primary_status = "output-limit"
            elif signal_is_primary:
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
        summary: dict[str, object] = {
            "child_process_closure": child_process_closure,
            "cleanup_failures": [asdict(failure) for failure in cleanup_failures],
            "cleanup_guarantee": CLEANUP_GUARANTEE,
            "cleanup_status": "incomplete" if cleanup_failures else "complete",
            "creation_origin_guarantee": CREATION_ORIGIN_GUARANTEE,
            "creation_origin_proven": False,
            "install_parent_is_sticky_world_writable": True,
            "no_child_runtime_profile": closure_proof.runtime_profile,
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
            "signal_number": lifecycle_fence.terminal_selected_signal,
            "source_head_bound": source_head_bound,
            "source_head_sha": (
                source_binding.head_sha if source_binding is not None else None
            ),
            "source_head_subtree_manifest_sha256": (
                source_binding.head_subtree_manifest_sha256
                if source_binding is not None
                else None
            ),
            "source_manifest_sha256": source_manifest_sha256,
            "timed_out": timeout_error is not None,
        }

        primary_failed = primary_status != "complete"
        diagnostic_lines: list[str] = []
        if primary_failure is not None:
            diagnostic_lines.append(
                "read-only installed supervisor primary failure: "
                + _serialize_terminal_json(
                    asdict(primary_failure),
                    operation="primary-diagnostic-serialization",
                )
            )
        if secondary_failures:
            diagnostic_lines.append(
                "read-only installed supervisor secondary failures: "
                + _serialize_terminal_json(
                    [asdict(failure) for failure in secondary_failures],
                    operation="secondary-diagnostic-serialization",
                )
            )
        if completed is not None and primary_failed:
            if completed.stdout:
                diagnostic_lines.append(_bounded_failure_text(completed.stdout))
            if completed.stderr:
                diagnostic_lines.append(_bounded_failure_text(completed.stderr))
        if timeout_error is not None:
            diagnostic_lines.append(
                "read-only installed supervisor regression timed out"
            )
        if cleanup_failures:
            diagnostic_lines.append(
                "read-only installed supervisor cleanup incomplete: "
                + _serialize_terminal_json(
                    [asdict(failure) for failure in cleanup_failures],
                    operation="cleanup-diagnostic-serialization",
                )
            )
        diagnostics = "".join(line + "\n" for line in diagnostic_lines)
    except TerminalPublicationError:
        raise
    except BaseException as error:
        raise TerminalPublicationError("summary-construction", error) from error

    if lifecycle_fence.terminal_selected_signal is not None:
        returncode = 128 + lifecycle_fence.terminal_selected_signal
    else:
        returncode = 1 if primary_failed or cleanup_failures else 0
    lifecycle_fence.terminal_exit_code = returncode
    _publish_terminal_output(
        summary,
        diagnostics,
        terminal_process=terminal_process,
    )
    lifecycle_fence.terminal_output_committed = True
    return returncode


def main(*, _terminal_process: bool = False) -> int:
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
    lifecycle_fence = _install_lifecycle_signal_fence()
    try:
        returncode = _run_main(
            lifecycle_fence,
            terminal_process=_terminal_process,
        )
    except TerminalPublicationError as publication_error:
        _report_terminal_publication_failure(publication_error)
        try:
            _restore_lifecycle_signal_fence(lifecycle_fence)
        except BaseException as restore_error:
            publication_error.add_note(
                "lifecycle signal restoration failed after publication error: "
                f"{type(restore_error).__name__}: {restore_error}"
            )
            _report_terminal_publication_failure(
                TerminalPublicationError(
                    "signal-fence-restoration",
                    restore_error,
                )
            )
            if lifecycle_fence.terminal_selected_signal is not None:
                if lifecycle_fence.terminal_exit_code is not None:
                    return lifecycle_fence.terminal_exit_code
                return 128 + lifecycle_fence.terminal_selected_signal
            return 1
        if lifecycle_fence.terminal_selected_signal is not None:
            if lifecycle_fence.terminal_exit_code is None:
                return 128 + lifecycle_fence.terminal_selected_signal
            return lifecycle_fence.terminal_exit_code
        return 1
    except BaseException as primary_error:
        try:
            _restore_lifecycle_signal_fence(lifecycle_fence)
        except BaseException as restore_error:
            primary_error.add_note(
                "lifecycle signal restoration failed: "
                f"{type(restore_error).__name__}: {restore_error}"
            )
        raise
    # The CLI exits with the sealed decision while lifecycle signals stay blocked.
    if _terminal_process and lifecycle_fence.terminal_output_committed:
        return returncode
    received_signal = _restore_lifecycle_signal_fence(lifecycle_fence)
    if not lifecycle_fence.terminal_output_committed and received_signal is not None:
        return 128 + received_signal
    return returncode


if __name__ == "__main__":
    raise SystemExit(main(_terminal_process=True))
