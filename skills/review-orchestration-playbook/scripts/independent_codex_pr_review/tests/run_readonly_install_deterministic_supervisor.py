from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import signal
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from types import FrameType
from typing import Any, Iterator

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
from review_supervisor.secureio import open_absolute_directory_chain
from review_supervisor.signal_relay import (
    DeferredSignalInterrupt,
    activate_deferred_signal_interrupt,
    begin_bound_signal_deferral,
    checkpoint_bound_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)
from .support import (
    CLEANUP_GUARANTEE,
    CREATION_ORIGIN_GUARANTEE,
    UnprovenCreatedDirectoryError,
    _CreatedPrivateDirectoryBinding,
    _DirectoryParentBinding,
    _cleanup_created_private_directory_binding,
    _create_owned_private_directory_binding,
    _private_runtime_parent,
)

EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
RUNNER_ENVIRONMENT_ENV = "CODEX_REVIEW_RUNNER_ENVIRONMENT"
RUNNER_ARCH_ENV = "CODEX_REVIEW_RUNNER_ARCH"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
CHILD_TIMEOUT_SECONDS = 600.0
CHILD_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
CHILD_STDERR_LIMIT_BYTES = 8 * 1024 * 1024
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
XATTR_NAMES_LIMIT_BYTES = 64 * 1024
XATTR_VALUE_LIMIT_BYTES = 16 * 1024 * 1024
XATTR_AGGREGATE_LIMIT_BYTES = 64 * 1024 * 1024
F_GETPATH = 50
DARWIN_MAXPATHLEN = 1024
_BoundDirectory = _DirectoryParentBinding | _CreatedPrivateDirectoryBinding


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
    retained: bool
    restore_error_kind: str | None
    restore_error_errno: int | None


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
    launch_attempted: bool = False
    proven: bool = False
    runtime_profile: str | None = None


class ChildOutputLimitExceeded(OverflowError):
    def __init__(self, *, scope: str, limit: int) -> None:
        self.scope = scope
        self.limit = limit
        super().__init__(
            f"bounded no-child test {scope} output exceeded its {limit}-byte cap"
        )


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


def _child_process_closure_status(proof: ChildProcessClosureProof) -> str:
    if not proof.launch_attempted:
        return "not-started"
    return "proven" if proof.proven else "unproven"


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
            handled[: len(previous_handlers)],
            previous_handlers,
            strict=True,
        ):
            signal.signal(signal_number, previous)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    return fence


def _restore_lifecycle_signal_fence(fence: LifecycleSignalFence) -> int | None:
    signal.pthread_sigmask(signal.SIG_BLOCK, fence.signals)
    if fence.terminal_decision_frozen:
        try:
            for signal_number in fence.signals:
                signal.signal(signal_number, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_SETMASK, fence.previous_mask)
            for signal_number, previous in zip(
                fence.signals,
                fence.previous_handlers,
                strict=True,
            ):
                signal.signal(signal_number, previous)
        except BaseException:
            signal.pthread_sigmask(signal.SIG_BLOCK, fence.signals)
            raise
        return fence.terminal_signal

    try:
        received_signal = fence.received_signal
        if received_signal is None:
            pending = signal.sigpending()
            received_signal = next(
                (
                    signal_number
                    for signal_number in fence.signals
                    if signal_number in pending
                ),
                None,
            )
        for signal_number, previous in zip(
            fence.signals,
            fence.previous_handlers,
            strict=True,
        ):
            signal.signal(signal_number, previous)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, fence.previous_mask)
    return received_signal


def _freeze_lifecycle_terminal_signal(
    fence: LifecycleSignalFence,
) -> int | None:
    if fence.terminal_decision_frozen:
        raise RuntimeError("lifecycle terminal decision is already frozen")
    signal.pthread_sigmask(signal.SIG_BLOCK, fence.signals)
    pending = signal.sigpending()
    terminal_signal = fence.received_signal
    if terminal_signal is None:
        terminal_signal = next(
            (
                signal_number
                for signal_number in fence.signals
                if signal_number in pending
            ),
            None,
        )
    fence.terminal_signal = terminal_signal
    fence.terminal_decision_frozen = True
    return terminal_signal


@contextmanager
def _bound_lifecycle_signals() -> Iterator[LifecycleSignalFence]:
    fence = _install_lifecycle_signal_fence()
    try:
        yield fence
    finally:
        _restore_lifecycle_signal_fence(fence)


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


def _run_no_child_test_suite(
    *,
    installed_root: pathlib.Path,
    install_container_binding: _BoundDirectory,
    runtime_parent_binding: _BoundDirectory,
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
    if _binding_node_key(install_container_binding) == _binding_node_key(
        runtime_parent_binding
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
            proof.launch_attempted = True
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
            if len(result.stdout) > stdout_limit:
                raise ChildOutputLimitExceeded(
                    scope="stdout",
                    limit=stdout_limit,
                )
            if len(result.stderr) > stderr_limit:
                raise ChildOutputLimitExceeded(
                    scope="stderr",
                    limit=stderr_limit,
                )
        finally:
            if proof_scope is not None:
                proof_scope.finish(deliver=proof.proven or not proof.launch_attempted)
    return subprocess.CompletedProcess(
        args=argv,
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", "replace"),
        stderr=result.stderr.decode("utf-8", "replace"),
    )


def _acl_entries(descriptor: int) -> tuple[bytes, ...]:
    return tuple(
        entry.encode("ascii", "strict") for entry in _macos_acl_entries(descriptor)
    )


def _xattr_snapshot(descriptor: int) -> tuple[tuple[bytes, str], ...]:
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
            if size == 0:
                return b""
            buffer = ctypes.create_string_buffer(size)
            ctypes.set_errno(0)
            actual = getxattr(
                descriptor,
                name,
                buffer,
                size,
                0,
                0,
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
    initial = os.stat(
        name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
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


def _descriptor_digest(descriptor: int) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "snapshot digest requires a regular file")
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if (
        _snapshot_binding_key(before) != _snapshot_binding_key(after)
        or before.st_size != after.st_size
        or offset != after.st_size
    ):
        raise OSError(errno.ESTALE, "regular file changed during snapshot")
    return digest.hexdigest()


def _access_policy_snapshot(
    descriptor: int,
) -> tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]]:
    return _xattr_snapshot(descriptor), _acl_entries(descriptor)


def _stable_access_policy_snapshot(
    descriptor: int,
) -> tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]]:
    first = _access_policy_snapshot(descriptor)
    second = _access_policy_snapshot(descriptor)
    if first != second:
        raise OSError(errno.ESTALE, "access policy changed during snapshot")
    return second


def _regular_entry_sample(
    descriptor: int,
) -> tuple[
    str,
    tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
]:
    digest_before = _descriptor_digest(descriptor)
    access_policy = _stable_access_policy_snapshot(descriptor)
    digest_after = _descriptor_digest(descriptor)
    if digest_before != digest_after:
        raise OSError(errno.ESTALE, "regular file changed during snapshot")
    return digest_after, access_policy


def _stable_regular_entry_sample(
    descriptor: int,
) -> tuple[
    str,
    tuple[tuple[tuple[bytes, str], ...], tuple[bytes, ...]],
]:
    first = _regular_entry_sample(descriptor)
    second = _regular_entry_sample(descriptor)
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
) -> TreeEntrySnapshot:
    if stat.S_ISREG(initial.st_mode):
        if initial.st_nlink != 1:
            raise RuntimeError(
                f"regular file has an external hardlink alias: {relative}"
            )
        digest, access_policy = _stable_regular_entry_sample(descriptor)
        kind = "file"
        link_count = initial.st_nlink
    elif stat.S_ISDIR(initial.st_mode):
        digest = None
        kind = "directory"
        link_count = None
        access_before = _stable_access_policy_snapshot(descriptor)
        names = tuple(sorted(os.listdir(descriptor)))
        for name in names:
            child_relative = name if relative == "." else f"{relative}/{name}"
            child_descriptor, child_initial = _open_snapshot_entry(descriptor, name)
            try:
                child_snapshot = _snapshot_opened_entry(
                    child_descriptor,
                    child_initial,
                    relative=child_relative,
                    snapshot=snapshot,
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
                        f"snapshot path no longer names the bound object: "
                        f"{child_relative}",
                    )
                snapshot[child_relative] = child_snapshot
            finally:
                os.close(child_descriptor)
        if names != tuple(sorted(os.listdir(descriptor))):
            raise OSError(
                errno.ESTALE, f"directory changed during snapshot: {relative}"
            )
        access_policy = _stable_access_policy_snapshot(descriptor)
        if access_before != access_policy:
            raise OSError(errno.ESTALE, "access policy changed during snapshot")
    else:
        raise OSError(errno.EPERM, "unsupported entry in read-only install tree")
    final_descriptor = os.fstat(descriptor)
    if _snapshot_binding_key(initial) != _snapshot_binding_key(final_descriptor):
        raise OSError(
            errno.ESTALE, f"snapshot object changed during capture: {relative}"
        )
    if stat.S_ISREG(initial.st_mode) and initial.st_size != final_descriptor.st_size:
        raise OSError(errno.ESTALE, f"regular file changed during snapshot: {relative}")
    xattrs, acl_entries = access_policy
    return TreeEntrySnapshot(
        kind=kind,
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


def _tree_snapshot_once(root: pathlib.Path) -> dict[str, TreeEntrySnapshot]:
    snapshot: dict[str, TreeEntrySnapshot] = {}
    descriptor, initial = _open_snapshot_root(root)
    try:
        root_snapshot = _snapshot_opened_entry(
            descriptor,
            initial,
            relative=".",
            snapshot=snapshot,
        )
        final_descriptor = os.fstat(descriptor)
        final_path = root.lstat()
        if _snapshot_binding_key(final_descriptor) != _snapshot_binding_key(final_path):
            raise OSError(
                errno.ESTALE,
                "snapshot root path no longer names the bound object",
            )
        snapshot["."] = root_snapshot
        return snapshot
    finally:
        os.close(descriptor)


def _tree_snapshot(root: pathlib.Path) -> dict[str, TreeEntrySnapshot]:
    first = _tree_snapshot_once(root)
    second = _tree_snapshot_once(root)
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
    message = str(error)
    notes = getattr(error, "__notes__", ())
    if notes:
        message += "; " + "; ".join(str(note) for note in notes)
    return PrimaryFailure(
        stage=stage,
        error_kind=type(error).__name__,
        error_errno=error_errno if isinstance(error_errno, int) else None,
        message=_bounded_failure_text(message, limit=2_048),
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
    retained: bool | None = None,
) -> CleanupFailure:
    error_errno = getattr(error, "errno", None)
    return CleanupFailure(
        path=str(path),
        error_kind=type(error).__name__,
        error_errno=error_errno if isinstance(error_errno, int) else None,
        retained=os.path.lexists(path) if retained is None else retained,
        restore_error_kind=None,
        restore_error_errno=None,
    )


def _list_bound_directory(
    binding: _BoundDirectory,
) -> tuple[str, ...]:
    binding.revalidate()
    entries = tuple(sorted(os.listdir(binding.fd)))
    binding.revalidate()
    return entries


def _node_key(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _binding_node_key(binding: _BoundDirectory) -> tuple[int, int, int, int]:
    return (
        binding.identity.device,
        binding.identity.inode,
        stat.S_IFMT(binding.identity.mode),
        binding.identity.uid,
    )


def _descriptor_path(descriptor: int) -> pathlib.Path:
    payload = fcntl.fcntl(descriptor, F_GETPATH, b"\0" * DARWIN_MAXPATHLEN)
    raw_path = payload.split(b"\0", 1)[0]
    if not raw_path or not raw_path.startswith(b"/"):
        raise OSError(errno.ESTALE, "bound directory path is unavailable")
    return pathlib.Path(os.fsdecode(raw_path))


def _descriptor_object_locator(metadata: os.stat_result) -> str:
    return f"descriptor-object://{metadata.st_dev}/{metadata.st_ino}"


def _bound_tree_retention_locator(
    binding: _BoundDirectory,
    *,
    primary_error: BaseException | None = None,
) -> tuple[str, bool]:
    fallback_locator = (
        f"descriptor-object://{binding.identity.device}/{binding.identity.inode}"
    )
    try:
        metadata = os.fstat(binding.fd)
        descriptor_locator = _descriptor_object_locator(metadata)
        if metadata.st_nlink == 0:
            return descriptor_locator, False
        candidate = _descriptor_path(binding.fd)
        candidate_fd, _candidate_identity = open_absolute_directory_chain(
            candidate,
            allow_sticky_writable_ancestors=(not binding.require_owned_private_parent),
        )
        try:
            if _node_key(os.fstat(candidate_fd)) != _node_key(metadata):
                raise OSError(
                    errno.ESTALE,
                    "descriptor path resolves to a different retained object",
                )
        except BaseException as error:
            try:
                os.close(candidate_fd)
            except BaseException as close_error:
                error.add_note(
                    "retention-locator candidate close failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            os.close(candidate_fd)
    except BaseException as locator_error:
        if primary_error is not None:
            primary_error.add_note(
                "retention locator fell back to recorded identity: "
                f"{type(locator_error).__name__}: {locator_error}"
            )
            for note in getattr(locator_error, "__notes__", ()):
                primary_error.add_note(str(note))
        return fallback_locator, True
    return str(candidate), True


def _cleanup_created_tree(
    binding: _CreatedPrivateDirectoryBinding | None,
    *,
    restore_owner_write: bool,
) -> CleanupFailure | None:
    if binding is None:
        return None
    try:
        _cleanup_created_private_directory_binding(
            binding,
            restore_owner_write=restore_owner_write,
        )
        return None
    except Exception as error:
        retained_locator, retained = _bound_tree_retention_locator(
            binding,
            primary_error=error,
        )
        return _cleanup_failure_from_error(
            retained_locator,
            error,
            retained=retained,
        )


def _close_created_directory_binding(
    binding: _CreatedPrivateDirectoryBinding,
    prior_cleanup_failure: CleanupFailure | None,
) -> CleanupFailure | None:
    if prior_cleanup_failure is not None:
        retained_locator = prior_cleanup_failure.path
        retained = prior_cleanup_failure.retained
    else:
        try:
            retained_locator, retained = _bound_tree_retention_locator(binding)
        except Exception:
            retained_locator = (
                "descriptor-object://"
                f"{binding.identity.device}/{binding.identity.inode}"
            )
            retained = True
    try:
        binding.close()
    except Exception as error:
        return _cleanup_failure_from_error(
            retained_locator,
            error,
            retained=retained,
        )
    return None


def _retained_bound_tree_for_unproven_child_closure(
    binding: _BoundDirectory | None,
) -> CleanupFailure | None:
    if binding is None:
        return None
    retained_locator, retained = _bound_tree_retention_locator(binding)
    return CleanupFailure(
        path=retained_locator,
        error_kind="ChildProcessClosureUnproven",
        error_errno=None,
        retained=retained,
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
    install_container_binding: _CreatedPrivateDirectoryBinding | None = None
    runtime_parent_binding: _CreatedPrivateDirectoryBinding | None = None
    installed_root: pathlib.Path | None = None
    completed: subprocess.CompletedProcess[str] | None = None
    before: dict[str, TreeEntrySnapshot] | None = None
    after: dict[str, TreeEntrySnapshot] | None = None
    runtime_residue: tuple[str, ...] = ()
    timeout_error: TimeoutError | None = None
    output_limit_error: OverflowError | None = None
    signal_error: ChildRunInterrupted | None = None
    signal_is_primary = False
    child_process_closure = "not-started"
    primary_failure: PrimaryFailure | None = None
    secondary_failures: list[SecondaryFailure] = []
    unproven_creation_failures: list[CleanupFailure] = []
    closure_proof = ChildProcessClosureProof()
    cleanup_failures: tuple[CleanupFailure, ...] = ()
    stage = "install-container-binding"
    try:
        install_container_binding = _create_owned_private_directory_binding(
            READONLY_INSTALL_PARENT,
            ".codex-review-readonly-install-",
            require_owned_private_parent=False,
        )
        install_container = install_container_binding.path
        stage = "runtime-parent-binding"
        runtime_parent_binding = _create_owned_private_directory_binding(
            _private_runtime_parent(),
            ".codex-review-readonly-runtime-",
        )
        stage = "permissions"
        installed_root = install_container / "independent_codex_pr_review"
        stage = "install-copy"
        install_container_binding.revalidate()
        shutil.copytree(
            source_root,
            installed_root,
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        install_container_binding.revalidate()
        stage = "install-read-only"
        _set_tree_read_only(installed_root)
        stage = "snapshot-before"
        install_container_binding.revalidate()
        before = _tree_snapshot(installed_root)
        stage = "access-policy"
        if any(entry.acl_entries for entry in before.values()):
            raise RuntimeError("read-only installed tree has an extended ACL")
        if lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        stage = "child-run"
        child_process_closure = "pending"
        completed = _run_no_child_test_suite(
            installed_root=installed_root,
            install_container_binding=install_container_binding,
            runtime_parent_binding=runtime_parent_binding,
            secondary_failures=secondary_failures,
            closure_proof=closure_proof,
            lifecycle_fence=lifecycle_fence,
        )
        child_process_closure = "proven"
        if lifecycle_fence.received_signal is not None:
            raise ChildRunInterrupted(lifecycle_fence.received_signal)
        stage = "snapshot-after"
        install_container_binding.revalidate()
        after = _tree_snapshot(installed_root)
        install_container_binding.revalidate()
        stage = "runtime-residue"
        runtime_residue = _list_bound_directory(runtime_parent_binding)
        stage = "complete"
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
        if child_process_closure == "pending":
            child_process_closure = _child_process_closure_status(closure_proof)
        if isinstance(error, UnprovenCreatedDirectoryError):
            unproven_creation_failures.append(
                CleanupFailure(
                    path=error.recovery_locator,
                    error_kind=type(error).__name__,
                    error_errno=error.errno,
                    retained=True,
                    restore_error_kind=None,
                    restore_error_errno=None,
                )
            )
        primary_failure = _primary_failure(stage, error)
    finally:
        if child_process_closure == "pending":
            child_process_closure = _child_process_closure_status(closure_proof)
        cleanup_results: list[CleanupFailure | None]
        if child_process_closure in {"pending", "unproven"}:
            cleanup_results = [
                _retained_bound_tree_for_unproven_child_closure(
                    install_container_binding
                ),
                _retained_bound_tree_for_unproven_child_closure(runtime_parent_binding),
            ]
        else:
            cleanup_results = [
                _cleanup_created_tree(
                    install_container_binding,
                    restore_owner_write=True,
                ),
                _cleanup_created_tree(
                    runtime_parent_binding,
                    restore_owner_write=False,
                ),
            ]
        if install_container_binding is not None:
            cleanup_results.append(
                _close_created_directory_binding(
                    install_container_binding,
                    cleanup_results[0],
                )
            )
        if runtime_parent_binding is not None:
            cleanup_results.append(
                _close_created_directory_binding(
                    runtime_parent_binding,
                    cleanup_results[1],
                )
            )
        cleanup_failures = (
            *unproven_creation_failures,
            *(failure for failure in cleanup_results if failure is not None),
        )

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
                failure.path for failure in cleanup_failures if failure.retained
            )
        )
        if primary_failure is not None:
            if timeout_error is not None:
                primary_status = "timed-out"
            elif output_limit_error is not None:
                primary_status = "output-limit"
            elif signal_is_primary:
                primary_status = "interrupted"
            elif child_process_closure == "unproven":
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
