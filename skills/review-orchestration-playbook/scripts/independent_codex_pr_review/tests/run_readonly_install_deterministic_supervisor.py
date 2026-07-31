from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import secrets
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
    _DirectoryParentBinding,
    _create_owned_private_directory,
    _open_directory_parent,
    _private_runtime_parent,
)
from .run_hosted_no_child_fail_closed import (
    RUNNER_ARCH_ENV,
    RUNNER_ENVIRONMENT_ENV,
    _select_hosted_runtime_profile,
)


EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
CHILD_TIMEOUT_SECONDS = 600.0
CHILD_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
CHILD_STDERR_LIMIT_BYTES = 8 * 1024 * 1024
NO_CHILD_SUITE_CODE = (
    "import errno,os,pathlib,runpy,sys,tempfile\n"
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
ACL_LISTING_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
XATTR_NOFOLLOW = 0x0001
XATTR_NAMES_LIMIT_BYTES = 64 * 1024
XATTR_VALUE_LIMIT_BYTES = 16 * 1024 * 1024
XATTR_AGGREGATE_LIMIT_BYTES = 64 * 1024 * 1024
F_GETPATH = 50
DARWIN_MAXPATHLEN = 1024
RENAME_EXCL = 0x00000004


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


@dataclass
class ChildProcessClosureProof:
    launch_attempted: bool = False
    proven: bool = False
    runtime_profile: str | None = None


def _select_no_child_runtime_profile() -> tuple[str, no_child_profile.RuntimePin]:
    runner_environment = os.environ.get(RUNNER_ENVIRONMENT_ENV)
    runner_arch = os.environ.get(RUNNER_ARCH_ENV)
    if runner_environment is None and runner_arch is None:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise RuntimeError(
                "read-only installed supervisor is missing explicit hosted runner "
                "identity"
            )
        return "production-current", no_child_profile.PINNED_RUNTIME
    if runner_environment != "github-hosted" or runner_arch != "ARM64":
        raise RuntimeError(
            "read-only installed supervisor received an incomplete or "
            "unsupported hosted runner identity"
        )
    if platform.machine() != "arm64":
        raise RuntimeError(
            "read-only installed supervisor requires an actual arm64 hosted process"
        )
    observed_runtime = no_child_profile._runtime_fingerprint()
    selected = _select_hosted_runtime_profile(observed_runtime)
    if selected is None:
        raise RuntimeError(
            "read-only installed supervisor runtime is not in the reviewed hosted "
            "profile catalog: "
            f"product={observed_runtime.macos_product_version!r} "
            f"build={observed_runtime.macos_build_version!r} "
            f"darwin={observed_runtime.darwin_release!r} "
            f"python={observed_runtime.python_version[:2]!r}"
        )
    return selected


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
    try:
        received_signal = fence.received_signal
        for signal_number, previous in zip(
            fence.signals,
            fence.previous_handlers,
            strict=True,
        ):
            signal.signal(signal_number, previous)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, fence.previous_mask)
    return received_signal


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
    argv = (
        sys.executable,
        "-B",
        "-c",
        NO_CHILD_SUITE_CODE,
        str(installed_root),
        str(runtime_parent),
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
                    _prepared_no_child_profile=prepared,
                )
            except BaseException as error:
                closure = bounded_command_process_closure(error)
                if _authenticated_no_child_closure(
                    closure,
                    require_stdio_closed=False,
                ):
                    proof.proven = True
                if isinstance(error, ValueError) and "command output exceeds" in str(
                    error
                ):
                    raise OverflowError(
                        "bounded no-child test output exceeded its byte cap"
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
            if len(result.stdout) > stdout_limit or len(result.stderr) > stderr_limit:
                raise OverflowError(
                    "bounded no-child test output exceeded its byte cap"
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
    binding: _DirectoryParentBinding,
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


def _binding_node_key(binding: _DirectoryParentBinding) -> tuple[int, int, int, int]:
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
    binding: _DirectoryParentBinding,
) -> tuple[str, bool]:
    metadata = os.fstat(binding.fd)
    descriptor_locator = _descriptor_object_locator(metadata)
    if metadata.st_nlink == 0:
        return descriptor_locator, False
    try:
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
        finally:
            os.close(candidate_fd)
    except Exception:
        return descriptor_locator, True
    return str(candidate), True


def _rename_exclusive(
    source_parent_fd: int,
    source_name: str,
    target_parent_fd: int,
    target_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = libc.renameatx_np
    renameatx_np.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx_np.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameatx_np(
        source_parent_fd,
        os.fsencode(source_name),
        target_parent_fd,
        os.fsencode(target_name),
        RENAME_EXCL,
    )
    if result != 0:
        raise OSError(
            ctypes.get_errno() or errno.EIO,
            "cannot exclusively stage a bound cleanup entry",
        )


def _exclusive_stage_name(parent_fd: int, source_name: str) -> str:
    for _attempt in range(8):
        staged_name = f".codex-cleanup-{secrets.token_hex(16)}"
        try:
            _rename_exclusive(
                parent_fd,
                source_name,
                parent_fd,
                staged_name,
            )
        except FileExistsError:
            continue
        return staged_name
    raise FileExistsError(errno.EEXIST, "cannot allocate a cleanup staging name")


def _path_entry_absent(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _open_bound_cleanup_entry(
    parent_fd: int,
    name: str,
) -> tuple[int, os.stat_result]:
    initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    common_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if stat.S_ISDIR(initial.st_mode):
        flags = common_flags | os.O_DIRECTORY | os.O_NOFOLLOW
    elif stat.S_ISREG(initial.st_mode):
        flags = common_flags | os.O_NOFOLLOW
    elif stat.S_ISLNK(initial.st_mode):
        symlink_flag = getattr(os, "O_SYMLINK", None)
        if symlink_flag is None:
            raise OSError(errno.ENOTSUP, "symlink descriptor opens are unavailable")
        flags = common_flags | symlink_flag
    else:
        raise OSError(errno.EPERM, "unsupported entry in bound cleanup tree")
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if _node_key(opened) != _node_key(initial):
            raise OSError(errno.ESTALE, "cleanup entry changed while opening")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _verify_staged_entry(
    parent_fd: int,
    staged_name: str,
    descriptor: int,
    expected_path: pathlib.Path,
) -> None:
    staged = os.stat(staged_name, dir_fd=parent_fd, follow_symlinks=False)
    if _node_key(staged) != _node_key(os.fstat(descriptor)):
        raise OSError(errno.ESTALE, "cleanup staging moved a different object")
    if _descriptor_path(descriptor) != expected_path:
        raise OSError(errno.ESTALE, "cleanup staging path changed")


def _remove_bound_directory_contents(
    descriptor: int,
    expected_path: pathlib.Path,
    *,
    restore_owner_write: bool,
) -> None:
    if restore_owner_write:
        metadata = os.fstat(descriptor)
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
    names = tuple(sorted(os.listdir(descriptor)))
    for name in names:
        entry_fd, initial = _open_bound_cleanup_entry(descriptor, name)
        try:
            staged_name = _exclusive_stage_name(descriptor, name)
            staged_path = expected_path / staged_name
            _verify_staged_entry(
                descriptor,
                staged_name,
                entry_fd,
                staged_path,
            )
            if not _path_entry_absent(descriptor, name):
                raise OSError(
                    errno.ESTALE,
                    "cleanup source name was repopulated after staging",
                )
            if stat.S_ISDIR(initial.st_mode):
                _remove_bound_directory_contents(
                    entry_fd,
                    staged_path,
                    restore_owner_write=restore_owner_write,
                )
                os.rmdir(staged_name, dir_fd=descriptor)
                if _descriptor_path(entry_fd) != staged_path or not _path_entry_absent(
                    descriptor, staged_name
                ):
                    raise OSError(
                        errno.ESTALE,
                        "bound cleanup directory survived final removal",
                    )
            else:
                os.unlink(staged_name, dir_fd=descriptor)
                if os.fstat(entry_fd).st_nlink != 0 or not _path_entry_absent(
                    descriptor, staged_name
                ):
                    raise OSError(
                        errno.ESTALE,
                        "bound cleanup entry survived final removal",
                    )
        finally:
            os.close(entry_fd)
    if os.listdir(descriptor):
        raise OSError(errno.ESTALE, "bound cleanup directory gained new entries")


def _cleanup_bound_tree(
    binding: _DirectoryParentBinding | None,
    *,
    restore_owner_write: bool,
) -> CleanupFailure | None:
    if binding is None:
        return None
    try:
        binding.revalidate()
    except Exception as error:
        retained_locator, retained = _bound_tree_retention_locator(binding)
        return _cleanup_failure_from_error(
            retained_locator,
            error,
            retained=retained,
        )
    parent_fd: int | None = None
    staged_path = binding.path
    try:
        parent_fd, _parent_identity = open_absolute_directory_chain(
            binding.path.parent,
            allow_sticky_writable_ancestors=(not binding.require_owned_private_parent),
        )
        staged_name = _exclusive_stage_name(parent_fd, binding.path.name)
        staged_path = binding.path.parent / staged_name
        staged = os.stat(
            staged_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if _node_key(staged) != _binding_node_key(binding):
            raise OSError(errno.ESTALE, "cleanup staged a different root object")
        if _descriptor_path(binding.fd) != staged_path:
            raise OSError(errno.ESTALE, "bound cleanup root staging path changed")
        if not _path_entry_absent(parent_fd, binding.path.name):
            raise OSError(
                errno.ESTALE,
                "cleanup root name was repopulated after staging",
            )
        _remove_bound_directory_contents(
            binding.fd,
            staged_path,
            restore_owner_write=restore_owner_write,
        )
        os.rmdir(staged_name, dir_fd=parent_fd)
        if _descriptor_path(binding.fd) != staged_path or not _path_entry_absent(
            parent_fd, staged_name
        ):
            raise OSError(
                errno.ESTALE,
                "bound cleanup root survived final removal",
            )
        if not _path_entry_absent(parent_fd, binding.path.name):
            raise OSError(
                errno.ESTALE,
                "cleanup root path was repopulated before completion",
            )
        return None
    except Exception as error:
        retained_locator, retained = _bound_tree_retention_locator(binding)
        return _cleanup_failure_from_error(
            retained_locator,
            error,
            retained=retained,
        )
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


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


def _retained_bound_tree_for_unproven_child_closure(
    binding: _DirectoryParentBinding | None,
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


def _run_main(lifecycle_fence: LifecycleSignalFence) -> int:
    source_root = pathlib.Path(__file__).resolve().parents[1]
    install_container: pathlib.Path | None = None
    install_container_binding: _DirectoryParentBinding | None = None
    runtime_parent: pathlib.Path | None = None
    runtime_parent_binding: _DirectoryParentBinding | None = None
    installed_root: pathlib.Path | None = None
    completed: subprocess.CompletedProcess[str] | None = None
    before: dict[str, TreeEntrySnapshot] | None = None
    after: dict[str, TreeEntrySnapshot] | None = None
    runtime_residue: tuple[str, ...] = ()
    timeout_error: TimeoutError | None = None
    output_limit_error: OverflowError | None = None
    signal_error: ChildRunInterrupted | None = None
    child_process_closure = "not-started"
    primary_failure: PrimaryFailure | None = None
    secondary_failures: list[SecondaryFailure] = []
    closure_proof = ChildProcessClosureProof()
    cleanup_failures: tuple[CleanupFailure, ...] = ()
    stage = "install-container"
    try:
        install_container = _create_owned_private_directory(
            READONLY_INSTALL_PARENT,
            ".codex-review-readonly-install-",
            require_owned_private_parent=False,
        )
        stage = "install-container-binding"
        install_container_binding = _open_directory_parent(
            install_container,
            require_owned_private_parent=False,
        )
        stage = "runtime-parent"
        runtime_parent = _create_owned_private_directory(
            _private_runtime_parent(),
            ".codex-review-readonly-runtime-",
        )
        stage = "runtime-parent-binding"
        runtime_parent_binding = _open_directory_parent(
            runtime_parent,
            require_owned_private_parent=True,
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
        child_process_closure = _child_process_closure_status(closure_proof)
        primary_failure = _primary_failure(stage, error)
    except Exception as error:
        if child_process_closure == "pending":
            child_process_closure = _child_process_closure_status(closure_proof)
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
            if install_container_binding is None:
                cleanup_results.append(
                    _retained_for_unproven_child_closure(install_container)
                )
            if runtime_parent_binding is None:
                cleanup_results.append(
                    _retained_for_unproven_child_closure(runtime_parent)
                )
        else:
            cleanup_results = [
                _cleanup_bound_tree(
                    install_container_binding,
                    restore_owner_write=True,
                ),
                _cleanup_bound_tree(
                    runtime_parent_binding,
                    restore_owner_write=False,
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
        if install_container_binding is not None:
            try:
                install_container_binding.close()
            except Exception as error:
                cleanup_results.append(
                    _cleanup_failure_from_error(
                        install_container_binding.path,
                        error,
                    )
                )
        if runtime_parent_binding is not None:
            try:
                runtime_parent_binding.close()
            except Exception as error:
                cleanup_results.append(
                    _cleanup_failure_from_error(runtime_parent_binding.path, error)
                )
        cleanup_failures = tuple(
            failure for failure in cleanup_results if failure is not None
        )

    if lifecycle_fence.received_signal is not None and signal_error is None:
        signal_error = ChildRunInterrupted(lifecycle_fence.received_signal)
        if primary_failure is None:
            primary_failure = _primary_failure(stage, signal_error)
    release_tree_immutable = (
        before is not None
        and after is not None
        and _tree_property_unchanged(before, after)
    )
    retained_paths = [failure.path for failure in cleanup_failures if failure.retained]
    if primary_failure is not None:
        if timeout_error is not None:
            primary_status = "timed-out"
        elif output_limit_error is not None:
            primary_status = "output-limit"
        elif signal_error is not None:
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
    summary = {
        "child_process_closure": child_process_closure,
        "cleanup_failures": [asdict(failure) for failure in cleanup_failures],
        "cleanup_status": "incomplete" if cleanup_failures else "complete",
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
        returncode = 128 + signal_error.signal_number
    else:
        returncode = 1 if primary_failed or cleanup_failures else 0
    sys.stdout.flush()
    sys.stderr.flush()
    if lifecycle_fence.received_signal is not None:
        return 128 + lifecycle_fence.received_signal
    return returncode


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
    lifecycle_fence = _install_lifecycle_signal_fence()
    try:
        returncode = _run_main(lifecycle_fence)
    except BaseException as primary_error:
        try:
            _restore_lifecycle_signal_fence(lifecycle_fence)
        except BaseException as restore_error:
            primary_error.add_note(
                "lifecycle signal restoration failed: "
                f"{type(restore_error).__name__}: {restore_error}"
            )
        raise
    received_signal = _restore_lifecycle_signal_fence(lifecycle_fence)
    if received_signal is not None:
        return 128 + received_signal
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
