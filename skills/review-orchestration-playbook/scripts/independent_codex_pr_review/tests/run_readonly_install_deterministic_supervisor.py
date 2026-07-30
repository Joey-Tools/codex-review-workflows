from __future__ import annotations

import ctypes
import errno
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

from review_supervisor.codex_executable import run_bounded_command
from review_supervisor.no_child_profile import (
    prepare_sandboxed_python_no_child_profile,
)
from review_supervisor.signal_relay import (
    DeferredSignalInterrupt,
    activate_deferred_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)
from .support import (
    _DirectoryParentBinding,
    _create_owned_private_directory,
    _open_directory_parent,
    _private_runtime_parent,
)


EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
CHILD_TIMEOUT_SECONDS = 600.0
CHILD_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
CHILD_STDERR_LIMIT_BYTES = 8 * 1024 * 1024
NO_CHILD_SUITE_CODE = (
    "import os,runpy,sys\n"
    "root=sys.argv[1]\n"
    f"os.environ[{EXPLICIT_RUNTIME_PARENT_ENV!r}]=sys.argv[2]\n"
    "os.chdir(root)\n"
    "sys.path.insert(0,root)\n"
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
class ChildProcessClosureProof:
    proven: bool = False


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
    runtime_parent: pathlib.Path,
    timeout: float = CHILD_TIMEOUT_SECONDS,
    stdout_limit: int = CHILD_STDOUT_LIMIT_BYTES,
    stderr_limit: int = CHILD_STDERR_LIMIT_BYTES,
    secondary_failures: list[SecondaryFailure] | None = None,
    closure_proof: ChildProcessClosureProof | None = None,
) -> subprocess.CompletedProcess[str]:
    diagnostics = secondary_failures if secondary_failures is not None else []
    proof = closure_proof if closure_proof is not None else ChildProcessClosureProof()
    prepared = prepare_sandboxed_python_no_child_profile()
    argv = (
        sys.executable,
        "-B",
        "-c",
        NO_CHILD_SUITE_CODE,
        str(installed_root),
        str(runtime_parent),
    )
    with _bound_child_signals(diagnostics):
        try:
            result = run_bounded_command(
                argv,
                timeout_seconds=timeout,
                max_output_bytes=stdout_limit + stderr_limit,
                _prepared_no_child_profile=prepared,
            )
        except ValueError as error:
            if "command output exceeds" in str(error):
                raise OverflowError(
                    "bounded no-child test output exceeded its byte cap"
                ) from error
            raise
    closure = result.process_closure
    if (
        closure is None
        or not closure.authenticated_no_child_profile
        or not closure.permitted_process_closure_proven
        or not closure.leader_reaped
        or not closure.stdio_closed
        or closure.process_group_emptiness_used_as_descendant_proof
    ):
        raise RuntimeError(
            "read-only installed test process closure lacks an authenticated "
            "no-child proof"
        )
    proof.proven = True
    if len(result.stdout) > stdout_limit or len(result.stderr) > stderr_limit:
        raise OverflowError("bounded no-child test output exceeded its byte cap")
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
    path: pathlib.Path,
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
        # A failed path revalidation leaves the held directory object retained,
        # even when its original lexical path is now absent.
        return _cleanup_failure_from_error(binding.path, error, retained=True)
    return _cleanup_tree(
        binding.path,
        restore_owner_write=restore_owner_write,
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


def _retained_bound_tree_for_unproven_child_closure(
    binding: _DirectoryParentBinding | None,
) -> CleanupFailure | None:
    if binding is None:
        return None
    return CleanupFailure(
        path=str(binding.path),
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
        stage = "child-run"
        child_process_closure = "pending"
        completed = _run_no_child_test_suite(
            installed_root=installed_root,
            runtime_parent=runtime_parent,
            secondary_failures=secondary_failures,
            closure_proof=closure_proof,
        )
        child_process_closure = "proven"
        stage = "snapshot-after"
        install_container_binding.revalidate()
        after = _tree_snapshot(installed_root)
        install_container_binding.revalidate()
        stage = "runtime-residue"
        runtime_residue = _list_bound_directory(runtime_parent_binding)
        stage = "complete"
    except TimeoutError as error:
        timeout_error = error
        child_process_closure = "proven" if closure_proof.proven else "unproven"
        primary_failure = _primary_failure(stage, error)
    except OverflowError as error:
        output_limit_error = error
        child_process_closure = "proven" if closure_proof.proven else "unproven"
        primary_failure = _primary_failure(stage, error)
    except ChildRunInterrupted as error:
        signal_error = error
        child_process_closure = "proven" if closure_proof.proven else "unproven"
        primary_failure = _primary_failure(stage, error)
    except Exception as error:
        if child_process_closure == "pending":
            child_process_closure = "proven" if closure_proof.proven else "unproven"
        primary_failure = _primary_failure(stage, error)
    finally:
        if child_process_closure == "pending" and closure_proof.proven:
            child_process_closure = "proven"
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
