from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass

from .support import _private_runtime_parent


EXPLICIT_RUNTIME_PARENT_ENV = "CODEX_REVIEW_TEST_RUNTIME_PARENT"
READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")
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
    link_count: int
    flags: int
    size: int
    mtime_ns: int
    ctime_ns: int
    digest: str | None
    xattrs: tuple[tuple[bytes, str], ...]
    acl_entries: tuple[bytes, ...]


@dataclass(frozen=True)
class CleanupFailure:
    path: str
    error_kind: str
    error_errno: int | None
    retained: bool
    restore_error_kind: str | None
    restore_error_errno: int | None


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
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            kind = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            digest = None
            kind = "directory"
        elif stat.S_ISLNK(metadata.st_mode):
            digest = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
            kind = "symlink"
        else:
            digest = None
            kind = "other"
        snapshot[relative] = TreeEntrySnapshot(
            kind=kind,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            generation=getattr(metadata, "st_gen", 0),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=mode,
            link_count=metadata.st_nlink,
            flags=getattr(metadata, "st_flags", 0),
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
            digest=digest,
            xattrs=_xattr_snapshot(path),
            acl_entries=_acl_entries(path),
        )
    return snapshot


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


def _cleanup_tree(
    path: pathlib.Path | None,
    *,
    restore_owner_write: bool,
) -> CleanupFailure | None:
    if path is None or not os.path.lexists(path):
        return None
    restore_error: OSError | None = None
    if restore_owner_write:
        try:
            _restore_owner_write(path)
        except OSError as error:
            restore_error = error
    try:
        shutil.rmtree(path)
    except OSError as error:
        return CleanupFailure(
            path=str(path),
            error_kind=type(error).__name__,
            error_errno=error.errno,
            retained=os.path.lexists(path),
            restore_error_kind=(
                type(restore_error).__name__ if restore_error is not None else None
            ),
            restore_error_errno=(
                restore_error.errno if restore_error is not None else None
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


def main() -> int:
    if sys.platform != "darwin":
        print("read-only installed supervisor regression requires Darwin", file=sys.stderr)
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
    runtime_parent: pathlib.Path | None = None
    installed_root: pathlib.Path | None = None
    completed: subprocess.CompletedProcess[str] | None = None
    before: dict[str, TreeEntrySnapshot] | None = None
    after: dict[str, TreeEntrySnapshot] | None = None
    runtime_residue: tuple[str, ...] = ()
    timeout_error: subprocess.TimeoutExpired | None = None
    cleanup_failures: tuple[CleanupFailure, ...] = ()
    try:
        install_container = pathlib.Path(
            tempfile.mkdtemp(
                prefix=".codex-review-readonly-install-",
                dir=READONLY_INSTALL_PARENT,
            )
        )
        runtime_parent = pathlib.Path(
            tempfile.mkdtemp(
                prefix=".codex-review-readonly-runtime-",
                dir=_private_runtime_parent(),
            )
        )
        os.chmod(install_container, 0o700)
        os.chmod(runtime_parent, 0o700)
        installed_root = install_container / "independent_codex_pr_review"
        shutil.copytree(
            source_root,
            installed_root,
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        _set_tree_read_only(installed_root)
        before = _tree_snapshot(installed_root)
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
        completed = subprocess.run(
            (
                sys.executable,
                "-B",
                "-m",
                "tests.run_required_deterministic_supervisor",
            ),
            cwd=installed_root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
        after = _tree_snapshot(installed_root)
        runtime_residue = tuple(sorted(path.name for path in runtime_parent.iterdir()))
    except subprocess.TimeoutExpired as error:
        timeout_error = error
    finally:
        cleanup_failures = tuple(
            failure
            for failure in (
                _cleanup_tree(install_container, restore_owner_write=True),
                _cleanup_tree(runtime_parent, restore_owner_write=False),
            )
            if failure is not None
        )

    release_tree_immutable = (
        before is not None and after is not None and after == before
    )
    retained_paths = [
        failure.path for failure in cleanup_failures if failure.retained
    ]
    summary = {
        "cleanup_failures": [asdict(failure) for failure in cleanup_failures],
        "cleanup_status": "incomplete" if cleanup_failures else "complete",
        "install_parent_is_sticky_world_writable": True,
        "release_tree_immutable": release_tree_immutable,
        "release_tree_property": "object-identity-content-access-policy",
        "retained_paths": retained_paths,
        "returncode": completed.returncode if completed is not None else None,
        "runtime_residue": list(runtime_residue),
        "timed_out": timeout_error is not None,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))

    primary_failed = (
        completed is None
        or completed.returncode != 0
        or not release_tree_immutable
        or bool(runtime_residue)
    )
    if completed is not None and primary_failed:
        if completed.stdout:
            print(_bounded_failure_text(completed.stdout), file=sys.stderr)
        if completed.stderr:
            print(_bounded_failure_text(completed.stderr), file=sys.stderr)
    if timeout_error is not None:
        print("read-only installed supervisor regression timed out", file=sys.stderr)
        for value in (timeout_error.stdout, timeout_error.stderr):
            if value:
                text = (
                    value.decode("utf-8", "replace")
                    if isinstance(value, bytes)
                    else value
                )
                print(_bounded_failure_text(text), file=sys.stderr)
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
    return 1 if primary_failed or cleanup_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
