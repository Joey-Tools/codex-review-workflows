from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.abc
import importlib.util
import json
import os
import pathlib
import pwd
import runpy
import stat
import sys
from dataclasses import dataclass
from types import CodeType, ModuleType


SOURCE_FILE_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_TOTAL_LIMIT_BYTES = 64 * 1024 * 1024
SOURCE_ENTRY_LIMIT = 4096
SOURCE_PATH_LIMIT_BYTES = 4 * 1024 * 1024
SOURCE_DEPTH_LIMIT = 32
SOURCE_MANIFEST_LIMIT_BYTES = 1024 * 1024
SOURCE_MANIFEST_HEADER = b"trusted-mac-gate-source-manifest-v1\n"
GIT_TOOLCHAIN_ENTRY_LIMIT = 1024
GIT_TOOLCHAIN_FILE_LIMIT_BYTES = 16 * 1024 * 1024
GIT_TOOLCHAIN_TOTAL_LIMIT_BYTES = 64 * 1024 * 1024
GIT_TOOLCHAIN_DEPTH_LIMIT = 8
GIT_TOOLCHAIN_RECEIPT_LIMIT_BYTES = 4096
GIT_TMPDIR_CUSTODY_DEPTH_LIMIT = 64
GIT_TMPDIR_CUSTODY_RECEIPT_LIMIT_BYTES = 16384
HOSTED_GIT_BINDING_PROFILE = "hosted-git-toolchain-v2-external-tmp-custody"
TRUSTED_MAC_GIT_BINDING_PROFILE = "trusted-mac-git-toolchain-tmp-custody-v3"
PERMITTED_GIT_DIRECTORY_XATTRS = frozenset({b"com.apple.provenance"})
PERMITTED_GIT_DIRECTORY_ANCESTOR_XATTRS = frozenset(
    {b"com.apple.provenance", b"com.apple.rootless"}
)
SOURCE_ROOTS = ("review_supervisor", "tests")
PROHIBITED_SUFFIXES = (".pyc", ".pyo", ".so", ".dylib", ".dll", ".pyd")
MODE_MODULES = {
    "hosted-readonly": "tests.run_readonly_install_deterministic_supervisor",
    "live": "tests.run_required_no_child_profile",
    "readonly": "tests.run_readonly_install_deterministic_supervisor",
}


@dataclass(frozen=True)
class _BoundSource:
    code: CodeType
    digest: str
    is_package: bool
    path: pathlib.Path
    payload: bytes


@dataclass(frozen=True)
class _ManifestEntry:
    git_mode: int
    size: int
    sha256: str


def _require_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RuntimeError(f"{label} is not one lowercase SHA-256")


def _raise_preserving_secondary_failures(
    primary: BaseException,
    secondary_failures: tuple[BaseException, ...],
    *,
    context: str,
) -> None:
    for secondary in secondary_failures:
        add_note = getattr(primary, "add_note", None)
        if add_note is not None:
            add_note(f"{context}: {type(secondary).__name__}: {secondary}")
    try:
        setattr(primary, "codex_secondary_failures", secondary_failures)
    except BaseException:
        pass
    raise primary.with_traceback(primary.__traceback__)


def _explicit_absolute_path(value: str, label: str) -> pathlib.Path:
    if (
        not value
        or "\0" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or not value.startswith("/")
        or value.startswith("//")
        or value != os.path.normpath(value)
    ):
        raise RuntimeError(f"{label} is not one explicit normalized absolute path")
    return pathlib.Path(value)


def _close_directory_chain(descriptors: list[int]) -> tuple[OSError, ...]:
    failures = []
    while descriptors:
        try:
            os.close(descriptors.pop())
        except OSError as error:
            failures.append(error)
    return tuple(failures)


def _raise_directory_chain_cleanup_failures(
    failures: tuple[OSError, ...],
) -> None:
    if not failures:
        return
    active_error = sys.exception()
    if active_error is None:
        _raise_preserving_secondary_failures(
            failures[0],
            tuple(failures[1:]),
            context="trusted Git custody directory descriptor cleanup also failed",
        )
    _raise_preserving_secondary_failures(
        active_error,
        failures,
        context="trusted Git custody directory cleanup also failed",
    )


def _open_directory_chain(
    path: pathlib.Path,
) -> tuple[list[int], tuple[os.stat_result, ...]]:
    components = path.parts[1:]
    if len(components) + 1 > GIT_TMPDIR_CUSTODY_DEPTH_LIMIT:
        raise RuntimeError("trusted Git custody directory exceeds its depth bound")
    descriptors: list[int] = []
    opened_records: list[os.stat_result] = []
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        for index, component in enumerate((path.anchor, *components)):
            if index == 0:
                named = pathlib.Path(component).lstat()
                descriptor = os.open(component, flags)
            else:
                named = os.stat(
                    component,
                    dir_fd=descriptors[-1],
                    follow_symlinks=False,
                )
                descriptor = os.open(
                    component,
                    flags,
                    dir_fd=descriptors[-1],
                )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if _tmpdir_stat_binding(named) != _tmpdir_stat_binding(opened):
                raise RuntimeError(
                    "trusted Git custody directory chain changed while opening"
                )
            opened_records.append(opened)
        return descriptors, tuple(opened_records)
    except OSError as error:
        if isinstance(error, FileNotFoundError):
            message = "trusted Git custody directory chain is missing"
        elif isinstance(error, PermissionError):
            message = "trusted Git custody directory chain is unreadable"
        else:
            message = "trusted Git custody directory chain revalidation failed"
        primary = RuntimeError(message)
        cleanup_failures = _close_directory_chain(descriptors)
        if cleanup_failures:
            primary.__cause__ = error
            _raise_preserving_secondary_failures(
                primary,
                cleanup_failures,
                context="trusted Git custody directory cleanup also failed",
            )
        raise primary from error
    except BaseException:
        cleanup_failures = _close_directory_chain(descriptors)
        _raise_directory_chain_cleanup_failures(cleanup_failures)
        raise


def _macos_acl_entry_count(descriptor: int) -> int:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended ACL inspection requires macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return 0
        raise OSError(error_number or errno.EIO, "cannot inspect extended ACL")
    try:
        return 1
    finally:
        if acl_free(acl) != 0:
            raise OSError(ctypes.get_errno() or errno.EIO, "cannot release ACL state")


def _macos_fd_xattr_names(descriptor: int) -> tuple[bytes, ...]:
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended attribute inspection requires macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    flistxattr = libc.flistxattr
    flistxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    flistxattr.restype = ctypes.c_ssize_t

    ctypes.set_errno(0)
    size = flistxattr(descriptor, None, 0, 0)
    if size < 0:
        raise OSError(
            ctypes.get_errno() or errno.EIO,
            "cannot size extended attribute names",
        )
    if size > 4096:
        raise RuntimeError("trusted Git TMPDIR xattrs exceed their byte bound")
    if size == 0:
        return ()
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    value = flistxattr(descriptor, buffer, size, 0)
    if value < 0:
        raise OSError(
            ctypes.get_errno() or errno.EIO,
            "cannot read extended attribute names",
        )
    if value != size:
        raise OSError(errno.ESTALE, "extended attributes changed during inspection")
    raw = bytes(buffer.raw[:size])
    if not raw.endswith(b"\0"):
        raise RuntimeError("trusted Git TMPDIR xattr names are malformed")
    raw_names = raw[:-1].split(b"\0")
    if any(not name for name in raw_names) or len(raw_names) > 128:
        raise RuntimeError("trusted Git TMPDIR xattrs exceed their count bound")
    names = tuple(sorted(raw_names))
    if len(set(names)) != len(names):
        raise RuntimeError("trusted Git TMPDIR xattr names contain duplicates")
    return names


def _tmpdir_stat_binding(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    """Bind directory object identity and access policy, not child-entry churn."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
    )


def _validate_directory_chain_access_policy(
    descriptors: list[int],
    records: tuple[os.stat_result, ...],
) -> None:
    last_index = len(records) - 1
    for index, (descriptor, metadata) in enumerate(zip(descriptors, records)):
        mode = stat.S_IMODE(metadata.st_mode)
        flags = getattr(metadata, "st_flags", 0)
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(
                "trusted Git custody directory chain contains a non-directory"
            )
        if index == last_index:
            if metadata.st_uid != os.getuid() or mode != 0o700 or flags != 0:
                raise RuntimeError(
                    "trusted Git custody directory target has an unsafe access policy"
                )
            permitted_xattrs = PERMITTED_GIT_DIRECTORY_XATTRS
        else:
            if metadata.st_uid not in {0, os.getuid()}:
                raise RuntimeError(
                    "trusted Git custody directory has an untrusted ancestor owner"
                )
            if mode & 0o022 and not (metadata.st_uid == 0 and mode & stat.S_ISVTX):
                raise RuntimeError(
                    "trusted Git custody directory has an unsafe writable ancestor"
                )
            permitted_xattrs = PERMITTED_GIT_DIRECTORY_ANCESTOR_XATTRS
        acl_count = _macos_acl_entry_count(descriptor)
        xattrs = _macos_fd_xattr_names(descriptor)
        if acl_count != 0 or not set(xattrs) <= permitted_xattrs:
            raise RuntimeError(
                "trusted Git custody directory chain has unsafe ACL or xattr metadata"
            )


def _directory_chain_records(
    metadata_records: tuple[os.stat_result, ...],
) -> list[dict[str, object]]:
    return [
        {
            "device": metadata.st_dev,
            "file_type": stat.S_IFMT(metadata.st_mode),
            "flags": getattr(metadata, "st_flags", 0),
            "group_gid": metadata.st_gid,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "owner_uid": metadata.st_uid,
        }
        for metadata in metadata_records
    ]


def _trusted_git_tmpdir_record(path: pathlib.Path) -> dict[str, object]:
    descriptors: list[int] = []
    revalidation_descriptors: list[int] = []
    try:
        descriptors, opened = _open_directory_chain(path)
        _validate_directory_chain_access_policy(descriptors, opened)
        middle = tuple(os.fstat(descriptor) for descriptor in descriptors)
        _validate_directory_chain_access_policy(descriptors, middle)
        closed = tuple(os.fstat(descriptor) for descriptor in descriptors)
        if tuple(map(_tmpdir_stat_binding, opened)) != tuple(
            map(_tmpdir_stat_binding, middle)
        ) or tuple(map(_tmpdir_stat_binding, middle)) != tuple(
            map(_tmpdir_stat_binding, closed)
        ):
            raise RuntimeError(
                "trusted Git custody directory chain changed during inspection"
            )
        revalidation_descriptors, revalidated = _open_directory_chain(path)
        _validate_directory_chain_access_policy(
            revalidation_descriptors,
            revalidated,
        )
        revalidated_closed = tuple(
            os.fstat(descriptor) for descriptor in revalidation_descriptors
        )
        if tuple(map(_tmpdir_stat_binding, closed)) != tuple(
            map(_tmpdir_stat_binding, revalidated_closed)
        ):
            raise RuntimeError(
                "trusted Git custody directory physical chain does not match"
            )
        return {
            "device": closed[-1].st_dev,
            "group_gid": closed[-1].st_gid,
            "inode": closed[-1].st_ino,
            "owner_uid": closed[-1].st_uid,
            "path": str(path),
            "physical_chain": _directory_chain_records(closed),
            "schema": "trusted-git-tmpdir-custody-v1",
        }
    finally:
        cleanup_failures = _close_directory_chain(
            revalidation_descriptors
        ) + _close_directory_chain(descriptors)
        _raise_directory_chain_cleanup_failures(cleanup_failures)


def _trusted_git_tmpdir_receipt_payload(arguments: list[str]) -> bytes:
    if len(arguments) != 1:
        raise RuntimeError("trusted Git TMPDIR receipt requires one directory")
    path = _explicit_absolute_path(arguments[0], "trusted Git TMPDIR")
    record = _trusted_git_tmpdir_record(path)
    payload = (
        json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    if len(payload) > GIT_TMPDIR_CUSTODY_RECEIPT_LIMIT_BYTES:
        raise RuntimeError("trusted Git TMPDIR receipt exceeds its closed output bound")
    return payload


def _validate_trusted_git_tmpdir(path: pathlib.Path, receipt: str) -> bytes:
    try:
        encoded = receipt.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("trusted Git TMPDIR receipt is not ASCII") from error
    if not encoded or len(encoded) >= GIT_TMPDIR_CUSTODY_RECEIPT_LIMIT_BYTES:
        raise RuntimeError("trusted Git TMPDIR receipt exceeds its closed input bound")
    if b"\n" in encoded or b"\r" in encoded or b"\0" in encoded:
        raise RuntimeError("trusted Git TMPDIR receipt is not one physical record")
    observed = _trusted_git_tmpdir_receipt_payload([str(path)])
    if observed != encoded + b"\n":
        raise RuntimeError("trusted Git TMPDIR does not match its custody receipt")
    return observed


def _require_candidate_readonly_physical_chain(path: pathlib.Path) -> None:
    if not path.is_absolute() or path != pathlib.Path(os.path.abspath(path)):
        raise RuntimeError("hosted Git toolchain path is not absolute and normalized")
    current = pathlib.Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("hosted Git toolchain path contains a symlink")
        if os.access(current, os.W_OK):
            raise RuntimeError("hosted Git toolchain is writable by the review account")


def _read_toolchain_file(path: pathlib.Path, *, expected_size: int) -> bytes:
    if expected_size < 0 or expected_size > GIT_TOOLCHAIN_FILE_LIMIT_BYTES:
        raise RuntimeError("hosted Git toolchain file exceeds its byte bound")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
            raise RuntimeError("hosted Git toolchain file changed while opening")
        chunks = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("hosted Git toolchain file is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("hosted Git toolchain file grew while reading")
        closed = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
            opened.st_uid,
            opened.st_gid,
            stat.S_IMODE(opened.st_mode),
            opened.st_size,
        ) != (
            closed.st_dev,
            closed.st_ino,
            stat.S_IFMT(closed.st_mode),
            closed.st_uid,
            closed.st_gid,
            stat.S_IMODE(closed.st_mode),
            closed.st_size,
        ):
            raise RuntimeError("hosted Git toolchain file changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _snapshot_git_exec_path(
    exec_path: pathlib.Path,
    *,
    developer_dir: pathlib.Path,
) -> str:
    records: list[bytes] = []
    entry_count = 0
    total_bytes = 0
    symlink_target_digests: dict[tuple[int, int], tuple[tuple[int, ...], str]] = {}

    def walk(directory: pathlib.Path, relative: tuple[str, ...], depth: int) -> None:
        nonlocal entry_count, total_bytes
        if depth > GIT_TOOLCHAIN_DEPTH_LIMIT:
            raise RuntimeError("hosted Git exec-path exceeds its depth bound")
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > GIT_TOOLCHAIN_ENTRY_LIMIT:
                    raise RuntimeError("hosted Git exec-path exceeds its entry bound")
                entries.append(entry)
        entries.sort(key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            path = directory / entry.name
            metadata = path.lstat()
            if os.access(path.parent, os.W_OK):
                raise RuntimeError(
                    "hosted Git exec-path parent is writable by the review account"
                )
            encoded_relative = os.fsencode("/".join((*relative, entry.name)))
            prefix = (
                encoded_relative
                + b"\0"
                + f"{metadata.st_uid}:{metadata.st_gid}:{stat.S_IMODE(metadata.st_mode)}".encode(
                    "ascii"
                )
                + b"\0"
            )
            if stat.S_ISDIR(metadata.st_mode):
                if os.access(path, os.W_OK):
                    raise RuntimeError(
                        "hosted Git exec-path directory is writable by the review account"
                    )
                records.append(prefix + b"D\0")
                walk(path, (*relative, entry.name), depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                if os.access(path, os.W_OK) or not os.access(path, os.R_OK):
                    raise RuntimeError(
                        "hosted Git exec-path file has unsafe review-account access"
                    )
                payload = _read_toolchain_file(path, expected_size=metadata.st_size)
                total_bytes += len(payload)
                if total_bytes > GIT_TOOLCHAIN_TOTAL_LIMIT_BYTES:
                    raise RuntimeError("hosted Git exec-path exceeds its byte bound")
                records.append(prefix + b"F" + hashlib.sha256(payload).digest() + b"\0")
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                encoded_target = os.fsencode(target)
                if len(encoded_target) > 4096:
                    raise RuntimeError(
                        "hosted Git exec-path symlink exceeds its byte bound"
                    )
                resolved = path.resolve(strict=True)
                try:
                    resolved_relative = resolved.relative_to(developer_dir)
                except ValueError as error:
                    raise RuntimeError(
                        "hosted Git exec-path symlink escapes the Developer directory"
                    ) from error
                _require_candidate_readonly_physical_chain(resolved)
                resolved_metadata = resolved.lstat()
                if (
                    not stat.S_ISREG(resolved_metadata.st_mode)
                    or os.access(resolved, os.W_OK)
                    or not os.access(resolved, os.R_OK | os.X_OK)
                ):
                    raise RuntimeError(
                        "hosted Git exec-path symlink target has unsafe review-account access"
                    )
                target_identity = (
                    resolved_metadata.st_dev,
                    resolved_metadata.st_ino,
                )
                target_policy = (
                    resolved_metadata.st_dev,
                    resolved_metadata.st_ino,
                    resolved_metadata.st_uid,
                    resolved_metadata.st_gid,
                    stat.S_IMODE(resolved_metadata.st_mode),
                    resolved_metadata.st_size,
                )
                cached_target = symlink_target_digests.get(target_identity)
                if cached_target is None:
                    target_payload = _read_toolchain_file(
                        resolved,
                        expected_size=resolved_metadata.st_size,
                    )
                    total_bytes += len(target_payload)
                    if total_bytes > GIT_TOOLCHAIN_TOTAL_LIMIT_BYTES:
                        raise RuntimeError(
                            "hosted Git exec-path exceeds its byte bound"
                        )
                    target_digest = hashlib.sha256(target_payload).hexdigest()
                    symlink_target_digests[target_identity] = (
                        target_policy,
                        target_digest,
                    )
                else:
                    cached_policy, target_digest = cached_target
                    if cached_policy != target_policy:
                        raise RuntimeError(
                            "hosted Git exec-path symlink target changed during snapshot"
                        )
                records.append(
                    prefix
                    + b"L"
                    + encoded_target
                    + b"\0"
                    + os.fsencode(resolved_relative.as_posix())
                    + b"\0"
                    + target_digest.encode("ascii")
                    + b"\0"
                )
            else:
                raise RuntimeError("hosted Git exec-path contains a special file")

    walk(exec_path, (), 1)
    return hashlib.sha256(b"".join(records)).hexdigest()


def _git_toolchain_receipt(
    *,
    developer_dir: pathlib.Path,
    git_executable: pathlib.Path,
    git_sha256: str,
    git_exec_path: pathlib.Path,
    git_exec_path_receipt: str,
) -> str:
    return hashlib.sha256(
        b"hosted-git-toolchain-v2\0"
        + os.fsencode(str(developer_dir))
        + b"\0"
        + os.fsencode(str(git_executable))
        + b"\0"
        + git_sha256.encode("ascii")
        + b"\0"
        + os.fsencode(str(git_exec_path))
        + b"\0"
        + git_exec_path_receipt.encode("ascii")
        + b"\0"
    ).hexdigest()


def _measure_hosted_git_toolchain(arguments: list[str]) -> tuple[str, str]:
    if len(arguments) != 4:
        raise RuntimeError(
            "hosted Git receipt requires Developer, executable, digest, and exec-path"
        )
    developer_dir = pathlib.Path(arguments[0])
    git_executable = pathlib.Path(arguments[1])
    expected_git_sha256 = arguments[2]
    git_exec_path = pathlib.Path(arguments[3])
    _require_sha256(expected_git_sha256, "hosted Git executable digest")
    for path in (
        developer_dir,
        git_executable,
        git_exec_path,
    ):
        if not path.is_absolute() or path != pathlib.Path(os.path.abspath(path)):
            raise RuntimeError("hosted Git receipt path is not absolute and normalized")
    if git_executable.resolve(strict=True) != git_executable:
        raise RuntimeError("hosted Git executable is not a physical path")
    if git_exec_path.resolve(strict=True) != git_exec_path:
        raise RuntimeError("hosted Git exec-path is not a physical path")
    try:
        git_executable.relative_to(developer_dir)
        git_exec_path.relative_to(developer_dir)
    except ValueError as error:
        raise RuntimeError(
            "hosted Git toolchain escapes the Developer directory"
        ) from error
    _require_candidate_readonly_physical_chain(developer_dir)
    _require_candidate_readonly_physical_chain(git_executable)
    _require_candidate_readonly_physical_chain(git_exec_path)
    metadata = git_executable.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(git_executable, os.R_OK | os.X_OK)
        or os.access(git_executable, os.W_OK)
    ):
        raise RuntimeError("hosted Git executable has unsafe review-account access")
    payload = _read_toolchain_file(git_executable, expected_size=metadata.st_size)
    if hashlib.sha256(payload).hexdigest() != expected_git_sha256:
        raise RuntimeError("hosted Git executable content does not match its receipt")
    exec_path_receipt = _snapshot_git_exec_path(
        git_exec_path,
        developer_dir=developer_dir,
    )
    toolchain_receipt = _git_toolchain_receipt(
        developer_dir=developer_dir,
        git_executable=git_executable,
        git_sha256=expected_git_sha256,
        git_exec_path=git_exec_path,
        git_exec_path_receipt=exec_path_receipt,
    )
    return exec_path_receipt, toolchain_receipt


def _hosted_git_receipt_payload(arguments: list[str]) -> bytes:
    exec_path_receipt, toolchain_receipt = _measure_hosted_git_toolchain(arguments)
    developer_dir, git_executable, git_sha256, git_exec_path = arguments
    record = {
        "developer_dir": developer_dir,
        "exec_path": git_exec_path,
        "exec_path_sha256": exec_path_receipt,
        "executable": git_executable,
        "executable_sha256": git_sha256,
        "schema": "hosted-git-toolchain-receipt-v2",
        "toolchain_sha256": toolchain_receipt,
    }
    payload = (
        json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    if len(payload) > GIT_TOOLCHAIN_RECEIPT_LIMIT_BYTES or payload.count(b"\n") != 1:
        raise RuntimeError("hosted Git receipt exceeds its closed output bound")
    return payload


def _parse_hosted_git_receipt(value: str) -> dict[str, str]:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("hosted Git receipt is not ASCII") from error
    if not encoded or len(encoded) >= GIT_TOOLCHAIN_RECEIPT_LIMIT_BYTES:
        raise RuntimeError("hosted Git receipt exceeds its closed input bound")
    if b"\n" in encoded or b"\r" in encoded or b"\0" in encoded:
        raise RuntimeError("hosted Git receipt is not one physical record")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise RuntimeError("hosted Git receipt is not valid JSON") from error
    expected_keys = {
        "developer_dir",
        "exec_path",
        "exec_path_sha256",
        "executable",
        "executable_sha256",
        "schema",
        "toolchain_sha256",
    }
    if (
        not isinstance(decoded, dict)
        or set(decoded) != expected_keys
        or any(not isinstance(item, str) for item in decoded.values())
        or decoded["schema"] != "hosted-git-toolchain-receipt-v2"
    ):
        raise RuntimeError("hosted Git receipt does not match its closed schema")
    record = {key: decoded[key] for key in sorted(expected_keys)}
    for key in (
        "exec_path_sha256",
        "executable_sha256",
        "toolchain_sha256",
    ):
        _require_sha256(record[key], f"hosted Git receipt {key}")
    canonical = json.dumps(
        record,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if canonical != value:
        raise RuntimeError("hosted Git receipt is not canonically encoded")
    return record


def _validate_bound_git_toolchain(
    arguments: list[str],
    *,
    profile: str,
) -> dict[str, str]:
    if profile == HOSTED_GIT_BINDING_PROFILE:
        expected_argument_count = 6
    elif profile == TRUSTED_MAC_GIT_BINDING_PROFILE:
        expected_argument_count = 7
    else:
        raise RuntimeError("trusted Git binding profile is unsupported")
    if len(arguments) != expected_argument_count:
        raise RuntimeError(
            "trusted Git binding requires TMPDIR, Developer, executable, "
            "digest, exec-path, toolchain receipt, and profile custody"
        )
    (
        runtime_parent_raw,
        developer_dir_raw,
        git_executable_raw,
        expected_git_sha256,
        git_exec_path_raw,
        expected_toolchain_receipt_json,
    ) = arguments[:6]
    _require_sha256(expected_git_sha256, "hosted Git executable digest")
    runtime_parent = pathlib.Path(runtime_parent_raw)
    developer_dir = pathlib.Path(developer_dir_raw)
    git_executable = pathlib.Path(git_executable_raw)
    git_exec_path = pathlib.Path(git_exec_path_raw)
    for path in (runtime_parent, developer_dir, git_executable, git_exec_path):
        if not path.is_absolute() or path != pathlib.Path(os.path.abspath(path)):
            raise RuntimeError("bound Git path is not absolute and normalized")
    expected_receipt = _parse_hosted_git_receipt(expected_toolchain_receipt_json)
    if (
        expected_receipt["developer_dir"] != str(developer_dir)
        or expected_receipt["executable"] != str(git_executable)
        or expected_receipt["executable_sha256"] != expected_git_sha256
        or expected_receipt["exec_path"] != str(git_exec_path)
    ):
        raise RuntimeError("hosted Git receipt does not bind the supplied toolchain")
    observed_tmpdir_receipt = None
    if profile == TRUSTED_MAC_GIT_BINDING_PROFILE:
        observed_tmpdir_receipt = _validate_trusted_git_tmpdir(
            runtime_parent,
            arguments[6],
        )
    observed_receipt = b""
    primary_failure: BaseException | None = None
    try:
        observed_receipt = _hosted_git_receipt_payload(
            [
                str(developer_dir),
                str(git_executable),
                expected_git_sha256,
                str(git_exec_path),
            ]
        )
        expected_payload = (expected_toolchain_receipt_json + "\n").encode("ascii")
        if observed_receipt != expected_payload:
            raise RuntimeError("hosted Git toolchain does not match its receipt")
    except BaseException as error:
        primary_failure = error
    if profile == TRUSTED_MAC_GIT_BINDING_PROFILE:
        custody_failure: BaseException | None = None
        try:
            _validate_trusted_git_tmpdir(
                runtime_parent,
                arguments[6],
            )
        except BaseException as error:
            custody_failure = error
        if primary_failure is not None and custody_failure is not None:
            _raise_preserving_secondary_failures(
                primary_failure,
                (custody_failure,),
                context="trusted Git post-measurement custody also failed",
            )
        if primary_failure is not None:
            raise primary_failure.with_traceback(primary_failure.__traceback__)
        if custody_failure is not None:
            raise custody_failure.with_traceback(custody_failure.__traceback__)
        assert observed_tmpdir_receipt is not None
        observed_toolchain_receipt = hashlib.sha256(
            b"trusted-mac-bound-git-profile-v3\0"
            + hashlib.sha256(observed_receipt).digest()
            + hashlib.sha256(observed_tmpdir_receipt).digest()
        ).hexdigest()
    else:
        if primary_failure is not None:
            raise primary_failure.with_traceback(primary_failure.__traceback__)
        observed_toolchain_receipt = hashlib.sha256(observed_receipt).hexdigest()
    return {
        "CODEX_REVIEW_BOUND_GIT_DEVELOPER_DIR": str(developer_dir),
        "CODEX_REVIEW_BOUND_GIT_EXECUTABLE": str(git_executable),
        "CODEX_REVIEW_BOUND_GIT_EXEC_PATH": str(git_exec_path),
        "CODEX_REVIEW_BOUND_GIT_RECEIPT_SHA256": observed_toolchain_receipt,
        "CODEX_REVIEW_BOUND_GIT_TMPDIR": str(runtime_parent),
    }


def _validate_hosted_git_toolchain(arguments: list[str]) -> dict[str, str]:
    if len(arguments) != 11:
        raise RuntimeError(
            "hosted readonly gate requires runtime, home, Git, and account receipts"
        )
    (
        runtime_parent_raw,
        home_raw,
        developer_dir_raw,
        git_executable_raw,
        expected_git_sha256,
        git_exec_path_raw,
        expected_toolchain_receipt_json,
        expected_account_name,
        expected_uid,
        expected_gid,
        expected_account_receipt,
    ) = arguments
    _require_sha256(expected_account_receipt, "hosted review-account receipt")
    account = pwd.getpwuid(os.getuid())
    if (
        account.pw_name != expected_account_name
        or str(account.pw_uid) != expected_uid
        or str(account.pw_gid) != expected_gid
    ):
        raise RuntimeError("hosted review-account receipt does not match this process")
    home = pathlib.Path(home_raw)
    if not home.is_absolute() or home != pathlib.Path(os.path.abspath(home)):
        raise RuntimeError("hosted readonly gate path is not absolute and normalized")
    environment = _validate_bound_git_toolchain(
        [
            runtime_parent_raw,
            developer_dir_raw,
            git_executable_raw,
            expected_git_sha256,
            git_exec_path_raw,
            expected_toolchain_receipt_json,
        ],
        profile=HOSTED_GIT_BINDING_PROFILE,
    )
    environment.update(
        {
            "CODEX_REVIEW_DEDICATED_ACCOUNT_CUSTODY_SHA256": expected_account_receipt,
            "HOME": str(home),
            "TMPDIR": environment["CODEX_REVIEW_BOUND_GIT_TMPDIR"],
        }
    )
    return environment


def _require_isolated_receipt_entry(label: str) -> None:
    if (
        not sys.flags.isolated
        or not sys.flags.ignore_environment
        or not sys.flags.no_site
        or not sys.flags.no_user_site
        or not sys.flags.safe_path
        or not sys.dont_write_bytecode
        or __file__ != "<stdin>"
        or sys.argv[0] != "-"
    ):
        raise RuntimeError(f"{label} requires isolated trusted stdin")


def _hosted_git_receipt_main() -> int:
    _require_isolated_receipt_entry("hosted Git receipt")
    sys.stdout.buffer.write(_hosted_git_receipt_payload(sys.argv[2:]))
    sys.stdout.buffer.flush()
    return 0


def _trusted_git_tmpdir_receipt_main() -> int:
    _require_isolated_receipt_entry("trusted Git TMPDIR receipt")
    sys.stdout.buffer.write(_trusted_git_tmpdir_receipt_payload(sys.argv[2:]))
    sys.stdout.buffer.flush()
    return 0


class _SourceOnlyLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, source: _BoundSource) -> None:
        self._fullname = fullname
        self._source = source

    def create_module(self, _spec: object) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        exec(self._source.code, module.__dict__)

    def get_code(self, fullname: str) -> CodeType:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return self._source.code

    def get_filename(self, fullname: str) -> str:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return str(self._source.path)

    def is_package(self, fullname: str) -> bool:
        if fullname != self._fullname:
            raise ImportError("source-only loader module mismatch")
        return self._source.is_package


class _ClosedSourceFinder(importlib.abc.MetaPathFinder):
    def __init__(self, sources: dict[str, _BoundSource]) -> None:
        self._sources = sources

    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> object:
        if not (
            fullname == "review_supervisor"
            or fullname.startswith("review_supervisor.")
            or fullname == "tests"
            or fullname.startswith("tests.")
        ):
            return None
        source = self._sources.get(fullname)
        if source is None:
            raise ImportError(f"source-only module is absent: {fullname}")
        loader = _SourceOnlyLoader(fullname, source)
        spec = importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=str(source.path),
            is_package=source.is_package,
        )
        if spec is None:
            raise ImportError(f"source-only module spec is unavailable: {fullname}")
        spec.has_location = True
        return spec


@dataclass
class _SnapshotBudget:
    entries_remaining: int = SOURCE_ENTRY_LIMIT
    bytes_remaining: int = SOURCE_TOTAL_LIMIT_BYTES
    path_bytes_remaining: int = SOURCE_PATH_LIMIT_BYTES

    def observe(self, name: str, *, depth: int) -> None:
        if depth > SOURCE_DEPTH_LIMIT:
            raise RuntimeError("trusted gate source exceeds its depth bound")
        encoded = os.fsencode(name)
        if self.entries_remaining <= 0:
            raise RuntimeError("trusted gate source exceeds its entry bound")
        if len(encoded) > self.path_bytes_remaining:
            raise RuntimeError("trusted gate source exceeds its path byte bound")
        self.entries_remaining -= 1
        self.path_bytes_remaining -= len(encoded)

    def consume_source(self, size: int, *, probe_bytes: int = 0) -> None:
        if size < 0 or size > SOURCE_FILE_LIMIT_BYTES:
            raise RuntimeError("trusted gate source file exceeds its byte bound")
        charged = size + probe_bytes
        if probe_bytes < 0 or charged > self.bytes_remaining:
            raise RuntimeError("trusted gate source exceeds its total byte bound")
        self.bytes_remaining -= charged


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    path: pathlib.Path,
) -> int:
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISDIR(initial.st_mode):
        raise RuntimeError(f"trusted gate source is not a directory: {path}")
    if initial.st_uid not in {0, os.getuid()}:
        raise RuntimeError(f"trusted gate source ownership is unsafe: {path}")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if _directory_identity(initial) != _directory_identity(opened):
            raise OSError("trusted gate source directory changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _bounded_directory_names(
    descriptor: int,
    *,
    budget: _SnapshotBudget,
    depth: int,
) -> tuple[str, ...]:
    names = []
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            budget.observe(entry.name, depth=depth)
            names.append(entry.name)
    return tuple(sorted(names))


def _read_source_at(
    parent_descriptor: int,
    name: str,
    path: pathlib.Path,
    *,
    budget: _SnapshotBudget,
) -> tuple[bytes, int]:
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(initial.st_mode):
        raise RuntimeError(f"trusted gate source is not a regular file: {path}")
    if initial.st_uid not in {0, os.getuid()} or initial.st_nlink != 1:
        raise RuntimeError(f"trusted gate source ownership is unsafe: {path}")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            initial.st_nlink != 1
            or opened.st_nlink != 1
            or (
                initial.st_dev,
                initial.st_ino,
                initial.st_mode,
                initial.st_uid,
                initial.st_gid,
                initial.st_size,
                initial.st_nlink,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_size,
                opened.st_nlink,
            )
        ):
            raise OSError("trusted gate source changed while opening")
        budget.consume_source(opened.st_size, probe_bytes=1)
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise OSError("trusted gate source changed while reading")
        final = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_nlink,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_uid,
            final.st_gid,
            final.st_size,
            final.st_nlink,
        ):
            raise OSError("trusted gate source changed while reading")
        git_mode = 0o100755 if final.st_mode & 0o111 else 0o100644
        return bytes(payload), git_mode
    finally:
        os.close(descriptor)


def _read_source_manifest(
    path: pathlib.Path,
    expected_digest: str,
) -> bytes:
    if len(expected_digest) != 64 or any(
        character not in "0123456789abcdef" for character in expected_digest
    ):
        raise RuntimeError("trusted gate source manifest digest is invalid")
    if not path.is_absolute():
        raise RuntimeError("trusted gate source manifest path must be absolute")
    initial = path.lstat()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
    )

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_nlink,
        )

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid not in {0, os.getuid()}
            or opened.st_nlink != 1
            or opened.st_size < len(SOURCE_MANIFEST_HEADER)
            or opened.st_size > SOURCE_MANIFEST_LIMIT_BYTES
            or identity(initial) != identity(opened)
        ):
            raise RuntimeError("trusted gate source manifest identity is unsafe")
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(65536, opened.st_size - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise OSError("trusted gate source manifest changed while reading")
        final = os.fstat(descriptor)
        if identity(opened) != identity(final):
            raise OSError("trusted gate source manifest changed while reading")
        result = bytes(payload)
        if hashlib.sha256(result).hexdigest() != expected_digest:
            raise RuntimeError("trusted gate source manifest digest mismatch")
        return result
    finally:
        os.close(descriptor)


def _parse_source_manifest(payload: bytes) -> dict[str, _ManifestEntry]:
    if not payload.startswith(SOURCE_MANIFEST_HEADER) or not payload.endswith(b"\n"):
        raise RuntimeError("trusted gate source manifest framing is invalid")
    records = payload[len(SOURCE_MANIFEST_HEADER) :].splitlines(keepends=True)
    if not records:
        raise RuntimeError("trusted gate source manifest is empty")
    entries: dict[str, _ManifestEntry] = {}
    previous_path: bytes | None = None
    for record in records:
        if not record.endswith(b"\n") or b"\r" in record or b"\0" in record:
            raise RuntimeError("trusted gate source manifest record is malformed")
        metadata, separator, raw_path = record[:-1].partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise RuntimeError("trusted gate source manifest record is malformed")
        raw_mode, raw_size, raw_digest = fields
        if raw_mode not in {b"100644", b"100755"}:
            raise RuntimeError("trusted gate source manifest mode is unsupported")
        if (
            not raw_size
            or len(raw_size) > 10
            or any(character not in b"0123456789" for character in raw_size)
        ):
            raise RuntimeError("trusted gate source manifest size is invalid")
        size = int(raw_size)
        if size < 0 or size > SOURCE_FILE_LIMIT_BYTES:
            raise RuntimeError("trusted gate source manifest size exceeds its bound")
        if len(raw_digest) != 64 or any(
            character not in b"0123456789abcdef" for character in raw_digest
        ):
            raise RuntimeError("trusted gate source manifest digest is invalid")
        if previous_path is not None and raw_path <= previous_path:
            raise RuntimeError(
                "trusted gate source manifest paths are not unique and sorted"
            )
        previous_path = raw_path
        try:
            relative = raw_path.decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                "trusted gate source manifest path is not ASCII"
            ) from error
        path = pathlib.PurePosixPath(relative)
        if (
            not relative
            or path.is_absolute()
            or path.as_posix() != relative
            or not path.parts
            or path.parts[0] not in SOURCE_ROOTS
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise RuntimeError("trusted gate source manifest path is outside its scope")
        entries[relative] = _ManifestEntry(
            git_mode=int(raw_mode, 8),
            size=size,
            sha256=raw_digest.decode("ascii"),
        )
    return entries


def _module_name(relative: tuple[str, ...], *, is_package: bool) -> str:
    components = relative[:-1] if is_package else (*relative[:-1], relative[-1][:-3])
    if not components or any(not component.isidentifier() for component in components):
        raise RuntimeError("trusted gate source has an invalid module path")
    return ".".join(components)


def _snapshot_sources(
    tool_root: pathlib.Path,
    manifest: dict[str, _ManifestEntry],
) -> dict[str, _BoundSource]:
    budget = _SnapshotBudget()
    captured: dict[str, tuple[pathlib.Path, bytes, bool, str]] = {}
    observed: set[str] = set()
    expected_directories = {
        tuple(pathlib.PurePosixPath(path).parts[:index])
        for path in manifest
        for index in range(1, len(pathlib.PurePosixPath(path).parts))
    }
    root_initial = tool_root.lstat()
    if not stat.S_ISDIR(root_initial.st_mode):
        raise RuntimeError("trusted gate tool root is not a directory")
    if root_initial.st_uid not in {0, os.getuid()}:
        raise RuntimeError("trusted gate tool root ownership is unsafe")
    root_descriptor = os.open(
        tool_root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    root_opened = os.fstat(root_descriptor)
    if _directory_identity(root_initial) != _directory_identity(root_opened):
        os.close(root_descriptor)
        raise OSError("trusted gate tool root changed while opening")

    def walk(
        parent_descriptor: int,
        relative: tuple[str, ...],
        *,
        depth: int,
    ) -> None:
        names = _bounded_directory_names(
            parent_descriptor,
            budget=budget,
            depth=depth,
        )
        for name in names:
            path = tool_root.joinpath(*relative, name)
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(f"trusted gate source contains a symlink: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                if name == "__pycache__":
                    raise RuntimeError("trusted gate source contains __pycache__")
                directory_relative = (*relative, name)
                if directory_relative not in expected_directories:
                    raise RuntimeError(
                        f"trusted gate source contains an unexpected directory: {path}"
                    )
                child = _open_directory_at(
                    parent_descriptor,
                    name,
                    path,
                )
                try:
                    walk(child, (*relative, name), depth=depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    f"trusted gate source has an unsupported entry: {path}"
                )
            if name.endswith(PROHIBITED_SUFFIXES):
                raise RuntimeError(f"trusted gate source contains a substitute: {path}")
            manifest_path = pathlib.PurePosixPath(*relative, name).as_posix()
            expected = manifest.get(manifest_path)
            if expected is None:
                raise RuntimeError(
                    f"trusted gate source contains an unexpected file: {path}"
                )
            payload, git_mode = _read_source_at(
                parent_descriptor,
                name,
                path,
                budget=budget,
            )
            second, second_git_mode = _read_source_at(
                parent_descriptor,
                name,
                path,
                budget=budget,
            )
            if payload != second or git_mode != second_git_mode:
                raise OSError("trusted gate source changed between reads")
            if (
                git_mode != expected.git_mode
                or len(payload) != expected.size
                or hashlib.sha256(payload).hexdigest() != expected.sha256
            ):
                raise RuntimeError(
                    f"trusted gate source does not match the exact manifest: {path}"
                )
            observed.add(manifest_path)
            if not name.endswith(".py"):
                continue
            is_package = name == "__init__.py"
            module = _module_name((*relative, name), is_package=is_package)
            if module in captured:
                raise RuntimeError(
                    f"trusted gate source maps duplicate module: {module}"
                )
            captured[module] = (
                path,
                payload,
                is_package,
                hashlib.sha256(payload).hexdigest(),
            )

    try:
        for package in SOURCE_ROOTS:
            budget.observe(package, depth=0)
            package_descriptor = _open_directory_at(
                root_descriptor,
                package,
                tool_root / package,
            )
            try:
                walk(package_descriptor, (package,), depth=1)
            finally:
                os.close(package_descriptor)
    finally:
        os.close(root_descriptor)
    missing = sorted(set(manifest) - observed)
    if missing:
        raise RuntimeError(
            "trusted gate source is missing exact manifest entries: "
            + ", ".join(missing[:10])
        )
    for required in ("review_supervisor", "tests", *MODE_MODULES.values()):
        if required not in captured:
            raise RuntimeError(f"trusted gate required source is absent: {required}")
    return {
        module: _BoundSource(
            code=compile(payload, str(path), "exec", dont_inherit=True),
            digest=digest,
            is_package=is_package,
            path=path,
            payload=payload,
        )
        for module, (path, payload, is_package, digest) in captured.items()
    }


def _configure_environment(mode: str, arguments: list[str]) -> str:
    account = pwd.getpwuid(os.getuid())
    if account.pw_uid != os.getuid() or not account.pw_name or not account.pw_dir:
        raise RuntimeError("trusted gate account identity is unavailable")
    environment = {
        "HOME": account.pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "USER": account.pw_name,
    }
    if mode == "live":
        if arguments:
            raise RuntimeError("trusted live gate accepts no arguments")
        environment["CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"] = "1"
    elif mode == "readonly":
        if (
            not arguments
            or len(arguments[0]) != 40
            or any(character not in "0123456789abcdef" for character in arguments[0])
        ):
            raise RuntimeError("trusted readonly gate requires one full SHA-1")
        environment["CODEX_REVIEW_EXPECTED_HEAD_SHA"] = arguments[0]
        trusted_mac_environment = _validate_bound_git_toolchain(
            arguments[1:],
            profile=TRUSTED_MAC_GIT_BINDING_PROFILE,
        )
        environment.update(trusted_mac_environment)
        environment["CODEX_REVIEW_TEST_RUNTIME_PARENT"] = trusted_mac_environment[
            "CODEX_REVIEW_BOUND_GIT_TMPDIR"
        ]
    elif mode == "hosted-readonly":
        hosted_environment = _validate_hosted_git_toolchain(arguments)
        environment.update(hosted_environment)
        environment["CODEX_REVIEW_TEST_RUNTIME_PARENT"] = hosted_environment[
            "CODEX_REVIEW_BOUND_GIT_TMPDIR"
        ]
    else:
        raise RuntimeError("trusted gate mode is unsupported")
    os.environ.clear()
    os.environ.update(environment)
    return MODE_MODULES[mode]


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--hosted-git-receipt":
        return _hosted_git_receipt_main()
    if len(sys.argv) >= 2 and sys.argv[1] == "--trusted-git-tmpdir-receipt":
        return _trusted_git_tmpdir_receipt_main()
    if (
        not sys.flags.isolated
        or not sys.flags.ignore_environment
        or not sys.flags.no_site
        or not sys.flags.no_user_site
        or not sys.flags.safe_path
        or not sys.dont_write_bytecode
    ):
        raise RuntimeError("trusted gate requires -I -B -S")
    if __file__ != "<stdin>" or sys.argv[0] != "-":
        raise RuntimeError("trusted gate must be executed from bounded trusted stdin")
    if len(sys.argv) < 5:
        raise RuntimeError(
            "trusted gate requires an absolute tool root, source manifest, "
            "manifest digest, and mode"
        )
    tool_root = pathlib.Path(sys.argv[1])
    if not tool_root.is_absolute():
        raise RuntimeError("trusted gate tool root must be absolute")
    manifest_path = pathlib.Path(sys.argv[2])
    manifest_payload = _read_source_manifest(manifest_path, sys.argv[3])
    manifest = _parse_source_manifest(manifest_payload)
    mode = sys.argv[4]
    module = _configure_environment(mode, sys.argv[5:])
    sources = _snapshot_sources(tool_root, manifest)
    sys.meta_path.insert(0, _ClosedSourceFinder(sources))
    sys.argv = [module]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
