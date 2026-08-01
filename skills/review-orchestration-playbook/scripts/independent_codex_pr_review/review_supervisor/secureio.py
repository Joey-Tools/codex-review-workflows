from __future__ import annotations

import contextlib
import contextvars
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import pathlib
import platform
import stat
import sys
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .errors import inconclusive, record_secondary_error
from .models import FilesystemMeasure, Identity


READ_CHUNK = 64 * 1024
MAX_JSON_DEPTH = 64
DARWIN_ROOT_ALIASES = {
    "etc": "private/etc",
    "tmp": "private/tmp",
    "var": "private/var",
}
DARWIN_BOOT_SESSION_MARKER = pathlib.Path("/private/var/run/bootSessionMA.txt")
DARWIN_BOOT_SESSION_PARENT_GID = 1
DARWIN_BOOT_SESSION_PARENT_MODE = 0o775
DARWIN_BOOT_SESSION_MARKER_MODE = 0o644
DARWIN_BOOT_SESSION_MARKER_XATTRS = frozenset(
    {"com.apple.TextEncoding", "com.apple.provenance"}
)


def require_python_313() -> None:
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError(
            f"Python 3.13 is required; running {sys.version_info.major}."
            f"{sys.version_info.minor}"
        )


def identity_from_stat(value: os.stat_result) -> Identity:
    return Identity(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        link_count=value.st_nlink,
        uid=value.st_uid,
        size=value.st_size,
    )


def identities_match(left: Identity, right: Identity) -> bool:
    return left == right


def directory_identities_match(left: Identity, right: Identity) -> bool:
    """Compare the stable directory fields carried by persisted Identity values.

    This compatibility shape cannot carry gid, flags, or extended metadata. Use
    DirectoryPolicyBinding for security-sensitive in-process revalidation.
    Directory size, link count, and timestamps remain deliberately excluded
    because ordinary child-entry churn can change them.
    """
    return (
        stat.S_ISDIR(left.mode)
        and stat.S_ISDIR(right.mode)
        and left.device == right.device
        and left.inode == right.inode
        and left.uid == right.uid
        and left.mode == right.mode
    )


@dataclass(frozen=True, slots=True)
class MacOSDirectoryMetadataBinding:
    acl_entry_count: int
    acl_entries: tuple[str, ...]
    xattrs: tuple[str, ...]
    quarantine_present: bool


@dataclass(frozen=True, slots=True)
class DirectoryPolicyBinding:
    """Bind directory object identity and the access policy used by this run."""

    device: int
    inode: int
    file_type: int
    generation: int
    uid: int
    gid: int
    mode: int
    flags: int
    macos_metadata: MacOSDirectoryMetadataBinding | None

    @property
    def stat_binding(self) -> tuple[int, int, int, int, int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.file_type,
            self.generation,
            self.uid,
            self.gid,
            self.mode,
            self.flags,
        )


def directory_stat_binding(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Return directory identity/access fields unaffected by child-entry churn."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
    )


def _macos_directory_metadata_binding(
    evidence: Any | None,
) -> MacOSDirectoryMetadataBinding | None:
    if evidence is None:
        return None
    return MacOSDirectoryMetadataBinding(
        acl_entry_count=evidence.acl_entry_count,
        acl_entries=tuple(evidence.acl_entries),
        xattrs=tuple(evidence.xattrs),
        quarantine_present=evidence.quarantine_present,
    )


_LEAF_METADATA_DIGEST_DOMAIN = b"targeted-cleanup-leaf-metadata-v2\0"
MAX_LEAF_XATTR_VALUE_BYTES = 64 * 1024
MAX_LEAF_XATTR_TOTAL_BYTES = 1024 * 1024
_LEAF_CONTENT_DIGEST_DOMAIN = b"targeted-cleanup-leaf-content-v1\0"
LEAF_CONTENT_STATE_REGULAR = 1
LEAF_CONTENT_STATE_SYMLINK = 2
LEAF_CONTENT_STATE_FIFO = 3
LEAF_CONTENT_STATE_SOCKET = 4
LEAF_CONTENT_STATE_CHARACTER_DEVICE = 5
LEAF_CONTENT_STATE_BLOCK_DEVICE = 6
LEAF_CONTENT_STATE_OTHER = 7
LEAF_CONTENT_STATES = frozenset(
    {
        LEAF_CONTENT_STATE_REGULAR,
        LEAF_CONTENT_STATE_SYMLINK,
        LEAF_CONTENT_STATE_FIFO,
        LEAF_CONTENT_STATE_SOCKET,
        LEAF_CONTENT_STATE_CHARACTER_DEVICE,
        LEAF_CONTENT_STATE_BLOCK_DEVICE,
        LEAF_CONTENT_STATE_OTHER,
    }
)
MAX_LEAF_CONTENT_BYTES = 512 * 1024 * 1024
_LEAF_CONTENT_READ_BYTES = 64 * 1024
_LEAF_CONTENT_ZEROES = bytes(_LEAF_CONTENT_READ_BYTES)


class LeafContentDeadlineExpired(TimeoutError):
    """The cleanup's own monotonic deadline expired between content reads."""


def _update_digest_string(
    digest: Any,
    value: str,
    *,
    encoding: str,
) -> None:
    encoded = value.encode(encoding)
    digest.update(len(encoded).to_bytes(4, "big"))
    digest.update(encoded)


def _update_digest_bytes(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _leaf_metadata_digest_prefix(
    metadata: MacOSDirectoryMetadataBinding | None,
) -> tuple[int, Any, tuple[str, ...]]:
    state = 0 if metadata is None else 1
    digest = hashlib.sha256()
    digest.update(_LEAF_METADATA_DIGEST_DOMAIN)
    digest.update(bytes((state,)))
    _update_digest_string(
        digest,
        "not-applicable" if metadata is None else "darwin",
        encoding="ascii",
    )
    if metadata is None:
        digest.update((0).to_bytes(4, "big") * 2)
        digest.update(b"\0")
        return state, digest, ()

    acl_entries = tuple(metadata.acl_entries)
    xattrs = tuple(sorted(metadata.xattrs))
    if (
        type(metadata.acl_entry_count) is not int
        or metadata.acl_entry_count != len(acl_entries)
        or not 0 <= metadata.acl_entry_count <= 128
        or any(
            not isinstance(entry, str)
            or not entry
            or "\0" in entry
            or "\n" in entry
            or "\r" in entry
            or len(entry.encode("ascii")) > 1024
            for entry in acl_entries
        )
        or len(set(acl_entries)) != len(acl_entries)
        or len(xattrs) > 128
        or any(
            not isinstance(name, str)
            or not name
            or "\0" in name
            or len(name.encode("utf-8")) > 4096
            for name in xattrs
        )
        or len(set(xattrs)) != len(xattrs)
        or sum(len(name.encode("utf-8")) for name in xattrs) > 4096
        or type(metadata.quarantine_present) is not bool
        or metadata.quarantine_present != ("com.apple.quarantine" in xattrs)
    ):
        raise ValueError("filesystem metadata binding is malformed")
    digest.update(len(acl_entries).to_bytes(4, "big"))
    digest.update(len(xattrs).to_bytes(4, "big"))
    digest.update(bytes((int(metadata.quarantine_present),)))
    for entry in acl_entries:
        _update_digest_string(digest, entry, encoding="ascii")
    return state, digest, xattrs


def macos_leaf_metadata_digest(
    metadata: MacOSDirectoryMetadataBinding | None,
    *,
    xattr_values: Iterable[tuple[str, bytes]] = (),
) -> tuple[int, bytes]:
    """Hash one normalized leaf metadata observation including xattr values."""

    state, digest, xattrs = _leaf_metadata_digest_prefix(metadata)
    value_iterator = iter(xattr_values)
    if metadata is None:
        try:
            next(value_iterator)
        except StopIteration:
            return state, digest.digest()
        raise ValueError("non-Darwin leaf metadata has xattr values")
    total_value_bytes = 0
    for expected_name in xattrs:
        try:
            name, value = next(value_iterator)
        except StopIteration as error:
            raise ValueError("leaf xattr value observation is incomplete") from error
        if name != expected_name or not isinstance(value, bytes):
            raise ValueError("leaf xattr value observation is inconsistent")
        if len(value) > MAX_LEAF_XATTR_VALUE_BYTES:
            raise ValueError("leaf xattr value exceeds its byte bound")
        total_value_bytes += len(value)
        if total_value_bytes > MAX_LEAF_XATTR_TOTAL_BYTES:
            raise ValueError("leaf xattr values exceed their aggregate byte bound")
        _update_digest_string(digest, name, encoding="utf-8")
        _update_digest_bytes(digest, value)
    try:
        next(value_iterator)
    except StopIteration:
        pass
    else:
        raise ValueError("leaf xattr value observation contains an extra entry")
    return state, digest.digest()


def _update_macos_leaf_xattr_digest(
    fd: int,
    names: tuple[str, ...],
    digest: Any,
) -> None:
    """Hash one bounded FD-relative value snapshot without returning raw bytes."""

    libc = ctypes.CDLL(None, use_errno=True)
    fgetxattr = libc.fgetxattr
    fgetxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    fgetxattr.restype = ctypes.c_ssize_t
    total_value_bytes = 0

    def required_size(name: bytes) -> int:
        ctypes.set_errno(0)
        value = fgetxattr(fd, name, None, 0, 0, 0)
        if value < 0:
            raise OSError(
                ctypes.get_errno() or errno.EIO,
                "cannot size leaf extended attribute value",
            )
        if value > MAX_LEAF_XATTR_VALUE_BYTES:
            raise ValueError("leaf xattr value exceeds its byte bound")
        return int(value)

    for name in names:
        raw_name = name.encode("utf-8")
        size = required_size(raw_name)
        next_total = total_value_bytes + size
        if next_total > MAX_LEAF_XATTR_TOTAL_BYTES:
            raise ValueError("leaf xattr values exceed their aggregate byte bound")
        total_value_bytes = next_total
        buffer: Any | None = None
        try:
            if size:
                buffer = ctypes.create_string_buffer(size)
                ctypes.set_errno(0)
                read_size = fgetxattr(fd, raw_name, buffer, size, 0, 0)
                if read_size < 0:
                    raise OSError(
                        ctypes.get_errno() or errno.EIO,
                        "cannot read leaf extended attribute value",
                    )
                if read_size != size:
                    raise OSError(
                        errno.ESTALE,
                        "leaf extended attribute value changed during inspection",
                    )
            if required_size(raw_name) != size:
                raise OSError(
                    errno.ESTALE,
                    "leaf extended attribute value changed during inspection",
                )
            _update_digest_string(digest, name, encoding="utf-8")
            digest.update(size.to_bytes(8, "big"))
            if buffer is not None:
                digest.update(memoryview(buffer).cast("B")[:size])
        finally:
            if buffer is not None:
                try:
                    ctypes.memset(buffer, 0, size)
                finally:
                    buffer = None


def _macos_leaf_metadata_digest_from_fd(
    fd: int,
    metadata: MacOSDirectoryMetadataBinding,
) -> tuple[int, bytes]:
    state, digest, xattrs = _leaf_metadata_digest_prefix(metadata)
    _update_macos_leaf_xattr_digest(fd, xattrs, digest)
    return state, digest.digest()


def _leaf_stat_policy_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
        metadata.st_size,
        metadata.st_nlink,
    )


def inspect_macos_leaf_metadata_digest(fd: int) -> tuple[int, bytes]:
    """Double-observe and immediately hash descriptor-bound leaf metadata.

    Callers that bind an already-admitted filesystem object need its exact ACL
    plus complete xattr value state even when that state is not the private-root
    policy. Keep the parser lazy so ``codex_executable`` can continue importing
    the recovery module without creating a module-import cycle.
    """

    if sys.platform != "darwin":
        return macos_leaf_metadata_digest(None)
    from .codex_executable import inspect_macos_filesystem_metadata

    before = os.fstat(fd)
    first_evidence = inspect_macos_filesystem_metadata(fd, "file")
    first_metadata = _macos_directory_metadata_binding(first_evidence)
    assert first_metadata is not None
    first = _macos_leaf_metadata_digest_from_fd(fd, first_metadata)
    middle = os.fstat(fd)
    second_evidence = inspect_macos_filesystem_metadata(fd, "file")
    second_metadata = _macos_directory_metadata_binding(second_evidence)
    assert second_metadata is not None
    second = _macos_leaf_metadata_digest_from_fd(fd, second_metadata)
    after = os.fstat(fd)
    if (
        _leaf_stat_policy_binding(before) != _leaf_stat_policy_binding(middle)
        or _leaf_stat_policy_binding(middle) != _leaf_stat_policy_binding(after)
        or first != second
    ):
        raise OSError(errno.ESTALE, "leaf metadata changed during inspection")
    return second


def leaf_content_state_for_file_type(file_type: int) -> int:
    if stat.S_ISREG(file_type):
        return LEAF_CONTENT_STATE_REGULAR
    if stat.S_ISLNK(file_type):
        return LEAF_CONTENT_STATE_SYMLINK
    if stat.S_ISFIFO(file_type):
        return LEAF_CONTENT_STATE_FIFO
    if stat.S_ISSOCK(file_type):
        return LEAF_CONTENT_STATE_SOCKET
    if stat.S_ISCHR(file_type):
        return LEAF_CONTENT_STATE_CHARACTER_DEVICE
    if stat.S_ISBLK(file_type):
        return LEAF_CONTENT_STATE_BLOCK_DEVICE
    if stat.S_ISDIR(file_type):
        raise ValueError("directory content cannot be bound as a leaf")
    return LEAF_CONTENT_STATE_OTHER


def _leaf_content_stat_binding(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_gen", 0),
        metadata.st_size,
    )


def _leaf_content_digest_once(
    fd: int,
    metadata: os.stat_result,
    *,
    deadline: float,
) -> tuple[int, bytes]:
    """Hash one bounded leaf-content observation without retaining raw chunks."""

    if time.monotonic() >= deadline:
        raise LeafContentDeadlineExpired("targeted cleanup monotonic deadline expired")
    file_type = stat.S_IFMT(metadata.st_mode)
    state = leaf_content_state_for_file_type(file_type)
    digest = hashlib.sha256()
    digest.update(_LEAF_CONTENT_DIGEST_DOMAIN)
    digest.update(bytes((state,)))
    digest.update(file_type.to_bytes(4, "big"))
    size = metadata.st_size
    if type(size) is not int or size < 0:
        raise ValueError("leaf content size is invalid")
    digest.update(size.to_bytes(8, "big"))
    if state != LEAF_CONTENT_STATE_REGULAR:
        return state, digest.digest()
    if size > MAX_LEAF_CONTENT_BYTES:
        raise ValueError("regular leaf content exceeds its byte bound")
    preadv = getattr(os, "preadv", None)
    if preadv is None:
        raise OSError(errno.ENOSYS, "descriptor-relative content reads are unavailable")
    offset = 0
    buffer: bytearray | None = bytearray(_LEAF_CONTENT_READ_BYTES)
    view: memoryview | None = memoryview(buffer)
    read_view: memoryview | None = None
    digest_view: memoryview | None = None
    try:
        while offset < size:
            if time.monotonic() >= deadline:
                raise LeafContentDeadlineExpired(
                    "targeted cleanup monotonic deadline expired"
                )
            remaining = size - offset
            assert view is not None
            requested = min(_LEAF_CONTENT_READ_BYTES, remaining)
            read_view = view[:requested]
            try:
                read_size = preadv(fd, [read_view], offset)
            finally:
                read_view.release()
                read_view = None
            if type(read_size) is not int or read_size <= 0:
                raise OSError(
                    errno.ESTALE,
                    "regular leaf content ended during inspection",
                )
            if read_size > requested:
                raise OSError(
                    errno.ESTALE,
                    "regular leaf content read exceeded its observed size",
                )
            digest_view = view[:read_size]
            try:
                digest.update(digest_view)
            finally:
                digest_view.release()
                digest_view = None
            offset += read_size
        return state, digest.digest()
    finally:
        try:
            if digest_view is not None:
                digest_view.release()
        finally:
            digest_view = None
            try:
                if read_view is not None:
                    read_view.release()
            finally:
                read_view = None
                try:
                    if view is not None:
                        view.release()
                finally:
                    view = None
                    if buffer is not None:
                        try:
                            buffer[:] = _LEAF_CONTENT_ZEROES
                        finally:
                            buffer = None


def inspect_leaf_content_digest(
    fd: int,
    *,
    deadline: float,
) -> tuple[int, bytes]:
    """Double-observe the complete bounded content property of one leaf FD."""

    before = os.fstat(fd)
    first = _leaf_content_digest_once(fd, before, deadline=deadline)
    middle = os.fstat(fd)
    second = _leaf_content_digest_once(fd, middle, deadline=deadline)
    after = os.fstat(fd)
    if (
        _leaf_content_stat_binding(before) != _leaf_content_stat_binding(middle)
        or _leaf_content_stat_binding(middle) != _leaf_content_stat_binding(after)
        or first != second
    ):
        raise OSError(errno.ESTALE, "leaf content changed during inspection")
    return second


def _directory_policy_binding(
    metadata: os.stat_result,
    macos_metadata: Any | None,
) -> DirectoryPolicyBinding:
    (
        device,
        inode,
        file_type,
        generation,
        uid,
        gid,
        mode,
        flags,
    ) = directory_stat_binding(metadata)
    return DirectoryPolicyBinding(
        device=device,
        inode=inode,
        file_type=file_type,
        generation=generation,
        uid=uid,
        gid=gid,
        mode=mode,
        flags=flags,
        macos_metadata=_macos_directory_metadata_binding(macos_metadata),
    )


def _verify_macos_metadata(
    fd: int,
    path: pathlib.Path,
    kind: str,
    *,
    private: bool,
    extra_permitted_xattrs: frozenset[str] = frozenset(),
) -> Any | None:
    if sys.platform != "darwin":
        return None
    # Keep one authoritative ACL/xattr parser for executable and runtime custody.
    from .codex_executable import (
        inspect_macos_filesystem_metadata,
        verify_macos_filesystem_metadata,
    )

    evidence = inspect_macos_filesystem_metadata(
        fd,
        kind,
        require_directory_metadata_stability=False,
    )
    if private:
        if (
            evidence.acl_entry_count != 0
            or evidence.acl_entries
            or evidence.quarantine_present
            or set(evidence.xattrs) - {"com.apple.provenance"}
        ):
            raise ValueError("private filesystem object has extended metadata")
        return evidence
    if (
        evidence.acl_entry_count == 0
        and not evidence.acl_entries
        and not evidence.quarantine_present
        and set(evidence.xattrs)
        <= {
            "com.apple.provenance",
            "com.apple.rootless",
            *extra_permitted_xattrs,
        }
    ):
        return evidence
    if extra_permitted_xattrs:
        raise ValueError("extended ACLs, xattrs, and quarantine are forbidden")
    return verify_macos_filesystem_metadata(
        fd,
        path,
        kind,
        require_directory_metadata_stability=(kind != "directory"),
    )


def _directory_is_trusted_ancestor(metadata: os.stat_result) -> bool:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {
        0,
        os.getuid(),
    }:
        return False
    writable_by_others = metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    return not writable_by_others or bool(metadata.st_mode & stat.S_ISVTX)


def _validate_directory_fd_with_policy(
    fd: int,
    path: pathlib.Path,
    *,
    private: bool,
) -> tuple[Identity, DirectoryPolicyBinding]:
    metadata_before = os.fstat(fd)
    if private:
        valid = (
            stat.S_ISDIR(metadata_before.st_mode)
            and metadata_before.st_uid == os.getuid()
            and stat.S_IMODE(metadata_before.st_mode) == 0o700
        )
    else:
        valid = _directory_is_trusted_ancestor(metadata_before)
    if not valid:
        raise OSError(errno.EPERM, f"directory metadata is unsafe: {path}")
    macos_metadata = _verify_macos_metadata(
        fd,
        path,
        "directory",
        private=private,
    )
    metadata_after = os.fstat(fd)
    if private:
        still_valid = (
            stat.S_ISDIR(metadata_after.st_mode)
            and metadata_after.st_uid == os.getuid()
            and stat.S_IMODE(metadata_after.st_mode) == 0o700
        )
    else:
        still_valid = _directory_is_trusted_ancestor(metadata_after)
    if not still_valid:
        raise OSError(errno.EPERM, f"directory metadata is unsafe: {path}")
    if directory_stat_binding(metadata_before) != directory_stat_binding(
        metadata_after
    ):
        raise OSError(
            errno.ESTALE,
            f"directory identity or access policy changed: {path}",
        )
    return (
        identity_from_stat(metadata_after),
        _directory_policy_binding(metadata_after, macos_metadata),
    )


def _validate_directory_fd(
    fd: int,
    path: pathlib.Path,
    *,
    private: bool,
) -> Identity:
    identity, _ = _validate_directory_fd_with_policy(
        fd,
        path,
        private=private,
    )
    return identity


def validate_directory_policy_fd(
    fd: int,
    path: pathlib.Path,
    *,
    private: bool,
) -> DirectoryPolicyBinding:
    _, policy = _validate_directory_fd_with_policy(
        fd,
        path,
        private=private,
    )
    return policy


def _validate_regular_fd(
    fd: int,
    path: pathlib.Path,
    *,
    expected_uid: int | None,
    expected_mode: int | None = None,
    require_link_one: bool = True,
    private_metadata: bool = False,
) -> Identity:
    metadata = os.fstat(fd)
    identity = identity_from_stat(metadata)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError(errno.EINVAL, "not a regular file")
    if expected_uid is not None and metadata.st_uid != expected_uid:
        raise OSError(errno.EPERM, "unexpected owner")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise OSError(errno.EPERM, "unexpected mode")
    if require_link_one and metadata.st_nlink != 1:
        raise OSError(errno.EMLINK, "unexpected link count")
    if private_metadata:
        if expected_uid != os.getuid():
            raise ValueError("private metadata validation requires the current owner")
        _verify_macos_metadata(fd, path, "file", private=True)
    return identity


def validate_private_directory_fd(fd: int, path: pathlib.Path) -> Identity:
    return _validate_directory_fd(fd, path, private=True)


def validate_private_regular_fd(
    fd: int,
    path: pathlib.Path,
    *,
    mode: int = 0o600,
) -> Identity:
    return _validate_regular_fd(
        fd,
        path,
        expected_uid=os.getuid(),
        expected_mode=mode,
        private_metadata=True,
    )


def require_private_directory(path: pathlib.Path, *, create: bool = False) -> Identity:
    try:
        fd, identity = open_absolute_directory_chain(
            path,
            create=create,
            private_leaf=True,
        )
    except (OSError, ValueError) as error:
        raise inconclusive(
            f"cannot inspect private directory {path}: {error}",
            stage="admission",
            code="private-directory-unavailable",
        ) from error
    else:
        os.close(fd)
        return identity


def open_directory(path: pathlib.Path) -> int:
    fd, _ = open_absolute_directory_chain(path)
    return fd


def open_directory_at(
    parent_fd: int,
    name: bytes,
    *,
    path_hint: pathlib.Path,
    private: bool = False,
) -> tuple[int, Identity]:
    """Open one child without following links and bind identity plus access policy."""

    if not name or b"/" in name or name in {b".", b".."} or b"\0" in name:
        raise ValueError("invalid directory leaf name")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        path_metadata_before = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        path_identity_before = identity_from_stat(path_metadata_before)
        descriptor_identity, descriptor_policy = _validate_directory_fd_with_policy(
            fd,
            path_hint,
            private=private,
        )
        path_metadata_after = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        path_identity_after = identity_from_stat(path_metadata_after)
        if not (
            directory_identities_match(descriptor_identity, path_identity_before)
            and directory_identities_match(descriptor_identity, path_identity_after)
            and descriptor_policy.stat_binding
            == directory_stat_binding(path_metadata_before)
            == directory_stat_binding(path_metadata_after)
        ):
            raise OSError(errno.ESTALE, "directory path identity changed while opening")
        return fd, descriptor_identity
    except BaseException:
        os.close(fd)
        raise


def canonical_directory_walk_path(path: pathlib.Path) -> pathlib.Path:
    if sys.platform != "darwin" or len(path.parts) < 2:
        return path
    alias = path.parts[1]
    target = DARWIN_ROOT_ALIASES.get(alias)
    if target is None:
        return path
    alias_path = pathlib.Path("/") / alias
    metadata = os.lstat(alias_path)
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or os.readlink(alias_path) != target
    ):
        raise OSError(errno.EPERM, f"trusted Darwin root alias changed: {alias_path}")
    return pathlib.Path("/") / target / pathlib.Path(*path.parts[2:])


@dataclass(slots=True)
class _DirectoryPathEquivalenceSnapshot:
    path: pathlib.Path
    walk_path: pathlib.Path
    prefix: pathlib.Path
    fd: int
    identity: Identity
    policy: DirectoryPolicyBinding
    remaining: tuple[str, ...]

    @property
    def key(self) -> tuple[int, int, tuple[str, ...]]:
        return self.identity.device, self.identity.inode, self.remaining

    def close(self) -> None:
        fd, self.fd = self.fd, -1
        if fd >= 0:
            os.close(fd)


def _open_directory_path_equivalence_snapshot(
    path: pathlib.Path,
) -> _DirectoryPathEquivalenceSnapshot:
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    walk_path = canonical_directory_walk_path(path)
    raw_parts = tuple(os.fsencode(part) for part in walk_path.parts[1:])
    if any(not part or part in {b".", b".."} or b"\0" in part for part in raw_parts):
        raise ValueError("directory path contains a dot component")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(b"/", flags)
    current = pathlib.Path("/")
    try:
        identity, policy = _validate_directory_fd_with_policy(
            fd,
            current,
            private=False,
        )
        for index, part in enumerate(raw_parts):
            current /= os.fsdecode(part)
            try:
                next_fd, next_identity = open_directory_at(
                    fd,
                    part,
                    path_hint=current,
                )
            except FileNotFoundError:
                remaining = tuple(
                    os.fsdecode(candidate).casefold() for candidate in raw_parts[index:]
                )
                return _DirectoryPathEquivalenceSnapshot(
                    path=path,
                    walk_path=walk_path,
                    prefix=current.parent,
                    fd=fd,
                    identity=identity,
                    policy=policy,
                    remaining=remaining,
                )
            os.close(fd)
            fd = next_fd
            identity = next_identity
            policy = validate_directory_policy_fd(
                fd,
                current,
                private=False,
            )
        return _DirectoryPathEquivalenceSnapshot(
            path=path,
            walk_path=walk_path,
            prefix=current,
            fd=fd,
            identity=identity,
            policy=policy,
            remaining=(),
        )
    except BaseException:
        os.close(fd)
        raise


def _revalidate_directory_path_equivalence_snapshot(
    snapshot: _DirectoryPathEquivalenceSnapshot,
) -> None:
    refreshed = _open_directory_path_equivalence_snapshot(snapshot.path)
    try:
        held_identity, held_policy = _validate_directory_fd_with_policy(
            snapshot.fd,
            snapshot.prefix,
            private=False,
        )
        if (
            not directory_identities_match(snapshot.identity, held_identity)
            or not directory_identities_match(snapshot.identity, refreshed.identity)
            or snapshot.policy != held_policy
            or snapshot.policy != refreshed.policy
            or snapshot.remaining != refreshed.remaining
        ):
            raise OSError(
                errno.ESTALE,
                "directory path changed while comparing account-local roots",
            )
    finally:
        refreshed.close()


@dataclass(slots=True)
class DirectoryPathEquivalenceBinding:
    left: _DirectoryPathEquivalenceSnapshot
    right: _DirectoryPathEquivalenceSnapshot
    equivalent: bool
    selected_walk_path: pathlib.Path
    selected_policy: DirectoryPolicyBinding | None = None

    def matches_selected_walk_path(self, walk_path: pathlib.Path) -> bool:
        return walk_path == self.selected_walk_path

    def duplicate_selected_prefix(
        self,
    ) -> tuple[int, pathlib.Path, tuple[bytes, ...]]:
        """Keep selected-root traversal under the originally held prefix object."""

        remaining_count = len(self.left.remaining)
        remaining_parts = (
            self.left.walk_path.parts[-remaining_count:] if remaining_count else ()
        )
        raw_parts = tuple(os.fsencode(part) for part in remaining_parts)
        return os.dup(self.left.fd), self.left.prefix, raw_parts

    @staticmethod
    def _revalidate_held_prefix(
        snapshot: _DirectoryPathEquivalenceSnapshot,
    ) -> None:
        held_identity, held_policy = _validate_directory_fd_with_policy(
            snapshot.fd,
            snapshot.prefix,
            private=False,
        )
        if (
            not directory_identities_match(snapshot.identity, held_identity)
            or snapshot.policy != held_policy
        ):
            raise OSError(
                errno.ESTALE,
                "directory path prefix changed while comparing account-local roots",
            )

    @staticmethod
    def _require_existing_snapshot_stable(
        original: _DirectoryPathEquivalenceSnapshot,
        current: _DirectoryPathEquivalenceSnapshot,
    ) -> None:
        if original.remaining:
            return
        if (
            current.remaining
            or not directory_identities_match(
                original.identity,
                current.identity,
            )
            or original.policy != current.policy
        ):
            raise OSError(
                errno.ESTALE,
                "directory path changed while comparing account-local roots",
            )

    def _revalidate_selected_policy(
        self,
        expected: DirectoryPolicyBinding,
    ) -> None:
        self._revalidate_held_prefix(self.left)
        self._revalidate_held_prefix(self.right)
        current_left = _open_directory_path_equivalence_snapshot(self.left.path)
        try:
            current_right = _open_directory_path_equivalence_snapshot(self.right.path)
            try:
                self._require_existing_snapshot_stable(self.left, current_left)
                self._require_existing_snapshot_stable(self.right, current_right)
                if current_left.remaining:
                    raise OSError(
                        errno.ESTALE,
                        "selected retention root is unavailable after path binding",
                    )
                strict_left_policy = validate_directory_policy_fd(
                    current_left.fd,
                    self.left.path,
                    private=True,
                )
                if (
                    current_left.policy != strict_left_policy
                    or expected != strict_left_policy
                ):
                    raise OSError(
                        errno.ESTALE,
                        "selected retention root changed after path binding",
                    )
                if (current_left.key == current_right.key) != self.equivalent:
                    raise OSError(
                        errno.ESTALE,
                        "retention root equivalence changed after path binding",
                    )
            finally:
                current_right.close()
        finally:
            current_left.close()

    def validate_before_selected_open(self) -> None:
        if self.selected_policy is None:
            _revalidate_directory_path_equivalence_snapshot(self.left)
            _revalidate_directory_path_equivalence_snapshot(self.right)
            return
        self._revalidate_selected_policy(self.selected_policy)

    def bind_selected_open(self, fd: int, identity: Identity) -> None:
        strict_policy = validate_directory_policy_fd(
            fd,
            self.left.path,
            private=True,
        )
        if (
            identity.device != strict_policy.device
            or identity.inode != strict_policy.inode
            or stat.S_IFMT(identity.mode) != strict_policy.file_type
            or identity.uid != strict_policy.uid
            or stat.S_IMODE(identity.mode) != strict_policy.mode
        ):
            raise OSError(
                errno.ESTALE,
                "selected retention root changed while being opened",
            )
        if self.selected_policy is not None and self.selected_policy != strict_policy:
            raise OSError(
                errno.ESTALE,
                "selected retention root changed after path binding",
            )
        self._revalidate_selected_policy(strict_policy)
        self.selected_policy = strict_policy

    def revalidate(self) -> None:
        if self.selected_policy is None:
            _revalidate_directory_path_equivalence_snapshot(self.left)
            _revalidate_directory_path_equivalence_snapshot(self.right)
            return
        self._revalidate_selected_policy(self.selected_policy)

    def close(self) -> None:
        cleanup_errors: list[OSError] = []
        for snapshot in (self.right, self.left):
            try:
                snapshot.close()
            except OSError as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            primary_error = cleanup_errors[0]
            for secondary_error in cleanup_errors[1:]:
                record_secondary_error(
                    primary_error,
                    label="directory path binding cleanup failed",
                    secondary_error=secondary_error,
                )
            raise primary_error


_ACTIVE_DIRECTORY_PATH_EQUIVALENCE_BINDING: contextvars.ContextVar[
    DirectoryPathEquivalenceBinding | None
] = contextvars.ContextVar(
    "active_directory_path_equivalence_binding",
    default=None,
)


def _open_directory_path_equivalence_binding(
    left: pathlib.Path,
    right: pathlib.Path,
) -> DirectoryPathEquivalenceBinding:
    left_snapshot = _open_directory_path_equivalence_snapshot(left)
    try:
        right_snapshot = _open_directory_path_equivalence_snapshot(right)
    except BaseException as error:
        try:
            left_snapshot.close()
        except BaseException as cleanup_error:
            record_secondary_error(
                error,
                label="directory path binding setup cleanup failed",
                secondary_error=cleanup_error,
            )
        raise
    binding = DirectoryPathEquivalenceBinding(
        left=left_snapshot,
        right=right_snapshot,
        equivalent=left_snapshot.key == right_snapshot.key,
        selected_walk_path=left_snapshot.walk_path,
    )
    try:
        binding.revalidate()
        return binding
    except BaseException as error:
        try:
            binding.close()
        except BaseException as cleanup_error:
            record_secondary_error(
                error,
                label="directory path binding setup cleanup failed",
                secondary_error=cleanup_error,
            )
        raise


@contextlib.contextmanager
def bind_directory_path_equivalence(
    left: pathlib.Path,
    right: pathlib.Path,
) -> Iterator[DirectoryPathEquivalenceBinding]:
    if _ACTIVE_DIRECTORY_PATH_EQUIVALENCE_BINDING.get() is not None:
        raise RuntimeError("directory path equivalence binding is already active")
    binding = _open_directory_path_equivalence_binding(left, right)
    token = _ACTIVE_DIRECTORY_PATH_EQUIVALENCE_BINDING.set(binding)
    primary_error: BaseException | None = None
    try:
        yield binding
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _ACTIVE_DIRECTORY_PATH_EQUIVALENCE_BINDING.reset(token)
        try:
            binding.close()
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            record_secondary_error(
                primary_error,
                label="directory path equivalence binding cleanup failed",
                secondary_error=cleanup_error,
            )


def directory_paths_equivalent(
    left: pathlib.Path,
    right: pathlib.Path,
) -> bool:
    """Bind existing prefixes by device/inode and case-fold only missing suffixes."""

    binding = _open_directory_path_equivalence_binding(left, right)
    try:
        return binding.equivalent
    finally:
        binding.close()


def open_absolute_directory_chain(
    path: pathlib.Path,
    *,
    create: bool = False,
    private_leaf: bool = False,
    allow_sticky_writable_ancestors: bool = True,
) -> tuple[int, Identity]:
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    walk_path = canonical_directory_walk_path(path)
    raw_parts = tuple(os.fsencode(part) for part in walk_path.parts[1:])
    if any(not part or part in {b".", b".."} or b"\0" in part for part in raw_parts):
        raise ValueError("directory path contains a dot component")
    active_binding = _ACTIVE_DIRECTORY_PATH_EQUIVALENCE_BINDING.get()
    selected_path = (
        allow_sticky_writable_ancestors
        and active_binding is not None
        and active_binding.matches_selected_walk_path(walk_path)
    )
    if selected_path:
        active_binding.validate_before_selected_open()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    if selected_path:
        fd, current, raw_parts = active_binding.duplicate_selected_prefix()
    else:
        fd = os.open(b"/", flags)
        current = pathlib.Path("/")
    try:
        identity, root_policy = _validate_directory_fd_with_policy(
            fd,
            current,
            private=private_leaf and not raw_parts,
        )
        if not allow_sticky_writable_ancestors and root_policy.mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise OSError(
                errno.EPERM,
                f"directory ancestor is group- or world-writable: {current}",
            )
        for index, part in enumerate(raw_parts):
            current /= os.fsdecode(part)
            created = False
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                os.fsync(fd)
                created = True
                next_fd = os.open(part, flags, dir_fd=fd)
            try:
                descriptor_identity, descriptor_policy = (
                    _validate_directory_fd_with_policy(
                        next_fd,
                        current,
                        private=created
                        or (private_leaf and index == len(raw_parts) - 1),
                    )
                )
                if not allow_sticky_writable_ancestors and descriptor_policy.mode & (
                    stat.S_IWGRP | stat.S_IWOTH
                ):
                    raise OSError(
                        errno.EPERM,
                        f"directory ancestor is group- or world-writable: {current}",
                    )
                path_metadata = os.stat(
                    part,
                    dir_fd=fd,
                    follow_symlinks=False,
                )
                path_identity = identity_from_stat(path_metadata)
                if not directory_identities_match(
                    descriptor_identity,
                    path_identity,
                ) or descriptor_policy.stat_binding != directory_stat_binding(
                    path_metadata
                ):
                    raise OSError(errno.ESTALE, "directory path identity changed")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
            identity = descriptor_identity
        if selected_path:
            active_binding.bind_selected_open(fd, identity)
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def open_regular_at(
    parent_fd: int,
    name: bytes,
    *,
    writable: bool = False,
    expected_uid: int | None = None,
    require_link_one: bool = True,
    private_metadata: bool = False,
) -> tuple[int, Identity]:
    if not name or b"/" in name or name in {b".", b".."} or b"\0" in name:
        raise ValueError("invalid leaf name")
    flags = (
        (os.O_RDWR if writable else os.O_RDONLY)
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = _validate_regular_fd(
            fd,
            pathlib.Path(os.fsdecode(name)),
            expected_uid=expected_uid,
            require_link_one=require_link_one,
            private_metadata=private_metadata,
        )
        if identity != identity_from_stat(path_stat):
            raise OSError(errno.ESTALE, "path identity changed while opening")
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def open_regular_nofollow(
    path: pathlib.Path,
    *,
    writable: bool = False,
    expected_uid: int | None = None,
    require_link_one: bool = True,
    private_metadata: bool = False,
) -> tuple[int, Identity]:
    flags = (
        (os.O_RDWR if writable else os.O_RDONLY)
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    fd = os.open(path, flags)
    try:
        path_metadata = os.lstat(path)
        identity = _validate_regular_fd(
            fd,
            path,
            expected_uid=expected_uid,
            require_link_one=require_link_one,
            private_metadata=private_metadata,
        )
        if identity != identity_from_stat(path_metadata):
            raise OSError(errno.ESTALE, "path identity changed while opening")
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def read_fd_exact(
    fd: int, *, max_bytes: int, expected_size: int | None = None
) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(READ_CHUNK, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"artifact exceeds {max_bytes} bytes")
        chunks.append(chunk)
    if expected_size is not None and total != expected_size:
        raise ValueError(
            f"artifact length changed: expected {expected_size}, got {total}"
        )
    return b"".join(chunks)


def stream_sha256(fd: int, *, expected_size: int, sink_fd: int | None = None) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(fd, min(READ_CHUNK, remaining))
        if not chunk:
            raise ValueError("artifact ended before its attested length")
        digest.update(chunk)
        if sink_fd is not None:
            write_all(sink_fd, chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise ValueError("artifact contains bytes beyond its attested length")
    return digest.hexdigest()


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path, *, max_bytes: int) -> tuple[int, str]:
    fd, identity = open_regular_nofollow(path, expected_uid=os.getuid())
    try:
        if identity.size > max_bytes:
            raise ValueError(f"artifact exceeds {max_bytes} bytes")
        digest = stream_sha256(fd, expected_size=identity.size)
        return identity.size, digest
    finally:
        os.close(fd)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _validate_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep")
    if isinstance(value, dict):
        for child in value.values():
            _validate_json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth + 1)


def decode_json_bytes(value: bytes) -> Any:
    if b"\0" in value:
        raise ValueError("JSON contains NUL")
    text = value.decode("utf-8", "strict")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_json_constant,
            parse_float=_parse_finite_json_float,
        )
        _validate_json_depth(parsed)
    except RecursionError as error:
        raise ValueError("JSON nesting is too deep") from error
    return parsed


def read_json_nofollow(
    path: pathlib.Path,
    *,
    max_bytes: int,
    expected_uid: int | None = None,
) -> tuple[Any, bytes, Identity]:
    fd, identity = open_regular_nofollow(path, expected_uid=expected_uid)
    try:
        raw = read_fd_exact(fd, max_bytes=max_bytes, expected_size=identity.size)
    finally:
        os.close(fd)
    return decode_json_bytes(raw), raw, identity


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def rename_noreplace(
    source_dir_fd: int,
    source: bytes,
    destination_dir_fd: int,
    destination: bytes,
) -> None:
    libc = _libc()
    system = platform.system()
    if system == "Linux" and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(source_dir_fd, source, destination_dir_fd, destination, 1)
    elif system == "Darwin" and hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            source_dir_fd, source, destination_dir_fd, destination, 0x00000004
        )
    else:
        raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def rename_exchange(
    left_dir_fd: int,
    left: bytes,
    right_dir_fd: int,
    right: bytes,
) -> None:
    libc = _libc()
    system = platform.system()
    if system == "Linux" and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(left_dir_fd, left, right_dir_fd, right, 2)
    elif system == "Darwin" and hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(left_dir_fd, left, right_dir_fd, right, 0x00000002)
    else:
        raise OSError(errno.ENOTSUP, "atomic exchange rename is unavailable")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def atomic_write_json_at(
    parent_fd: int,
    destination: bytes,
    value: Any,
    *,
    replace: bool,
    path_hint: pathlib.Path,
) -> tuple[Identity, str]:
    if (
        not destination
        or b"/" in destination
        or destination in {b".", b".."}
        or b"\0" in destination
    ):
        raise ValueError("invalid JSON destination name")
    data = canonical_json(value)
    temp_name = (
        b"." + destination + f".tmp-{os.getpid()}-{os.urandom(8).hex()}".encode("ascii")
    )
    temp_fd: int | None = None
    try:
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        write_all(temp_fd, data)
        os.fsync(temp_fd)
        written_identity = _validate_regular_fd(
            temp_fd,
            path_hint.parent / os.fsdecode(temp_name),
            expected_uid=os.getuid(),
            expected_mode=0o600,
            private_metadata=True,
        )
        if written_identity.size != len(data):
            raise OSError(errno.EINVAL, "temporary state length is unsafe")
        os.close(temp_fd)
        temp_fd = None
        if replace:
            os.rename(
                temp_name, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
        else:
            rename_noreplace(parent_fd, temp_name, parent_fd, destination)
        os.fsync(parent_fd)
        fd = os.open(
            destination, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        try:
            identity = _validate_regular_fd(
                fd,
                path_hint,
                expected_uid=os.getuid(),
                expected_mode=0o600,
                private_metadata=True,
            )
            if identity != written_identity:
                raise OSError(errno.ESTALE, "published state identity changed")
            actual = read_fd_exact(fd, max_bytes=len(data), expected_size=len(data))
            if actual != data:
                raise OSError(errno.EIO, "published state readback mismatch")
        finally:
            os.close(fd)
        return identity, sha256_bytes(data)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def atomic_write_json(
    path: pathlib.Path, value: Any, *, replace: bool
) -> tuple[Identity, str]:
    parent_fd, _ = open_absolute_directory_chain(path.parent, private_leaf=True)
    try:
        return atomic_write_json_at(
            parent_fd,
            os.fsencode(path.name),
            value,
            replace=replace,
            path_hint=path,
        )
    finally:
        os.close(parent_fd)


def publish_bytes_at(
    parent_fd: int,
    name: bytes,
    data: bytes,
    *,
    path_hint: pathlib.Path,
    mode: int = 0o600,
) -> Identity:
    if not name or b"/" in name or name in {b".", b".."} or b"\0" in name:
        raise ValueError("invalid publication name")
    temp_name = (
        b"." + name + f".tmp-{os.getpid()}-{os.urandom(8).hex()}".encode("ascii")
    )
    temp_fd: int | None = None
    try:
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=parent_fd,
        )
        write_all(temp_fd, data)
        os.fsync(temp_fd)
        written_identity = _validate_regular_fd(
            temp_fd,
            path_hint.parent / os.fsdecode(temp_name),
            expected_uid=os.getuid(),
            expected_mode=mode,
            private_metadata=True,
        )
        if written_identity.size != len(data):
            raise OSError(errno.EINVAL, "temporary artifact metadata is unsafe")
        os.close(temp_fd)
        temp_fd = None
        rename_noreplace(parent_fd, temp_name, parent_fd, name)
        os.fsync(parent_fd)
        read_fd = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        try:
            read_identity = _validate_regular_fd(
                read_fd,
                path_hint,
                expected_uid=os.getuid(),
                expected_mode=mode,
                private_metadata=True,
            )
            if written_identity != read_identity:
                raise OSError(errno.ESTALE, "published artifact identity changed")
            actual = read_fd_exact(
                read_fd, max_bytes=len(data), expected_size=len(data)
            )
            if actual != data:
                raise OSError(errno.EIO, "published artifact readback mismatch")
        finally:
            os.close(read_fd)
        return read_identity
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def publish_bytes(path: pathlib.Path, data: bytes, *, mode: int = 0o600) -> Identity:
    parent_fd, _ = open_absolute_directory_chain(path.parent, private_leaf=True)
    try:
        return publish_bytes_at(
            parent_fd,
            os.fsencode(path.name),
            data,
            path_hint=path,
            mode=mode,
        )
    finally:
        os.close(parent_fd)


def acquire_flock(fd: int, operation: int, *, deadline: float) -> None:
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise TimeoutError("BSD flock deadline expired")
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def measure_filesystem_fd(directory_fd: int) -> FilesystemMeasure:
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("filesystem measurement root is not a directory")
    values = os.fstatvfs(directory_fd)
    allocation_unit = max(4096, values.f_frsize or values.f_bsize)
    free_bytes = values.f_bavail * (values.f_frsize or values.f_bsize)
    fsid = getattr(values, "f_fsid", None)
    identity = f"dev:{metadata.st_dev}:fsid:{fsid if fsid is not None else 'unknown'}"
    return FilesystemMeasure(
        identity=identity,
        device=metadata.st_dev,
        allocation_unit=allocation_unit,
        free_bytes=free_bytes,
    )


def measure_filesystem(path: pathlib.Path) -> FilesystemMeasure:
    directory_fd = open_directory(path)
    try:
        return measure_filesystem_fd(directory_fd)
    finally:
        os.close(directory_fd)


def allocated_bytes_fd(directory_fd: int, *, entry_cap: int = 200_000) -> int:
    root_metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("allocated-byte inventory root is not a directory")
    total = root_metadata.st_blocks * 512
    count = 1
    stack = [os.dup(directory_fd)]
    try:
        while stack:
            current_fd = stack.pop()
            try:
                scan_fd = os.dup(current_fd)
                try:
                    with os.scandir(scan_fd) as iterator:
                        for entry in iterator:
                            name = os.fsencode(entry.name)
                            if not name or b"/" in name or b"\0" in name:
                                raise ValueError(
                                    "allocated-byte inventory returned an invalid entry"
                                )
                            count += 1
                            if count > entry_cap:
                                raise ValueError(
                                    "allocated-byte inventory exceeds entry cap"
                                )
                            metadata = os.stat(
                                name,
                                dir_fd=current_fd,
                                follow_symlinks=False,
                            )
                            total = checked_add(total, metadata.st_blocks * 512)
                            if stat.S_ISDIR(metadata.st_mode):
                                child_fd = os.open(
                                    name,
                                    os.O_RDONLY
                                    | os.O_DIRECTORY
                                    | os.O_CLOEXEC
                                    | os.O_NOFOLLOW,
                                    dir_fd=current_fd,
                                )
                                child_identity = identity_from_stat(os.fstat(child_fd))
                                if not directory_identities_match(
                                    child_identity,
                                    identity_from_stat(metadata),
                                ):
                                    os.close(child_fd)
                                    raise OSError(
                                        errno.ESTALE,
                                        "allocated-byte directory identity changed",
                                    )
                                stack.append(child_fd)
                finally:
                    os.close(scan_fd)
            finally:
                os.close(current_fd)
        return total
    finally:
        for pending_fd in stack:
            os.close(pending_fd)


def allocated_bytes(path: pathlib.Path, *, entry_cap: int = 200_000) -> int:
    directory_fd = open_directory(path)
    try:
        return allocated_bytes_fd(directory_fd, entry_cap=entry_cap)
    finally:
        os.close(directory_fd)


def raw_directory_entries(path: pathlib.Path, *, cap: int) -> tuple[bytes, ...]:
    fd = open_directory(path)
    try:
        names = os.listdir(fd)
    finally:
        os.close(fd)
    if len(names) > cap:
        raise ValueError("directory entry count exceeds cap")
    encoded = tuple(os.fsencode(name) for name in names)
    if any(b"/" in name or b"\0" in name or not name for name in encoded):
        raise ValueError("directory returned an invalid raw entry name")
    return encoded


def _darwin_boot_access_policy_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
    )


def _darwin_boot_content_stability_key(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    return (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_trusted_boot_marker_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != DARWIN_BOOT_SESSION_MARKER_MODE
        or getattr(metadata, "st_flags", 0) != 0
        or not 1 <= metadata.st_size <= 128
    ):
        raise ValueError("Darwin boot-session marker access policy is unsafe")


def _require_trusted_boot_parent_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != DARWIN_BOOT_SESSION_PARENT_GID
        or stat.S_IMODE(metadata.st_mode) != DARWIN_BOOT_SESSION_PARENT_MODE
        or getattr(metadata, "st_flags", 0) != 0
    ):
        raise ValueError("Darwin boot-session marker parent access policy is unsafe")


def _open_darwin_boot_marker_parent(marker: pathlib.Path) -> tuple[int, Identity]:
    if marker != DARWIN_BOOT_SESSION_MARKER:
        raise ValueError("Darwin boot-session marker path is invalid")
    ancestor_fd, _ = open_absolute_directory_chain(marker.parent.parent)
    parent_fd: int | None = None
    try:
        raw_parent_name = os.fsencode(marker.parent.name)
        parent_fd = os.open(
            raw_parent_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=ancestor_fd,
        )
        descriptor_metadata = os.fstat(parent_fd)
        path_metadata = os.stat(
            raw_parent_name,
            dir_fd=ancestor_fd,
            follow_symlinks=False,
        )
        _require_trusted_boot_parent_metadata(descriptor_metadata)
        _require_trusted_boot_parent_metadata(path_metadata)
        descriptor_identity = identity_from_stat(descriptor_metadata)
        path_identity = identity_from_stat(path_metadata)
        if not directory_identities_match(descriptor_identity, path_identity):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker parent identity changed while opening",
            )
        _verify_macos_metadata(parent_fd, marker.parent, "directory", private=False)
        return parent_fd, descriptor_identity
    except BaseException:
        if parent_fd is not None:
            os.close(parent_fd)
        raise
    finally:
        os.close(ancestor_fd)


def _read_darwin_boot_session_marker(
    marker: pathlib.Path = DARWIN_BOOT_SESSION_MARKER,
) -> bytes:
    if marker != DARWIN_BOOT_SESSION_MARKER:
        raise ValueError("Darwin boot-session marker path is invalid")
    parent_fd, parent_identity = _open_darwin_boot_marker_parent(marker)
    marker_fd: int | None = None
    refreshed_parent_fd: int | None = None
    try:
        marker_fd, opened_identity = open_regular_at(
            parent_fd,
            os.fsencode(marker.name),
            expected_uid=0,
            require_link_one=True,
        )
        opened_metadata = os.fstat(marker_fd)
        _require_trusted_boot_marker_metadata(opened_metadata)
        opened_access_policy = _darwin_boot_access_policy_key(opened_metadata)
        opened_content_stability = _darwin_boot_content_stability_key(opened_metadata)
        before = identity_from_stat(opened_metadata)
        if before != opened_identity:
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker identity changed after opening",
            )
        first_metadata = _verify_macos_metadata(
            marker_fd,
            marker,
            "file",
            private=False,
            extra_permitted_xattrs=DARWIN_BOOT_SESSION_MARKER_XATTRS,
        )
        first = read_fd_exact(
            marker_fd,
            max_bytes=128,
            expected_size=opened_identity.size,
        )
        middle_metadata = os.fstat(marker_fd)
        _require_trusted_boot_marker_metadata(middle_metadata)
        middle = identity_from_stat(middle_metadata)
        second_metadata = _verify_macos_metadata(
            marker_fd,
            marker,
            "file",
            private=False,
            extra_permitted_xattrs=DARWIN_BOOT_SESSION_MARKER_XATTRS,
        )
        second = read_fd_exact(
            marker_fd,
            max_bytes=128,
            expected_size=opened_identity.size,
        )
        after_read_metadata = os.fstat(marker_fd)
        _require_trusted_boot_marker_metadata(after_read_metadata)
        final_extended_metadata = _verify_macos_metadata(
            marker_fd,
            marker,
            "file",
            private=False,
            extra_permitted_xattrs=DARWIN_BOOT_SESSION_MARKER_XATTRS,
        )
        final_metadata = os.fstat(marker_fd)
        path_after_metadata = os.stat(
            os.fsencode(marker.name),
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        _require_trusted_boot_marker_metadata(final_metadata)
        _require_trusted_boot_marker_metadata(path_after_metadata)
        after_read = identity_from_stat(after_read_metadata)
        final = identity_from_stat(final_metadata)
        path_after = identity_from_stat(path_after_metadata)
        if any(
            identity != opened_identity
            for identity in (middle, after_read, final, path_after)
        ):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker identity or access policy changed",
            )
        if any(
            _darwin_boot_access_policy_key(metadata) != opened_access_policy
            for metadata in (
                middle_metadata,
                after_read_metadata,
                final_metadata,
                path_after_metadata,
            )
        ):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker access policy changed",
            )
        if any(
            _darwin_boot_content_stability_key(metadata) != opened_content_stability
            for metadata in (
                middle_metadata,
                after_read_metadata,
                final_metadata,
                path_after_metadata,
            )
        ):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker content metadata changed",
            )
        if not (first_metadata == second_metadata == final_extended_metadata):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker extended metadata changed",
            )
        if first != second:
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker content changed while reading",
            )
        refreshed_parent_fd, refreshed_parent_identity = (
            _open_darwin_boot_marker_parent(marker)
        )
        if not directory_identities_match(
            parent_identity,
            refreshed_parent_identity,
        ):
            raise OSError(
                errno.ESTALE,
                "Darwin boot-session marker parent path changed while reading",
            )
        return second.strip()
    finally:
        if refreshed_parent_fd is not None:
            os.close(refreshed_parent_fd)
        if marker_fd is not None:
            os.close(marker_fd)
        os.close(parent_fd)


def boot_identifier() -> str:
    linux_path = pathlib.Path("/proc/sys/kernel/random/boot_id")
    if linux_path.is_file():
        raw = linux_path.read_bytes()
        if len(raw) > 128:
            raise ValueError("Linux boot identifier is oversized")
        return "linux:" + sha256_bytes(raw.strip())
    if platform.system() == "Darwin":

        class Timeval(ctypes.Structure):
            _fields_ = (("seconds", ctypes.c_long), ("microseconds", ctypes.c_int))

        libc = _libc()
        if hasattr(libc, "sysctlbyname"):
            function = libc.sysctlbyname
            function.argtypes = [
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            function.restype = ctypes.c_int
            value = Timeval()
            length = ctypes.c_size_t(ctypes.sizeof(value))
            if (
                function(
                    b"kern.boottime",
                    ctypes.byref(value),
                    ctypes.byref(length),
                    None,
                    0,
                )
                == 0
                and length.value == ctypes.sizeof(value)
                and value.seconds > 0
                and 0 <= value.microseconds < 1_000_000
            ):
                raw = f"{value.seconds}:{value.microseconds}".encode("ascii")
                return "darwin-kern-boottime:" + sha256_bytes(raw)

        raw = _read_darwin_boot_session_marker()
        try:
            marker_text = raw.decode("ascii", "strict")
            uuid.UUID(marker_text)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Darwin boot-session marker is malformed") from error
        return "darwin-boot-session:" + sha256_bytes(raw)
    raise ValueError("boot identity is unsupported on this platform")


def fsync_directory(path: pathlib.Path) -> None:
    fd = open_directory(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bounded_tail(path: pathlib.Path, limit: int) -> bytes:
    fd, identity = open_regular_nofollow(path, expected_uid=os.getuid())
    try:
        offset = max(0, identity.size - limit)
        os.lseek(fd, offset, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = min(identity.size, limit)
        while remaining:
            chunk = os.read(fd, min(READ_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def checked_add(*values: int, limit: int = (1 << 63) - 1) -> int:
    total = 0
    for value in values:
        if value < 0 or total > limit - value:
            raise OverflowError("bounded accounting integer overflow")
        total += value
    return total


def checked_mul(left: int, right: int, *, limit: int = (1 << 63) - 1) -> int:
    if left < 0 or right < 0 or (left and right > limit // left):
        raise OverflowError("bounded accounting integer overflow")
    return left * right


def align_up(value: int, unit: int) -> int:
    if value < 0 or unit <= 0:
        raise ValueError("invalid alignment inputs")
    remainder = value % unit
    return value if remainder == 0 else checked_add(value, unit - remainder)


def ensure_no_path_value(values: Iterable[str], forbidden: pathlib.Path) -> None:
    needle = os.fsdecode(os.fsencode(forbidden))
    for value in values:
        if needle and needle in value:
            raise ValueError(
                "retained helper workspace path appears in reviewer environment"
            )
