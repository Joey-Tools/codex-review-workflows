#!/usr/bin/env python3
from __future__ import annotations

import sys


if sys.version_info < (3, 10):
    print(
        "active catalog binding requires Python 3.10 or later",
        file=sys.stderr,
    )
    raise SystemExit(2)

if not (
    sys.flags.isolated
    and sys.flags.ignore_environment
    and sys.flags.no_site
    and sys.flags.no_user_site
    and sys.flags.dont_write_bytecode
):
    print(
        "active catalog binding requires an absolute Python interpreter "
        "invoked with -I -B -S",
        file=sys.stderr,
    )
    raise SystemExit(2)

# Import only after isolated-mode admission. In particular, a resolver-local or
# current-directory json.py/argparse.py must never execute before validation.
import argparse
import contextlib
import errno
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import types
from typing import Any


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_CATALOG_BYTES = 64 * 1024
MAX_INTERPRETER_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_FILES = 8
MAX_CLI_OUTPUT_BYTES = 1024 * 1024
RELEASE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_NAMESPACE = "review_runtime"
BOOTSTRAP_CONTRACT_VERSION = 1
RUNTIME_MANIFEST_SCHEMA_VERSION = 1
RUNTIME_PROFILE = "synthetic-catalog-authoring-v1"
RUNTIME_MANIFEST_LEAF = "synthetic-catalog-runtime-manifest.json"
RUNTIME_ENTRY_PATH = "scripts/synthetic_catalog_entry"
CONTROL_RUNTIME_INIT_PATH = "scripts/review_runtime/__init__.py"
CONTROL_BOOTSTRAP_PATH = "scripts/review_runtime/catalog_bootstrap.py"
CONTROL_RESOLVER_PATH = "scripts/active_catalog_binding.py"
RUNTIME_SOURCE_PATHS = {
    "review_runtime": ("scripts/review_runtime/__init__.py", True),
    "review_runtime.common": ("scripts/review_runtime/common.py", False),
    "review_runtime.cli": ("scripts/review_runtime/cli.py", False),
    "review_runtime.synthetic_tokens": (
        "scripts/review_runtime/synthetic_tokens.py",
        False,
    ),
}
RUNTIME_DATA_PATHS = {
    "synthetic-token-catalog": ("scripts/review_runtime/synthetic-token-catalog.json"),
}
# These local filesystems expose either no ACL or Linux POSIX ACL semantics,
# where the ACL mask is the inode's group mode class. Remote, programmable,
# and unclassified stacked filesystems are deliberately absent because
# fstatfs alone cannot prove that richer ACLs are constrained by those bits.
_LINUX_POSIX_ACL_FILESYSTEMS = {
    0x0000EF53: "ext2/ext3/ext4",
    0x01021994: "tmpfs",
    0x58465342: "XFS",
    0x858458F6: "ramfs",
    0x9123683E: "Btrfs",
    0xF2F52010: "F2FS",
}
_LINUX_UNVERIFIED_ACL_FILESYSTEMS = {
    0x01021997: "9P",
    0x2FC12FC1: "ZFS",
    0x5346414F: "AFS",
    0x65735546: "FUSE",
    0x00006969: "NFS/NFSv4",
    0x73757245: "CODA",
    0x794C7630: "overlayfs",
    0xFF534D42: "CIFS/SMB",
}
_DARWIN_ACL_TYPE_EXTENDED = 0x00000100
_DARWIN_ACL_FIRST_ENTRY = 0
_DARWIN_ACL_NEXT_ENTRY = -1
_DARWIN_ACL_EXTENDED_ALLOW = 1
_DARWIN_ACL_EXTENDED_DENY = 2
_DARWIN_MUTATING_ACL_PERMISSIONS = (
    (1 << 2)  # WRITE_DATA / ADD_FILE
    | (1 << 4)  # DELETE
    | (1 << 5)  # APPEND_DATA / ADD_SUBDIRECTORY
    | (1 << 6)  # DELETE_CHILD
    | (1 << 8)  # WRITE_ATTRIBUTES
    | (1 << 10)  # WRITE_EXTATTRIBUTES
    | (1 << 12)  # WRITE_SECURITY
    | (1 << 13)  # CHANGE_OWNER
)
# Bind only flags that change write, unlink, namespace, or protected-data
# semantics. NODUMP, COMPRESSED, TRACKED, HIDDEN, and ARCHIVED are deliberately
# excluded because their churn does not change the protected access property.
_DARWIN_ACCESS_POLICY_FLAGS = (
    0x00000002  # UF_IMMUTABLE
    | 0x00000004  # UF_APPEND
    | 0x00000008  # UF_OPAQUE
    | 0x00000010  # UF_NOUNLINK
    | 0x00000080  # UF_DATAVAULT
    | 0x00020000  # SF_IMMUTABLE
    | 0x00040000  # SF_APPEND
    | 0x00080000  # SF_RESTRICTED
    | 0x00100000  # SF_NOUNLINK
    | 0x00200000  # SF_SNAPSHOT
    | 0x00800000  # SF_FIRMLINK
    | 0xC0000000  # SF_SYNTHETIC, including SF_DATALESS
)
_DARWIN_BENIGN_METADATA_FLAGS = (
    0x00000001  # UF_NODUMP
    | 0x00000020  # UF_COMPRESSED
    | 0x00000040  # UF_TRACKED
    | 0x00008000  # UF_HIDDEN
    | 0x00010000  # SF_ARCHIVED
)
_DARWIN_KNOWN_STAT_FLAGS = _DARWIN_ACCESS_POLICY_FLAGS | _DARWIN_BENIGN_METADATA_FLAGS
_LINUX_STATFS_API: tuple[Any, Any] | None = None
_DARWIN_ACL_API: tuple[Any, Any] | None = None


class BindingError(RuntimeError):
    pass


def _linux_statfs_api() -> tuple[Any, Any]:
    global _LINUX_STATFS_API
    if not sys.platform.startswith("linux"):
        raise BindingError(
            "Linux filesystem inspection was requested on another platform"
        )
    if _LINUX_STATFS_API is not None:
        return _LINUX_STATFS_API
    try:
        import ctypes

        library = ctypes.CDLL(None, use_errno=True)
        library.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        library.fstatfs.restype = ctypes.c_int
    except (AttributeError, ImportError, OSError) as error:
        raise BindingError(
            f"Linux filesystem inspection primitives are unavailable: {error}"
        ) from error
    _LINUX_STATFS_API = ctypes, library
    return _LINUX_STATFS_API


def _linux_filesystem_type(descriptor: int, *, label: str) -> int:
    ctypes, library = _linux_statfs_api()
    # Linux struct statfs is smaller than this aligned buffer on every
    # supported libc ABI. Its first __fsword_t is the filesystem magic.
    storage = (ctypes.c_long * 128)()
    ctypes.set_errno(0)
    if library.fstatfs(descriptor, ctypes.byref(storage)) != 0:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "unknown error"
        raise BindingError(
            f"{label} filesystem ACL semantics cannot be inspected: "
            f"fstatfs failed: {detail}"
        )
    return int(storage[0]) & 0xFFFFFFFF


def _require_linux_posix_acl_filesystem(
    filesystem_type: int,
    *,
    label: str,
) -> None:
    normalized = filesystem_type & 0xFFFFFFFF
    if normalized in _LINUX_POSIX_ACL_FILESYSTEMS:
        return
    filesystem_name = _LINUX_UNVERIFIED_ACL_FILESYSTEMS.get(
        normalized,
        "unknown",
    )
    raise BindingError(
        f"{label} filesystem {filesystem_name} (0x{normalized:08x}) "
        "has unverified ACL semantics"
    )


def _darwin_acl_api() -> tuple[Any, Any]:
    global _DARWIN_ACL_API
    if sys.platform != "darwin":
        raise BindingError("Darwin ACL inspection was requested on another platform")
    if _DARWIN_ACL_API is not None:
        return _DARWIN_ACL_API
    try:
        import ctypes

        library = ctypes.CDLL(None, use_errno=True)
        library.acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
        library.acl_get_fd_np.restype = ctypes.c_void_p
        library.acl_valid.argtypes = (ctypes.c_void_p,)
        library.acl_valid.restype = ctypes.c_int
        library.acl_get_entry.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        )
        library.acl_get_entry.restype = ctypes.c_int
        library.acl_get_tag_type.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        )
        library.acl_get_tag_type.restype = ctypes.c_int
        library.acl_get_permset_mask_np.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
        )
        library.acl_get_permset_mask_np.restype = ctypes.c_int
        library.acl_get_qualifier.argtypes = (ctypes.c_void_p,)
        library.acl_get_qualifier.restype = ctypes.c_void_p
        library.acl_free.argtypes = (ctypes.c_void_p,)
        library.acl_free.restype = ctypes.c_int
        library.mbr_uid_to_uuid.argtypes = (
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
        )
        library.mbr_uid_to_uuid.restype = ctypes.c_int
    except (AttributeError, ImportError, OSError) as error:
        raise BindingError(
            f"Darwin ACL inspection primitives are unavailable: {error}"
        ) from error
    _DARWIN_ACL_API = ctypes, library
    return _DARWIN_ACL_API


def _darwin_acl_error(operation: str) -> str:
    ctypes, _library = _darwin_acl_api()
    error_number = ctypes.get_errno()
    detail = os.strerror(error_number) if error_number else "unknown error"
    return f"{operation} failed: {detail}"


def _darwin_owner_uuid(uid: int, *, label: str) -> bytes:
    ctypes, library = _darwin_acl_api()
    owner_uuid = (ctypes.c_ubyte * 16)()
    result = library.mbr_uid_to_uuid(uid, owner_uuid)
    if result != 0:
        detail = os.strerror(result) if result > 0 else f"status {result}"
        raise BindingError(f"{label} owner UUID cannot be resolved: {detail}")
    return bytes(owner_uuid)


def _validate_darwin_acl(
    descriptor: int,
    *,
    owner_uid: int,
    label: str,
) -> None:
    ctypes, library = _darwin_acl_api()
    ctypes.set_errno(0)
    acl = library.acl_get_fd_np(descriptor, _DARWIN_ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise BindingError(
            f"{label} access policy cannot be inspected: "
            f"{_darwin_acl_error('acl_get_fd_np')}"
        )
    try:
        if library.acl_valid(acl) != 0:
            raise BindingError(
                f"{label} access policy is invalid: {_darwin_acl_error('acl_valid')}"
            )
        entry = ctypes.c_void_p()
        entry_id = _DARWIN_ACL_FIRST_ENTRY
        while True:
            ctypes.set_errno(0)
            result = library.acl_get_entry(acl, entry_id, ctypes.byref(entry))
            if result == -1 and ctypes.get_errno() == errno.EINVAL:
                break
            if result != 0:
                raise BindingError(
                    f"{label} access policy cannot be enumerated: "
                    f"{_darwin_acl_error('acl_get_entry')}"
                )
            tag = ctypes.c_int()
            if library.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                raise BindingError(
                    f"{label} access policy tag cannot be inspected: "
                    f"{_darwin_acl_error('acl_get_tag_type')}"
                )
            if tag.value not in {
                _DARWIN_ACL_EXTENDED_ALLOW,
                _DARWIN_ACL_EXTENDED_DENY,
            }:
                raise BindingError(f"{label} access policy has an unknown ACL tag")
            permissions = ctypes.c_uint64()
            if (
                library.acl_get_permset_mask_np(
                    entry,
                    ctypes.byref(permissions),
                )
                != 0
            ):
                raise BindingError(
                    f"{label} access policy permissions cannot be inspected: "
                    f"{_darwin_acl_error('acl_get_permset_mask_np')}"
                )
            if (
                tag.value == _DARWIN_ACL_EXTENDED_ALLOW
                and permissions.value & _DARWIN_MUTATING_ACL_PERMISSIONS
            ):
                ctypes.set_errno(0)
                qualifier = library.acl_get_qualifier(entry)
                if not qualifier:
                    raise BindingError(
                        f"{label} access policy qualifier cannot be inspected: "
                        f"{_darwin_acl_error('acl_get_qualifier')}"
                    )
                try:
                    subject_uuid = ctypes.string_at(qualifier, 16)
                finally:
                    library.acl_free(qualifier)
                if subject_uuid != _darwin_owner_uuid(owner_uid, label=label):
                    raise BindingError(
                        f"{label} grants non-owner mutation through an extended ACL"
                    )
            entry_id = _DARWIN_ACL_NEXT_ENTRY
    finally:
        library.acl_free(acl)


def _validate_access_policy(
    metadata: os.stat_result,
    descriptor: int,
    *,
    label: str,
) -> int:
    """Validate the non-owner mutation property and bind security flags."""
    if sys.platform.startswith("linux"):
        filesystem_type = _linux_filesystem_type(descriptor, label=label)
        _require_linux_posix_acl_filesystem(filesystem_type, label=label)
        # On the closed filesystem set, a POSIX ACL mutation grant is bounded
        # by the group mode class already rejected by the mode-policy check.
        return 0
    if sys.platform != "darwin":
        raise BindingError(
            f"{label} access policy cannot be verified on {sys.platform}"
        )
    raw_flags = getattr(metadata, "st_flags", None)
    if not isinstance(raw_flags, int) or isinstance(raw_flags, bool):
        raise BindingError(f"{label} security flags cannot be inspected")
    unknown_flags = raw_flags & ~_DARWIN_KNOWN_STAT_FLAGS
    if unknown_flags:
        raise BindingError(
            f"{label} has unknown security-relevant flags 0x{unknown_flags:x}"
        )
    _validate_darwin_acl(
        descriptor,
        owner_uid=metadata.st_uid,
        label=label,
    )
    return raw_flags & _DARWIN_ACCESS_POLICY_FLAGS


def _require_safe_file_primitives() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise BindingError("active catalog binding requires a POSIX runtime")
    for name in (
        "O_CLOEXEC",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_NONBLOCK",
    ):
        if not hasattr(os, name):
            raise BindingError(f"active catalog binding requires {name}")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _validate_directory_policy(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BindingError(f"{label} is not an ordinary non-symlink directory")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise BindingError(f"{label} has an untrusted owner")
    if metadata.st_mode & 0o022:
        shared_sticky_root = (
            metadata.st_uid == 0
            and bool(metadata.st_mode & stat.S_ISVTX)
            and bool(metadata.st_mode & 0o002)
        )
        if not shared_sticky_root:
            raise BindingError(f"{label} is group/world writable")


def _require_canonical_absolute(path: Path, *, label: str) -> None:
    raw = str(path)
    if not path.is_absolute():
        raise BindingError(f"{label} must be an absolute path")
    if raw != os.path.normpath(raw):
        raise BindingError(f"{label} must be lexically canonical")


def _require_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BindingError(f"{label} is unavailable: {error}") from error
    _validate_directory_policy(metadata, label=label)
    if metadata.st_uid != os.geteuid():
        raise BindingError(f"{label} is not owned by the current user")
    return metadata


class _BoundDirectory:
    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        identity: tuple[int, int, int, int],
        access_policy_flags: int,
        parent: _BoundDirectory | None,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.access_policy_flags = access_policy_flags
        self.parent = parent

    def close(self, *, revalidate: bool = False) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: BindingError | None = None
        try:
            if revalidate:
                current = os.fstat(descriptor)
                _validate_directory_policy(
                    current,
                    label=f"bound directory {self.path}",
                )
                if _directory_identity(current) != self.identity:
                    raise BindingError(
                        f"bound directory identity changed for {self.path}"
                    )
                if (
                    _validate_access_policy(
                        current,
                        descriptor,
                        label=f"bound directory {self.path}",
                    )
                    != self.access_policy_flags
                ):
                    raise BindingError(
                        f"bound directory security flags changed for {self.path}"
                    )
                if self.parent is not None:
                    lexical = os.stat(
                        self.path.name,
                        dir_fd=self.parent.descriptor,
                        follow_symlinks=False,
                    )
                    _validate_directory_policy(
                        lexical,
                        label=f"bound parent entry {self.path}",
                    )
                    if _directory_identity(lexical) != self.identity:
                        raise BindingError(
                            f"bound parent entry identity changed for {self.path}"
                        )
                final = os.fstat(descriptor)
                _validate_directory_policy(
                    final,
                    label=f"final bound directory {self.path}",
                )
                if _directory_identity(final) != self.identity:
                    raise BindingError(
                        f"bound directory identity changed for {self.path}"
                    )
                if (
                    _validate_access_policy(
                        final,
                        descriptor,
                        label=f"final bound directory {self.path}",
                    )
                    != self.access_policy_flags
                ):
                    raise BindingError(
                        f"bound directory security flags changed for {self.path}"
                    )
        except (BindingError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, BindingError)
                else BindingError(
                    f"cannot revalidate the bound directory {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise BindingError(
                f"cannot close the bound directory {self.path}: {error}"
            ) from error
        if validation_error is not None:
            raise validation_error


class _BoundFile:
    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        identity: tuple[int, int, int, int, int],
        access_policy_flags: int,
        payload: bytes | None,
        sha256: str,
        limit: int,
        parent: _BoundDirectory | None,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.identity = identity
        self.access_policy_flags = access_policy_flags
        self.payload = payload
        self.sha256 = sha256
        self.limit = limit
        self.parent = parent

    def close(self, *, revalidate: bool = False) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        validation_error: BindingError | None = None
        try:
            if revalidate:
                metadata = os.fstat(descriptor)
                if _file_identity(metadata) != self.identity:
                    raise BindingError(
                        f"bound descriptor identity changed for {self.path}"
                    )
                if (
                    _validate_access_policy(
                        metadata,
                        descriptor,
                        label=f"bound descriptor {self.path}",
                    )
                    != self.access_policy_flags
                ):
                    raise BindingError(
                        f"bound descriptor security flags changed for {self.path}"
                    )
                _payload, digest, size = _read_descriptor(
                    descriptor,
                    label=f"final descriptor revalidation for {self.path}",
                    limit=self.limit,
                    retain_payload=False,
                )
                if size != self.identity[-1] or digest != self.sha256:
                    raise BindingError(
                        f"bound descriptor content changed for {self.path}"
                    )
                if self.parent is not None:
                    lexical = os.stat(
                        self.path.name,
                        dir_fd=self.parent.descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(lexical.st_mode)
                        or stat.S_ISLNK(lexical.st_mode)
                        or _file_identity(lexical) != self.identity
                    ):
                        raise BindingError(
                            f"bound parent entry identity changed for {self.path}"
                        )
                final = os.fstat(descriptor)
                if _file_identity(final) != self.identity:
                    raise BindingError(
                        f"bound descriptor identity changed for {self.path}"
                    )
                if (
                    _validate_access_policy(
                        final,
                        descriptor,
                        label=f"final bound descriptor {self.path}",
                    )
                    != self.access_policy_flags
                ):
                    raise BindingError(
                        f"bound descriptor security flags changed for {self.path}"
                    )
        except (BindingError, OSError) as error:
            validation_error = (
                error
                if isinstance(error, BindingError)
                else BindingError(
                    f"cannot revalidate the bound descriptor for {self.path}: {error}"
                )
            )
        try:
            os.close(descriptor)
        except OSError as error:
            raise BindingError(
                f"cannot close the bound descriptor for {self.path}: {error}"
            ) from error
        if validation_error is not None:
            raise validation_error


def _read_descriptor(
    descriptor: int,
    *,
    label: str,
    limit: int,
    retain_payload: bool,
) -> tuple[bytes | None, str, int]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise BindingError(f"{label} cannot be rewound safely: {error}") from error
    retained = bytearray() if retain_payload else None
    digest = hashlib.sha256()
    size = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - size))
        except OSError as error:
            raise BindingError(f"{label} cannot be read safely: {error}") from error
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise BindingError(f"{label} exceeds its byte limit")
        digest.update(chunk)
        if retained is not None:
            retained.extend(chunk)
    return (
        bytes(retained) if retained is not None else None,
        digest.hexdigest(),
        size,
    )


def _open_bound_file(
    path: Path,
    *,
    label: str,
    limit: int = MAX_FILE_BYTES,
    allow_root_owner: bool = False,
    retain_payload: bool = True,
    parent: _BoundDirectory | None = None,
) -> _BoundFile:
    try:
        if parent is None:
            lexical = path.lstat()
        else:
            if path.parent != parent.path:
                raise BindingError(f"{label} parent binding is inconsistent")
            lexical = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
    except OSError as error:
        raise BindingError(f"{label} cannot be inspected safely: {error}") from error
    if not stat.S_ISREG(lexical.st_mode) or stat.S_ISLNK(lexical.st_mode):
        raise BindingError(f"{label} is not an ordinary non-symlink regular file")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        if parent is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(path.name, flags, dir_fd=parent.descriptor)
    except OSError as error:
        raise BindingError(f"{label} cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise BindingError(f"{label} changed to a non-regular file")
        if _file_identity(opened) != _file_identity(lexical):
            raise BindingError(f"{label} identity changed before the validated read")
        if opened.st_uid != os.geteuid() and not (
            allow_root_owner and opened.st_uid == 0
        ):
            raise BindingError(f"{label} is not owned by an accepted user")
        if opened.st_mode & 0o022:
            raise BindingError(f"{label} is group/world writable")
        if opened.st_size > limit:
            raise BindingError(f"{label} exceeds its byte limit")
        access_policy_flags = _validate_access_policy(
            opened,
            descriptor,
            label=label,
        )

        payload, digest, size = _read_descriptor(
            descriptor,
            label=label,
            limit=limit,
            retain_payload=retain_payload,
        )
        repeated_payload, repeated_digest, repeated_size = _read_descriptor(
            descriptor,
            label=label,
            limit=limit,
            retain_payload=retain_payload,
        )
        final = os.fstat(descriptor)
        if _file_identity(final) != _file_identity(opened):
            raise BindingError(f"{label} identity changed during the validated read")
        if (
            _validate_access_policy(
                final,
                descriptor,
                label=f"final {label}",
            )
            != access_policy_flags
        ):
            raise BindingError(f"{label} security flags changed during binding")
        if (
            size != opened.st_size
            or repeated_size != size
            or repeated_digest != digest
            or repeated_payload != payload
        ):
            raise BindingError(f"{label} content changed during the validated read")
        return _BoundFile(
            path=path,
            descriptor=descriptor,
            identity=_file_identity(opened),
            access_policy_flags=access_policy_flags,
            payload=payload,
            sha256=digest,
            limit=limit,
            parent=parent,
        )
    except BaseException:
        os.close(descriptor)
        raise


class _BindingTransaction:
    def __init__(self) -> None:
        self._retained: list[_BoundFile] = []
        self._directories: list[_BoundDirectory] = []
        self._directories_by_path: dict[Path, _BoundDirectory] = {}

    def bind_parent_chain(
        self,
        path: Path,
        *,
        label: str,
    ) -> _BoundDirectory:
        _require_canonical_absolute(path, label=label)
        existing = self._directories_by_path.get(path)
        if existing is not None:
            return existing

        root_path = Path("/")
        root = self._directories_by_path.get(root_path)
        if root is None:
            descriptor = os.open(
                root_path,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
            )
            try:
                metadata = os.fstat(descriptor)
                _validate_directory_policy(metadata, label="absolute path root")
                access_policy_flags = _validate_access_policy(
                    metadata,
                    descriptor,
                    label="absolute path root",
                )
                root = _BoundDirectory(
                    path=root_path,
                    descriptor=descriptor,
                    identity=_directory_identity(metadata),
                    access_policy_flags=access_policy_flags,
                    parent=None,
                )
            except BaseException:
                os.close(descriptor)
                raise
            self._directories.append(root)
            self._directories_by_path[root_path] = root

        parent = root
        current = root_path
        for component in path.parts[1:]:
            current = current / component
            existing = self._directories_by_path.get(current)
            if existing is not None:
                if existing.parent is not parent:
                    raise BindingError(
                        f"{label} has an inconsistent bound parent chain"
                    )
                parent = existing
                continue
            try:
                lexical = os.stat(
                    component,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise BindingError(
                    f"{label} component {current} cannot be inspected: {error}"
                ) from error
            _validate_directory_policy(
                lexical,
                label=f"{label} component {current}",
            )
            try:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK,
                    dir_fd=parent.descriptor,
                )
            except OSError as error:
                raise BindingError(
                    f"{label} component {current} cannot be opened: {error}"
                ) from error
            try:
                opened = os.fstat(descriptor)
                if _directory_identity(opened) != _directory_identity(lexical):
                    raise BindingError(
                        f"{label} component {current} changed before binding"
                    )
                access_policy_flags = _validate_access_policy(
                    opened,
                    descriptor,
                    label=f"{label} component {current}",
                )
                final = os.fstat(descriptor)
                if _directory_identity(final) != _directory_identity(opened):
                    raise BindingError(
                        f"{label} component {current} changed during binding"
                    )
                if (
                    _validate_access_policy(
                        final,
                        descriptor,
                        label=f"final {label} component {current}",
                    )
                    != access_policy_flags
                ):
                    raise BindingError(
                        f"{label} component {current} security flags changed "
                        "during binding"
                    )
                bound = _BoundDirectory(
                    path=current,
                    descriptor=descriptor,
                    identity=_directory_identity(opened),
                    access_policy_flags=access_policy_flags,
                    parent=parent,
                )
            except BaseException:
                os.close(descriptor)
                raise
            self._directories.append(bound)
            self._directories_by_path[current] = bound
            parent = bound
        return parent

    def directory(self, path: Path) -> _BoundDirectory:
        try:
            return self._directories_by_path[path]
        except KeyError as error:
            raise BindingError(f"directory was not bound: {path}") from error

    def bind(
        self,
        path: Path,
        *,
        label: str,
        limit: int = MAX_FILE_BYTES,
        allow_root_owner: bool = False,
        retain_descriptor: bool = False,
        retain_payload: bool = True,
        parent: _BoundDirectory | None = None,
    ) -> _BoundFile:
        bound = _open_bound_file(
            path,
            label=label,
            limit=limit,
            allow_root_owner=allow_root_owner,
            retain_payload=retain_payload,
            parent=parent,
        )
        if retain_descriptor:
            self._retained.append(bound)
        else:
            bound.close()
        return bound

    def close(self) -> None:
        errors: list[str] = []
        while self._retained:
            bound = self._retained.pop()
            try:
                bound.close(revalidate=True)
            except BindingError as error:
                errors.append(str(error))
        while self._directories:
            bound = self._directories.pop()
            try:
                bound.close(revalidate=True)
            except BindingError as error:
                errors.append(str(error))
        self._directories_by_path.clear()
        if errors:
            raise BindingError("; ".join(errors))


def _validate_original_layout(
    resolver: Path,
    loaded_skill_root: Path,
    transaction: _BindingTransaction,
) -> tuple[Path, Path, Path, Path, _BoundDirectory]:
    _require_canonical_absolute(resolver, label="binding resolver path")
    _require_canonical_absolute(loaded_skill_root, label="loaded skill root")
    if resolver.name != "active_catalog_binding.py":
        raise BindingError("binding resolver has an unexpected leaf name")

    scripts_root = resolver.parent
    synthetic_root = scripts_root.parent
    skills_root = synthetic_root.parent
    payload_root = skills_root.parent
    release_root = payload_root.parent
    if scripts_root.name != "scripts":
        raise BindingError("binding resolver is not inside the skill scripts directory")
    if synthetic_root.name != "synthetic-token-fixtures":
        raise BindingError("resolver is not inside synthetic-token-fixtures")
    if skills_root.name != "skills" or payload_root.name != "personal_codex":
        raise BindingError("resolver is not inside a personal Codex release payload")
    if (
        release_root.parent.name != "releases"
        or RELEASE_ID.fullmatch(release_root.name) is None
    ):
        raise BindingError("resolver is not inside a versioned immutable release")
    if loaded_skill_root != synthetic_root:
        raise BindingError(
            "binding resolver is not inside the explicitly loaded synthetic skill"
        )

    resolver_parent = transaction.bind_parent_chain(
        resolver.parent,
        label="binding resolver absolute parent chain",
    )
    for path, label in (
        (release_root, "release root"),
        (payload_root, "release payload root"),
        (skills_root, "release skills root"),
        (synthetic_root, "loaded synthetic skill root"),
        (scripts_root, "loaded synthetic skill scripts root"),
    ):
        bound = transaction.directory(path)
        metadata = os.fstat(bound.descriptor)
        _validate_directory_policy(metadata, label=label)
        if metadata.st_uid != os.geteuid():
            raise BindingError(f"{label} is not owned by the current user")

    return release_root, payload_root, skills_root, synthetic_root, resolver_parent


def _canonical_runtime_path(review_root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BindingError(f"{label} path is invalid")
    relative = Path(value)
    if relative.is_absolute() or str(relative) != relative.as_posix():
        raise BindingError(f"{label} path is not canonical relative POSIX")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise BindingError(f"{label} path contains traversal")
    path = review_root / relative
    if path.parent == review_root.parent or review_root not in path.parents:
        raise BindingError(f"{label} path escapes the review skill")
    return path


def _parse_runtime_manifest(
    content: bytes,
    *,
    review_root: Path,
) -> tuple[
    dict[str, tuple[Path, bool, str]],
    Path,
    str,
    Path,
    str,
]:
    manifest = _load_json_object(content, label="catalog runtime manifest")
    expected_fields = {
        "schema_version",
        "profile",
        "runtime_version",
        "external_trust_root",
        "control_sources",
        "co_release_sources",
        "entrypoint",
        "sources",
        "data",
        "allowed_modules",
    }
    if set(manifest) != expected_fields:
        raise BindingError("catalog runtime manifest fields are not closed")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != RUNTIME_MANIFEST_SCHEMA_VERSION
    ):
        raise BindingError("catalog runtime manifest schema is unsupported")
    if manifest.get("profile") != RUNTIME_PROFILE:
        raise BindingError("catalog runtime manifest profile is unsupported")
    runtime_version = manifest.get("runtime_version")
    if type(runtime_version) is not int or runtime_version != 1:
        raise BindingError("catalog runtime manifest version is unsupported")
    _manifest_control_digests(manifest)

    entrypoint = manifest.get("entrypoint")
    if not isinstance(entrypoint, dict) or set(entrypoint) != {"path", "sha256"}:
        raise BindingError("catalog runtime entrypoint fields are invalid")
    if entrypoint.get("path") != RUNTIME_ENTRY_PATH:
        raise BindingError("catalog runtime entrypoint is not the dedicated surface")
    entry_sha256 = entrypoint.get("sha256")
    if not isinstance(entry_sha256, str) or SHA256.fullmatch(entry_sha256) is None:
        raise BindingError("catalog runtime entrypoint digest is invalid")
    entry_path = _canonical_runtime_path(
        review_root,
        entrypoint["path"],
        label="catalog runtime entrypoint",
    )

    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list) or len(raw_sources) != len(
        RUNTIME_SOURCE_PATHS
    ):
        raise BindingError("catalog runtime source manifest is not the minimal closure")
    sources: dict[str, tuple[Path, bool, str]] = {}
    for entry in raw_sources:
        if not isinstance(entry, dict) or set(entry) != {
            "module",
            "path",
            "package",
            "sha256",
        }:
            raise BindingError("catalog runtime source fields are invalid")
        module = entry.get("module")
        if not isinstance(module, str) or module not in RUNTIME_SOURCE_PATHS:
            raise BindingError("catalog runtime source module is unlisted")
        expected_path, expected_package = RUNTIME_SOURCE_PATHS[module]
        if (
            entry.get("path") != expected_path
            or entry.get("package") is not expected_package
        ):
            raise BindingError(f"catalog runtime source contract changed for {module}")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise BindingError(f"catalog runtime source digest is invalid for {module}")
        if module in sources:
            raise BindingError("catalog runtime source module is duplicated")
        sources[module] = (
            _canonical_runtime_path(
                review_root,
                expected_path,
                label=f"catalog runtime source {module}",
            ),
            expected_package,
            digest,
        )
    if set(sources) != set(RUNTIME_SOURCE_PATHS):
        raise BindingError("catalog runtime source closure is incomplete")

    allowed_modules = manifest.get("allowed_modules")
    if not isinstance(allowed_modules, list) or allowed_modules != sorted(
        RUNTIME_SOURCE_PATHS
    ):
        raise BindingError("catalog runtime allowed modules are not the exact closure")

    raw_data = manifest.get("data")
    if not isinstance(raw_data, list) or len(raw_data) != 1:
        raise BindingError("catalog runtime data manifest is not the exact closure")
    data_entry = raw_data[0]
    if not isinstance(data_entry, dict) or set(data_entry) != {
        "id",
        "path",
        "sha256",
    }:
        raise BindingError("catalog runtime data fields are invalid")
    data_id = data_entry.get("id")
    if data_id not in RUNTIME_DATA_PATHS:
        raise BindingError("catalog runtime data entry is unlisted")
    expected_data_path = RUNTIME_DATA_PATHS[str(data_id)]
    if data_entry.get("path") != expected_data_path:
        raise BindingError("catalog runtime data path changed")
    data_sha256 = data_entry.get("sha256")
    if not isinstance(data_sha256, str) or SHA256.fullmatch(data_sha256) is None:
        raise BindingError("catalog runtime data digest is invalid")
    data_path = _canonical_runtime_path(
        review_root,
        expected_data_path,
        label="catalog runtime data",
    )
    return sources, entry_path, entry_sha256, data_path, data_sha256


def _manifest_control_digests(
    manifest: dict[str, Any],
) -> tuple[dict[str, str], str]:
    if manifest.get("external_trust_root") != {
        "path": "scripts/named_lane_guard",
        "authority": "prior-trusted-canonical-bundle",
    }:
        raise BindingError("catalog runtime external trust root is invalid")
    control_sources = manifest.get("control_sources")
    expected = (
        (CONTROL_RUNTIME_INIT_PATH, "runtime-package"),
        (CONTROL_BOOTSTRAP_PATH, "binding-runtime"),
    )
    if not isinstance(control_sources, list) or len(control_sources) != len(expected):
        raise BindingError(
            "catalog runtime control source set is not the exact closure"
        )
    control: dict[str, str] = {}
    for record, (path, role) in zip(control_sources, expected, strict=True):
        if not isinstance(record, dict) or set(record) != {
            "path",
            "role",
            "sha256",
        }:
            raise BindingError("catalog runtime control source fields are invalid")
        if record.get("path") != path or record.get("role") != role:
            raise BindingError(
                "catalog runtime control source ordering/role is invalid"
            )
        digest = record.get("sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise BindingError("catalog runtime control source digest is invalid")
        control[path] = digest

    co_release = manifest.get("co_release_sources")
    if (
        not isinstance(co_release, list)
        or len(co_release) != 1
        or not isinstance(co_release[0], dict)
        or set(co_release[0]) != {"skill", "path", "role", "sha256"}
        or co_release[0].get("skill") != "synthetic-token-fixtures"
        or co_release[0].get("path") != CONTROL_RESOLVER_PATH
        or co_release[0].get("role") != "catalog-resolver"
    ):
        raise BindingError(
            "catalog runtime co-release source set is not the exact closure"
        )
    resolver_digest = co_release[0].get("sha256")
    if (
        not isinstance(resolver_digest, str)
        or SHA256.fullmatch(resolver_digest) is None
    ):
        raise BindingError("catalog runtime resolver digest is invalid")
    return control, resolver_digest


def _runtime_snapshot(
    *,
    review_root: Path,
    manifest_bytes: bytes,
    transaction: _BindingTransaction,
) -> tuple[
    dict[str, tuple[Path, bytes, bool]],
    _BoundFile,
    _BoundFile,
    tuple[dict[str, object], ...],
]:
    scripts_root = review_root / "scripts"
    scripts_parent = transaction.bind_parent_chain(
        scripts_root,
        label="catalog runtime scripts root",
    )
    for leaf in (
        "review_runtime.py",
        "review_runtime.pyc",
        "review_runtime.pyo",
        "review_runtime.so",
        "review_runtime.pyd",
        "review_runtime.dylib",
        "review_runtime.dll",
    ):
        try:
            os.stat(
                leaf,
                dir_fd=scripts_parent.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise BindingError(
                f"cannot inspect catalog runtime import substitute {leaf}: {error}"
            ) from error
        raise BindingError(f"catalog runtime has an import substitute: {leaf}")

    sources, entry_path, entry_sha256, data_path, data_sha256 = _parse_runtime_manifest(
        manifest_bytes, review_root=review_root
    )
    bound_records: list[dict[str, object]] = []
    source_specs: dict[str, tuple[Path, bytes, bool]] = {}
    total = 0
    for module, (path, is_package, expected_sha256) in sources.items():
        parent = transaction.bind_parent_chain(
            path.parent,
            label=f"catalog runtime source parent for {module}",
        )
        bound = transaction.bind(
            path,
            label=f"catalog runtime source {module}",
            retain_descriptor=True,
            parent=parent,
        )
        if bound.payload is None or bound.sha256 != expected_sha256:
            raise BindingError(f"catalog runtime source digest changed for {module}")
        total += len(bound.payload)
        source_specs[module] = (path, bound.payload, is_package)
        bound_records.append(
            {
                "kind": "source",
                "module": module,
                "path": str(path),
                "sha256": bound.sha256,
                "identity": list(bound.identity),
            }
        )

    entry_parent = transaction.bind_parent_chain(
        entry_path.parent,
        label="catalog runtime entrypoint parent",
    )
    entry_bound = transaction.bind(
        entry_path,
        label="catalog runtime entrypoint",
        retain_descriptor=True,
        parent=entry_parent,
    )
    if entry_bound.payload is None or entry_bound.sha256 != entry_sha256:
        raise BindingError("catalog runtime entrypoint digest changed")
    total += len(entry_bound.payload)
    bound_records.append(
        {
            "kind": "entrypoint",
            "path": str(entry_path),
            "sha256": entry_bound.sha256,
            "identity": list(entry_bound.identity),
        }
    )

    data_parent = transaction.bind_parent_chain(
        data_path.parent,
        label="catalog runtime data parent",
    )
    data_bound = transaction.bind(
        data_path,
        label="catalog runtime catalog data",
        limit=MAX_CATALOG_BYTES,
        retain_descriptor=True,
        parent=data_parent,
    )
    if data_bound.payload is None or data_bound.sha256 != data_sha256:
        raise BindingError("catalog runtime data digest changed")
    total += len(data_bound.payload)
    bound_records.append(
        {
            "kind": "data",
            "id": "synthetic-token-catalog",
            "path": str(data_path),
            "sha256": data_bound.sha256,
            "identity": list(data_bound.identity),
        }
    )
    if total > MAX_RUNTIME_BYTES or len(bound_records) > MAX_RUNTIME_FILES:
        raise BindingError("catalog runtime exceeds its closed resource limits")
    return source_specs, entry_bound, data_bound, tuple(bound_records)


def _load_json_object(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BindingError(f"{label} contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BindingError(f"{label} JSON is invalid: {error}") from error
    if not isinstance(payload, dict):
        raise BindingError(f"{label} root is not an object")
    return payload


def _parse_pool_version(catalog: bytes) -> str:
    if len(catalog) > MAX_CATALOG_BYTES:
        raise BindingError("catalog exceeds the helper's byte limit")
    payload = _load_json_object(catalog, label="catalog")
    authoring_pool = payload.get("authoring_pool")
    if not isinstance(authoring_pool, dict):
        raise BindingError("catalog authoring_pool is not an object")
    pool_version = authoring_pool.get("version")
    if (
        not isinstance(pool_version, str)
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", pool_version)
        is None
    ):
        raise BindingError("catalog pool_version is not a stable identifier")
    return pool_version


def _validate_sync_manifest(content: bytes) -> None:
    manifest = _load_json_object(content, label="release sync manifest")
    if manifest.get("version") != 1:
        raise BindingError("release sync manifest version is unsupported")
    links = manifest.get("links")
    if not isinstance(links, list):
        raise BindingError("release sync manifest links are not a list")

    required = {
        (
            "personal_codex/skills/review-orchestration-playbook",
            "skills/review-orchestration-playbook",
            "skill",
        ),
        (
            "personal_codex/skills/synthetic-token-fixtures",
            "skills/synthetic-token-fixtures",
            "skill",
        ),
    }
    authority_sources = {source for source, _, _ in required}
    authority_targets = {target for _, target, _ in required}
    observed: list[tuple[object, object, object]] = []
    for entry in links:
        if not isinstance(entry, dict):
            raise BindingError("release sync manifest contains a non-object link")
        candidate = (
            entry.get("source"),
            entry.get("target"),
            entry.get("kind"),
        )
        if (
            candidate[0] in authority_sources or candidate[1] in authority_targets
        ) and candidate not in required:
            raise BindingError("release sync manifest has an ambiguous authority link")
        if candidate in required:
            observed.append(candidate)
    if len(observed) != len(set(observed)):
        raise BindingError("release sync manifest duplicates an authority link")
    if set(observed) != required:
        raise BindingError(
            "release sync manifest does not bind both co-release skill sources"
        )


class _BoundSourceLoader:
    def __init__(
        self,
        *,
        module_name: str,
        origin: Path,
        code: types.CodeType,
    ) -> None:
        self.module_name = module_name
        self.origin = origin
        self.code = code

    def create_module(
        self,
        _spec: importlib.machinery.ModuleSpec,
    ) -> types.ModuleType | None:
        return None

    def exec_module(self, module: types.ModuleType) -> None:
        if module.__name__ != self.module_name:
            raise ImportError("bound catalog runtime module mismatch")
        exec(self.code, module.__dict__)

    def get_filename(self, fullname: str) -> str:
        if fullname != self.module_name:
            raise ImportError("bound catalog runtime module mismatch")
        return str(self.origin)


class _BoundRuntimeFinder:
    def __init__(
        self,
        specs: dict[str, tuple[Path, bytes, bool]],
    ) -> None:
        self._specs = specs
        self._loaders: dict[str, _BoundSourceLoader] = {}
        for module_name, (path, payload, _is_package) in specs.items():
            try:
                code = compile(payload, str(path), "exec", dont_inherit=True)
            except Exception as error:
                raise BindingError(
                    f"cannot compile bound review runtime source {path.name}: {error}"
                ) from error
            self._loaders[module_name] = _BoundSourceLoader(
                module_name=module_name,
                origin=path,
                code=code,
            )

    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname != RUNTIME_NAMESPACE and not fullname.startswith(
            f"{RUNTIME_NAMESPACE}."
        ):
            return None
        try:
            source_path, _payload, is_package = self._specs[fullname]
            loader = self._loaders[fullname]
        except KeyError as error:
            raise ImportError(
                f"bound catalog runtime import is outside the closed manifest: {fullname}"
            ) from error
        spec = importlib.machinery.ModuleSpec(
            fullname,
            loader,
            origin=str(source_path),
            is_package=is_package,
        )
        spec.has_location = True
        if is_package:
            spec.submodule_search_locations = []
        return spec


class _BoundTextSink:
    encoding = "utf-8"

    def __init__(self, *, label: str) -> None:
        self._label = label
        self._parts: list[str] = []
        self._size = 0

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("bound text sink accepts only text")
        encoded = value.encode("utf-8")
        self._size += len(encoded)
        if self._size > MAX_CLI_OUTPUT_BYTES:
            raise BindingError(f"{self._label} exceeds its byte limit")
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        return None

    def value(self) -> str:
        return "".join(self._parts)


def _remove_runtime_namespace() -> None:
    for module_name in tuple(sys.modules):
        if module_name == RUNTIME_NAMESPACE or module_name.startswith(
            f"{RUNTIME_NAMESPACE}."
        ):
            sys.modules.pop(module_name, None)


def _validate_catalog_result(
    *,
    action: str,
    requested_id: str | None,
    result: dict[str, Any],
    pool_version: str,
) -> None:
    if result.get("pool_version") != pool_version:
        raise BindingError("catalog CLI result has a mismatched pool_version")
    if action == "validate":
        if set(result) != {"pool_version", "schema_version", "status"}:
            raise BindingError("catalog validate result fields are not closed")
        if result["schema_version"] != 1 or result["status"] != "valid":
            raise BindingError("catalog validate result is not valid")
        return
    if action == "list":
        if set(result) != {"pool_version", "tokens"}:
            raise BindingError("catalog list result fields are not closed")
        tokens = result["tokens"]
        if not isinstance(tokens, list):
            raise BindingError("catalog list result tokens are not a list")
        for token in tokens:
            if not isinstance(token, dict) or set(token) != {
                "id",
                "role",
                "rule",
                "state",
                "value_sha256",
            }:
                raise BindingError(
                    "catalog list result exposes an invalid token record"
                )
            if "value" in token:
                raise BindingError("catalog list result exposed a raw token value")
        return
    if action == "get":
        if set(result) != {"pool_version", "token"}:
            raise BindingError("catalog get result fields are not closed")
        token = result["token"]
        if not isinstance(token, dict) or set(token) != {
            "id",
            "role",
            "rule",
            "state",
            "value",
            "value_sha256",
        }:
            raise BindingError("catalog get result token record is invalid")
        value = token["value"]
        if token["id"] != requested_id or not isinstance(value, str) or not value:
            raise BindingError("catalog get result does not match the requested token")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise BindingError("catalog get result value is not exact ASCII") from error
        if hashlib.sha256(encoded).hexdigest() != token["value_sha256"]:
            raise BindingError("catalog get result value digest is invalid")
        return
    raise BindingError("unknown catalog authoring action")


def _execute_catalog_snapshot(
    *,
    action: str,
    requested_id: str | None,
    source_specs: dict[str, tuple[Path, bytes, bool]],
    catalog_entry_path: Path,
    catalog_entry_bytes: bytes,
    catalog_bytes: bytes,
    pool_version: str,
) -> dict[str, Any]:
    preexisting = sorted(
        name
        for name in sys.modules
        if name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
    )
    if preexisting:
        raise BindingError("a review_runtime module was loaded before catalog binding")

    if set(source_specs) != set(RUNTIME_SOURCE_PATHS):
        raise BindingError("catalog runtime source closure changed before execution")
    finder = _BoundRuntimeFinder(source_specs)
    try:
        entry_code = compile(
            catalog_entry_bytes,
            str(catalog_entry_path),
            "exec",
            dont_inherit=True,
        )
    except Exception as error:
        raise BindingError(
            f"catalog entrypoint snapshot cannot compile: {error}"
        ) from error

    stdout = _BoundTextSink(label="catalog CLI stdout")
    stderr = _BoundTextSink(label="catalog CLI stderr")
    sys.meta_path.insert(0, finder)
    try:
        wrapper_namespace = {
            "__builtins__": __builtins__,
            "__file__": str(catalog_entry_path),
            "__name__": "_active_catalog_bound_cli",
            "__package__": None,
        }
        exec(entry_code, wrapper_namespace)
        package = sys.modules.get(RUNTIME_NAMESPACE)
        cli_module = sys.modules.get(f"{RUNTIME_NAMESPACE}.cli")
        synthetic_module = sys.modules.get(f"{RUNTIME_NAMESPACE}.synthetic_tokens")
        if not all(
            isinstance(module, types.ModuleType)
            for module in (package, cli_module, synthetic_module)
        ):
            raise BindingError("bound catalog CLI did not load its required modules")
        if wrapper_namespace.get("main") is not getattr(
            cli_module,
            "catalog_main",
            None,
        ):
            raise BindingError("catalog CLI wrapper entrypoint binding changed")
        if (
            "BOUND_CATALOG_BYTES" not in synthetic_module.__dict__
            or synthetic_module.__dict__["BOUND_CATALOG_BYTES"] is not None
        ):
            raise BindingError("catalog CLI bound-catalog byte hook changed")

        arguments = [action]
        if action == "list":
            arguments.append("--json")
        elif action == "get":
            if requested_id is None:
                raise BindingError("catalog get requires one token ID")
            arguments.extend((requested_id, "--json"))

        synthetic_module.__dict__["BOUND_CATALOG_BYTES"] = catalog_bytes
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                returncode = wrapper_namespace["main"](arguments)
        finally:
            synthetic_module.__dict__["BOUND_CATALOG_BYTES"] = None
        if returncode != 0:
            raise BindingError(f"catalog CLI snapshot returned exit {returncode}")
        if stderr.value():
            raise BindingError("catalog CLI snapshot emitted unexpected stderr")

        loaded_names = {
            name
            for name in sys.modules
            if name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
        }
        if loaded_names != set(source_specs):
            raise BindingError("catalog CLI runtime escaped its closed module manifest")
        for module_name in loaded_names:
            module = sys.modules[module_name]
            loader = getattr(module, "__loader__", None)
            if loader is not finder._loaders[module_name]:
                raise BindingError("catalog CLI runtime module loader changed")

        result = _load_json_object(
            stdout.value().encode("utf-8"),
            label="catalog CLI result",
        )
        _validate_catalog_result(
            action=action,
            requested_id=requested_id,
            result=result,
            pool_version=pool_version,
        )
        return result
    except BindingError:
        raise
    except BaseException as error:
        raise BindingError(
            f"catalog CLI snapshot execution failed: {type(error).__name__}: {error}"
        ) from error
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
        _remove_runtime_namespace()
        if any(
            name == RUNTIME_NAMESPACE or name.startswith(f"{RUNTIME_NAMESPACE}.")
            for name in sys.modules
        ):
            raise BindingError("catalog CLI runtime cleanup was incomplete")


def _validated_bootstrap_binding(
    binding: object,
) -> dict[str, object]:
    if not isinstance(binding, dict):
        raise BindingError(
            "active catalog binding requires the trusted catalog bootstrap"
        )
    expected_fields = {
        "schema_version",
        "mode",
        "release_id",
        "trusted_review_skill_root",
        "synthetic_skill_root",
        "synthetic_skill_sha256",
        "resolver_path",
        "resolver_sha256",
        "resolver_identity",
        "sync_manifest_path",
        "sync_manifest_sha256",
        "catalog_bootstrap_source_sha256",
        "catalog_runtime_package_sha256",
        "runtime_manifest_path",
        "runtime_manifest_sha256",
        "runtime_manifest_identity",
        "runtime_profile",
    }
    if set(binding) != expected_fields:
        raise BindingError("trusted catalog bootstrap binding fields are not closed")
    if binding.get("schema_version") != 1 or binding.get("mode") != (
        "trusted-guard-manifest-bound-source"
    ):
        raise BindingError("trusted catalog bootstrap binding mode is invalid")
    if (
        not isinstance(binding.get("release_id"), str)
        or RELEASE_ID.fullmatch(str(binding["release_id"])) is None
    ):
        raise BindingError("trusted catalog bootstrap release ID is invalid")
    for field in (
        "synthetic_skill_sha256",
        "resolver_sha256",
        "sync_manifest_sha256",
        "catalog_bootstrap_source_sha256",
        "catalog_runtime_package_sha256",
        "runtime_manifest_sha256",
    ):
        value = binding.get(field)
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise BindingError(
                f"trusted catalog bootstrap {field} is not canonical SHA-256"
            )
    identity = binding.get("resolver_identity")
    if (
        not isinstance(identity, list)
        or len(identity) != 5
        or any(
            not isinstance(value, int) or isinstance(value, bool) for value in identity
        )
    ):
        raise BindingError("trusted catalog bootstrap resolver identity is invalid")
    runtime_manifest_identity = binding.get("runtime_manifest_identity")
    if (
        not isinstance(runtime_manifest_identity, list)
        or len(runtime_manifest_identity) != 5
        or any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in runtime_manifest_identity
        )
    ):
        raise BindingError(
            "trusted catalog bootstrap runtime manifest identity is invalid"
        )
    if binding.get("runtime_profile") != RUNTIME_PROFILE:
        raise BindingError("trusted catalog bootstrap runtime profile is invalid")
    for field in (
        "trusted_review_skill_root",
        "synthetic_skill_root",
        "resolver_path",
        "sync_manifest_path",
        "runtime_manifest_path",
    ):
        value = binding.get(field)
        if not isinstance(value, str):
            raise BindingError(f"trusted catalog bootstrap {field} is invalid")
        _require_canonical_absolute(Path(value), label=f"bootstrap {field}")
    return dict(binding)


def _build_binding(
    *,
    resolver: Path,
    loaded_skill_root: Path,
    bootstrap_binding: dict[str, object],
    trusted_runtime_manifest_bytes: bytes,
    transaction: _BindingTransaction,
) -> tuple[
    dict[str, object],
    dict[str, tuple[Path, bytes, bool]],
    Path,
    bytes,
    bytes,
]:
    (
        release_root,
        payload_root,
        skills_root,
        synthetic_root,
        resolver_parent,
    ) = _validate_original_layout(
        resolver,
        loaded_skill_root,
        transaction,
    )
    resolver_bound = transaction.bind(
        resolver,
        label="binding resolver",
        retain_descriptor=True,
        parent=resolver_parent,
    )
    synthetic_skill = transaction.bind(
        synthetic_root / "SKILL.md",
        label="loaded synthetic skill",
        retain_descriptor=True,
        parent=transaction.directory(synthetic_root),
    )

    review_root = skills_root / "review-orchestration-playbook"
    sync_manifest = payload_root / "sync-manifest.json"
    manifest_bound = transaction.bind(
        sync_manifest,
        label="release sync manifest",
        retain_descriptor=True,
        parent=transaction.directory(payload_root),
    )
    if manifest_bound.payload is None:
        raise BindingError("release sync manifest snapshot omitted its content")
    _validate_sync_manifest(manifest_bound.payload)
    expected_bootstrap = {
        "release_id": release_root.name,
        "trusted_review_skill_root": str(skills_root / "review-orchestration-playbook"),
        "synthetic_skill_root": str(synthetic_root),
        "synthetic_skill_sha256": synthetic_skill.sha256,
        "resolver_path": str(resolver),
        "resolver_sha256": resolver_bound.sha256,
        "resolver_identity": list(resolver_bound.identity),
        "sync_manifest_path": str(sync_manifest),
        "sync_manifest_sha256": manifest_bound.sha256,
    }
    for field, expected in expected_bootstrap.items():
        if bootstrap_binding.get(field) != expected:
            raise BindingError(f"trusted catalog bootstrap binding changed for {field}")

    runtime_manifest = (
        review_root / "scripts" / RUNTIME_NAMESPACE / RUNTIME_MANIFEST_LEAF
    )
    if (
        type(trusted_runtime_manifest_bytes) is not bytes
        or len(trusted_runtime_manifest_bytes) > MAX_FILE_BYTES
    ):
        raise BindingError("trusted catalog runtime manifest bytes are invalid")
    runtime_manifest_parent = transaction.bind_parent_chain(
        runtime_manifest.parent,
        label="catalog runtime manifest absolute parent chain",
    )
    runtime_manifest_bound = transaction.bind(
        runtime_manifest,
        label="catalog runtime manifest",
        retain_descriptor=True,
        parent=runtime_manifest_parent,
    )
    if (
        runtime_manifest_bound.payload != trusted_runtime_manifest_bytes
        or runtime_manifest_bound.sha256 != bootstrap_binding["runtime_manifest_sha256"]
        or str(runtime_manifest) != bootstrap_binding["runtime_manifest_path"]
        or list(runtime_manifest_bound.identity)
        != bootstrap_binding["runtime_manifest_identity"]
    ):
        raise BindingError("trusted catalog runtime manifest binding changed")
    runtime_manifest_object = _load_json_object(
        trusted_runtime_manifest_bytes,
        label="catalog runtime manifest",
    )
    control_digests, resolver_digest = _manifest_control_digests(
        runtime_manifest_object
    )
    if (
        bootstrap_binding["catalog_runtime_package_sha256"]
        != control_digests[CONTROL_RUNTIME_INIT_PATH]
        or bootstrap_binding["catalog_bootstrap_source_sha256"]
        != control_digests[CONTROL_BOOTSTRAP_PATH]
        or bootstrap_binding["resolver_sha256"] != resolver_digest
    ):
        raise BindingError(
            "trusted catalog bootstrap control digests changed from the manifest"
        )

    source_specs, entry_bound, catalog_bound, runtime_records = _runtime_snapshot(
        review_root=review_root,
        manifest_bytes=trusted_runtime_manifest_bytes,
        transaction=transaction,
    )
    if catalog_bound.payload is None or entry_bound.payload is None:
        raise BindingError("catalog runtime snapshot omitted required content")
    catalog_bytes = catalog_bound.payload
    pool_version = _parse_pool_version(catalog_bytes)

    interpreter = Path(sys.executable).resolve(strict=True)
    interpreter_parent = transaction.bind_parent_chain(
        interpreter.parent,
        label="active Python interpreter absolute parent chain",
    )
    interpreter_bound = transaction.bind(
        interpreter,
        label="active Python interpreter",
        limit=MAX_INTERPRETER_BYTES,
        allow_root_owner=True,
        retain_descriptor=True,
        retain_payload=False,
        parent=interpreter_parent,
    )
    binding: dict[str, object] = {
        "schema_version": 4,
        "catalog_bootstrap": bootstrap_binding,
        "release_id": release_root.name,
        "release_root": str(release_root),
        "sync_manifest_path": str(sync_manifest),
        "sync_manifest_sha256": manifest_bound.sha256,
        "synthetic_skill_root": str(synthetic_root),
        "synthetic_skill_sha256": synthetic_skill.sha256,
        "binding_resolver_path": str(resolver),
        "binding_resolver_sha256": resolver_bound.sha256,
        "binding_resolver_identity": list(resolver_bound.identity),
        "review_skill_root": str(review_root),
        "catalog_runtime_profile": RUNTIME_PROFILE,
        "catalog_runtime_version": 1,
        "catalog_runtime_manifest_path": str(runtime_manifest),
        "catalog_runtime_manifest_sha256": runtime_manifest_bound.sha256,
        "catalog_runtime_manifest_identity": list(runtime_manifest_bound.identity),
        "catalog_runtime_files": list(runtime_records),
        "catalog_entry_path": str(entry_bound.path),
        "catalog_entry_sha256": entry_bound.sha256,
        "catalog_entry_identity": list(entry_bound.identity),
        "catalog_path": str(catalog_bound.path),
        "catalog_sha256": catalog_bound.sha256,
        "catalog_identity": list(catalog_bound.identity),
        "pool_version": pool_version,
        "python_executable": str(interpreter),
        "python_executable_sha256": interpreter_bound.sha256,
        "python_executable_identity": list(interpreter_bound.identity),
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_flags": ["-I", "-B", "-S"],
        "execution_mode": "trusted-manifest-bound-source-snapshot",
        "import_mode": "exact-closed-runtime-manifest",
    }
    encoded = json.dumps(
        binding,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    binding["binding_sha256"] = hashlib.sha256(encoded).hexdigest()
    return (
        binding,
        source_specs,
        entry_bound.path,
        entry_bound.payload,
        catalog_bytes,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bind and execute synthetic-token authoring through one active-release "
            "snapshot transaction."
        )
    )
    parser.add_argument("--loaded-skill-root", required=True)
    parser.add_argument("--expect-binding-sha256")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("bind")
    actions.add_parser("validate")
    actions.add_parser("list")
    get_parser = actions.add_parser("get")
    get_parser.add_argument("id")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    bootstrap_binding: object = None,
    runtime_manifest_bytes: object = None,
) -> int:
    try:
        trusted_bootstrap = _validated_bootstrap_binding(bootstrap_binding)
    except BindingError as error:
        print(f"active catalog binding failed: {error}", file=sys.stderr)
        return 2
    arguments = _build_parser().parse_args(argv)
    transaction = _BindingTransaction()
    output: dict[str, object] | None = None
    try:
        expected = arguments.expect_binding_sha256
        if arguments.action != "bind" and expected is None:
            raise BindingError(
                "--expect-binding-sha256 is required for validate, list, and get"
            )
        resolver = Path(__file__)
        loaded_skill_root = Path(arguments.loaded_skill_root)
        if type(runtime_manifest_bytes) is not bytes:
            raise BindingError(
                "active catalog binding requires trusted runtime manifest bytes"
            )
        (
            binding,
            source_specs,
            catalog_entry_path,
            catalog_entry_bytes,
            catalog_bytes,
        ) = _build_binding(
            resolver=resolver,
            loaded_skill_root=loaded_skill_root,
            bootstrap_binding=trusted_bootstrap,
            trusted_runtime_manifest_bytes=runtime_manifest_bytes,
            transaction=transaction,
        )
        if expected is not None:
            if SHA256.fullmatch(expected) is None:
                raise BindingError("expected binding digest is not canonical SHA-256")
            if expected != binding["binding_sha256"]:
                raise BindingError("active catalog binding changed")

        if arguments.action == "bind":
            output = binding
        else:
            result = _execute_catalog_snapshot(
                action=arguments.action,
                requested_id=getattr(arguments, "id", None),
                source_specs=source_specs,
                catalog_entry_path=catalog_entry_path,
                catalog_entry_bytes=catalog_entry_bytes,
                catalog_bytes=catalog_bytes,
                pool_version=str(binding["pool_version"]),
            )
            canonical_result = json.dumps(
                result,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            output = {
                "schema_version": 1,
                "operation": arguments.action,
                "binding": binding,
                "result": result,
                "result_sha256": hashlib.sha256(canonical_result).hexdigest(),
            }
    except (BindingError, OSError) as error:
        try:
            transaction.close()
        except BindingError as cleanup_error:
            print(
                f"active catalog binding cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
        print(f"active catalog binding failed: {error}", file=sys.stderr)
        return 2

    try:
        transaction.close()
    except BindingError as error:
        print(f"active catalog binding cleanup failed: {error}", file=sys.stderr)
        return 2
    if output is None:
        print(
            "active catalog binding failed: missing transaction output", file=sys.stderr
        )
        return 2
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    print(
        "active catalog binding failed: launch through the trusted "
        "named_lane_guard catalog-bootstrap profile",
        file=sys.stderr,
    )
    raise SystemExit(2)
