from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import stat
import sys
import time
import uuid
from collections.abc import Iterable
from typing import Any

from .errors import inconclusive
from .models import FilesystemMeasure, Identity


READ_CHUNK = 64 * 1024
MAX_JSON_DEPTH = 64


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
    return (
        stat.S_ISDIR(left.mode)
        and stat.S_ISDIR(right.mode)
        and left.device == right.device
        and left.inode == right.inode
        and left.uid == right.uid
        and left.mode == right.mode
    )


def require_private_directory(path: pathlib.Path, *, create: bool = False) -> Identity:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise inconclusive(
            f"cannot inspect private directory {path}: {error}",
            stage="admission",
            code="private-directory-unavailable",
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise inconclusive(
            f"directory is not an owner-controlled no-follow directory: {path}",
            stage="admission",
            code="unsafe-directory",
        )
    return identity_from_stat(metadata)


def open_directory(path: pathlib.Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    return os.open(path, flags)


def open_absolute_directory_chain(path: pathlib.Path) -> tuple[int, Identity]:
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    raw_parts = os.fsencode(os.path.normpath(path)).split(b"/")
    if any(part in {b".", b".."} for part in raw_parts):
        raise ValueError("directory path contains a dot component")
    fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in raw_parts:
            if not part:
                continue
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        return fd, identity_from_stat(os.fstat(fd))
    except BaseException:
        os.close(fd)
        raise


def open_regular_at(
    parent_fd: int,
    name: bytes,
    *,
    expected_uid: int | None = None,
    require_link_one: bool = True,
) -> tuple[int, Identity]:
    if not name or b"/" in name or name in {b".", b".."} or b"\0" in name:
        raise ValueError("invalid leaf name")
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        descriptor_stat = os.fstat(fd)
        path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = identity_from_stat(descriptor_stat)
        if identity != identity_from_stat(path_stat):
            raise OSError(errno.ESTALE, "path identity changed while opening")
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if expected_uid is not None and descriptor_stat.st_uid != expected_uid:
            raise OSError(errno.EPERM, "unexpected owner")
        if require_link_one and descriptor_stat.st_nlink != 1:
            raise OSError(errno.EMLINK, "unexpected link count")
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
) -> tuple[int, Identity]:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        path_metadata = os.lstat(path)
        identity = identity_from_stat(metadata)
        if identity != identity_from_stat(path_metadata):
            raise OSError(errno.ESTALE, "path identity changed while opening")
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if expected_uid is not None and metadata.st_uid != expected_uid:
            raise OSError(errno.EPERM, "unexpected owner")
        if require_link_one and metadata.st_nlink != 1:
            raise OSError(errno.EMLINK, "unexpected link count")
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
    parsed = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    _validate_json_depth(parsed)
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
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
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


def atomic_write_json(
    path: pathlib.Path, value: Any, *, replace: bool
) -> tuple[Identity, str]:
    data = canonical_json(value)
    parent_fd = open_directory(path.parent)
    temp_name = f".{path.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}".encode("ascii")
    destination = os.fsencode(path.name)
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
            identity = identity_from_stat(os.fstat(fd))
            if not stat.S_ISREG(identity.mode) or identity.link_count != 1:
                raise OSError(
                    errno.EINVAL, "published state is not a private regular file"
                )
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
        os.close(parent_fd)


def publish_bytes(path: pathlib.Path, data: bytes, *, mode: int = 0o600) -> Identity:
    parent_fd = open_directory(path.parent)
    name = os.fsencode(path.name)
    temp_name = f".{path.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}".encode("ascii")
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
        written_identity = identity_from_stat(os.fstat(temp_fd))
        if (
            not stat.S_ISREG(written_identity.mode)
            or written_identity.link_count != 1
            or written_identity.uid != os.getuid()
            or written_identity.size != len(data)
            or stat.S_IMODE(written_identity.mode) != mode
        ):
            raise OSError(errno.EINVAL, "temporary artifact metadata is unsafe")
        os.close(temp_fd)
        temp_fd = None
        rename_noreplace(parent_fd, temp_name, parent_fd, name)
        os.fsync(parent_fd)
        read_fd = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        try:
            read_identity = identity_from_stat(os.fstat(read_fd))
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


def measure_filesystem(path: pathlib.Path) -> FilesystemMeasure:
    directory_fd = open_directory(path)
    try:
        metadata = os.fstat(directory_fd)
        values = os.fstatvfs(directory_fd)
    finally:
        os.close(directory_fd)
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


def allocated_bytes(path: pathlib.Path, *, entry_cap: int = 200_000) -> int:
    total = 0
    count = 0
    stack = [path]
    while stack:
        current = stack.pop()
        metadata = os.lstat(current)
        count += 1
        if count > entry_cap:
            raise ValueError("allocated-byte inventory exceeds entry cap")
        total += metadata.st_blocks * 512
        if stat.S_ISDIR(metadata.st_mode):
            with os.scandir(current) as iterator:
                children = list(iterator)
            for child in children:
                stack.append(pathlib.Path(child.path))
    return total


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

        marker = pathlib.Path("/private/var/run/bootSessionMA.txt")
        fd, identity = open_regular_nofollow(
            marker,
            expected_uid=0,
            require_link_one=True,
        )
        try:
            if not 1 <= identity.size <= 128:
                raise ValueError("Darwin boot-session marker has an invalid size")
            raw = read_fd_exact(fd, max_bytes=128, expected_size=identity.size).strip()
        finally:
            os.close(fd)
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
