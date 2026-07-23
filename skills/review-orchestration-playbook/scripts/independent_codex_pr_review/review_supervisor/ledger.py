from __future__ import annotations

import errno
import fcntl
import math
import os
import pathlib
import re
import stat
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .constants import (
    CHECKOUT_ACCOUNTING_CAP_BYTES,
    CHECKOUT_SYNTHETIC_PATH_BYTES_BOUND,
    HOST_FREE_SPACE_FLOOR_BYTES,
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    MIB,
    NAMED_LANE_ELIGIBLE,
    PROCESS_ENVELOPE_BYTES,
    PRIMARY_DIFF_RELATIVE_PATH,
    REGISTRATION_DESCENDANT_COUNT_CAP,
    REGISTRATION_PATH_BYTES_CAP,
    RETENTION_CAP_BYTES,
    SCHEMA_VERSION,
    TARGETED_MANIFEST_FORMAT_HEADER_BOUND,
    TARGETED_MANIFEST_RECORD_BYTES,
    UNSUPPORTED_CLAUSES,
)
from .errors import SupervisorError, blocked, inconclusive
from .models import Admission, FilesystemMeasure, HelperCustody, Identity, TreeManifest
from .process import require_authenticated_no_child_process_profile
from .secureio import (
    acquire_flock,
    align_up,
    atomic_write_json_at,
    boot_identifier,
    canonical_json,
    checked_add,
    checked_mul,
    decode_json_bytes,
    directory_identities_match,
    identity_from_stat,
    measure_filesystem,
    open_absolute_directory_chain,
    open_regular_at,
    read_fd_exact,
    rename_noreplace,
    sha256_bytes,
    validate_private_directory_fd,
    validate_private_regular_fd,
)


MAX_ATTEMPT_STATE_BYTES = 1024 * 1024
ATTEMPT_DIRECTORY_PATTERN = re.compile(rb"attempt-([0-9]+)-[0-9a-f]{32}\Z")
RECLAIM_DIRECTORY_PATTERN = re.compile(
    rb"\.reclaim-(attempt-[0-9]+-[0-9a-f]{32})-[0-9a-f]{32}\Z"
)
ATOMIC_STATE_TEMP_PATTERN = re.compile(
    rb"\.state\.json\.tmp-([1-9][0-9]*)-[0-9a-f]{16}\Z"
)
INITIAL_CRASH_RECLAIM_AGE_SECONDS = 30.0
INITIAL_CRASH_TIMESTAMP_SKEW_SECONDS = 300.0
INITIAL_CRASH_TEMP_CAP = 8
RETENTION_LOCK_TOKEN_PREFIX = b"retention-lease-v1:"
RETENTION_LOCK_TOKEN_BYTES = len(RETENTION_LOCK_TOKEN_PREFIX) + 32 + 1


class EntryCountMismatch(ValueError):
    pass


def _validate_review_contract(state: dict[str, Any]) -> None:
    if (
        state.get("review_contract") != LOW_LEVEL_HELPER_REVIEW_CONTRACT
        or state.get("named_lane_eligible") is not NAMED_LANE_ELIGIBLE
    ):
        raise ValueError("attempt state review contract is invalid")


@dataclass(frozen=True)
class ParentAggregation:
    unique_parent_directory_count: int
    unique_parent_path_bytes: int
    consumed_paths: int


@dataclass(frozen=True)
class ProjectionInvariants:
    checkout_allocation_unit: int
    entry_count: int
    metadata_bytes: int
    checkout_base_bound_without_parents: int
    git_admin_bound: int
    review_diff_bound: int


@dataclass(frozen=True)
class LedgerSnapshot:
    process_logical_bytes: int
    checkout_logical_bytes: int
    process_physical_remaining_by_fs: dict[str, int]
    checkout_physical_remaining_by_fs: dict[str, int]
    retained_worktree_attempt: str | None
    attempt_count: int


@dataclass(frozen=True)
class AttemptBinding:
    name: bytes
    identity: Identity


_IDENTITY_FIELDS = frozenset({"device", "inode", "mode", "link_count", "uid", "size"})


def _identity_from_binding(value: Any, *, label: str) -> Identity:
    if (
        not isinstance(value, dict)
        or set(value) != _IDENTITY_FIELDS
        or any(type(value[field]) is not int for field in _IDENTITY_FIELDS)
    ):
        raise ValueError(f"{label} identity is malformed")
    return Identity(**value)


@dataclass
class RetentionLease:
    root: pathlib.Path
    fd: int
    root_fd: int
    root_identity: Identity
    lock_identity: Identity
    lock_token: bytes

    def transfer_binding(self) -> dict[str, Any]:
        self.revalidate_root()
        return {
            "version": 1,
            "retention_root": str(self.root),
            "root_identity": self.root_identity.to_json(),
            "lock_identity": self.lock_identity.to_json(),
            "lock_token_hex": self.lock_token.hex(),
        }

    def revalidate_root(self) -> Identity:
        if self.fd < 0 or self.root_fd < 0:
            raise OSError(errno.EBADF, "retention lease is closed")
        held_identity = validate_private_directory_fd(self.root_fd, self.root)
        current_fd, current_identity = open_absolute_directory_chain(
            self.root,
            private_leaf=True,
        )
        try:
            if not directory_identities_match(
                held_identity, self.root_identity
            ) or not directory_identities_match(current_identity, self.root_identity):
                raise OSError(errno.ESTALE, "retention root binding changed")
        finally:
            os.close(current_fd)

        probe_fd, current_lock_identity = open_regular_at(
            self.root_fd,
            b"retention.lock",
            expected_uid=os.getuid(),
            private_metadata=True,
        )
        try:
            if current_lock_identity != self.lock_identity:
                raise OSError(errno.ESTALE, "retention lock path identity changed")
            held_lock_identity = validate_private_regular_fd(
                self.fd,
                self.root / "retention.lock",
            )
            if held_lock_identity != self.lock_identity:
                raise OSError(
                    errno.ESTALE,
                    "retention lock descriptor identity changed",
                )
            if _read_retention_lock_token(self.fd) != self.lock_token:
                raise OSError(
                    errno.ESTALE,
                    "retention lock ownership token changed",
                )
            if _read_retention_lock_token(probe_fd) != self.lock_token:
                raise OSError(errno.ESTALE, "retention lock ownership token changed")
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(probe_fd, fcntl.LOCK_UN)
                raise OSError(errno.ENOLCK, "exclusive retention lock is not held")
            path_lock_identity = identity_from_stat(
                os.stat(
                    b"retention.lock",
                    dir_fd=self.root_fd,
                    follow_symlinks=False,
                )
            )
            if path_lock_identity != self.lock_identity:
                raise OSError(errno.ESTALE, "retention lock path identity changed")
        finally:
            os.close(probe_fd)
        final_root_fd, final_root_identity = open_absolute_directory_chain(
            self.root,
            private_leaf=True,
        )
        try:
            if not directory_identities_match(
                final_root_identity,
                self.root_identity,
            ):
                raise OSError(errno.ESTALE, "retention root binding changed")
        finally:
            os.close(final_root_fd)
        return held_identity

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def __enter__(self) -> "RetentionLease":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


@dataclass
class AttemptLease:
    retention: RetentionLease
    path: pathlib.Path
    fd: int
    identity: Identity

    @property
    def name(self) -> bytes:
        return os.fsencode(self.path.name)

    def revalidate(self, state: dict[str, Any] | None = None) -> Identity:
        self.retention.revalidate_root()
        if self.fd < 0:
            raise OSError(errno.EBADF, "attempt lease is closed")
        held_identity = validate_private_directory_fd(self.fd, self.path)
        path_identity = identity_from_stat(
            os.stat(
                self.name,
                dir_fd=self.retention.root_fd,
                follow_symlinks=False,
            )
        )
        if not directory_identities_match(held_identity, self.identity) or not (
            directory_identities_match(path_identity, self.identity)
        ):
            raise OSError(errno.ESTALE, "attempt directory binding changed")
        if state is not None:
            _validate_durable_bindings(state, lease=self.retention, attempt=self)
        self.retention.revalidate_root()
        return held_identity

    def transfer_binding(self) -> dict[str, Any]:
        self.revalidate()
        return {
            **self.retention.transfer_binding(),
            "attempt_dir": str(self.path),
            "attempt_identity": self.identity.to_json(),
        }

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "AttemptLease":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _validate_durable_bindings(
    state: dict[str, Any],
    *,
    lease: RetentionLease,
    attempt: AttemptLease,
) -> None:
    root_binding = state.get("retention_root_binding")
    if not isinstance(root_binding, dict) or set(root_binding) != {"path", "identity"}:
        raise ValueError("attempt state retention root binding is missing or malformed")
    if root_binding.get("path") != str(lease.root) or not directory_identities_match(
        _identity_from_binding(
            root_binding.get("identity"),
            label="retention root binding",
        ),
        lease.root_identity,
    ):
        raise OSError(errno.ESTALE, "attempt state retention root binding changed")

    attempt_binding = state.get("attempt_directory_binding")
    if not isinstance(attempt_binding, dict) or set(attempt_binding) != {
        "path",
        "identity",
    }:
        raise ValueError("attempt state directory binding is missing or malformed")
    if attempt_binding.get("path") != str(attempt.path) or not (
        directory_identities_match(
            _identity_from_binding(
                attempt_binding.get("identity"),
                label="attempt directory binding",
            ),
            attempt.identity,
        )
    ):
        raise OSError(errno.ESTALE, "attempt state directory binding changed")


def accept_attempt_lease_transfer(
    *,
    lease_fd: int,
    root_fd: int,
    attempt_fd: int,
    binding: Any,
) -> AttemptLease:
    expected_fields = {
        "version",
        "retention_root",
        "root_identity",
        "lock_identity",
        "lock_token_hex",
        "attempt_dir",
        "attempt_identity",
    }
    if not isinstance(binding, dict) or set(binding) != expected_fields:
        raise ValueError("attempt lease transfer binding is malformed")
    if binding.get("version") != 1:
        raise ValueError("attempt lease transfer version is unsupported")
    root = pathlib.Path(binding.get("retention_root", ""))
    attempt_path = pathlib.Path(binding.get("attempt_dir", ""))
    if not root.is_absolute() or attempt_path.parent != root:
        raise ValueError("attempt lease transfer paths are invalid")
    token_hex = binding.get("lock_token_hex")
    if (
        not isinstance(token_hex, str)
        or len(token_hex) != RETENTION_LOCK_TOKEN_BYTES * 2
    ):
        raise ValueError("attempt lease transfer token is malformed")
    try:
        token = bytes.fromhex(token_hex)
    except ValueError as error:
        raise ValueError("attempt lease transfer token is malformed") from error
    lease = RetentionLease(
        root=root,
        fd=lease_fd,
        root_fd=root_fd,
        root_identity=_identity_from_binding(
            binding.get("root_identity"), label="transferred retention root"
        ),
        lock_identity=_identity_from_binding(
            binding.get("lock_identity"), label="transferred retention lock"
        ),
        lock_token=token,
    )
    attempt: AttemptLease | None = None
    try:
        fcntl.flock(lease.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease.revalidate_root()
        attempt = AttemptLease(
            retention=lease,
            path=attempt_path,
            fd=attempt_fd,
            identity=_identity_from_binding(
                binding.get("attempt_identity"), label="transferred attempt"
            ),
        )
        attempt.revalidate()
        if attempt.transfer_binding() != binding:
            raise OSError(errno.ESTALE, "attempt lease transfer binding changed")
        return attempt
    except BaseException:
        if attempt is not None:
            attempt.close()
        else:
            os.close(attempt_fd)
        lease.close()
        raise


def acquire_retention_lease(root: pathlib.Path, *, deadline: float) -> RetentionLease:
    root_fd, root_identity = open_absolute_directory_chain(
        root,
        create=True,
        private_leaf=True,
    )
    lock_fd = -1
    try:
        try:
            lock_fd, identity = open_regular_at(
                root_fd,
                b"retention.lock",
                writable=True,
                expected_uid=os.getuid(),
                private_metadata=True,
            )
        except FileNotFoundError:
            lock_fd = os.open(
                b"retention.lock",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
            os.fsync(lock_fd)
            os.fsync(root_fd)
            identity = validate_private_regular_fd(
                lock_fd,
                root / "retention.lock",
            )
        if not stat.S_ISREG(identity.mode) or stat.S_IMODE(identity.mode) != 0o600:
            os.close(lock_fd)
            lock_fd = -1
            raise ValueError("retention lock has an unsafe identity or mode")
        acquire_flock(lock_fd, fcntl.LOCK_EX, deadline=deadline)
        lock_token = (
            RETENTION_LOCK_TOKEN_PREFIX + uuid.uuid4().hex.encode("ascii") + b"\n"
        )
        identity = _write_retention_lock_token(lock_fd, lock_token)
        path_identity = identity_from_stat(
            os.stat(
                b"retention.lock",
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        )
        if path_identity != identity:
            raise OSError(errno.ESTALE, "retention lock path changed after acquire")
        lease = RetentionLease(
            root=root,
            fd=lock_fd,
            root_fd=root_fd,
            root_identity=root_identity,
            lock_identity=identity,
            lock_token=lock_token,
        )
        lease.revalidate_root()
        return lease
    except BaseException as error:
        cleanup_failures = 0
        if lock_fd >= 0:
            try:
                os.close(lock_fd)
            except OSError:
                cleanup_failures += 1
        try:
            os.close(root_fd)
        except OSError:
            cleanup_failures += 1
        if not isinstance(error, Exception):
            if cleanup_failures:
                error.add_note("retention lease descriptor cleanup was incomplete")
            raise
        cleanup_suffix = (
            "; descriptor cleanup was incomplete" if cleanup_failures else ""
        )
        raise inconclusive(
            "cannot acquire independent-review retention lock: "
            f"{error}{cleanup_suffix}",
            stage="admission",
            code="retention-lock-unavailable",
        ) from error


def _write_retention_lock_token(fd: int, token: bytes) -> Identity:
    if (
        len(token) != RETENTION_LOCK_TOKEN_BYTES
        or not token.startswith(RETENTION_LOCK_TOKEN_PREFIX)
        or not token.endswith(b"\n")
    ):
        raise ValueError("retention lock token is malformed")
    os.ftruncate(fd, 0)
    offset = 0
    while offset < len(token):
        written = os.pwrite(fd, token[offset:], offset)
        if written <= 0:
            raise OSError(errno.EIO, "retention lock token write made no progress")
        offset += written
    os.fsync(fd)
    identity = validate_private_regular_fd(fd, pathlib.Path("retention.lock"))
    if identity.size != len(token):
        raise OSError(errno.EIO, "retention lock token size is invalid")
    if _read_retention_lock_token(fd) != token:
        raise OSError(errno.EIO, "retention lock token readback mismatch")
    return identity


def _read_retention_lock_token(fd: int) -> bytes:
    metadata = os.fstat(fd)
    if metadata.st_size != RETENTION_LOCK_TOKEN_BYTES:
        raise OSError(errno.EIO, "retention lock token size is invalid")
    chunks: list[bytes] = []
    offset = 0
    while offset < RETENTION_LOCK_TOKEN_BYTES:
        chunk = os.pread(fd, RETENTION_LOCK_TOKEN_BYTES - offset, offset)
        if not chunk:
            raise OSError(errno.EIO, "retention lock token read was truncated")
        chunks.append(chunk)
        offset += len(chunk)
    token = b"".join(chunks)
    if (
        not token.startswith(RETENTION_LOCK_TOKEN_PREFIX)
        or not token.endswith(b"\n")
        or len(token) != RETENTION_LOCK_TOKEN_BYTES
    ):
        raise OSError(errno.EIO, "retention lock token is malformed")
    return token


def _read_attempt_state_fd(
    attempt_fd: int,
) -> tuple[dict[str, Any], bytes, str]:
    state_fd, identity = open_regular_at(
        attempt_fd,
        b"state.json",
        expected_uid=os.getuid(),
        private_metadata=True,
    )
    try:
        if identity.size > MAX_ATTEMPT_STATE_BYTES:
            raise ValueError("attempt state exceeds its byte limit")
        raw = read_fd_exact(
            state_fd,
            max_bytes=MAX_ATTEMPT_STATE_BYTES,
            expected_size=identity.size,
        )
    finally:
        os.close(state_fd)
    state = decode_json_bytes(raw)
    if not isinstance(state, dict) or state.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("attempt state schema is invalid")
    _validate_review_contract(state)
    return state, raw, sha256_bytes(raw)


def read_bound_attempt_state(
    attempt: AttemptLease,
) -> tuple[dict[str, Any], bytes, str]:
    attempt.revalidate()
    state, raw, digest = _read_attempt_state_fd(attempt.fd)
    attempt.revalidate(state)
    return state, raw, digest


def _open_attempt_directory_at(
    root_fd: int,
    name: bytes,
) -> tuple[int, Identity]:
    metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    identity = identity_from_stat(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("retained attempt has unsafe ownership or mode")
    attempt_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=root_fd,
    )
    try:
        descriptor_identity = identity_from_stat(os.fstat(attempt_fd))
        if not directory_identities_match(descriptor_identity, identity):
            raise OSError(errno.ESTALE, "retained attempt identity changed")
        return attempt_fd, descriptor_identity
    except BaseException:
        os.close(attempt_fd)
        raise


def open_attempt_lease(
    lease: RetentionLease,
    attempt_dir: pathlib.Path,
    *,
    expected_identity: Identity | None = None,
) -> AttemptLease:
    if attempt_dir.parent != lease.root:
        raise ValueError("attempt directory is not an exact retention-root child")
    name = os.fsencode(attempt_dir.name)
    lease.revalidate_root()
    attempt_fd, identity = _open_attempt_directory_at(lease.root_fd, name)
    attempt = AttemptLease(
        retention=lease,
        path=attempt_dir,
        fd=attempt_fd,
        identity=expected_identity or identity,
    )
    try:
        if expected_identity is not None and not directory_identities_match(
            identity, expected_identity
        ):
            raise OSError(errno.ESTALE, "attempt directory identity changed")
        attempt.revalidate()
        return attempt
    except BaseException:
        attempt.close()
        raise


def read_attempt_state(
    attempt_dir: pathlib.Path,
    *,
    lease: RetentionLease | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    if lease is None:
        with acquire_retention_lease(
            attempt_dir.parent,
            deadline=time.monotonic() + 30,
        ) as owned_lease:
            return read_attempt_state(attempt_dir, lease=owned_lease)
    with open_attempt_lease(lease, attempt_dir) as attempt:
        return read_bound_attempt_state(attempt)


def _measure_filesystem_fd(directory_fd: int) -> FilesystemMeasure:
    metadata = os.fstat(directory_fd)
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


def _bounded_directory_names(directory_fd: int, *, cap: int) -> tuple[bytes, ...]:
    if cap < 0:
        raise ValueError("directory entry cap is negative")
    scan_fd = os.dup(directory_fd)
    names: list[bytes] = []
    try:
        with os.scandir(scan_fd) as iterator:
            for entry in iterator:
                if len(names) >= cap:
                    raise ValueError("directory entry count exceeds cap")
                name = os.fsencode(entry.name)
                if not name or b"/" in name or b"\0" in name:
                    raise ValueError("directory returned an invalid entry name")
                names.append(name)
    finally:
        os.close(scan_fd)
    return tuple(names)


def _allocated_bytes_fd(directory_fd: int, *, entry_cap: int) -> int:
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


def _remove_bound_attempt_directory(
    *,
    root_fd: int,
    name: bytes,
    attempt_fd: int,
) -> None:
    expected = identity_from_stat(os.fstat(attempt_fd))
    quarantine = b".reclaim-" + name + b"-" + uuid.uuid4().hex.encode("ascii")
    isolated = False
    quarantine_deleted = False
    try:
        rename_noreplace(root_fd, name, root_fd, quarantine)
        isolated = True
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError(errno.ESTALE, "reclaimed attempt name was replaced")
        isolated_identity = identity_from_stat(
            os.stat(quarantine, dir_fd=root_fd, follow_symlinks=False)
        )
        if not directory_identities_match(isolated_identity, expected):
            raise OSError(
                errno.ESTALE,
                "isolated reclaim directory identity changed",
            )
        if _bounded_directory_names(attempt_fd, cap=1):
            raise ValueError("isolated reclaim directory is not empty")
        os.rmdir(quarantine, dir_fd=root_fd)
        quarantine_deleted = True
        os.fsync(root_fd)
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError(errno.ESTALE, "reclaimed attempt name was replaced")
        isolated = False
    except BaseException as error:
        if isolated and not quarantine_deleted:
            try:
                rename_noreplace(root_fd, quarantine, root_fd, name)
                os.fsync(root_fd)
            except BaseException:
                error.add_note(
                    "isolated reclaim directory could not be restored safely"
                )
        raise


def remove_bound_attempt_directory(attempt: AttemptLease) -> None:
    attempt.revalidate()
    _remove_bound_attempt_directory(
        root_fd=attempt.retention.root_fd,
        name=attempt.name,
        attempt_fd=attempt.fd,
    )
    attempt.retention.revalidate_root()
    try:
        os.stat(
            attempt.name,
            dir_fd=attempt.retention.root_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise OSError(errno.ESTALE, "reclaimed attempt name was replaced")


def _reclaim_initial_crash_attempt(
    *,
    root_fd: int,
    name: bytes,
    directory_metadata: os.stat_result,
    match: re.Match[bytes],
    entries: tuple[bytes, ...],
    now: float,
) -> bool:
    if not entries:
        attempt_fd, attempt_identity = _open_attempt_directory_at(root_fd, name)
        try:
            if not directory_identities_match(
                attempt_identity,
                identity_from_stat(directory_metadata),
            ):
                raise OSError(errno.ESTALE, "initial attempt identity changed")
            _remove_bound_attempt_directory(
                root_fd=root_fd,
                name=name,
                attempt_fd=attempt_fd,
            )
        finally:
            os.close(attempt_fd)
        return True
    if b"state.json" in entries:
        return False
    if len(entries) > INITIAL_CRASH_TEMP_CAP:
        raise ValueError("initial attempt crash residue exceeds its entry cap")
    attempt_timestamp = int(match.group(1))
    if (
        attempt_timestamp > now
        or abs(directory_metadata.st_mtime - attempt_timestamp)
        > INITIAL_CRASH_TIMESTAMP_SKEW_SECONDS
    ):
        raise ValueError("initial attempt crash residue has an invalid timestamp")

    attempt_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=root_fd,
    )
    identities: list[tuple[bytes, Any]] = []
    authenticated_state: bytes | None = None
    try:
        descriptor = identity_from_stat(os.fstat(attempt_fd))
        if not directory_identities_match(
            descriptor, identity_from_stat(directory_metadata)
        ):
            raise ValueError("initial attempt directory identity changed")
        newest_timestamp = max(directory_metadata.st_mtime, directory_metadata.st_ctime)
        for entry in entries:
            temp_match = ATOMIC_STATE_TEMP_PATTERN.fullmatch(entry)
            if temp_match is None:
                raise ValueError("state-less attempt contains an unknown entry")
            metadata = os.stat(entry, dir_fd=attempt_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_ATTEMPT_STATE_BYTES
            ):
                raise ValueError(
                    "initial attempt state temporary has an unsafe identity"
                )
            if (
                metadata.st_mtime
                < attempt_timestamp - INITIAL_CRASH_TIMESTAMP_SKEW_SECONDS
                or metadata.st_mtime
                > attempt_timestamp + INITIAL_CRASH_TIMESTAMP_SKEW_SECONDS
            ):
                raise ValueError("initial attempt state temporary has an invalid age")
            newest_timestamp = max(
                newest_timestamp,
                metadata.st_mtime,
                metadata.st_ctime,
            )
            pid = int(temp_match.group(1))
            if pid > 2_147_483_647:
                raise ValueError("initial attempt state writer PID is invalid")
            temp_fd, identity = open_regular_at(
                attempt_fd,
                entry,
                expected_uid=os.getuid(),
                private_metadata=True,
            )
            try:
                raw = read_fd_exact(
                    temp_fd,
                    max_bytes=MAX_ATTEMPT_STATE_BYTES,
                    expected_size=identity.size,
                )
            finally:
                os.close(temp_fd)
            if identity != identity_from_stat(metadata):
                raise ValueError("initial attempt state temporary identity changed")
            candidate = decode_json_bytes(raw)
            attempt_id = os.fsdecode(name).removeprefix("attempt-")
            created_at = (
                candidate.get("created_at") if isinstance(candidate, dict) else None
            )
            if (
                not isinstance(candidate, dict)
                or canonical_json(candidate) != raw
                or candidate.get("schema_version") != SCHEMA_VERSION
                or candidate.get("review_contract") != LOW_LEVEL_HELPER_REVIEW_CONTRACT
                or candidate.get("named_lane_eligible") is not NAMED_LANE_ELIGIBLE
                or candidate.get("attempt_id") != attempt_id
                or type(candidate.get("record_generation")) is not int
                or candidate["record_generation"] != 1
                or candidate.get("previous_record_sha256") is not None
                or type(created_at) not in {int, float}
                or (isinstance(created_at, float) and not math.isfinite(created_at))
                or created_at < attempt_timestamp
                or created_at > attempt_timestamp + INITIAL_CRASH_TIMESTAMP_SKEW_SECONDS
                or candidate.get("phase") != "reserved"
                or candidate.get("launch_status") != "not-attempted"
                or candidate.get("reservation_status") != "outstanding"
                or candidate.get("closure") != "unproven"
                or candidate.get("process_settlement") != "outstanding"
                or candidate.get("checkout_settlement") != "outstanding"
                or candidate.get("retention_state") != "active/unsafe"
                or candidate.get("leader") is not None
            ):
                raise ValueError(
                    "initial attempt state temporary content is not authentic"
                )
            if authenticated_state is not None and raw != authenticated_state:
                raise ValueError("initial attempt state temporaries disagree")
            authenticated_state = raw
            identities.append((entry, identity))
        if now - newest_timestamp < INITIAL_CRASH_RECLAIM_AGE_SECONDS:
            raise ValueError("initial attempt crash residue is not old enough")
        if tuple(
            sorted(_bounded_directory_names(attempt_fd, cap=len(entries)))
        ) != tuple(sorted(entries)):
            raise ValueError("initial attempt crash residue changed during inspection")
        for entry, expected in identities:
            current = identity_from_stat(
                os.stat(entry, dir_fd=attempt_fd, follow_symlinks=False)
            )
            if current != expected:
                raise ValueError(
                    "initial attempt state temporary changed before reclaim"
                )
        for entry, _ in identities:
            os.unlink(entry, dir_fd=attempt_fd)
        os.fsync(attempt_fd)
        if _bounded_directory_names(attempt_fd, cap=1):
            raise ValueError("initial attempt crash residue is not empty after reclaim")
        _remove_bound_attempt_directory(
            root_fd=root_fd,
            name=name,
            attempt_fd=attempt_fd,
        )
    finally:
        os.close(attempt_fd)
    return True


def _attempt_directories(
    *,
    lease: RetentionLease,
) -> tuple[AttemptBinding, ...]:
    names = _bounded_directory_names(lease.root_fd, cap=10_000)
    attempts: list[AttemptBinding] = []
    for discovered_name in names:
        lease.revalidate_root()
        name = discovered_name
        if name == b"retention.lock":
            continue
        reclaim_match = RECLAIM_DIRECTORY_PATTERN.fullmatch(name)
        if reclaim_match is not None:
            restored_name = reclaim_match.group(1)
            try:
                os.stat(
                    restored_name,
                    dir_fd=lease.root_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise ValueError(
                    "isolated reclaim residue conflicts with its attempt name"
                )
            metadata = os.stat(name, dir_fd=lease.root_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError("isolated reclaim residue has unsafe metadata")
            rename_noreplace(
                lease.root_fd,
                name,
                lease.root_fd,
                restored_name,
            )
            os.fsync(lease.root_fd)
            name = restored_name
            lease.revalidate_root()
        metadata = os.stat(name, dir_fd=lease.root_fd, follow_symlinks=False)
        if not name.startswith(b"attempt-") or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("retention root contains an unrecognized entry")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("retained attempt has unsafe ownership or mode")
        attempt_fd, attempt_identity = _open_attempt_directory_at(
            lease.root_fd,
            name,
        )
        try:
            if not directory_identities_match(
                attempt_identity,
                identity_from_stat(metadata),
            ):
                raise OSError(errno.ESTALE, "retained attempt identity changed")
            try:
                os.stat(
                    b"state.json",
                    dir_fd=attempt_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                has_state = False
                entries = _bounded_directory_names(
                    attempt_fd,
                    cap=INITIAL_CRASH_TEMP_CAP,
                )
            else:
                has_state = True
                entries = ()
        finally:
            os.close(attempt_fd)
        attempt_match = ATTEMPT_DIRECTORY_PATTERN.fullmatch(name)
        if attempt_match is not None and not has_state:
            lease.revalidate_root()
            if _reclaim_initial_crash_attempt(
                root_fd=lease.root_fd,
                name=name,
                directory_metadata=metadata,
                match=attempt_match,
                entries=entries,
                now=time.time(),
            ):
                lease.revalidate_root()
                continue
        attempts.append(AttemptBinding(name=name, identity=attempt_identity))
    lease.revalidate_root()
    return tuple(sorted(attempts, key=lambda attempt: attempt.name))


def reconcile_ledger(
    root: pathlib.Path,
    *,
    lease: RetentionLease | None = None,
) -> LedgerSnapshot:
    if lease is None:
        with acquire_retention_lease(
            root,
            deadline=time.monotonic() + 30,
        ) as owned_lease:
            return reconcile_ledger(root, lease=owned_lease)
    if lease.root != root:
        raise ValueError("retention lease does not bind the reconciled root")
    lease.revalidate_root()

    process_bytes = 0
    checkout_bytes = 0
    process_physical: dict[str, int] = {}
    checkout_physical: dict[str, int] = {}
    retained_worktree: str | None = None
    attempts = _attempt_directories(lease=lease)
    for attempt in attempts:
        attempt_name = attempt.name
        attempt_dir = root / os.fsdecode(attempt_name)
        attempt_fd = -1
        try:
            lease.revalidate_root()
            attempt_fd, attempt_identity = _open_attempt_directory_at(
                lease.root_fd,
                attempt_name,
            )
            if not directory_identities_match(
                attempt_identity,
                attempt.identity,
            ):
                raise OSError(
                    errno.ESTALE,
                    "retained attempt changed after enumeration",
                )
            bound_attempt = AttemptLease(
                retention=lease,
                path=attempt_dir,
                fd=attempt_fd,
                identity=attempt_identity,
            )
            state, _, _ = read_bound_attempt_state(bound_attempt)
            attempt_id = state.get("attempt_id")
            if (
                not isinstance(attempt_id, str)
                or os.fsdecode(attempt_name) != f"attempt-{attempt_id}"
            ):
                raise ValueError("attempt directory does not match state identity")
            process_remaining = state.get("process_physical_remaining_by_fs", {})
            checkout_remaining = state.get("checkout_physical_remaining_by_fs", {})
            if not isinstance(process_remaining, dict) or not isinstance(
                checkout_remaining, dict
            ):
                raise ValueError("physical charge map is malformed")
            for identity, charge in (
                *process_remaining.items(),
                *checkout_remaining.items(),
            ):
                if (
                    not isinstance(identity, str)
                    or type(charge) is not int
                    or charge < 0
                ):
                    raise ValueError("physical charge map entry is malformed")

            retention_state = state.get("retention_state")
            if retention_state not in {
                "active/unsafe",
                "held",
                "released",
                "reclaiming",
                "reclaimed",
            }:
                raise ValueError("attempt retention state is invalid")
            attempt_fs = _measure_filesystem_fd(attempt_fd)
            process_settlement = state.get("process_settlement")
            if process_settlement == "outstanding":
                process_charge = PROCESS_ENVELOPE_BYTES
            elif process_settlement == "exact":
                if state.get("closure") != "proven-by-boot-change" and (
                    state.get("leader_started") is True
                    or state.get("launch_status") == "launched"
                    or state.get("leader") is not None
                ):
                    try:
                        require_authenticated_no_child_process_profile(state)
                    except ChildProcessError as error:
                        raise ValueError(
                            "exact launched process settlement lacks authenticated "
                            "no-child-process profile evidence"
                        ) from error
                recorded_process_charge = state.get("retained_process_bytes")
                if (
                    type(recorded_process_charge) is not int
                    or recorded_process_charge < 0
                    or recorded_process_charge > PROCESS_ENVELOPE_BYTES
                ):
                    raise ValueError("exact process settlement is malformed")
                if retention_state == "reclaimed":
                    if recorded_process_charge != 0 or process_remaining:
                        raise ValueError("reclaimed process settlement is not zero")
                    if sorted(_bounded_directory_names(attempt_fd, cap=2)) != [
                        b"state.json"
                    ]:
                        raise ValueError("reclaimed tombstone still contains artifacts")
                    process_charge = 0
                else:
                    measured_process_charge = _allocated_bytes_fd(
                        attempt_fd,
                        entry_cap=1_000,
                    )
                    if measured_process_charge > PROCESS_ENVELOPE_BYTES:
                        raise ValueError(
                            "retained process artifacts exceed their envelope"
                        )
                    process_charge = max(
                        recorded_process_charge, measured_process_charge
                    )
            else:
                raise ValueError("attempt process settlement is invalid")
            process_bytes = checked_add(process_bytes, process_charge)
            if process_charge:
                process_physical[attempt_fs.identity] = checked_add(
                    process_physical.get(attempt_fs.identity, 0), process_charge
                )

            checkout_settlement = state.get("checkout_settlement")
            if checkout_settlement == "outstanding":
                admission = state.get("admission")
                if not isinstance(admission, dict):
                    raise ValueError(
                        "outstanding checkout charge has no admission record"
                    )
                checkout_charge = admission.get("checkout_accounting_bound")
                if type(checkout_charge) is not int or checkout_charge < 0:
                    raise ValueError("outstanding checkout charge is malformed")
                checkout_bytes = checked_add(checkout_bytes, checkout_charge)
                if (
                    state.get("worktree_status")
                    in {
                        "retained-worktree",
                        "manual-recovery-required",
                        "cleanup-warning",
                    }
                    or state.get("registration") is not None
                    or state.get("phase")
                    in {
                        "worktree-adding",
                        "validating",
                        "spawn-intent",
                        "launched",
                    }
                ):
                    if retained_worktree is not None:
                        raise ValueError(
                            "more than one retained worktree record exists"
                        )
                    retained_worktree = attempt_id
            elif checkout_settlement != "exact":
                raise ValueError("attempt checkout settlement is invalid")

            for identity, charge in checkout_remaining.items():
                checkout_physical[identity] = checked_add(
                    checkout_physical.get(identity, 0), charge
                )
            current_attempt_identity = identity_from_stat(
                os.stat(
                    attempt_name,
                    dir_fd=lease.root_fd,
                    follow_symlinks=False,
                )
            )
            if not directory_identities_match(
                current_attempt_identity,
                attempt_identity,
            ) or not directory_identities_match(
                current_attempt_identity,
                attempt.identity,
            ):
                raise OSError(errno.ESTALE, "retained attempt identity changed")
            lease.revalidate_root()
        except (OSError, ValueError, OverflowError) as error:
            raise inconclusive(
                f"retention reconciliation is uncertain for {attempt_dir.name}: {error}",
                stage="admission",
                code="retention-reconciliation-uncertain",
            ) from error
        finally:
            if attempt_fd >= 0:
                os.close(attempt_fd)
    lease.revalidate_root()
    snapshot = LedgerSnapshot(
        process_logical_bytes=process_bytes,
        checkout_logical_bytes=checkout_bytes,
        process_physical_remaining_by_fs=process_physical,
        checkout_physical_remaining_by_fs=checkout_physical,
        retained_worktree_attempt=retained_worktree,
        attempt_count=len(attempts),
    )
    lease.revalidate_root()
    return snapshot


def aggregate_unique_parents(
    paths: Iterable[bytes],
    *,
    expected_count: int,
    projector: Callable[[int, int, int], None],
) -> ParentAggregation:
    if expected_count < 0:
        raise ValueError("expected path count is negative")
    parent_count = 0
    parent_bytes = 0
    consumed = 0
    previous: bytes | None = None
    projector(parent_count, parent_bytes, consumed)
    iterator = iter(paths)
    while True:
        try:
            current = next(iterator)
        except StopIteration:
            break
        consumed += 1
        if consumed > expected_count:
            raise EntryCountMismatch("path stream contains an extra record")
        if not isinstance(current, bytes):
            raise ValueError("path stream record is not bytes")
        if not current or current[0] == 0x2F or current[-1] == 0x2F:
            raise ValueError("path has a leading or trailing slash")
        prefix_equal = True
        ordering: int | None = None
        last_was_slash = False
        for index, byte in enumerate(current):
            if byte == 0:
                raise ValueError("path contains NUL")
            previous_byte = (
                previous[index]
                if previous is not None and index < len(previous)
                else None
            )
            equal_here = previous_byte == byte
            if ordering is None and previous is not None and not equal_here:
                ordering = (
                    -1
                    if byte < (previous_byte if previous_byte is not None else -1)
                    else 1
                )
            shared_through = prefix_equal and equal_here
            if byte == 0x2F:
                if index == 0 or last_was_slash:
                    raise ValueError("path contains an empty component")
                if not shared_through:
                    parent_count = checked_add(parent_count, 1)
                    parent_bytes = checked_add(parent_bytes, index)
                    projector(parent_count, parent_bytes, consumed)
                last_was_slash = True
            else:
                last_was_slash = False
            prefix_equal = prefix_equal and equal_here
        if previous is not None:
            if ordering is None:
                ordering = 1 if len(current) > len(previous) else 0
            if ordering <= 0:
                raise ValueError("path stream is not in strict full raw-byte order")
        previous = current
    if consumed != expected_count:
        raise EntryCountMismatch(
            "path stream ended before the authenticated entry count"
        )
    return ParentAggregation(parent_count, parent_bytes, consumed)


def _projection_invariants(
    *,
    manifest: TreeManifest,
    checkout_fs: FilesystemMeasure,
    git_fs: FilesystemMeasure,
    diff_length: int,
) -> ProjectionInvariants:
    a_checkout = checkout_fs.allocation_unit
    a_git = git_fs.allocation_unit
    entry_count = manifest.entry_count
    blob_allocation = 0
    for entry in manifest.entries:
        entry_size = entry.size
        if entry_size is not None:
            blob_allocation = checked_add(
                blob_allocation,
                align_up(entry_size, a_checkout),
                a_checkout,
            )
    checkout_base = checked_add(
        64 * MIB,
        manifest.metadata_bytes,
        blob_allocation,
        checked_mul(a_checkout, manifest.gitlink_count),
    )
    git_admin_bound = checked_add(
        64 * MIB,
        manifest.metadata_bytes,
        checked_mul(a_git, checked_add(entry_count, 16)),
    )
    review_diff_bound = checked_add(
        align_up(diff_length, a_checkout),
        checked_mul(2, a_checkout),
    )
    return ProjectionInvariants(
        checkout_allocation_unit=a_checkout,
        entry_count=entry_count,
        metadata_bytes=manifest.metadata_bytes,
        checkout_base_bound_without_parents=checkout_base,
        git_admin_bound=git_admin_bound,
        review_diff_bound=review_diff_bound,
    )


def _projection_for(
    *,
    invariants: ProjectionInvariants,
    parent_count: int,
    parent_bytes: int,
) -> dict[str, int]:
    a_checkout = invariants.checkout_allocation_unit
    entry_count = invariants.entry_count
    checkout_manifest_entry_bound = checked_add(1, entry_count, parent_count, 3)
    targeted_manifest_entry_bound = checked_add(
        checkout_manifest_entry_bound,
        1,
        REGISTRATION_DESCENDANT_COUNT_CAP,
    )
    targeted_manifest_payload_bound = checked_add(
        TARGETED_MANIFEST_FORMAT_HEADER_BOUND,
        invariants.metadata_bytes,
        parent_bytes,
        CHECKOUT_SYNTHETIC_PATH_BYTES_BOUND,
        REGISTRATION_PATH_BYTES_CAP,
        checked_mul(TARGETED_MANIFEST_RECORD_BYTES, targeted_manifest_entry_bound),
    )
    targeted_manifest_file_bound = checked_add(
        align_up(targeted_manifest_payload_bound, a_checkout),
        a_checkout,
    )
    targeted_manifest_bound = checked_add(
        checked_mul(2, targeted_manifest_file_bound),
        checked_mul(2, a_checkout),
    )
    checkout_root_bound = checked_add(
        invariants.checkout_base_bound_without_parents,
        checked_mul(a_checkout, parent_count),
        targeted_manifest_bound,
        invariants.review_diff_bound,
    )
    return {
        "checkout_base_bound_without_parents": invariants.checkout_base_bound_without_parents,
        "checkout_root_bound": checkout_root_bound,
        "git_admin_bound": invariants.git_admin_bound,
        "checkout_accounting_bound": checked_add(
            checkout_root_bound, invariants.git_admin_bound
        ),
        "review_diff_bound": invariants.review_diff_bound,
        "targeted_manifest_entry_bound": targeted_manifest_entry_bound,
        "targeted_manifest_payload_bound": targeted_manifest_payload_bound,
        "targeted_manifest_file_bound": targeted_manifest_file_bound,
        "targeted_manifest_bound": targeted_manifest_bound,
    }


def calculate_admission(
    *,
    snapshot: LedgerSnapshot,
    retention_root: pathlib.Path,
    lease: RetentionLease | None = None,
    checkout_parent: pathlib.Path,
    common_git_dir: pathlib.Path,
    git_admin_parent: pathlib.Path | None = None,
    manifest: TreeManifest,
    diff_length: int,
) -> Admission:
    if snapshot.retained_worktree_attempt is not None:
        raise blocked(
            f"retained worktree blocks admission: {snapshot.retained_worktree_attempt}",
            stage="admission",
            code="blocked-worktree-capacity",
        )
    if lease is not None:
        if lease.root != retention_root:
            raise ValueError("retention lease does not bind the admission root")
        lease.revalidate_root()
        retention_fs = _measure_filesystem_fd(lease.root_fd)
        lease.revalidate_root()
    else:
        retention_fs = measure_filesystem(retention_root)
    checkout_fs = measure_filesystem(checkout_parent)
    git_fs = measure_filesystem(
        common_git_dir if git_admin_parent is None else git_admin_parent
    )
    if (
        checked_add(snapshot.process_logical_bytes, PROCESS_ENVELOPE_BYTES)
        > RETENTION_CAP_BYTES
    ):
        raise blocked(
            "independent-review process retention cap would be exceeded",
            stage="admission",
            code="blocked-retention",
        )
    process_physical = dict(snapshot.process_physical_remaining_by_fs)
    process_physical[retention_fs.identity] = checked_add(
        process_physical.get(retention_fs.identity, 0),
        PROCESS_ENVELOPE_BYTES,
    )
    if (
        retention_fs.free_bytes - process_physical[retention_fs.identity]
        < HOST_FREE_SPACE_FLOOR_BYTES
    ):
        raise blocked(
            "retention filesystem cannot preserve the 1 GiB process-only floor",
            stage="admission",
            code="blocked-retention",
        )

    try:
        invariants = _projection_invariants(
            manifest=manifest,
            checkout_fs=checkout_fs,
            git_fs=git_fs,
            diff_length=diff_length,
        )
    except OverflowError as error:
        raise inconclusive(
            f"checkout invariant accounting overflow: {error}",
            stage="admission",
            code="checkout-accounting-overflow",
        ) from error

    grouped_base = dict(process_physical)
    for identity, charge in snapshot.checkout_physical_remaining_by_fs.items():
        grouped_base[identity] = checked_add(grouped_base.get(identity, 0), charge)
    measures = {
        retention_fs.identity: retention_fs,
        checkout_fs.identity: checkout_fs,
        git_fs.identity: git_fs,
    }
    latest: dict[str, int] = {}

    def projector(parent_count: int, parent_bytes: int, consumed: int) -> None:
        nonlocal latest
        try:
            latest = _projection_for(
                invariants=invariants,
                parent_count=parent_count,
                parent_bytes=parent_bytes,
            )
            projected_checkout = checked_add(
                snapshot.checkout_logical_bytes,
                latest["checkout_accounting_bound"],
            )
            if projected_checkout > CHECKOUT_ACCOUNTING_CAP_BYTES:
                raise blocked(
                    "checkout accounting cap would be exceeded",
                    stage="admission",
                    code="blocked-worktree-capacity",
                )
            grouped = dict(grouped_base)
            grouped[checkout_fs.identity] = checked_add(
                grouped.get(checkout_fs.identity, 0),
                latest["checkout_root_bound"],
            )
            grouped[git_fs.identity] = checked_add(
                grouped.get(git_fs.identity, 0),
                latest["git_admin_bound"],
            )
            for identity, charge in grouped.items():
                measure = measures.get(identity)
                if (
                    measure is not None
                    and measure.free_bytes - charge < HOST_FREE_SPACE_FLOOR_BYTES
                ):
                    raise blocked(
                        "combined process/checkout projection cannot preserve the 1 GiB floor",
                        stage="admission",
                        code="blocked-worktree-capacity",
                    )
        except OverflowError as error:
            raise inconclusive(
                f"checkout accounting overflow after {consumed} paths: {error}",
                stage="admission",
                code="checkout-accounting-overflow",
            ) from error

    try:
        parents = aggregate_unique_parents(
            (entry.path for entry in manifest.entries),
            expected_count=manifest.entry_count,
            projector=projector,
        )
    except SupervisorError:
        raise
    except (ValueError, OverflowError) as error:
        raise inconclusive(
            f"frozen path accounting failed closed: {error}",
            stage="admission",
            code=(
                "fail-closed-entry-count-mismatch"
                if isinstance(error, EntryCountMismatch)
                else "frozen-path-accounting-invalid"
            ),
        ) from error
    admission = Admission(
        retention_fs=retention_fs,
        checkout_fs=checkout_fs,
        git_fs=git_fs,
        entry_count=manifest.entry_count,
        tree_metadata_bytes=manifest.metadata_bytes,
        unique_parent_directory_count=parents.unique_parent_directory_count,
        unique_parent_path_bytes=parents.unique_parent_path_bytes,
        gitlink_count=manifest.gitlink_count,
        process_charge=PROCESS_ENVELOPE_BYTES,
        **latest,
    )
    if lease is not None:
        lease.revalidate_root()
    return admission


def _group_charges(entries: Iterable[tuple[str, int]]) -> dict[str, int]:
    grouped: dict[str, int] = {}
    for identity, charge in entries:
        grouped[identity] = checked_add(grouped.get(identity, 0), charge)
    return grouped


def create_reserved_attempt(
    *,
    lease: RetentionLease,
    checkout_parent: pathlib.Path,
    prompt: bytes,
    prompt_sha256: str,
    custody: HelperCustody,
    admission: Admission,
    base_manifest_sha256: str,
    head_manifest_sha256: str,
    repo: pathlib.Path,
    common_git_dir: pathlib.Path,
    pr_url: str,
    git_executable: str,
    codex_executable: str,
    exec_budget: dict[str, int],
    attempt_id: str | None = None,
) -> tuple[pathlib.Path, dict[str, Any], str]:
    attempt_id = attempt_id or f"{int(time.time())}-{uuid.uuid4().hex}"
    attempt_dir = lease.root / f"attempt-{attempt_id}"
    worktree_path = checkout_parent / f"review-{attempt_id}"
    control_namespace = checkout_parent / f".review-control-{attempt_id}"
    prompt_path = attempt_dir / "prompt.txt"
    final_fifo = attempt_dir / "final.fifo"
    binding_fds: list[int] = []
    attempt_identity: Identity
    try:
        retention_identity = lease.revalidate_root()
        checkout_parent_fd, checkout_parent_identity = open_absolute_directory_chain(
            checkout_parent,
            private_leaf=True,
        )
        binding_fds.append(checkout_parent_fd)
        common_git_fd, common_git_identity = open_absolute_directory_chain(
            common_git_dir
        )
        binding_fds.append(common_git_fd)

        attempt_name = os.fsencode(attempt_dir.name)
        os.mkdir(attempt_name, 0o700, dir_fd=lease.root_fd)
        os.fsync(lease.root_fd)
        attempt_fd = os.open(
            attempt_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=lease.root_fd,
        )
        try:
            attempt_identity = validate_private_directory_fd(attempt_fd, attempt_dir)
            path_identity = identity_from_stat(
                os.stat(
                    attempt_name,
                    dir_fd=lease.root_fd,
                    follow_symlinks=False,
                )
            )
            if not directory_identities_match(attempt_identity, path_identity):
                raise OSError(errno.ESTALE, "attempt directory binding changed")
        finally:
            os.close(attempt_fd)
        lease.revalidate_root()
    finally:
        for binding_fd in binding_fds:
            os.close(binding_fd)
    state = {
        "schema_version": SCHEMA_VERSION,
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "attempt_id": attempt_id,
        "record_generation": 1,
        "previous_record_sha256": None,
        "boot_id": boot_identifier(),
        "created_at": time.time(),
        "phase": "reserved",
        "handoff": "none",
        "process_owner": "outer",
        "admission_status": "reserved",
        "launch_status": "not-attempted",
        "runtime_stage": None,
        "review_status": "not-run",
        "cleanup_status": "pending",
        "worktree_status": "absent",
        "reservation_status": "outstanding",
        "failure_stage": None,
        "closure": "unproven",
        "process_settlement": "outstanding",
        "checkout_settlement": "outstanding",
        "retained_process_bytes": None,
        "retention_state": "active/unsafe",
        "released_at": None,
        "release_reason": None,
        "repo": str(repo),
        "retention_root_binding": {
            "path": str(lease.root),
            "identity": retention_identity.to_json(),
        },
        "attempt_directory_binding": {
            "path": str(attempt_dir),
            "identity": attempt_identity.to_json(),
        },
        "checkout_parent_binding": {
            "path": str(checkout_parent),
            "identity": checkout_parent_identity.to_json(),
        },
        "common_git_dir_binding": {
            "path": str(common_git_dir),
            "identity": common_git_identity.to_json(),
        },
        "pr_url": pr_url,
        "git_executable": git_executable,
        "codex_executable": codex_executable,
        "requested_model": "gpt-5.6-sol",
        "requested_reasoning_effort": "xhigh",
        "exec_budget": exec_budget,
        "review_range": custody.review_range,
        "base_sha": custody.base_sha,
        "head_sha": custody.head_sha,
        "base_manifest_sha256": base_manifest_sha256,
        "head_manifest_sha256": head_manifest_sha256,
        "prompt_path": str(prompt_path),
        "prompt_length": len(prompt),
        "prompt_sha256": prompt_sha256,
        "worktree_path": str(worktree_path),
        "control_namespace": str(control_namespace),
        "targeted_manifest_temporary": str(control_namespace / "manifest.tmp"),
        "targeted_manifest_published": str(control_namespace / "manifest.bin"),
        "final_fifo_path": str(final_fifo),
        "helper_custody": custody.to_json(),
        "diff_length": custody.diff_length,
        "diff_sha256": custody.diff_sha256,
        "diff_destination": PRIMARY_DIFF_RELATIVE_PATH,
        "admission": admission.to_json(),
        "process_physical_remaining_by_fs": {
            admission.retention_fs.identity: PROCESS_ENVELOPE_BYTES,
        },
        "checkout_physical_remaining_by_fs": _group_charges(
            (
                (admission.checkout_fs.identity, admission.checkout_root_bound),
                (admission.git_fs.identity, admission.git_admin_bound),
            )
        ),
        "registration": None,
        "git_control_binding": None,
        "worktree_create_intent": None,
        "leader": None,
        "runtime_process_binding": None,
        "no_child_process_profile": None,
        "process_history": [],
        "final_seal": None,
        "observed_runtime": {},
        "unsupported_clauses": list(UNSUPPORTED_CLAUSES),
    }
    try:
        with open_attempt_lease(
            lease,
            attempt_dir,
            expected_identity=attempt_identity,
        ) as attempt:
            attempt.revalidate()
            _, digest = atomic_write_json_at(
                attempt.fd,
                b"state.json",
                state,
                replace=False,
                path_hint=attempt_dir / "state.json",
            )
            attempt.revalidate(state)
            readback, raw, readback_digest = read_bound_attempt_state(attempt)
            if (
                readback != state
                or readback_digest != digest
                or raw != canonical_json(state)
            ):
                raise ValueError("reserved attempt state exact readback failed")
        return attempt_dir, state, digest
    except Exception as error:
        raise inconclusive(
            f"cannot durably reserve the independent review attempt: {error}",
            stage="reservation",
            code="reservation-durability-uncertain",
        ) from error


def commit_state(
    attempt: AttemptLease | pathlib.Path,
    current: dict[str, Any],
    current_digest: str,
    **updates: Any,
) -> tuple[dict[str, Any], str]:
    if isinstance(attempt, pathlib.Path):
        with acquire_retention_lease(
            attempt.parent,
            deadline=time.monotonic() + 30,
        ) as lease:
            with open_attempt_lease(lease, attempt) as bound_attempt:
                return commit_state(
                    bound_attempt,
                    current,
                    current_digest,
                    **updates,
                )
    attempt.revalidate(current)
    disk, _, disk_digest = read_bound_attempt_state(attempt)
    if disk_digest != current_digest or disk != current:
        raise ValueError("attempt state predecessor changed")
    next_state = dict(current)
    next_state.update(updates)
    next_state["record_generation"] = current["record_generation"] + 1
    next_state["previous_record_sha256"] = current_digest
    _validate_review_contract(next_state)
    _validate_durable_bindings(next_state, lease=attempt.retention, attempt=attempt)
    _, next_digest = atomic_write_json_at(
        attempt.fd,
        b"state.json",
        next_state,
        replace=True,
        path_hint=attempt.path / "state.json",
    )
    attempt.revalidate(next_state)
    readback, raw, readback_digest = read_bound_attempt_state(attempt)
    if (
        readback != next_state
        or readback_digest != next_digest
        or raw != canonical_json(next_state)
    ):
        raise ValueError("attempt state exact readback failed")
    return next_state, next_digest
