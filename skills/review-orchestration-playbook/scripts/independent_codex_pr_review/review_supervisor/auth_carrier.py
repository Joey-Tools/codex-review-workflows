from __future__ import annotations

import base64
import ctypes
import functools
import hashlib
import json
import math
import os
import pathlib
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .appserver_protocol import ExternalChatGPTAuth
from .codex_executable import (
    ExtendedMetadataEvidence,
    FilesystemMetadataVerifier,
    verify_filesystem_metadata_evidence,
)
from .secureio import open_regular_at


MAX_AUTH_FILE_BYTES = 64 * 1024
AUTH_DIGEST_CHUNK_BYTES = 16 * 1024
MAX_JWT_PAYLOAD_BYTES = 32 * 1024
MAX_ACCESS_TOKEN_BYTES = 32 * 1024
MAX_JWT_TOKEN_BYTES = MAX_AUTH_FILE_BYTES
MAX_ACCOUNT_ID_BYTES = 512
MAX_PLAN_TYPE_BYTES = 64
MIN_ACCESS_TOKEN_REMAINING_SECONDS = 45 * 60
JWT_PART_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
# One second covers cross-clock sampling skew. It never extends token lifetime:
# revalidation preserves the latest observed, derived, or accepted high water.
WALL_CLOCK_ROLLBACK_TOLERANCE_SECONDS = 1.0


class AuthCarrierError(ValueError):
    classification = "invalid"


class AuthCarrierRefreshRequired(AuthCarrierError):
    classification = "refresh-required"


class AuthCarrierSourceMissing(AuthCarrierError):
    classification = "missing"


class AuthCarrierInspectionFailure(AuthCarrierError):
    classification = "inspection-failure"


class AuthCarrierObjectIdentityMismatch(AuthCarrierError):
    classification = "object-identity-mismatch"


class AuthCarrierContentMismatch(AuthCarrierError):
    classification = "content-mismatch"


class AuthCarrierAccessPolicyMismatch(AuthCarrierError):
    classification = "access-policy-mismatch"


class AuthCarrierMalformedEvidence(AuthCarrierError):
    classification = "malformed-evidence"


@dataclass(slots=True)
class _ClockHighWater:
    lock: Any
    last_monotonic_time: float
    effective_wall_time: float


@dataclass(frozen=True, slots=True)
class _AuthObjectIdentity:
    """Bind replacement-sensitive identity without content metadata proxies."""

    device: int
    inode: int
    file_type: int
    generation: int | None


@dataclass(frozen=True, slots=True)
class _AuthAccessPolicy:
    """Bind owner, mode, flags, and exact accepted ACL/xattr evidence."""

    uid: int
    gid: int
    mode: int
    flags: int
    extended_metadata: ExtendedMetadataEvidence


@dataclass(frozen=True)
class ExternalAuthEvidence:
    auth: ExternalChatGPTAuth
    source_directory_identity: _AuthObjectIdentity
    source_directory_access_policy: _AuthAccessPolicy
    source_identity: _AuthObjectIdentity
    source_access_policy: _AuthAccessPolicy
    source_size: int
    source_content_sha256: str
    access_token_expires_at: int
    access_token_sha256: str
    account_id_sha256: str
    minimum_remaining_seconds: int
    wall_time_baseline: float
    monotonic_time_baseline: float
    clock_high_water: _ClockHighWater = field(repr=False, compare=False)

    def to_json(self) -> dict[str, bool | str]:
        return {
            "auth_mode": "external-chatgpt",
            "carrier_generation_verified": True,
        }


@dataclass(frozen=True, slots=True)
class _AuthLoadFailure:
    message: str
    kind: str
    error_type: type[AuthCarrierError] | None = None


@dataclass(frozen=True, slots=True)
class _AuthLoadOutcome:
    evidence: ExternalAuthEvidence | None = None
    failure: _AuthLoadFailure | None = None


@dataclass(frozen=True, slots=True)
class _AuthSourceSnapshot:
    raw: bytearray
    directory_identity: _AuthObjectIdentity
    directory_access_policy: _AuthAccessPolicy
    source_identity: _AuthObjectIdentity
    source_access_policy: _AuthAccessPolicy
    source_size: int
    source_content_sha256: str


@dataclass(frozen=True, slots=True)
class _SelectedAuth:
    access_token: str = field(repr=False)
    account_id: str
    plan_type: str | None
    expiration: int
    access_token_sha256: str
    account_id_sha256: str
    has_managed_refresh_token: bool


@dataclass(frozen=True, slots=True)
class _ClockSample:
    wall_time: float
    monotonic_time: float


def load_external_auth(
    auth_path: pathlib.Path,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    minimum_remaining_seconds: int = MIN_ACCESS_TOKEN_REMAINING_SECONDS,
    now: float | None = None,
    monotonic_now: float | None = None,
) -> ExternalAuthEvidence:
    outcome = _load_external_auth_boundary(
        auth_path=auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
        minimum_remaining_seconds=minimum_remaining_seconds,
        now=now,
        monotonic_now=monotonic_now,
    )
    if outcome.failure is not None:
        if outcome.failure.kind == "refresh":
            raise AuthCarrierRefreshRequired(outcome.failure.message) from None
        if outcome.failure.kind == "keyboard-interrupt":
            raise KeyboardInterrupt() from None
        if outcome.failure.kind == "system-exit":
            raise SystemExit(1) from None
        error_type = outcome.failure.error_type or AuthCarrierError
        raise error_type(outcome.failure.message) from None
    if outcome.evidence is None:
        raise AuthCarrierError("auth carrier validation produced no result") from None
    return outcome.evidence


def _load_external_auth_boundary(
    *,
    auth_path: pathlib.Path,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    minimum_remaining_seconds: int,
    now: float | None,
    monotonic_now: float | None,
) -> _AuthLoadOutcome:
    try:
        return _AuthLoadOutcome(
            evidence=_load_external_auth_inner(
                auth_path,
                filesystem_metadata_verifier=filesystem_metadata_verifier,
                minimum_remaining_seconds=minimum_remaining_seconds,
                now=now,
                monotonic_now=monotonic_now,
            )
        )
    except AuthCarrierRefreshRequired as error:
        return _AuthLoadOutcome(failure=_AuthLoadFailure(str(error), "refresh"))
    except AuthCarrierError as error:
        return _AuthLoadOutcome(
            failure=_AuthLoadFailure(str(error), "invalid", type(error))
        )
    except KeyboardInterrupt:
        return _AuthLoadOutcome(failure=_AuthLoadFailure("", "keyboard-interrupt"))
    except SystemExit:
        return _AuthLoadOutcome(failure=_AuthLoadFailure("", "system-exit"))
    except BaseException:
        return _AuthLoadOutcome(
            failure=_AuthLoadFailure(
                "auth carrier validation failed at a closed boundary",
                "invalid",
            )
        )


def _load_external_auth_inner(
    auth_path: pathlib.Path,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    minimum_remaining_seconds: int,
    now: float | None,
    monotonic_now: float | None,
) -> ExternalAuthEvidence:
    if (
        not isinstance(auth_path, pathlib.Path)
        or not auth_path.is_absolute()
        or any(part in {".", ".."} for part in auth_path.parts)
        or type(minimum_remaining_seconds) is not int
        or not 60 <= minimum_remaining_seconds <= 24 * 60 * 60
    ):
        raise AuthCarrierError("external-auth input policy is invalid")
    snapshot = _inspect_auth_source(
        auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
    )
    raw = snapshot.raw
    try:
        selected = _select_auth_from_content(raw)
        clock_sample = _validated_clock_sample(now, monotonic_now)
        if selected.expiration < (
            math.ceil(clock_sample.wall_time) + minimum_remaining_seconds
        ):
            if not selected.has_managed_refresh_token:
                raise AuthCarrierError("auth carrier has no managed refresh token")
            raise AuthCarrierRefreshRequired(
                "access token does not cover the review deadline"
            )
        try:
            auth = ExternalChatGPTAuth(
                access_token=selected.access_token,
                chatgpt_account_id=selected.account_id,
                chatgpt_plan_type=selected.plan_type,
            )
        except ValueError:
            raise AuthCarrierError(
                "auth carrier selected credentials are malformed"
            ) from None
        return ExternalAuthEvidence(
            auth=auth,
            source_directory_identity=snapshot.directory_identity,
            source_directory_access_policy=snapshot.directory_access_policy,
            source_identity=snapshot.source_identity,
            source_access_policy=snapshot.source_access_policy,
            source_size=snapshot.source_size,
            source_content_sha256=snapshot.source_content_sha256,
            access_token_expires_at=selected.expiration,
            access_token_sha256=selected.access_token_sha256,
            account_id_sha256=selected.account_id_sha256,
            minimum_remaining_seconds=minimum_remaining_seconds,
            wall_time_baseline=clock_sample.wall_time,
            monotonic_time_baseline=clock_sample.monotonic_time,
            clock_high_water=_ClockHighWater(
                lock=threading.Lock(),
                last_monotonic_time=clock_sample.monotonic_time,
                effective_wall_time=clock_sample.wall_time,
            ),
        )
    finally:
        _zero_bytearray(raw, label="auth-file-content")


def revalidate_external_auth_source(
    auth_path: pathlib.Path,
    evidence: ExternalAuthEvidence,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    now: float | None = None,
    monotonic_now: float | None = None,
) -> None:
    _validate_external_auth_evidence(evidence)
    snapshot = _inspect_auth_source(
        auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
    )
    raw = snapshot.raw
    try:
        if (
            snapshot.directory_identity != evidence.source_directory_identity
            or snapshot.source_identity != evidence.source_identity
        ):
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier object identity mismatch"
            )
        if (
            snapshot.source_size != evidence.source_size
            or snapshot.source_content_sha256 != evidence.source_content_sha256
        ):
            raise AuthCarrierContentMismatch("auth carrier content commitment mismatch")
        if (
            snapshot.directory_access_policy != evidence.source_directory_access_policy
            or snapshot.source_access_policy != evidence.source_access_policy
        ):
            raise AuthCarrierAccessPolicyMismatch("auth carrier access policy mismatch")
        try:
            selected = _select_auth_from_content(raw)
        except AuthCarrierError:
            raise AuthCarrierMalformedEvidence(
                "auth carrier committed content is malformed"
            ) from None
        if (
            selected.access_token != evidence.auth.access_token
            or selected.account_id != evidence.auth.chatgpt_account_id
            or selected.plan_type != evidence.auth.chatgpt_plan_type
            or selected.expiration != evidence.access_token_expires_at
            or selected.access_token_sha256 != evidence.access_token_sha256
            or selected.account_id_sha256 != evidence.account_id_sha256
        ):
            raise AuthCarrierMalformedEvidence(
                "external-auth evidence semantics do not match committed content"
            )
    finally:
        _zero_bytearray(raw, label="auth-file-content")
    _revalidate_clock_and_lifetime(
        evidence,
        now=now,
        monotonic_now=monotonic_now,
    )


def _validate_external_auth_evidence(evidence: object) -> None:
    try:
        if (
            type(evidence) is not ExternalAuthEvidence
            or not _auth_object_identity_is_valid(
                evidence.source_directory_identity,
                expected_file_type=stat.S_IFDIR,
            )
            or not _auth_object_identity_is_valid(
                evidence.source_identity,
                expected_file_type=stat.S_IFREG,
            )
            or not _auth_access_policy_is_valid(
                evidence.source_directory_access_policy,
                expected_mode=0o700,
            )
            or not _auth_access_policy_is_valid(
                evidence.source_access_policy,
                expected_mode=0o600,
            )
            or type(evidence.source_size) is not int
            or not 1 <= evidence.source_size <= MAX_AUTH_FILE_BYTES
            or not _is_sha256_hex(evidence.source_content_sha256)
            or type(evidence.access_token_expires_at) is not int
            or not _is_sha256_hex(evidence.access_token_sha256)
            or not _is_sha256_hex(evidence.account_id_sha256)
            or type(evidence.minimum_remaining_seconds) is not int
            or not 60 <= evidence.minimum_remaining_seconds <= 24 * 60 * 60
            or not _is_finite_clock_value(evidence.wall_time_baseline)
            or not _is_finite_clock_value(evidence.monotonic_time_baseline)
            or type(evidence.clock_high_water) is not _ClockHighWater
        ):
            raise AuthCarrierMalformedEvidence("external-auth evidence is malformed")
        expiration, access_token_sha256, account_id_sha256 = _credential_commitment(
            evidence.auth,
            require_exact_auth_type=True,
        )
        if (
            expiration != evidence.access_token_expires_at
            or access_token_sha256 != evidence.access_token_sha256
            or account_id_sha256 != evidence.account_id_sha256
        ):
            raise AuthCarrierMalformedEvidence("external-auth evidence is malformed")
    except AuthCarrierMalformedEvidence:
        raise
    except (AttributeError, TypeError, ValueError):
        raise AuthCarrierMalformedEvidence(
            "external-auth evidence is malformed"
        ) from None


def _auth_object_identity_is_valid(
    value: object,
    *,
    expected_file_type: int,
) -> bool:
    return (
        type(value) is _AuthObjectIdentity
        and type(value.device) is int
        and value.device >= 0
        and type(value.inode) is int
        and value.inode >= 0
        and type(value.file_type) is int
        and value.file_type == expected_file_type
        and (
            value.generation is None
            or (type(value.generation) is int and value.generation >= 0)
        )
    )


def _auth_access_policy_is_valid(
    value: object,
    *,
    expected_mode: int,
) -> bool:
    return (
        type(value) is _AuthAccessPolicy
        and type(value.uid) is int
        and value.uid == os.getuid()
        and type(value.gid) is int
        and value.gid >= 0
        and type(value.mode) is int
        and value.mode == expected_mode
        and type(value.flags) is int
        and value.flags >= 0
        and _extended_metadata_evidence_is_valid(value.extended_metadata)
    )


def _extended_metadata_evidence_is_valid(value: object) -> bool:
    return (
        type(value) is ExtendedMetadataEvidence
        and type(value.acl_entry_count) is int
        and value.acl_entry_count >= 0
        and type(value.acl_entries) is tuple
        and value.acl_entry_count == len(value.acl_entries)
        and all(
            type(entry) is str
            and bool(entry)
            and "\0" not in entry
            and "\n" not in entry
            and "\r" not in entry
            for entry in value.acl_entries
        )
        and len(set(value.acl_entries)) == len(value.acl_entries)
        and type(value.xattrs) is tuple
        and all(type(name) is str and bool(name) for name in value.xattrs)
        and len(set(value.xattrs)) == len(value.xattrs)
        and type(value.quarantine_present) is bool
        and value.quarantine_present == ("com.apple.quarantine" in value.xattrs)
    )


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _inspect_auth_source(
    auth_path: pathlib.Path,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
) -> _AuthSourceSnapshot:
    if (
        not isinstance(auth_path, pathlib.Path)
        or not auth_path.is_absolute()
        or auth_path.name != "auth.json"
        or any(part in {".", ".."} for part in auth_path.parts)
        or not callable(filesystem_metadata_verifier)
    ):
        raise AuthCarrierError("external-auth input policy is invalid")
    directory_fd = -1
    source_fd = -1
    raw: bytearray | None = None
    snapshot: _AuthSourceSnapshot | None = None
    failure: BaseException | None = None
    try:
        directory_fd = _source_path_operation(
            os.open,
            auth_path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_before = os.fstat(directory_fd)
        directory_path_before = _source_path_operation(os.lstat, auth_path.parent)
        directory_identity = _auth_object_identity(directory_before)
        if not stat.S_ISDIR(directory_before.st_mode):
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier directory object identity mismatch"
            )
        if _auth_object_identity(directory_path_before) != directory_identity:
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier directory object identity mismatch"
            )
        if (
            _auth_stat_access_key(directory_path_before)
            != _auth_stat_access_key(directory_before)
            or directory_before.st_uid != os.getuid()
            or stat.S_IMODE(directory_before.st_mode) != 0o700
        ):
            raise AuthCarrierAccessPolicyMismatch(
                "auth carrier directory access policy mismatch"
            )
        directory_metadata_before = _verify_auth_metadata(
            filesystem_metadata_verifier,
            directory_fd,
            auth_path.parent,
            "directory",
        )
        directory_access_policy = _auth_access_policy(
            directory_before,
            directory_metadata_before,
        )

        source_fd, _ = _source_path_operation(
            open_regular_at,
            directory_fd,
            b"auth.json",
            expected_uid=None,
            require_link_one=True,
        )
        source_before = os.fstat(source_fd)
        source_path_before = _source_path_operation(
            os.stat,
            b"auth.json",
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        source_identity = _auth_object_identity(source_before)
        source_size = source_before.st_size
        if not stat.S_ISREG(source_before.st_mode):
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier file object identity mismatch"
            )
        if _auth_object_identity(source_path_before) != source_identity:
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier file object identity mismatch"
            )
        if (
            _auth_stat_access_key(source_path_before)
            != _auth_stat_access_key(source_before)
            or source_before.st_uid != os.getuid()
            or stat.S_IMODE(source_before.st_mode) != 0o600
        ):
            raise AuthCarrierAccessPolicyMismatch(
                "auth carrier file access policy mismatch"
            )
        # Link count remains a point-in-time anti-exposure admission rule. It is
        # never retained or compared as object identity or content evidence.
        if source_before.st_nlink != 1 or source_path_before.st_nlink != 1:
            raise AuthCarrierAccessPolicyMismatch(
                "auth carrier file access policy mismatch"
            )
        if not 1 <= source_size <= MAX_AUTH_FILE_BYTES:
            raise AuthCarrierContentMismatch(
                "auth carrier content size is outside its bound"
            )
        if source_path_before.st_size != source_size:
            raise AuthCarrierContentMismatch("auth carrier content size mismatch")
        source_metadata_before = _verify_auth_metadata(
            filesystem_metadata_verifier,
            source_fd,
            auth_path,
            "file",
        )
        source_access_policy = _auth_access_policy(
            source_before,
            source_metadata_before,
        )
        raw, source_content_sha256 = _read_auth_fd_exact(
            source_fd,
            expected_size=source_size,
        )

        directory_metadata_after = _verify_auth_metadata(
            filesystem_metadata_verifier,
            directory_fd,
            auth_path.parent,
            "directory",
        )
        source_metadata_after = _verify_auth_metadata(
            filesystem_metadata_verifier,
            source_fd,
            auth_path,
            "file",
        )
        directory_path_after = _source_path_operation(os.lstat, auth_path.parent)
        directory_after = os.fstat(directory_fd)
        source_after = os.fstat(source_fd)
        source_path_after = _source_path_operation(
            os.stat,
            b"auth.json",
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        directory_identity_after = _auth_object_identity(directory_after)
        source_identity_after = _auth_object_identity(source_after)
        confirmed_content_sha256 = _sha256_auth_fd(
            source_fd,
            expected_size=source_size,
        )
        if (
            directory_identity_after != directory_identity
            or _auth_object_identity(directory_path_after) != directory_identity
            or source_identity_after != source_identity
            or _auth_object_identity(source_path_after) != source_identity
        ):
            raise AuthCarrierObjectIdentityMismatch(
                "auth carrier object identity changed during inspection"
            )
        if (
            source_after.st_size != source_size
            or source_path_after.st_size != source_size
            or confirmed_content_sha256 != source_content_sha256
        ):
            raise AuthCarrierContentMismatch(
                "auth carrier content changed during inspection"
            )
        if (
            _auth_access_policy(directory_after, directory_metadata_after)
            != directory_access_policy
            or _auth_access_policy(source_after, source_metadata_after)
            != source_access_policy
            or _auth_stat_access_key(directory_path_after)
            != _auth_stat_access_key(directory_after)
            or _auth_stat_access_key(source_path_after)
            != _auth_stat_access_key(source_after)
            or source_after.st_nlink != 1
            or source_path_after.st_nlink != 1
        ):
            raise AuthCarrierAccessPolicyMismatch(
                "auth carrier access policy changed during inspection"
            )
        snapshot = _AuthSourceSnapshot(
            raw=raw,
            directory_identity=directory_identity,
            directory_access_policy=directory_access_policy,
            source_identity=source_identity,
            source_access_policy=source_access_policy,
            source_size=source_size,
            source_content_sha256=source_content_sha256,
        )
    except BaseException as error:
        failure = error
    finally:
        for fd in (source_fd, directory_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None or (
                    isinstance(error, (KeyboardInterrupt, SystemExit))
                    and not isinstance(failure, (KeyboardInterrupt, SystemExit))
                ):
                    failure = error
        if failure is not None and raw is not None:
            _zero_bytearray(raw, label="auth-file-content")
    if isinstance(failure, (KeyboardInterrupt, SystemExit)):
        raise failure.with_traceback(None) from None
    if isinstance(failure, AuthCarrierError):
        raise failure
    if failure is not None:
        raise AuthCarrierInspectionFailure(
            "auth carrier source inspection failed"
        ) from None
    if snapshot is None:
        raise AuthCarrierInspectionFailure(
            "auth carrier source inspection produced no snapshot"
        )
    return snapshot


def _source_path_operation(operation: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return operation(*args, **kwargs)
    except FileNotFoundError:
        raise AuthCarrierSourceMissing("auth carrier source is missing") from None


def _auth_object_identity(value: os.stat_result) -> _AuthObjectIdentity:
    return _AuthObjectIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        file_type=stat.S_IFMT(value.st_mode),
        generation=getattr(value, "st_gen", None),
    )


def _auth_stat_access_key(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        getattr(value, "st_flags", 0),
    )


def _auth_access_policy(
    value: os.stat_result,
    extended_metadata: ExtendedMetadataEvidence,
) -> _AuthAccessPolicy:
    return _AuthAccessPolicy(
        uid=value.st_uid,
        gid=value.st_gid,
        mode=stat.S_IMODE(value.st_mode),
        flags=getattr(value, "st_flags", 0),
        extended_metadata=extended_metadata,
    )


def _verify_auth_metadata(
    verifier: FilesystemMetadataVerifier,
    fd: int,
    path: pathlib.Path,
    kind: str,
) -> ExtendedMetadataEvidence:
    try:
        return verify_filesystem_metadata_evidence(verifier, fd, path, kind)
    except ValueError as error:
        if str(error) == "filesystem metadata verifier returned malformed evidence":
            raise AuthCarrierInspectionFailure(
                "auth carrier metadata inspection failed"
            ) from None
        raise AuthCarrierAccessPolicyMismatch(
            "auth carrier ACL/xattr policy mismatch"
        ) from None


def _read_auth_fd_exact(fd: int, *, expected_size: int) -> tuple[bytearray, str]:
    if (
        type(fd) is not int
        or fd < 0
        or type(expected_size) is not int
        or not 1 <= expected_size <= MAX_AUTH_FILE_BYTES
    ):
        raise ValueError("auth carrier read input is outside its bound")
    os.lseek(fd, 0, os.SEEK_SET)
    content = bytearray(expected_size)
    extra = bytearray(1)
    view = memoryview(content)
    completed = False
    try:
        offset = 0
        while offset < expected_size:
            target = view[offset:]
            try:
                count = os.readv(fd, (target,))
            finally:
                target.release()
            if not 1 <= count <= expected_size - offset:
                raise AuthCarrierContentMismatch(
                    "auth carrier ended before its attested size"
                )
            offset += count
        if os.readv(fd, (extra,)):
            raise AuthCarrierContentMismatch("auth carrier exceeds its attested size")
        result = (content, hashlib.sha256(content).hexdigest())
        completed = True
        return result
    finally:
        view.release()
        _zero_bytearray(extra, label="auth-file-extra")
        if not completed:
            _zero_bytearray(content, label="auth-file-content")


def _sha256_auth_fd(fd: int, *, expected_size: int) -> str:
    """Digest one exact bounded descriptor read and zero its mutable buffers."""

    if (
        type(fd) is not int
        or fd < 0
        or type(expected_size) is not int
        or not 1 <= expected_size <= MAX_AUTH_FILE_BYTES
    ):
        raise ValueError("auth carrier digest input is outside its bound")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    scratch = bytearray(min(AUTH_DIGEST_CHUNK_BYTES, expected_size))
    extra = bytearray(1)
    view = memoryview(scratch)
    try:
        remaining = expected_size
        while remaining:
            requested = min(len(view), remaining)
            chunk_view = view[:requested]
            try:
                count = os.readv(fd, (chunk_view,))
            finally:
                chunk_view.release()
            if not 1 <= count <= requested:
                raise AuthCarrierContentMismatch(
                    "auth carrier ended before its attested size"
                )
            digest.update(view[:count])
            remaining -= count
        if os.readv(fd, (extra,)):
            raise AuthCarrierContentMismatch("auth carrier exceeds its attested size")
        return digest.hexdigest()
    finally:
        view.release()
        _zero_bytearray(scratch, label="auth-digest-scratch")
        _zero_bytearray(extra, label="auth-digest-extra")


def _zero_bytearray(value: bytearray, *, label: str) -> None:
    del label
    if value:
        value[:] = b"\0" * len(value)
        value.clear()


def _select_auth_from_content(raw: bytearray) -> _SelectedAuth:
    # The selected access-token str must survive through runtime handoff and
    # cannot be forcibly zeroized in Python. Remove refresh and ID token string
    # references promptly; mutable raw, JWT, and encoding buffers are wiped by
    # their owners on every success and failure path.
    value = _decode_json(raw)
    tokens: dict[str, Any] | None = None
    id_claims: dict[str, Any] | None = None
    id_token: object = None
    refresh_token: object = None
    try:
        if value.pop("auth_mode", None) != "chatgpt":
            raise AuthCarrierError("auth carrier is not in ChatGPT auth mode")
        candidate_tokens = value.pop("tokens", None)
        if not isinstance(candidate_tokens, dict):
            raise AuthCarrierError("auth carrier has no ChatGPT token record")
        tokens = candidate_tokens
        access_token = tokens.pop("access_token", None)
        account_id = tokens.pop("account_id", None)
        id_token = tokens.pop("id_token", None)
        refresh_token = tokens.pop("refresh_token", None)
        has_managed_refresh_token = type(refresh_token) is str and bool(refresh_token)
        refresh_token = None

        if type(access_token) is not str:
            raise AuthCarrierError("auth carrier has no access token")
        plan_type: str | None = None
        if id_token is not None and type(id_token) is not str:
            raise AuthCarrierError("auth carrier contains a malformed ID token")
        if type(id_token) is str:
            id_claims = _decode_jwt_claims(id_token)
            auth_claims = id_claims.get("https://api.openai.com/auth")
            if isinstance(auth_claims, dict):
                if type(account_id) is not str or not account_id:
                    account_id = auth_claims.get("chatgpt_account_id")
                candidate_plan = auth_claims.get("chatgpt_plan_type")
                if type(candidate_plan) is str and candidate_plan:
                    plan_type = candidate_plan
        id_token = None
        if type(account_id) is not str or not account_id:
            raise AuthCarrierError("auth carrier has no ChatGPT account ID")
        expiration, access_token_sha256, account_id_sha256 = (
            _credential_values_commitment(
                access_token,
                account_id,
                plan_type,
            )
        )
        return _SelectedAuth(
            access_token=access_token,
            account_id=account_id,
            plan_type=plan_type,
            expiration=expiration,
            access_token_sha256=access_token_sha256,
            account_id_sha256=account_id_sha256,
            has_managed_refresh_token=has_managed_refresh_token,
        )
    finally:
        refresh_token = None
        id_token = None
        if id_claims is not None:
            id_claims.clear()
        if tokens is not None:
            tokens.clear()
        value.clear()


def _credential_commitment(
    auth: object,
    *,
    require_exact_auth_type: bool,
) -> tuple[int, str, str]:
    if (
        require_exact_auth_type and type(auth) is not ExternalChatGPTAuth
    ) or not isinstance(auth, ExternalChatGPTAuth):
        raise AuthCarrierError("external auth object has an invalid type")
    return _credential_values_commitment(
        auth.access_token,
        auth.chatgpt_account_id,
        auth.chatgpt_plan_type,
    )


def _credential_values_commitment(
    access_token: object,
    account_id: object,
    plan_type: object,
) -> tuple[int, str, str]:
    access_token_buffer = _bounded_mutable_text(
        access_token,
        encoding="ascii",
        maximum=MAX_ACCESS_TOKEN_BYTES,
        label="access-token-encoding",
    )
    account_id_buffer: bytearray | None = None
    plan_type_buffer: bytearray | None = None
    claims: dict[str, Any] | None = None
    try:
        if not _jwt_buffer_shape_is_valid(access_token_buffer):
            raise AuthCarrierError("external access token is not a bounded JWT")
        account_id_buffer = _bounded_mutable_text(
            account_id,
            encoding="utf-8",
            maximum=MAX_ACCOUNT_ID_BYTES,
            label="account-id-encoding",
        )
        if plan_type is not None:
            plan_type_buffer = _bounded_mutable_text(
                plan_type,
                encoding="utf-8",
                maximum=MAX_PLAN_TYPE_BYTES,
                label="plan-type-encoding",
            )
        claims = _decode_jwt_claims_buffer(access_token_buffer)
        expiration = claims.get("exp")
        if type(expiration) is not int:
            raise AuthCarrierError("access token has no integer expiration")
        return (
            expiration,
            hashlib.sha256(access_token_buffer).hexdigest(),
            hashlib.sha256(account_id_buffer).hexdigest(),
        )
    finally:
        if claims is not None:
            claims.clear()
        _zero_bytearray(
            access_token_buffer,
            label="access-token-encoding",
        )
        if account_id_buffer is not None:
            _zero_bytearray(
                account_id_buffer,
                label="account-id-encoding",
            )
        if plan_type_buffer is not None:
            _zero_bytearray(
                plan_type_buffer,
                label="plan-type-encoding",
            )


def _bounded_mutable_text(
    value: object,
    *,
    encoding: str,
    maximum: int,
    label: str,
) -> bytearray:
    if type(value) is not str:
        raise AuthCarrierError("auth carrier selected text is malformed")
    try:
        encoded = bytearray(value, encoding, errors="strict")
    except UnicodeEncodeError:
        raise AuthCarrierError("auth carrier selected text is malformed") from None
    try:
        if (
            not 1 <= len(encoded) <= maximum
            or "\0" in value
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
        ):
            raise AuthCarrierError("auth carrier selected text is malformed")
        return encoded
    except BaseException:
        _zero_bytearray(encoded, label=label)
        raise


def _jwt_buffer_shape_is_valid(token: bytearray) -> bool:
    first_separator = token.find(b".")
    second_separator = token.find(b".", first_separator + 1)
    return (
        first_separator > 0
        and second_separator > first_separator + 1
        and second_separator < len(token) - 1
        and token.find(b".", second_separator + 1) == -1
        and all(value == ord(".") or value in JWT_PART_BYTES for value in token)
    )


def _validated_clock_sample(
    now: float | None,
    monotonic_now: float | None,
) -> _ClockSample:
    # Sampling the suspend-aware clock first makes any delay before the wall read
    # conservative while still accounting for time spent asleep.
    monotonic_time = _read_clock_value(monotonic_now, _suspend_aware_monotonic)
    return _ClockSample(
        wall_time=_read_clock_value(now, time.time),
        monotonic_time=monotonic_time,
    )


def _read_clock_value(
    supplied_value: float | None,
    clock: Any,
) -> float:
    if supplied_value is None:
        try:
            value = clock()
        except Exception:
            raise AuthCarrierError("external-auth clock is unavailable") from None
    else:
        value = supplied_value
    if not _is_finite_clock_value(value):
        raise AuthCarrierError("external-auth clock value is invalid")
    return float(value)


def _is_finite_clock_value(value: object) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _suspend_aware_monotonic() -> float:
    boot_clock = getattr(time, "CLOCK_BOOTTIME", None)
    if type(boot_clock) is int:
        return time.clock_gettime(boot_clock)
    if sys.platform == "darwin":
        return _darwin_continuous_seconds()
    raise OSError("no suspend-aware monotonic clock is available")


@functools.cache
def _darwin_continuous_clock_binding() -> tuple[Any, Any, int, int]:
    class MachTimebaseInfo(ctypes.Structure):
        _fields_ = (("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32))

    try:
        library = ctypes.CDLL(None)
        clock = library.mach_continuous_time
        clock.argtypes = ()
        clock.restype = ctypes.c_uint64
        timebase = library.mach_timebase_info
        timebase.argtypes = (ctypes.POINTER(MachTimebaseInfo),)
        timebase.restype = ctypes.c_int
        info = MachTimebaseInfo()
        status = timebase(ctypes.byref(info))
    except Exception as error:
        raise OSError("Darwin continuous clock is unavailable") from error
    if status != 0 or info.numer == 0 or info.denom == 0:
        raise OSError("Darwin continuous clock timebase is invalid")
    return library, clock, int(info.numer), int(info.denom)


def _darwin_continuous_seconds() -> float:
    _, clock, numerator, denominator = _darwin_continuous_clock_binding()
    ticks = int(clock())
    if ticks < 0:
        raise OSError("Darwin continuous clock returned an invalid value")
    return (ticks * numerator) / denominator / 1_000_000_000


def _revalidate_clock_and_lifetime(
    evidence: ExternalAuthEvidence,
    *,
    now: float | None,
    monotonic_now: float | None,
) -> None:
    state = evidence.clock_high_water
    try:
        with state.lock:
            if not _is_finite_clock_value(
                state.last_monotonic_time
            ) or not _is_finite_clock_value(state.effective_wall_time):
                raise AuthCarrierError("external-auth evidence is malformed")
            clock_sample = _validated_clock_sample(now, monotonic_now)
            monotonic_elapsed = (
                clock_sample.monotonic_time - evidence.monotonic_time_baseline
            )
            if not math.isfinite(monotonic_elapsed):
                raise AuthCarrierError("external-auth clock value is invalid")
            if (
                monotonic_elapsed < 0
                or clock_sample.monotonic_time < state.last_monotonic_time
            ):
                raise AuthCarrierError("external-auth monotonic clock moved backwards")
            expected_wall_time = evidence.wall_time_baseline + monotonic_elapsed
            if not math.isfinite(expected_wall_time):
                raise AuthCarrierError("external-auth clock value is invalid")
            backward_drift = expected_wall_time - clock_sample.wall_time
            if not math.isfinite(backward_drift):
                raise AuthCarrierError("external-auth clock value is invalid")
            if backward_drift > WALL_CLOCK_ROLLBACK_TOLERANCE_SECONDS:
                raise AuthCarrierError("external-auth wall clock moved backwards")
            candidate_wall_time = max(
                clock_sample.wall_time,
                expected_wall_time,
            )
            if (
                state.effective_wall_time - candidate_wall_time
                > WALL_CLOCK_ROLLBACK_TOLERANCE_SECONDS
            ):
                raise AuthCarrierError("external-auth wall clock moved backwards")
            effective_wall_time = max(
                candidate_wall_time,
                state.effective_wall_time,
            )
            state.last_monotonic_time = clock_sample.monotonic_time
            state.effective_wall_time = effective_wall_time
            if evidence.access_token_expires_at < (
                math.ceil(effective_wall_time) + evidence.minimum_remaining_seconds
            ):
                raise AuthCarrierError(
                    "access token no longer covers the bounded review runtime"
                )
    except AuthCarrierError:
        raise
    except Exception:
        raise AuthCarrierError("external-auth clock state is unavailable") from None


def _decode_json(raw: bytes | bytearray) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthCarrierError("auth carrier contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise AuthCarrierError(f"invalid JSON number: {value}")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except AuthCarrierError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise AuthCarrierError("auth carrier is not strict UTF-8 JSON") from None
    try:
        _reject_non_finite_json_floats(value)
    except RecursionError as error:
        raise AuthCarrierError("auth carrier JSON nesting is too deep") from error
    if not isinstance(value, dict):
        raise AuthCarrierError("auth carrier root is not an object")
    return value


def _reject_non_finite_json_floats(value: Any) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuthCarrierError("auth carrier contains a non-finite JSON number")
        return
    if isinstance(value, dict):
        for child in value.values():
            _reject_non_finite_json_floats(child)
        return
    if isinstance(value, list):
        for child in value:
            _reject_non_finite_json_floats(child)


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    token_buffer = _bounded_mutable_text(
        token,
        encoding="ascii",
        maximum=MAX_JWT_TOKEN_BYTES,
        label="jwt-token-encoding",
    )
    try:
        return _decode_jwt_claims_buffer(token_buffer)
    finally:
        _zero_bytearray(
            token_buffer,
            label="jwt-token-encoding",
        )


def _decode_jwt_claims_buffer(token: bytearray) -> dict[str, Any]:
    if not _jwt_buffer_shape_is_valid(token):
        raise AuthCarrierError("auth carrier contains a malformed JWT")
    first_separator = token.find(b".")
    second_separator = token.find(b".", first_separator + 1)
    encoded_payload = token[first_separator + 1 : second_separator]
    if len(encoded_payload) > 4 * MAX_JWT_PAYLOAD_BYTES // 3 + 4:
        _zero_bytearray(
            encoded_payload,
            label="jwt-encoded-payload",
        )
        raise AuthCarrierError("JWT payload exceeds its encoded bound")
    decoded_payload: bytearray | None = None
    try:
        encoded_payload.extend(b"=" * (-len(encoded_payload) % 4))
        try:
            immutable_decoded = base64.b64decode(
                encoded_payload,
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, TypeError):
            raise AuthCarrierError("JWT payload is not canonical base64url") from None
        decoded_payload = bytearray(immutable_decoded)
        del immutable_decoded
        if len(decoded_payload) > MAX_JWT_PAYLOAD_BYTES:
            raise AuthCarrierError("JWT payload exceeds its decoded bound")
        return _decode_json(decoded_payload)
    finally:
        _zero_bytearray(
            encoded_payload,
            label="jwt-encoded-payload",
        )
        if decoded_payload is not None:
            _zero_bytearray(
                decoded_payload,
                label="jwt-decoded-payload",
            )
