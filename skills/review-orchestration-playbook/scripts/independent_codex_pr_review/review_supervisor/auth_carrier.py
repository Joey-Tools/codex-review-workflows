from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import pathlib
import stat
import time
from dataclasses import dataclass
from typing import Any

from .appserver_protocol import ExternalChatGPTAuth
from .codex_executable import (
    FilesystemMetadataVerifier,
    verify_filesystem_metadata_evidence,
)
from .models import Identity
from .secureio import identity_from_stat, open_regular_at, read_fd_exact


MAX_AUTH_FILE_BYTES = 64 * 1024
MAX_JWT_PAYLOAD_BYTES = 32 * 1024
MIN_ACCESS_TOKEN_REMAINING_SECONDS = 45 * 60


class AuthCarrierError(ValueError):
    pass


class AuthCarrierRefreshRequired(AuthCarrierError):
    pass


@dataclass(frozen=True)
class ExternalAuthEvidence:
    auth: ExternalChatGPTAuth
    source_directory_identity: tuple[int, int, int, int, int, int, int]
    source_identity: Identity
    source_mtime_ns: int
    source_ctime_ns: int
    access_token_expires_at: int
    access_token_sha256: str
    account_id_sha256: str
    minimum_remaining_seconds: int

    @property
    def source_size(self) -> int:
        return self.source_identity.size

    def to_json(self) -> dict[str, bool | str]:
        return {
            "auth_mode": "external-chatgpt",
            "carrier_generation_verified": True,
        }


@dataclass(frozen=True, slots=True)
class _AuthLoadFailure:
    message: str
    kind: str


@dataclass(frozen=True, slots=True)
class _AuthLoadOutcome:
    evidence: ExternalAuthEvidence | None = None
    failure: _AuthLoadFailure | None = None


@dataclass(frozen=True, slots=True)
class _AuthSourceSnapshot:
    raw: bytes | None
    directory_identity: tuple[int, int, int, int, int, int, int]
    source_identity: Identity
    source_mtime_ns: int
    source_ctime_ns: int


def load_external_auth(
    auth_path: pathlib.Path,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    minimum_remaining_seconds: int = MIN_ACCESS_TOKEN_REMAINING_SECONDS,
    now: float | None = None,
) -> ExternalAuthEvidence:
    outcome = _load_external_auth_boundary(
        auth_path=auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
        minimum_remaining_seconds=minimum_remaining_seconds,
        now=now,
    )
    if outcome.failure is not None:
        if outcome.failure.kind == "refresh":
            raise AuthCarrierRefreshRequired(outcome.failure.message) from None
        if outcome.failure.kind == "keyboard-interrupt":
            raise KeyboardInterrupt() from None
        if outcome.failure.kind == "system-exit":
            raise SystemExit(1) from None
        raise AuthCarrierError(outcome.failure.message) from None
    if outcome.evidence is None:
        raise AuthCarrierError("auth carrier validation produced no result") from None
    return outcome.evidence


def _load_external_auth_boundary(
    *,
    auth_path: pathlib.Path,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    minimum_remaining_seconds: int,
    now: float | None,
) -> _AuthLoadOutcome:
    try:
        return _AuthLoadOutcome(
            evidence=_load_external_auth_inner(
                auth_path,
                filesystem_metadata_verifier=filesystem_metadata_verifier,
                minimum_remaining_seconds=minimum_remaining_seconds,
                now=now,
            )
        )
    except AuthCarrierRefreshRequired as error:
        return _AuthLoadOutcome(failure=_AuthLoadFailure(str(error), "refresh"))
    except AuthCarrierError as error:
        return _AuthLoadOutcome(failure=_AuthLoadFailure(str(error), "invalid"))
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
) -> ExternalAuthEvidence:
    if (
        not auth_path.is_absolute()
        or any(part in {".", ".."} for part in auth_path.parts)
        or type(minimum_remaining_seconds) is not int
        or not 60 <= minimum_remaining_seconds <= 24 * 60 * 60
    ):
        raise AuthCarrierError("external-auth input policy is invalid")
    snapshot = _inspect_auth_source(
        auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
        read_content=True,
    )
    raw = snapshot.raw
    if raw is None:
        raise AuthCarrierError("auth carrier validation produced no content")

    value = _decode_json(raw)
    if value.get("auth_mode") != "chatgpt":
        raise AuthCarrierError("auth carrier is not in ChatGPT auth mode")
    tokens = value.get("tokens")
    if not isinstance(tokens, dict):
        raise AuthCarrierError("auth carrier has no ChatGPT token record")
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise AuthCarrierError("auth carrier has no access token")
    claims = _decode_jwt_claims(access_token)
    expiration = claims.get("exp")
    if type(expiration) is not int:
        raise AuthCarrierError("access token has no integer expiration")

    account_id = tokens.get("account_id")
    plan_type: str | None = None
    id_token = tokens.get("id_token")
    if id_token is not None and not isinstance(id_token, str):
        raise AuthCarrierError("auth carrier contains a malformed ID token")
    if isinstance(id_token, str):
        id_claims = _decode_jwt_claims(id_token)
        auth_claims = id_claims.get("https://api.openai.com/auth")
        if isinstance(auth_claims, dict):
            if not isinstance(account_id, str) or not account_id:
                account_id = auth_claims.get("chatgpt_account_id")
            candidate_plan = auth_claims.get("chatgpt_plan_type")
            if isinstance(candidate_plan, str) and candidate_plan:
                plan_type = candidate_plan
    if not isinstance(account_id, str) or not account_id:
        raise AuthCarrierError("auth carrier has no ChatGPT account ID")
    try:
        access_token_bytes = access_token.encode("ascii", "strict")
        account_id_bytes = account_id.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise AuthCarrierError("auth carrier token identity is malformed") from None
    current_time = _validated_current_time(now)
    if expiration < math.ceil(current_time) + minimum_remaining_seconds:
        refresh_token = tokens.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise AuthCarrierError("auth carrier has no managed refresh token")
        raise AuthCarrierRefreshRequired(
            "access token does not cover the review deadline"
        )

    auth = ExternalChatGPTAuth(
        access_token=access_token,
        chatgpt_account_id=account_id,
        chatgpt_plan_type=plan_type,
    )
    return ExternalAuthEvidence(
        auth=auth,
        source_directory_identity=snapshot.directory_identity,
        source_identity=snapshot.source_identity,
        source_mtime_ns=snapshot.source_mtime_ns,
        source_ctime_ns=snapshot.source_ctime_ns,
        access_token_expires_at=expiration,
        access_token_sha256=hashlib.sha256(access_token_bytes).hexdigest(),
        account_id_sha256=hashlib.sha256(account_id_bytes).hexdigest(),
        minimum_remaining_seconds=minimum_remaining_seconds,
    )


def revalidate_external_auth_source(
    auth_path: pathlib.Path,
    evidence: ExternalAuthEvidence,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    now: float | None = None,
) -> None:
    if (
        not isinstance(evidence, ExternalAuthEvidence)
        or type(evidence.access_token_expires_at) is not int
        or type(evidence.minimum_remaining_seconds) is not int
        or not 60 <= evidence.minimum_remaining_seconds <= 24 * 60 * 60
    ):
        raise AuthCarrierError("external-auth evidence is malformed")
    snapshot = _inspect_auth_source(
        auth_path,
        filesystem_metadata_verifier=filesystem_metadata_verifier,
        read_content=False,
    )
    if (
        snapshot.directory_identity != evidence.source_directory_identity
        or _snapshot_generation(snapshot) != _evidence_generation(evidence)
    ):
        raise AuthCarrierError("auth carrier generation changed before use")
    current_time = _validated_current_time(now)
    if evidence.access_token_expires_at < (
        math.ceil(current_time) + evidence.minimum_remaining_seconds
    ):
        raise AuthCarrierError(
            "access token no longer covers the bounded review runtime"
        )


def _inspect_auth_source(
    auth_path: pathlib.Path,
    *,
    filesystem_metadata_verifier: FilesystemMetadataVerifier,
    read_content: bool,
) -> _AuthSourceSnapshot:
    if (
        not isinstance(auth_path, pathlib.Path)
        or not auth_path.is_absolute()
        or auth_path.name != "auth.json"
        or any(part in {".", ".."} for part in auth_path.parts)
        or not callable(filesystem_metadata_verifier)
        or type(read_content) is not bool
    ):
        raise AuthCarrierError("external-auth input policy is invalid")
    directory_fd = -1
    source_fd = -1
    snapshot: _AuthSourceSnapshot | None = None
    failure: BaseException | None = None
    try:
        directory_fd = os.open(
            auth_path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_before = os.fstat(directory_fd)
        directory_path_before = os.lstat(auth_path.parent)
        directory_identity = _directory_object_identity(directory_before)
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_uid != os.getuid()
            or stat.S_IMODE(directory_before.st_mode) != 0o700
            or _directory_object_identity(directory_path_before) != directory_identity
        ):
            raise AuthCarrierError("auth carrier directory is not owner-only")
        directory_metadata_before = verify_filesystem_metadata_evidence(
            filesystem_metadata_verifier,
            directory_fd,
            auth_path.parent,
            "directory",
        )

        source_fd, source_identity = open_regular_at(
            directory_fd,
            b"auth.json",
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        source_before = os.fstat(source_fd)
        source_path_before = os.stat(
            b"auth.json",
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        source_generation = _auth_generation(source_before)
        if (
            identity_from_stat(source_before) != source_identity
            or _auth_generation(source_path_before) != source_generation
        ):
            raise AuthCarrierError("auth carrier changed before it was read")
        if stat.S_IMODE(source_before.st_mode) != 0o600:
            raise AuthCarrierError("auth carrier mode is not exactly 0600")
        if not 1 <= source_before.st_size <= MAX_AUTH_FILE_BYTES:
            raise AuthCarrierError("auth carrier length is outside its bound")
        source_metadata_before = verify_filesystem_metadata_evidence(
            filesystem_metadata_verifier,
            source_fd,
            auth_path,
            "file",
        )
        raw = (
            read_fd_exact(
                source_fd,
                max_bytes=MAX_AUTH_FILE_BYTES,
                expected_size=source_before.st_size,
            )
            if read_content
            else None
        )

        directory_metadata_after = verify_filesystem_metadata_evidence(
            filesystem_metadata_verifier,
            directory_fd,
            auth_path.parent,
            "directory",
        )
        source_metadata_after = verify_filesystem_metadata_evidence(
            filesystem_metadata_verifier,
            source_fd,
            auth_path,
            "file",
        )
        directory_path_after = os.lstat(auth_path.parent)
        directory_after = os.fstat(directory_fd)
        source_after = os.fstat(source_fd)
        source_path_after = os.stat(
            b"auth.json",
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            _auth_generation(source_after) != source_generation
            or _auth_generation(source_path_after) != source_generation
            or _directory_object_identity(directory_after) != directory_identity
            or _directory_object_identity(directory_path_after) != directory_identity
            or directory_metadata_after != directory_metadata_before
            or source_metadata_after != source_metadata_before
        ):
            raise AuthCarrierError("auth carrier changed while it was inspected")
        snapshot = _AuthSourceSnapshot(
            raw=raw,
            directory_identity=directory_identity,
            source_identity=source_identity,
            source_mtime_ns=source_after.st_mtime_ns,
            source_ctime_ns=source_after.st_ctime_ns,
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
                if failure is None:
                    failure = error
    if isinstance(failure, AuthCarrierError):
        raise failure
    if failure is not None:
        raise AuthCarrierError("auth carrier could not be inspected safely") from None
    if snapshot is None:
        raise AuthCarrierError("auth carrier validation produced no snapshot")
    return snapshot


def _directory_object_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        getattr(value, "st_flags", 0),
        getattr(value, "st_gen", 0),
    )


def _validated_current_time(now: float | None) -> int | float:
    if now is None:
        try:
            current_time = time.time()
        except Exception:
            raise AuthCarrierError("external-auth clock is unavailable") from None
    else:
        current_time = now
    if type(current_time) not in {int, float} or not math.isfinite(current_time):
        raise AuthCarrierError("external-auth clock value is invalid")
    return current_time


def _auth_generation(value: os.stat_result) -> tuple[Identity, int, int, int]:
    return (
        identity_from_stat(value),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _evidence_generation(
    evidence: ExternalAuthEvidence,
) -> tuple[Identity, int, int, int]:
    return (
        evidence.source_identity,
        evidence.source_size,
        evidence.source_mtime_ns,
        evidence.source_ctime_ns,
    )


def _snapshot_generation(
    snapshot: _AuthSourceSnapshot,
) -> tuple[Identity, int, int, int]:
    return (
        snapshot.source_identity,
        snapshot.source_identity.size,
        snapshot.source_mtime_ns,
        snapshot.source_ctime_ns,
    )


def _decode_json(raw: bytes) -> dict[str, Any]:
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
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except AuthCarrierError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthCarrierError("auth carrier is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AuthCarrierError("auth carrier root is not an object")
    return value


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise AuthCarrierError("auth carrier contains a malformed JWT")
    payload = parts[1]
    if len(payload) > 4 * MAX_JWT_PAYLOAD_BYTES // 3 + 4:
        raise AuthCarrierError("JWT payload exceeds its encoded bound")
    try:
        padding = "=" * (-len(payload) % 4)
        decoded = base64.b64decode(
            payload + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise AuthCarrierError("JWT payload is not canonical base64url") from error
    if len(decoded) > MAX_JWT_PAYLOAD_BYTES:
        raise AuthCarrierError("JWT payload exceeds its decoded bound")
    return _decode_json(decoded)
