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
from .models import Identity
from .secureio import identity_from_stat, open_regular_nofollow, read_fd_exact


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


def load_external_auth(
    auth_path: pathlib.Path,
    *,
    minimum_remaining_seconds: int = MIN_ACCESS_TOKEN_REMAINING_SECONDS,
    now: float | None = None,
) -> ExternalAuthEvidence:
    outcome = _load_external_auth_boundary(
        auth_path=auth_path,
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
    minimum_remaining_seconds: int,
    now: float | None,
) -> _AuthLoadOutcome:
    try:
        return _AuthLoadOutcome(
            evidence=_load_external_auth_inner(
                auth_path,
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
    try:
        fd, identity = open_regular_nofollow(
            auth_path,
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        try:
            descriptor_before = os.fstat(fd)
            path_before = os.lstat(auth_path)
            generation_before = _auth_generation(descriptor_before)
            if (
                identity_from_stat(descriptor_before) != identity
                or _auth_generation(path_before) != generation_before
            ):
                raise AuthCarrierError("auth carrier changed before it was read")
            if stat.S_IMODE(descriptor_before.st_mode) != 0o600:
                raise AuthCarrierError("auth carrier mode is not exactly 0600")
            if not 1 <= descriptor_before.st_size <= MAX_AUTH_FILE_BYTES:
                raise AuthCarrierError("auth carrier length is outside its bound")
            raw = read_fd_exact(
                fd,
                max_bytes=MAX_AUTH_FILE_BYTES,
                expected_size=descriptor_before.st_size,
            )
            descriptor_after = os.fstat(fd)
            path_after = os.lstat(auth_path)
            if any(
                _auth_generation(candidate) != generation_before
                for candidate in (descriptor_after, path_after)
            ):
                raise AuthCarrierError("auth carrier changed while it was read")
        finally:
            os.close(fd)
    except AuthCarrierError:
        raise
    except (OSError, ValueError) as error:
        raise AuthCarrierError("auth carrier could not be read safely") from error

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
        source_identity=identity,
        source_mtime_ns=descriptor_after.st_mtime_ns,
        source_ctime_ns=descriptor_after.st_ctime_ns,
        access_token_expires_at=expiration,
        access_token_sha256=hashlib.sha256(access_token_bytes).hexdigest(),
        account_id_sha256=hashlib.sha256(account_id_bytes).hexdigest(),
        minimum_remaining_seconds=minimum_remaining_seconds,
    )


def revalidate_external_auth_source(
    auth_path: pathlib.Path,
    evidence: ExternalAuthEvidence,
    *,
    now: float | None = None,
) -> None:
    if (
        not isinstance(evidence, ExternalAuthEvidence)
        or type(evidence.access_token_expires_at) is not int
        or type(evidence.minimum_remaining_seconds) is not int
        or not 60 <= evidence.minimum_remaining_seconds <= 24 * 60 * 60
    ):
        raise AuthCarrierError("external-auth evidence is malformed")
    try:
        fd, identity = open_regular_nofollow(
            auth_path,
            expected_uid=os.getuid(),
            require_link_one=True,
        )
        try:
            descriptor = os.fstat(fd)
            path_metadata = os.lstat(auth_path)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise AuthCarrierError(
            "auth carrier generation cannot be revalidated"
        ) from None
    if (
        _auth_generation(descriptor) != _evidence_generation(evidence)
        or _auth_generation(path_metadata) != _evidence_generation(evidence)
        or identity != evidence.source_identity
    ):
        raise AuthCarrierError("auth carrier generation changed before use")
    current_time = _validated_current_time(now)
    if evidence.access_token_expires_at < (
        math.ceil(current_time) + evidence.minimum_remaining_seconds
    ):
        raise AuthCarrierError(
            "access token no longer covers the bounded review runtime"
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
