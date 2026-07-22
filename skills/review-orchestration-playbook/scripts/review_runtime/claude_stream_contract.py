from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
from dataclasses import dataclass
from typing import Any

from .claude_version_policy import CLAUDE_COMPATIBILITY_SPEC


COMPATIBILITY_SCHEMA_ID = "claude-code-stream-compatible-v1"
COMPATIBILITY_MODE = "strict-version-and-launch-profiles"
VERSION_POLICY_REFERENCE = (
    "review_runtime.claude_version_policy.CLAUDE_COMPATIBILITY_SPEC"
)
BASELINE_SCHEMA_NAME = "claude-2.1.212-stream-schema.json"
BASELINE_VERSION = "2.1.212"
PROFILE_SCHEMA_NAME = "claude-stream-schema.json"
REFERENCE_ROOT = pathlib.Path(__file__).resolve().parents[2] / "references"
COMPATIBILITY_PATH = REFERENCE_ROOT / "claude-stream-compatibility.json"
BASELINE_PATH = REFERENCE_ROOT / BASELINE_SCHEMA_NAME
PROFILE_PATH = REFERENCE_ROOT / PROFILE_SCHEMA_NAME
CAPABILITY_PATH = pathlib.Path(__file__).with_name("claude_capabilities.py")
MAX_CONTRACT_BYTES = 256 * 1024


class ClaudeStreamContractError(ValueError):
    pass


@dataclass(frozen=True)
class ClaudeStreamContractBinding:
    schema_id: str
    digest: str
    compatibility_digest: str
    baseline_digest: str
    capability_digest: str


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable(path: pathlib.Path) -> bytes:
    descriptor = -1
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CONTRACT_BYTES:
            raise ClaudeStreamContractError(
                f"stream contract is not a bounded regular file: {path.name}"
            )
        descriptor = os.open(resolved, flags)
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_size > MAX_CONTRACT_BYTES
            or _identity(opened_before) != _identity(before)
        ):
            raise ClaudeStreamContractError(
                f"stream contract identity changed before reading: {path.name}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CONTRACT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONTRACT_BYTES:
                raise ClaudeStreamContractError(
                    f"stream contract exceeds its size bound: {path.name}"
                )
        opened_after = os.fstat(descriptor)
        after = resolved.stat(follow_symlinks=False)
    except ClaudeStreamContractError:
        raise
    except (OSError, RuntimeError) as error:
        raise ClaudeStreamContractError(
            f"cannot read a stable stream contract: {path.name}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identities = {
        _identity(value) for value in (before, opened_before, opened_after, after)
    }
    if len(identities) != 1 or not stat.S_ISREG(opened_before.st_mode):
        raise ClaudeStreamContractError(
            f"stream contract identity changed while reading: {path.name}"
        )
    return b"".join(chunks)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ClaudeStreamContractError(f"duplicate stream-contract key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ClaudeStreamContractError(f"nonstandard JSON constant: {value}")


def _parse_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except ClaudeStreamContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ClaudeStreamContractError(
            f"invalid stream contract JSON: {label}"
        ) from error
    if type(value) is not dict:
        raise ClaudeStreamContractError(
            f"stream contract root is not an object: {label}"
        )
    return value


def load_stream_contract(
    *,
    compatibility_path: pathlib.Path = COMPATIBILITY_PATH,
    baseline_path: pathlib.Path = BASELINE_PATH,
    profile_path: pathlib.Path = PROFILE_PATH,
) -> tuple[
    ClaudeStreamContractBinding,
    bytes,
    bytes,
]:
    compatibility_raw = _read_stable(compatibility_path)
    baseline_raw = _read_stable(baseline_path)
    profile_raw = _read_stable(profile_path)
    capability_raw = _read_stable(CAPABILITY_PATH)
    compatibility = _parse_json(compatibility_raw, label=compatibility_path.name)
    baseline = _parse_json(baseline_raw, label=baseline_path.name)
    profile = _parse_json(profile_raw, label=profile_path.name)
    expected_compatibility = {
        "schema_id": COMPATIBILITY_SCHEMA_ID,
        "version_policy": VERSION_POLICY_REFERENCE,
        "compatibility_mode": COMPATIBILITY_MODE,
        "baseline_schema": BASELINE_SCHEMA_NAME,
        "baseline_version": BASELINE_VERSION,
        "profile_schema": PROFILE_SCHEMA_NAME,
        "profile_version_policy": CLAUDE_COMPATIBILITY_SPEC,
        "version_profiles": {
            "legacy-base": ">=2.1.211,<2.1.216",
            "extended-2x": ">=2.1.216,<3.0.0",
        },
        "launch_profiles": ["helper-darwin", "helper-linux", "named-direct"],
        "fail_closed_surfaces": [
            "stream_envelope",
            "init_field_set",
            "init_field_values",
            "intermediate_event_field_sets",
            "intermediate_session_binding",
            "terminal_field_set",
            "terminal_variants",
            "model_identity",
        ],
    }
    if compatibility != expected_compatibility:
        raise ClaudeStreamContractError("stream compatibility profile does not match")
    if baseline.get("claude_code_version") != BASELINE_VERSION:
        raise ClaudeStreamContractError("stream baseline version does not match")
    version_contract = profile.get("claude_code_version")
    if version_contract != {
        "rule": "strict_release_semver_range",
        "minimum_inclusive": "2.1.211",
        "maximum_exclusive": "3.0.0",
    }:
        raise ClaudeStreamContractError("stream profile version policy does not match")
    compatibility_digest = hashlib.sha256(compatibility_raw).hexdigest()
    baseline_digest = hashlib.sha256(baseline_raw).hexdigest()
    capability_digest = hashlib.sha256(capability_raw).hexdigest()
    digest = hashlib.sha256(
        compatibility_raw
        + b"\0"
        + baseline_raw
        + b"\0"
        + profile_raw
        + b"\0"
        + capability_raw
    ).hexdigest()
    return (
        ClaudeStreamContractBinding(
            schema_id=COMPATIBILITY_SCHEMA_ID,
            digest=digest,
            compatibility_digest=compatibility_digest,
            baseline_digest=baseline_digest,
            capability_digest=capability_digest,
        ),
        compatibility_raw,
        profile_raw,
    )
