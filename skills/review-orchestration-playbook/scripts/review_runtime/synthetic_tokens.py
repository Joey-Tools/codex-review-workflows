from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import re
import stat
from dataclasses import dataclass
from typing import Any, Iterable

from .common import ReviewError


CATALOG_PATH = pathlib.Path(__file__).with_name("synthetic-token-catalog.json")
CATALOG_SCHEMA_VERSION = 1
MAX_CATALOG_BYTES = 64 * 1024
MAX_AUTHORING_TOKENS = 128
MAX_LEGACY_EXEMPTIONS = 64
MAX_LEGACY_VALUES = 512
MAX_SOURCE_OCCURRENCES = 100_000
ALLOWED_AUTHORING_RULES = frozenset({"generic-secret-assignment"})
ALLOWED_LEGACY_RULES = frozenset(
    {"generic-secret-assignment", "github-token"}
)
ALLOWED_ROLES = frozenset({"access", "refresh", "id", "api-key", "bearer"})
ALLOWED_STATES = frozenset({"active", "expired", "consumed"})
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
LEGACY_MATCH_MODE = "non-increasing-global-count"
GENERIC_SECRET_VALUE_BYTE_CLASS = rb"[-A-Za-z0-9_./+=!@#$%^&*?~:;]"
AUTHORING_VALUE = re.compile(
    rb"(?:" + GENERIC_SECRET_VALUE_BYTE_CLASS + rb"){16,512}"
)


@dataclass(frozen=True)
class AuthoringToken:
    identifier: str
    role: str
    state: str
    rule: str
    value: bytes

    @property
    def value_sha256(self) -> str:
        return hashlib.sha256(self.value).hexdigest()


@dataclass(frozen=True)
class LegacyToken:
    identifier: str
    rule: str
    value_sha256: str
    value_length: int
    containing_commit: str
    source_occurrences: int

    def matches(self, candidate: bytes) -> bool:
        return len(candidate) == self.value_length and hmac.compare_digest(
            hashlib.sha256(candidate).hexdigest(),
            self.value_sha256,
        )


@dataclass(frozen=True)
class LegacyExemption:
    identifier: str
    repository: str
    verified_master_tip: str
    match: str
    values: tuple[LegacyToken, ...]


@dataclass(frozen=True)
class SyntheticTokenCatalog:
    schema_version: int
    pool_version: str
    authoring_tokens: tuple[AuthoringToken, ...]
    legacy_exemptions: tuple[LegacyExemption, ...]

    def authoring_token(self, identifier: str) -> AuthoringToken:
        for token in self.authoring_tokens:
            if token.identifier == identifier:
                return token
        raise ReviewError(f"unknown synthetic authoring token: {identifier}")

    def legacy_exemption(self, identifier: str) -> LegacyExemption:
        for exemption in self.legacy_exemptions:
            if exemption.identifier == identifier:
                return exemption
        raise ReviewError(f"unknown synthetic secret exemption: {identifier}")


@dataclass(frozen=True)
class AcceptedSyntheticValue:
    kind: str
    catalog_version: str
    identifier: str
    rule: str
    value: bytes | None
    value_sha256: str
    value_length: int
    exemption_id: str | None = None

    def matches(self, candidate: bytes) -> bool:
        if self.value is not None:
            return candidate == self.value
        return len(candidate) == self.value_length and hmac.compare_digest(
            hashlib.sha256(candidate).hexdigest(),
            self.value_sha256,
        )


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewError(f"synthetic token catalog has duplicate key: {key}")
        value[key] = item
    return value


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReviewError(f"synthetic token catalog {label} must be an object")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail: list[str] = []
        if missing:
            detail.append(f"missing={','.join(missing)}")
        if extra:
            detail.append(f"extra={','.join(extra)}")
        raise ReviewError(
            f"synthetic token catalog {label} fields are invalid: {'; '.join(detail)}"
        )


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ReviewError(f"synthetic token catalog {label} is not a stable identifier")
    return value


def _require_ascii_value(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise ReviewError(f"synthetic token catalog {label} value must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ReviewError(
            f"synthetic token catalog {label} value must be exact ASCII"
        ) from error
    if not 16 <= len(encoded) <= 512:
        raise ReviewError(
            f"synthetic token catalog {label} value length must be 16..512 bytes"
        )
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ReviewError(
            f"synthetic token catalog {label} value must use visible ASCII bytes"
        )
    return encoded


def _require_authoring_value(value: Any, *, label: str) -> bytes:
    encoded = _require_ascii_value(value, label=label)
    if AUTHORING_VALUE.fullmatch(encoded) is None:
        raise ReviewError(
            f"synthetic token catalog {label} value must use scanner-compatible "
            "ASCII bytes"
        )
    return encoded


def _require_string_choice(
    value: Any,
    choices: frozenset[str],
    label: str,
) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ReviewError(f"synthetic token catalog {label} is not allowed")
    return value


def _parse_authoring_tokens(value: Any) -> tuple[str, tuple[AuthoringToken, ...]]:
    pool = _require_object(value, "authoring_pool")
    _require_keys(pool, {"version", "tokens"}, "authoring_pool")
    version = _require_identifier(pool["version"], "authoring_pool.version")
    raw_tokens = pool["tokens"]
    if not isinstance(raw_tokens, list) or not raw_tokens:
        raise ReviewError("synthetic token catalog authoring_pool.tokens must be non-empty")
    if len(raw_tokens) > MAX_AUTHORING_TOKENS:
        raise ReviewError("synthetic token catalog has too many authoring tokens")
    tokens: list[AuthoringToken] = []
    for index, raw_token in enumerate(raw_tokens):
        label = f"authoring_pool.tokens[{index}]"
        token = _require_object(raw_token, label)
        _require_keys(token, {"id", "role", "state", "rule", "value"}, label)
        identifier = _require_identifier(token["id"], f"{label}.id")
        tokens.append(
            AuthoringToken(
                identifier=identifier,
                role=_require_string_choice(
                    token["role"], ALLOWED_ROLES, f"{label}.role"
                ),
                state=_require_string_choice(
                    token["state"], ALLOWED_STATES, f"{label}.state"
                ),
                rule=_require_string_choice(
                    token["rule"], ALLOWED_AUTHORING_RULES, f"{label}.rule"
                ),
                value=_require_authoring_value(
                    token["value"],
                    label=f"{label}.value",
                ),
            )
        )
    return version, tuple(tokens)


def _parse_legacy_exemptions(value: Any) -> tuple[LegacyExemption, ...]:
    if not isinstance(value, list):
        raise ReviewError("synthetic token catalog legacy_exemptions must be a list")
    if len(value) > MAX_LEGACY_EXEMPTIONS:
        raise ReviewError("synthetic token catalog has too many legacy exemptions")
    exemptions: list[LegacyExemption] = []
    total_values = 0
    for index, raw_exemption in enumerate(value):
        label = f"legacy_exemptions[{index}]"
        exemption = _require_object(raw_exemption, label)
        _require_keys(
            exemption,
            {"id", "repository", "verified_master_tip", "match", "values"},
            label,
        )
        identifier = _require_identifier(exemption["id"], f"{label}.id")
        repository = exemption["repository"]
        if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
            raise ReviewError(
                f"synthetic token catalog {label}.repository is invalid"
            )
        verified_master_tip = exemption["verified_master_tip"]
        if (
            not isinstance(verified_master_tip, str)
            or COMMIT_OID.fullmatch(verified_master_tip) is None
        ):
            raise ReviewError(
                f"synthetic token catalog {label}.verified_master_tip is invalid"
            )
        if exemption["match"] != LEGACY_MATCH_MODE:
            raise ReviewError(f"synthetic token catalog {label}.match is invalid")
        raw_values = exemption["values"]
        if not isinstance(raw_values, list) or not raw_values:
            raise ReviewError(f"synthetic token catalog {label}.values must be non-empty")
        total_values += len(raw_values)
        if total_values > MAX_LEGACY_VALUES:
            raise ReviewError("synthetic token catalog has too many legacy values")
        values: list[LegacyToken] = []
        for value_index, raw_token in enumerate(raw_values):
            value_label = f"{label}.values[{value_index}]"
            token = _require_object(raw_token, value_label)
            _require_keys(
                token,
                {
                    "id",
                    "rule",
                    "value_sha256",
                    "value_length",
                    "containing_commit",
                    "source_occurrences",
                },
                value_label,
            )
            token_id = _require_identifier(token["id"], f"{value_label}.id")
            containing_commit = token["containing_commit"]
            if (
                not isinstance(containing_commit, str)
                or COMMIT_OID.fullmatch(containing_commit) is None
                or len(containing_commit) != len(verified_master_tip)
            ):
                raise ReviewError(
                    f"synthetic token catalog {value_label}.containing_commit is invalid"
                )
            source_occurrences = token["source_occurrences"]
            if (
                type(source_occurrences) is not int
                or not 1 <= source_occurrences <= MAX_SOURCE_OCCURRENCES
            ):
                raise ReviewError(
                    f"synthetic token catalog {value_label}.source_occurrences is invalid"
                )
            value_sha256 = token["value_sha256"]
            if not isinstance(value_sha256, str) or SHA256.fullmatch(value_sha256) is None:
                raise ReviewError(
                    f"synthetic token catalog {value_label}.value_sha256 is invalid"
                )
            value_length = token["value_length"]
            if type(value_length) is not int or not 16 <= value_length <= 512:
                raise ReviewError(
                    f"synthetic token catalog {value_label}.value_length is invalid"
                )
            values.append(
                LegacyToken(
                    identifier=token_id,
                    rule=_require_string_choice(
                        token["rule"], ALLOWED_LEGACY_RULES, f"{value_label}.rule"
                    ),
                    value_sha256=value_sha256,
                    value_length=value_length,
                    containing_commit=containing_commit,
                    source_occurrences=source_occurrences,
                )
            )
        exemptions.append(
            LegacyExemption(
                identifier=identifier,
                repository=repository,
                verified_master_tip=verified_master_tip,
                match=LEGACY_MATCH_MODE,
                values=tuple(values),
            )
        )
    return tuple(exemptions)


def _validate_unique_entries(catalog: SyntheticTokenCatalog) -> None:
    identifiers: dict[str, str] = {}
    values: list[tuple[str, bytes]] = []
    legacy_digests: dict[tuple[str, int], str] = {}
    public_metadata = {catalog.pool_version}
    for token in catalog.authoring_tokens:
        public_metadata.update(
            (
                token.identifier,
                token.role,
                token.state,
                token.rule,
                token.value_sha256,
            )
        )
    for exemption in catalog.legacy_exemptions:
        public_metadata.update(
            (
                exemption.identifier,
                exemption.repository,
                exemption.verified_master_tip,
                exemption.match,
            )
        )
        for token in exemption.values:
            public_metadata.update(
                (
                    token.identifier,
                    token.rule,
                    token.value_sha256,
                    token.containing_commit,
                )
            )
    encoded_metadata = tuple(item.encode("ascii") for item in public_metadata)
    if any(
        token.value in metadata
        for token in catalog.authoring_tokens
        for metadata in encoded_metadata
    ):
        raise ReviewError(
            "synthetic token catalog authoring value overlaps public metadata"
        )

    def register(identifier: str, value: bytes, label: str) -> None:
        previous = identifiers.get(identifier)
        if previous is not None:
            raise ReviewError(
                f"synthetic token catalog duplicate id {identifier}: {previous}, {label}"
            )
        identifiers[identifier] = label
        values.append((identifier, value))

    for token in catalog.authoring_tokens:
        register(token.identifier, token.value, "authoring token")
    exemption_ids: set[str] = set()
    for exemption in catalog.legacy_exemptions:
        if exemption.identifier in exemption_ids or exemption.identifier in identifiers:
            raise ReviewError(
                f"synthetic token catalog duplicate exemption id: {exemption.identifier}"
            )
        exemption_ids.add(exemption.identifier)
        identifiers[exemption.identifier] = "legacy exemption"
        for token in exemption.values:
            previous = identifiers.get(token.identifier)
            if previous is not None:
                raise ReviewError(
                    "synthetic token catalog duplicate id "
                    f"{token.identifier}: {previous}, {exemption.identifier}"
                )
            identifiers[token.identifier] = exemption.identifier
            digest_key = (token.value_sha256, token.value_length)
            previous_digest = legacy_digests.get(digest_key)
            if previous_digest is not None:
                raise ReviewError(
                    "synthetic token catalog duplicate legacy digest: "
                    f"{previous_digest}, {token.identifier}"
                )
            legacy_digests[digest_key] = token.identifier

    for token in catalog.authoring_tokens:
        digest_key = (token.value_sha256, len(token.value))
        previous_digest = legacy_digests.get(digest_key)
        if previous_digest is not None:
            raise ReviewError(
                "synthetic token catalog authoring and legacy values collide: "
                f"{token.identifier}, {previous_digest}"
            )

    for index, (identifier, value) in enumerate(values):
        for other_id, other in values[index + 1 :]:
            if value == other:
                raise ReviewError(
                    f"synthetic token catalog duplicate value: {identifier}, {other_id}"
                )
            if value in other or other in value:
                raise ReviewError(
                    "synthetic token catalog overlapping values: "
                    f"{identifier}, {other_id}"
                )


def parse_catalog_bytes(data: bytes) -> SyntheticTokenCatalog:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError("synthetic token catalog is not valid UTF-8") from error
    try:
        raw = json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except json.JSONDecodeError as error:
        raise ReviewError(
            "synthetic token catalog is not valid JSON: "
            f"line {error.lineno} column {error.colno}"
        ) from error
    root = _require_object(raw, "root")
    _require_keys(
        root,
        {"schema_version", "authoring_pool", "legacy_exemptions"},
        "root",
    )
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != CATALOG_SCHEMA_VERSION
    ):
        raise ReviewError("synthetic token catalog schema_version is unsupported")
    pool_version, authoring_tokens = _parse_authoring_tokens(root["authoring_pool"])
    catalog = SyntheticTokenCatalog(
        schema_version=CATALOG_SCHEMA_VERSION,
        pool_version=pool_version,
        authoring_tokens=authoring_tokens,
        legacy_exemptions=_parse_legacy_exemptions(root["legacy_exemptions"]),
    )
    _validate_unique_entries(catalog)
    return catalog


def _read_catalog_file(path: pathlib.Path) -> bytes:
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        directory_fd = os.open(path.parent, directory_flags)
    except OSError as error:
        raise ReviewError(f"cannot open synthetic token catalog directory: {error}") from error
    try:
        try:
            descriptor = os.open(path.name, file_flags, dir_fd=directory_fd)
        except OSError as error:
            raise ReviewError(f"cannot open synthetic token catalog: {error}") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ReviewError("synthetic token catalog must be a regular file")
            if metadata.st_nlink != 1:
                raise ReviewError("synthetic token catalog must have exactly one hard link")
            if metadata.st_uid != os.getuid():
                raise ReviewError("synthetic token catalog must be owned by the current user")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ReviewError(
                    "synthetic token catalog must not be group or other writable"
                )
            if metadata.st_size > MAX_CATALOG_BYTES:
                raise ReviewError("synthetic token catalog exceeds the size limit")
            chunks: list[bytes] = []
            remaining = MAX_CATALOG_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_CATALOG_BYTES:
                raise ReviewError("synthetic token catalog exceeds the size limit")
            final_metadata = os.fstat(descriptor)
            if (
                len(data) != metadata.st_size
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
                != (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_mode,
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                    final_metadata.st_ctime_ns,
                )
            ):
                raise ReviewError("synthetic token catalog changed while it was read")
            return data
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def load_catalog() -> SyntheticTokenCatalog:
    return parse_catalog_bytes(_read_catalog_file(CATALOG_PATH))


def resolve_legacy_exemptions(
    catalog: SyntheticTokenCatalog,
    identifiers: Iterable[str],
) -> tuple[LegacyExemption, ...]:
    selected: list[LegacyExemption] = []
    seen: set[str] = set()
    for identifier in identifiers:
        if identifier in seen:
            raise ReviewError(f"duplicate synthetic secret exemption: {identifier}")
        seen.add(identifier)
        selected.append(catalog.legacy_exemption(identifier))
    return tuple(selected)


def accepted_authoring_values(
    catalog: SyntheticTokenCatalog,
) -> tuple[AcceptedSyntheticValue, ...]:
    return tuple(
        AcceptedSyntheticValue(
            kind="authoring",
            catalog_version=catalog.pool_version,
            identifier=token.identifier,
            rule=token.rule,
            value=token.value,
            value_sha256=token.value_sha256,
            value_length=len(token.value),
        )
        for token in catalog.authoring_tokens
    )


def accepted_legacy_values(
    catalog: SyntheticTokenCatalog,
    exemptions: Iterable[LegacyExemption],
) -> tuple[AcceptedSyntheticValue, ...]:
    accepted: list[AcceptedSyntheticValue] = []
    for exemption in exemptions:
        for token in exemption.values:
            accepted.append(
                AcceptedSyntheticValue(
                    kind="legacy",
                    catalog_version=catalog.pool_version,
                    identifier=token.identifier,
                    rule=token.rule,
                    value=None,
                    value_sha256=token.value_sha256,
                    value_length=token.value_length,
                    exemption_id=exemption.identifier,
                )
            )
    return tuple(accepted)


def authoring_metadata(catalog: SyntheticTokenCatalog) -> list[dict[str, Any]]:
    return [
        {
            "id": token.identifier,
            "role": token.role,
            "rule": token.rule,
            "state": token.state,
            "value_sha256": token.value_sha256,
        }
        for token in sorted(catalog.authoring_tokens, key=lambda item: item.identifier)
    ]


def legacy_metadata(catalog: SyntheticTokenCatalog) -> list[dict[str, Any]]:
    return [
        {
            "id": exemption.identifier,
            "match": exemption.match,
            "repository": exemption.repository,
            "values": [
                {
                    "containing_commit": token.containing_commit,
                    "id": token.identifier,
                    "rule": token.rule,
                    "source_occurrences": token.source_occurrences,
                    "value_sha256": token.value_sha256,
                    "value_length": token.value_length,
                }
                for token in sorted(exemption.values, key=lambda item: item.identifier)
            ],
            "verified_master_tip": exemption.verified_master_tip,
        }
        for exemption in sorted(
            catalog.legacy_exemptions, key=lambda item: item.identifier
        )
    ]
