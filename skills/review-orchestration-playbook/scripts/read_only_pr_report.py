"""Validate delivery handoffs and cross-field read-only PR report semantics."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

MAX_REPORT_BYTES = 1 << 20
MAX_BINDING_ATTEMPTS = 128
MAX_ERROR_CHARS = 240
MAX_INTEGER_DIGITS = 128
MAX_NUMBER_CHARS = 256
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 32_768
MAX_JSON_STRUCTURE_MARKERS = MAX_JSON_NODES * 2
READ_CHUNK_BYTES = 64 * 1024
MAX_CI_ROLLUP_ENTRIES = 1_000
MAX_CI_ROLLUP_PAGES = 10
MAX_CI_PAGE_ITEMS = 100
MAX_REVIEW_THREADS = 1_000
MAX_REVIEW_THREAD_PAGES = 10
MAX_REVIEW_THREAD_PAGE_ITEMS = 100
MAX_CONNECTION_PROVIDER_CALLS = 22
MAX_CONNECTION_DEADLINE_MS = 60_000
PAGE_DIGEST_DOMAIN = b"joey-tools:pr-readiness-page:v1\x00"
IDENTIFIER_RE = re.compile(
    r"^(?P<kind>report|target|snapshot|observation):(?P<value>[0-9a-f]{32})$"
)
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPOSITORY_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
REPOSITORY_OWNER_RE = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
REPOSITORY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]*[A-Za-z0-9_][A-Za-z0-9._-]*$")
GITHUB_APP_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
GITHUB_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_:+/=-]{1,256}$")
GITHUB_LOGIN_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
GITHUB_ACTOR_TYPENAMES = {
    "Bot",
    "EnterpriseUserAccount",
    "Mannequin",
    "Organization",
    "User",
}
EVIDENCE_NAMES = {
    "pr_selection": "pr-selection",
    "pr_lifecycle": "pr-lifecycle",
    "ci_status": "ci-status",
    "conversation_state": "conversation-state",
    "base_and_head": "base-and-head",
}
DELIVERY_RESULT_FIELDS = {
    "schema_version",
    "profile",
    "constraints",
    "head_sha",
    "local_mutation",
    "commit_mode",
    "formal_review_required",
    "remote_mutation",
    "terminal_outcome",
    "terminal_reason",
    "terminal_evidence",
    "handoff",
    "handoff_profile",
}
DELIVERY_TERMINAL_EVIDENCE_FIELDS = {
    "local_gate",
    "build",
    "tests",
    "docs",
    "journal",
    "committed_range",
    "formal_review",
    "signature",
    "signature_verified_head_oid",
    "authorization",
    "input",
}
READ_ONLY_DELIVERY_SUCCESS_MATRIX = {
    "pr-readiness-read-only-probe-ready": {
        "local_mutation": "forbidden",
        "commit_mode": "forbidden",
        "formal_review_required": False,
        "terminal_evidence": {
            "local_gate": "checked",
            "build": "read-only-observed",
            "tests": "read-only-observed",
            "docs": "read-only-observed",
            "journal": "read-only-observed",
            "committed_range": "missing",
            "formal_review": "not-required",
            "signature": "not-required",
            "signature_verified_head_oid": None,
            "authorization": "not-required",
            "input": "satisfied",
        },
    },
    "pr-readiness-read-only-reviewed-probe-ready": {
        "local_mutation": "forbidden",
        "commit_mode": "forbidden",
        "formal_review_required": True,
        "terminal_evidence": {
            "local_gate": "checked",
            "build": "read-only-observed",
            "tests": "read-only-observed",
            "docs": "read-only-observed",
            "journal": "read-only-observed",
            "committed_range": "present",
            "formal_review": "clean",
            "signature": "verified",
            "signature_verified_head_oid": "required",
            "authorization": "not-required",
            "input": "satisfied",
        },
    },
    "pr-readiness-read-only-gate-ready": {
        "local_mutation": "allowed",
        "commit_mode": "allowed",
        "formal_review_required": True,
        "terminal_evidence": {
            "local_gate": "succeeded",
            "build": "satisfied",
            "tests": "satisfied",
            "docs": "satisfied",
            "journal": "satisfied",
            "committed_range": "present",
            "formal_review": "clean",
            "signature": "verified",
            "signature_verified_head_oid": "required",
            "authorization": "not-required",
            "input": "satisfied",
        },
    },
    "pr-readiness-read-only-uncommitted-probe-ready": {
        "local_mutation": "allowed",
        "commit_mode": "forbidden",
        "formal_review_required": False,
        "terminal_evidence": {
            "local_gate": "checked",
            "build": "satisfied",
            "tests": "satisfied",
            "docs": "satisfied",
            "journal": "satisfied",
            "committed_range": "missing",
            "formal_review": "not-required",
            "signature": "not-required",
            "signature_verified_head_oid": None,
            "authorization": "not-required",
            "input": "satisfied",
        },
    },
    "pr-readiness-read-only-existing-range-probe-ready": {
        "local_mutation": "allowed",
        "commit_mode": "forbidden",
        "formal_review_required": True,
        "terminal_evidence": {
            "local_gate": "checked",
            "build": "satisfied",
            "tests": "satisfied",
            "docs": "satisfied",
            "journal": "satisfied",
            "committed_range": "present",
            "formal_review": "clean",
            "signature": "verified",
            "signature_verified_head_oid": "required",
            "authorization": "not-required",
            "input": "satisfied",
        },
    },
}
PR_READINESS_DELIVERY_SUCCESS_MATRIX = {
    "pr-readiness-handoff-ready": {
        "local_mutation": "allowed",
        "commit_mode": "allowed",
        "formal_review_required": True,
        "terminal_evidence": {
            "local_gate": "succeeded",
            "build": "satisfied",
            "tests": "satisfied",
            "docs": "satisfied",
            "journal": "satisfied",
            "committed_range": "present",
            "formal_review": "clean",
            "signature": "verified",
            "signature_verified_head_oid": "required",
            "authorization": "satisfied",
            "input": "satisfied",
        },
    },
    "pr-readiness-existing-range-handoff-ready": {
        "local_mutation": "allowed",
        "commit_mode": "forbidden",
        "formal_review_required": True,
        "terminal_evidence": {
            "local_gate": "checked",
            "build": "satisfied",
            "tests": "satisfied",
            "docs": "satisfied",
            "journal": "satisfied",
            "committed_range": "present",
            "formal_review": "clean",
            "signature": "verified",
            "signature_verified_head_oid": "required",
            "authorization": "satisfied",
            "input": "satisfied",
        },
    },
}
CI_GATE_BUCKETS_BY_TYPENAME = {
    "CheckRun": {
        ("QUEUED", None): "pending",
        ("IN_PROGRESS", None): "pending",
        ("REQUESTED", None): "pending",
        ("WAITING", None): "pending",
        ("PENDING", None): "pending",
        ("COMPLETED", "SUCCESS"): "success",
        ("COMPLETED", "NEUTRAL"): "success",
        ("COMPLETED", "SKIPPED"): "success",
        ("COMPLETED", "FAILURE"): "failure",
        ("COMPLETED", "TIMED_OUT"): "failure",
        ("COMPLETED", "ACTION_REQUIRED"): "failure",
        ("COMPLETED", "STALE"): "failure",
        ("COMPLETED", "STARTUP_FAILURE"): "failure",
        ("COMPLETED", "CANCELLED"): "cancelled",
    },
    "StatusContext": {
        "SUCCESS": "success",
        "FAILURE": "failure",
        "ERROR": "failure",
        "PENDING": "pending",
        "EXPECTED": "pending",
    },
}


def new_bindings() -> dict[str, str]:
    """Return four independently generated report-instance bindings."""

    bindings: dict[str, str] = {}
    used_tokens: set[str] = set()
    for field, kind in (
        ("report_id", "report"),
        ("target_binding", "target"),
        ("snapshot_binding", "snapshot"),
        ("snapshot_id", "observation"),
    ):
        for _ in range(MAX_BINDING_ATTEMPTS):
            token = secrets.token_hex(16)
            if re.fullmatch(r"[0-9a-f]{32}", token) and token not in used_tokens:
                used_tokens.add(token)
                bindings[field] = f"{kind}:{token}"
                break
        else:
            raise RuntimeError("unable to generate unique report bindings")
    return bindings


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_nullable_positive_int(value: object) -> bool:
    return value is None or _is_positive_int(value)


def _is_oid(value: object) -> bool:
    return isinstance(value, str) and OID_RE.fullmatch(value) is not None


def _is_github_node_id(value: object) -> bool:
    return isinstance(value, str) and GITHUB_NODE_ID_RE.fullmatch(value) is not None


def _canonical_page_digest(kind: str, payload: object) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(PAGE_DIGEST_DOMAIN)
    digest.update(kind.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical)
    return digest.hexdigest()


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: object) -> Sequence[Any] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _identifier(
    errors: list[str],
    value: object,
    expected_kind: str,
    location: str,
) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{location} must be a {expected_kind} identifier")
        return None
    match = IDENTIFIER_RE.fullmatch(value)
    if match is None or match.group("kind") != expected_kind:
        errors.append(f"{location} must be a {expected_kind} identifier")
        return None
    return match.group("value")


def _observed_record(
    errors: list[str],
    evidence: Mapping[str, Any],
    location: str,
) -> Mapping[str, Any] | None:
    observed = _sequence(evidence.get("observed"))
    if observed is None:
        errors.append(f"{location}.observed must be an array")
        return None
    status = evidence.get("status")
    if status == "observed":
        if len(observed) != 1 or _mapping(observed[0]) is None:
            errors.append(f"{location} must contain exactly one observed record")
            return None
        return _mapping(observed[0])
    if observed:
        errors.append(f"{location} must not retain a non-observed record")
    return None


def _delivery_signature_head_errors(
    delivery: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    head_sha = delivery.get("head_sha")
    if not _is_oid(head_sha):
        errors.append("delivery_record.head_sha must be a full lowercase object ID")
    signature = evidence.get("signature")
    verified_head_oid = evidence.get("signature_verified_head_oid")
    if signature == "verified":
        if not _is_oid(verified_head_oid):
            errors.append(
                "verified delivery signature requires signature_verified_head_oid"
            )
        elif _is_oid(head_sha) and verified_head_oid != head_sha:
            errors.append(
                "verified delivery signature must bind delivery_record.head_sha"
            )
    elif verified_head_oid is not None:
        errors.append(
            "non-verified delivery signature must not bind a verified head OID"
        )
    return errors


def _read_only_delivery_errors(record: object) -> list[str]:
    errors: list[str] = []
    delivery = _mapping(record)
    if delivery is None:
        return ["delivery_record must be an object"]
    if set(delivery) != DELIVERY_RESULT_FIELDS:
        return ["delivery_record fields do not match the closed v3 contract"]
    if delivery.get("schema_version") != 3:
        errors.append("delivery_record.schema_version must be 3")
    if delivery.get("profile") != "local-gate":
        errors.append("read-only PR probe requires the local-gate profile")
    constraints = _sequence(delivery.get("constraints"))
    constraints_are_strings = constraints is not None and all(
        isinstance(item, str) for item in constraints
    )
    constraint_set = set(constraints) if constraints_are_strings else set()
    if (
        constraints is None
        or not constraints_are_strings
        or len(constraints) != len(constraint_set)
        or not constraint_set
        <= {
            "local-only",
            "report-only",
            "probe-only",
            "read-only",
            "no-remote",
            "no-commit",
        }
    ):
        errors.append("delivery_record.constraints are malformed")
    elif not constraint_set & {
        "report-only",
        "probe-only",
        "read-only",
        "no-remote",
    }:
        errors.append("read-only PR probe lacks a remote-mutation limit")
    if "local-only" in constraint_set:
        errors.append("local-only delivery cannot hand off to a remote PR probe")

    local_mutation_forbidden = bool(
        constraint_set & {"report-only", "probe-only", "read-only"}
    )
    expected_local_mutation = "forbidden" if local_mutation_forbidden else "allowed"
    if delivery.get("local_mutation") != expected_local_mutation:
        errors.append("delivery_record.local_mutation contradicts constraints")
    commit_forbidden = bool(
        constraint_set
        & {
            "report-only",
            "probe-only",
            "read-only",
            "no-commit",
        }
    )
    expected_commit_mode = "forbidden" if commit_forbidden else "allowed"
    if delivery.get("commit_mode") != expected_commit_mode:
        errors.append("delivery_record.commit_mode contradicts constraints")
    if delivery.get("remote_mutation") != "forbidden":
        errors.append("read-only PR probe must forbid remote mutation")
    if delivery.get("terminal_outcome") != "succeeded":
        errors.append("read-only PR probe requires a succeeded delivery terminal")
    if delivery.get("handoff") != "review-orchestration-playbook":
        errors.append("read-only PR probe must route to the review skill")
    if delivery.get("handoff_profile") != "pr-readiness-read-only-probe":
        errors.append("delivery_record handoff profile is not read-only PR probe")

    evidence = _mapping(delivery.get("terminal_evidence"))
    if evidence is None or set(evidence) != DELIVERY_TERMINAL_EVIDENCE_FIELDS:
        errors.append("delivery terminal evidence is not a closed record")
        return errors
    errors.extend(_delivery_signature_head_errors(delivery, evidence))

    formal_required = delivery.get("formal_review_required")
    if not isinstance(formal_required, bool):
        errors.append("delivery formal_review_required must be boolean")

    reason = delivery.get("terminal_reason")
    expected = READ_ONLY_DELIVERY_SUCCESS_MATRIX.get(reason)
    if expected is None:
        errors.append("read-only PR probe requires an exact ready reason")
        return errors
    for field in (
        "local_mutation",
        "commit_mode",
        "formal_review_required",
    ):
        if delivery.get(field) != expected[field]:
            errors.append(
                f"delivery_record.{field} contradicts terminal_reason {reason}"
            )
    static_evidence = dict(evidence)
    verified_head_oid = static_evidence.pop("signature_verified_head_oid", None)
    expected_evidence = dict(expected["terminal_evidence"])
    expected_verified_head = expected_evidence.pop(
        "signature_verified_head_oid",
        None,
    )
    if static_evidence != expected_evidence:
        errors.append(
            f"delivery terminal evidence contradicts terminal_reason {reason}"
        )
    if expected_verified_head != "required" and verified_head_oid is not None:
        errors.append("delivery reason must not bind a verified head OID")
    return errors


def _pr_readiness_delivery_errors(record: object) -> list[str]:
    errors: list[str] = []
    delivery = _mapping(record)
    if delivery is None:
        return ["delivery_record must be an object"]
    if set(delivery) != DELIVERY_RESULT_FIELDS:
        return ["delivery_record fields do not match the closed v3 contract"]
    if delivery.get("schema_version") != 3:
        errors.append("delivery_record.schema_version must be 3")
    if delivery.get("profile") != "pr-readiness-handoff":
        errors.append("ordinary PR readiness requires the PR handoff profile")

    constraints = _sequence(delivery.get("constraints"))
    constraints_are_strings = constraints is not None and all(
        isinstance(item, str) for item in constraints
    )
    constraint_set = set(constraints) if constraints_are_strings else set()
    if (
        constraints is None
        or not constraints_are_strings
        or len(constraints) != len(constraint_set)
        or not constraint_set
        <= {
            "local-only",
            "report-only",
            "probe-only",
            "read-only",
            "no-remote",
            "no-commit",
        }
    ):
        errors.append("delivery_record.constraints are malformed")
    elif constraint_set & {
        "local-only",
        "report-only",
        "probe-only",
        "read-only",
        "no-remote",
    }:
        errors.append("ordinary PR readiness cannot discard a remote-mutation limit")

    expected_commit_mode = "forbidden" if "no-commit" in constraint_set else "allowed"
    if delivery.get("local_mutation") != "allowed":
        errors.append("ordinary PR readiness requires allowed local mutation")
    if delivery.get("commit_mode") != expected_commit_mode:
        errors.append("delivery_record.commit_mode contradicts constraints")
    if delivery.get("formal_review_required") is not True:
        errors.append("ordinary PR readiness requires formal review")
    if delivery.get("remote_mutation") != "review-authorization-required":
        errors.append("ordinary PR readiness requires review authorization")
    if delivery.get("terminal_outcome") != "succeeded":
        errors.append("ordinary PR readiness requires a succeeded delivery terminal")
    if delivery.get("handoff") != "review-orchestration-playbook":
        errors.append("ordinary PR readiness must route to the review skill")
    if delivery.get("handoff_profile") != "pr-readiness":
        errors.append("delivery_record handoff profile is not ordinary PR readiness")

    evidence = _mapping(delivery.get("terminal_evidence"))
    if evidence is None or set(evidence) != DELIVERY_TERMINAL_EVIDENCE_FIELDS:
        errors.append("delivery terminal evidence is not a closed record")
        return errors
    errors.extend(_delivery_signature_head_errors(delivery, evidence))

    reason = delivery.get("terminal_reason")
    expected = PR_READINESS_DELIVERY_SUCCESS_MATRIX.get(reason)
    if expected is None:
        errors.append("ordinary PR readiness requires an exact ready reason")
        return errors
    for field in (
        "local_mutation",
        "commit_mode",
        "formal_review_required",
    ):
        if delivery.get(field) != expected[field]:
            errors.append(
                f"delivery_record.{field} contradicts terminal_reason {reason}"
            )
    static_evidence = dict(evidence)
    static_evidence.pop("signature_verified_head_oid", None)
    expected_evidence = dict(expected["terminal_evidence"])
    expected_evidence.pop("signature_verified_head_oid", None)
    if static_evidence != expected_evidence:
        errors.append(
            f"delivery terminal evidence contradicts terminal_reason {reason}"
        )
    return errors


def validate_delivery_handoff(record: object) -> None:
    """Raise ValueError unless one exact delivery handoff is receiver-safe."""

    delivery = _mapping(record)
    handoff_profile = delivery.get("handoff_profile") if delivery is not None else None
    if handoff_profile == "pr-readiness-read-only-probe":
        errors = _read_only_delivery_errors(record)
    elif handoff_profile == "pr-readiness":
        errors = _pr_readiness_delivery_errors(record)
    else:
        errors = ["delivery_record has no supported receiver handoff profile"]
    if errors:
        raise ValueError("; ".join(errors))


def _repository_identity_valid(value: object) -> bool:
    repository = _mapping(value)
    if repository is None:
        return False
    return (
        set(repository) == {"node_id", "host", "owner", "name"}
        and _is_github_node_id(repository.get("node_id"))
        and isinstance(repository.get("host"), str)
        and 1 <= len(repository["host"]) <= 253
        and REPOSITORY_HOST_RE.fullmatch(repository["host"]) is not None
        and isinstance(repository.get("owner"), str)
        and 1 <= len(repository["owner"]) <= 39
        and REPOSITORY_OWNER_RE.fullmatch(repository["owner"]) is not None
        and isinstance(repository.get("name"), str)
        and 1 <= len(repository["name"]) <= 100
        and REPOSITORY_NAME_RE.fullmatch(repository["name"]) is not None
    )


def _bind_observed_target_identity(
    errors: list[str],
    record: Mapping[str, Any],
    target: Mapping[str, Any],
    *,
    location: str,
    require_pull_request: bool,
) -> None:
    identity = _mapping(record.get("target_identity"))
    if identity is None:
        errors.append(f"{location}.target_identity must be an object")
        return
    required = {"provider", "repository", "head"}
    if require_pull_request:
        required.add("pull_request")
    if set(identity) != required:
        errors.append(f"{location}.target_identity fields do not match target state")
        return
    for field in required:
        if identity.get(field) != target.get(field):
            errors.append(
                f"{location}.target_identity.{field} must exactly equal target.{field}"
            )


def _validate_paginated_scan(
    errors: list[str],
    *,
    label: str,
    digest_kind: str,
    expected_connection: Mapping[str, Any],
    expected_scan_role: str,
    pages_value: object,
    items: Sequence[Any],
    server_total_count: object,
    snapshot_binding: object,
    snapshot_id: object,
    max_pages: int,
    max_page_items: int,
    max_items: int,
) -> tuple[Mapping[str, Any], ...] | None:
    pages = _sequence(pages_value)
    if pages is None or not 1 <= len(pages) <= max_pages:
        errors.append(f"{label} pages are missing or exceed the bounded page cap")
        return None

    page_item_total = 0
    item_offset = 0
    previous_end_cursor: object = None
    seen_end_cursors: set[str] = set()
    projections: list[Mapping[str, Any]] = []
    for offset, item in enumerate(pages, start=1):
        page = _mapping(item)
        if page is None:
            errors.append(f"{label} page {offset} must be an object")
            continue
        if page.get("scan_role") != expected_scan_role:
            errors.append(
                f"{label} page {offset} is not bound to the {expected_scan_role} scan"
            )
        if page.get("connection") != expected_connection:
            errors.append(f"{label} page {offset} changed connection identity")
        page_head_oid = page.get("observed_head_oid")
        if page_head_oid != expected_connection.get("head_oid"):
            errors.append(
                f"{label} page {offset} observed a different provider head; "
                "evidence must be unavailable"
            )
        page_snapshot_binding = page.get("snapshot_binding")
        page_snapshot_id = page.get("snapshot_id")
        if page_snapshot_binding != snapshot_binding or page_snapshot_id != snapshot_id:
            errors.append(f"{label} page {offset} changed report snapshot identity")
        if page.get("page_index") != offset:
            errors.append(f"{label} page indexes must be contiguous from one")
        expected_after = None if offset == 1 else previous_end_cursor
        if page.get("request_after") != expected_after:
            errors.append(f"{label} page {offset} request cursor drifted")
        item_count = page.get("item_count")
        if not _is_nonnegative_int(item_count) or item_count > max_page_items:
            errors.append(f"{label} page {offset} item count is invalid")
            item_count = 0
        if page.get("server_total_count") != server_total_count:
            errors.append(
                f"{label} observed mid-pagination total drift; "
                "evidence must be unavailable"
            )
        page_item_total += item_count

        page_info = _mapping(page.get("page_info"))
        if page_info is None:
            errors.append(f"{label} page {offset} pageInfo is missing")
            previous_end_cursor = None
            continue
        end_cursor = page_info.get("end_cursor")
        has_next_page = page_info.get("has_next_page")
        if not isinstance(has_next_page, bool):
            errors.append(f"{label} page {offset} hasNextPage is not boolean")
        if item_count == 0:
            if end_cursor is not None:
                errors.append(f"an empty {label} page must have a null end cursor")
        elif not isinstance(end_cursor, str) or not end_cursor:
            errors.append(f"a non-empty {label} page must have a non-empty end cursor")
        if isinstance(end_cursor, str):
            if end_cursor in seen_end_cursors:
                errors.append(f"{label} end cursors must not repeat")
            seen_end_cursors.add(end_cursor)
        if offset < len(pages):
            if has_next_page is not True:
                errors.append(
                    f"every non-final {label} page must advertise a next page"
                )
            if not isinstance(end_cursor, str) or not end_cursor:
                errors.append(
                    f"every non-final {label} page needs a continuation cursor"
                )
        elif has_next_page is not False:
            errors.append(f"the final {label} page must prove hasNextPage=false")

        page_slice = list(items[item_offset : item_offset + item_count])
        digest_payload = {
            "connection": dict(expected_connection),
            "observed_head_oid": page_head_oid,
            "snapshot_binding": page_snapshot_binding,
            "snapshot_id": page_snapshot_id,
            "server_total_count": server_total_count,
            "page_index": offset,
            "request_after": expected_after,
            "item_count": item_count,
            "page_info": dict(page_info),
            "items": page_slice,
        }
        content_sha256 = page.get("content_sha256")
        if content_sha256 != _canonical_page_digest(digest_kind, digest_payload):
            errors.append(
                f"{label} page {offset} content digest does not bind "
                "its ordered flat-list slice"
            )
        projections.append(
            {
                "connection": dict(expected_connection),
                "observed_head_oid": page_head_oid,
                "page_index": offset,
                "request_after": expected_after,
                "item_count": item_count,
                "server_total_count": server_total_count,
                "page_info": dict(page_info),
                "content_sha256": content_sha256,
            }
        )
        item_offset += item_count
        previous_end_cursor = end_cursor

    if _is_nonnegative_int(server_total_count):
        if server_total_count > max_items:
            errors.append(f"{label} server totalCount exceeds the bounded complete cap")
        if page_item_total != server_total_count:
            errors.append(f"{label} item counts do not match server totalCount")
        if len(items) != server_total_count:
            errors.append(f"{label} flat-list length does not match server totalCount")
    if item_offset != len(items):
        errors.append(f"{label} page concatenation does not equal the flat list")
    if len(projections) != len(pages):
        return None
    return tuple(projections)


def _validate_connection_stability(
    errors: list[str],
    *,
    label: str,
    stability_value: object,
    expected_connection: Mapping[str, Any],
    primary_pages: object,
    primary_projection: tuple[Mapping[str, Any], ...] | None,
    verification_pages: object,
    verification_projection: tuple[Mapping[str, Any], ...] | None,
) -> None:
    stability = _mapping(stability_value)
    if stability is None:
        errors.append(f"{label} stability evidence must be an object")
        return
    if stability.get("strategy") != "double-scan":
        errors.append(f"{label} stability strategy must be double-scan")
    if stability.get("cache_mode") != "disabled":
        errors.append(f"{label} acquisition must disable provider caches")
    if stability.get("mutation_mode") != "read-only":
        errors.append(f"{label} acquisition must remain read-only")

    expected_head_connection = {
        "provider": "github-graphql",
        "field": "pullRequest.headRefOid",
        "repository_node_id": expected_connection.get("repository_node_id"),
        "pull_request_node_id": expected_connection.get("pull_request_node_id"),
    }
    head_observations = _sequence(stability.get("head_observations"))
    expected_phases = ("before-primary", "after-verification")
    if head_observations is None or len(head_observations) != 2:
        errors.append(
            f"{label} stability requires exactly two independent head observations"
        )
    else:
        for phase, item in zip(expected_phases, head_observations):
            observation = _mapping(item)
            if observation is None:
                errors.append(f"{label} {phase} head observation must be an object")
                continue
            if observation.get("phase") != phase:
                errors.append(f"{label} head observations are out of acquisition order")
            if observation.get("connection") != expected_head_connection:
                errors.append(
                    f"{label} {phase} head observation changed target identity"
                )
            if observation.get("head_oid") != expected_connection.get("head_oid"):
                errors.append(
                    f"{label} provider head changed during the stable double scan; "
                    "evidence must be unavailable"
                )

    deadline_ms = stability.get("deadline_ms")
    elapsed_ms = stability.get("elapsed_ms")
    if not _is_positive_int(deadline_ms) or deadline_ms > MAX_CONNECTION_DEADLINE_MS:
        errors.append(f"{label} deadline exceeds the bounded acquisition cap")
    if (
        not _is_nonnegative_int(elapsed_ms)
        or not _is_positive_int(deadline_ms)
        or elapsed_ms > deadline_ms
    ):
        errors.append(f"{label} acquisition exceeded or lacks its monotonic deadline")

    primary_page_sequence = _sequence(primary_pages)
    verification_page_sequence = _sequence(verification_pages)
    expected_calls = (
        2
        + (len(primary_page_sequence) if primary_page_sequence is not None else 0)
        + (
            len(verification_page_sequence)
            if verification_page_sequence is not None
            else 0
        )
    )
    provider_call_count = stability.get("provider_call_count")
    if (
        not _is_positive_int(provider_call_count)
        or provider_call_count > MAX_CONNECTION_PROVIDER_CALLS
        or provider_call_count != expected_calls
    ):
        errors.append(
            f"{label} provider-call count does not match the bounded double scan"
        )

    if (
        primary_projection is not None
        and verification_projection is not None
        and primary_projection != verification_projection
    ):
        errors.append(
            f"{label} verification scan changed total, cursor, page slice, "
            "or content digest; evidence must be unavailable"
        )


def _validate_ci_pagination(
    errors: list[str],
    record: Mapping[str, Any],
    rollup: Sequence[Any],
    *,
    snapshot_binding: object,
    snapshot_id: object,
) -> None:
    pagination = _mapping(record.get("pagination"))
    identity = _mapping(record.get("target_identity"))
    if pagination is None:
        errors.append("CI pagination evidence must be an object")
        return
    if identity is None:
        errors.append("CI pagination lacks a target identity")
        return
    repository = _mapping(identity.get("repository"))
    pull_request = _mapping(identity.get("pull_request"))
    head = _mapping(identity.get("head"))
    if repository is None or pull_request is None or head is None:
        errors.append("CI pagination target identity is incomplete")
        return
    expected_connection = {
        "provider": "github-graphql",
        "field": "commit.statusCheckRollup.contexts",
        "repository_node_id": repository.get("node_id"),
        "pull_request_node_id": pull_request.get("node_id"),
        "head_oid": head.get("oid"),
    }
    if pagination.get("connection") != expected_connection:
        errors.append("CI pagination connection does not match the exact PR head")

    server_total_count = pagination.get("server_total_count")
    primary_pages = pagination.get("pages")
    primary_projection = _validate_paginated_scan(
        errors,
        label="CI primary pagination",
        digest_kind="ci-status",
        expected_connection=expected_connection,
        expected_scan_role="primary",
        pages_value=primary_pages,
        items=rollup,
        server_total_count=server_total_count,
        snapshot_binding=snapshot_binding,
        snapshot_id=snapshot_id,
        max_pages=MAX_CI_ROLLUP_PAGES,
        max_page_items=MAX_CI_PAGE_ITEMS,
        max_items=MAX_CI_ROLLUP_ENTRIES,
    )

    stability = _mapping(pagination.get("stability"))
    verification = (
        _mapping(stability.get("verification")) if stability is not None else None
    )
    if verification is None:
        errors.append("CI stability verification scan must be an object")
        return
    if verification.get("connection") != expected_connection:
        errors.append("CI verification scan changed connection identity")
    verification_rollup = _sequence(verification.get("status_check_rollup"))
    if verification_rollup is None:
        errors.append("CI verification statusCheckRollup must be an array")
        verification_rollup = ()
    verification_total_count = verification.get("server_total_count")
    verification_pages = verification.get("pages")
    verification_projection = _validate_paginated_scan(
        errors,
        label="CI verification pagination",
        digest_kind="ci-status",
        expected_connection=expected_connection,
        expected_scan_role="verification",
        pages_value=verification_pages,
        items=verification_rollup,
        server_total_count=verification_total_count,
        snapshot_binding=snapshot_binding,
        snapshot_id=snapshot_id,
        max_pages=MAX_CI_ROLLUP_PAGES,
        max_page_items=MAX_CI_PAGE_ITEMS,
        max_items=MAX_CI_ROLLUP_ENTRIES,
    )
    if list(verification_rollup) != list(rollup):
        errors.append(
            "CI ordered content changed between primary and verification scans; "
            "evidence must be unavailable"
        )
    _validate_connection_stability(
        errors,
        label="CI",
        stability_value=stability,
        expected_connection=expected_connection,
        primary_pages=primary_pages,
        primary_projection=primary_projection,
        verification_pages=verification_pages,
        verification_projection=verification_projection,
    )


def _validate_review_thread_pagination(
    errors: list[str],
    record: Mapping[str, Any],
    threads: Sequence[Any],
    *,
    snapshot_binding: object,
    snapshot_id: object,
) -> None:
    pagination = _mapping(record.get("pagination"))
    identity = _mapping(record.get("target_identity"))
    if pagination is None:
        errors.append("review-thread pagination evidence must be an object")
        return
    if identity is None:
        errors.append("review-thread pagination lacks a target identity")
        return
    repository = _mapping(identity.get("repository"))
    pull_request = _mapping(identity.get("pull_request"))
    head = _mapping(identity.get("head"))
    if repository is None or pull_request is None or head is None:
        errors.append("review-thread pagination target identity is incomplete")
        return
    expected_connection = {
        "provider": "github-graphql",
        "field": "pullRequest.reviewThreads",
        "repository_node_id": repository.get("node_id"),
        "pull_request_node_id": pull_request.get("node_id"),
        "head_oid": head.get("oid"),
    }
    if pagination.get("connection") != expected_connection:
        errors.append(
            "review-thread pagination connection does not match the exact PR head"
        )

    server_total_count = pagination.get("server_total_count")
    primary_pages = pagination.get("pages")
    primary_projection = _validate_paginated_scan(
        errors,
        label="review-thread primary pagination",
        digest_kind="review-threads",
        expected_connection=expected_connection,
        expected_scan_role="primary",
        pages_value=primary_pages,
        items=threads,
        server_total_count=server_total_count,
        snapshot_binding=snapshot_binding,
        snapshot_id=snapshot_id,
        max_pages=MAX_REVIEW_THREAD_PAGES,
        max_page_items=MAX_REVIEW_THREAD_PAGE_ITEMS,
        max_items=MAX_REVIEW_THREADS,
    )

    stability = _mapping(pagination.get("stability"))
    verification = (
        _mapping(stability.get("verification")) if stability is not None else None
    )
    if verification is None:
        errors.append("review-thread stability verification scan must be an object")
        return
    if verification.get("connection") != expected_connection:
        errors.append("review-thread verification scan changed connection identity")
    verification_threads = _sequence(verification.get("review_threads"))
    if verification_threads is None:
        errors.append("review-thread verification list must be an array")
        verification_threads = ()
    verification_total_count = verification.get("server_total_count")
    verification_pages = verification.get("pages")
    verification_projection = _validate_paginated_scan(
        errors,
        label="review-thread verification pagination",
        digest_kind="review-threads",
        expected_connection=expected_connection,
        expected_scan_role="verification",
        pages_value=verification_pages,
        items=verification_threads,
        server_total_count=verification_total_count,
        snapshot_binding=snapshot_binding,
        snapshot_id=snapshot_id,
        max_pages=MAX_REVIEW_THREAD_PAGES,
        max_page_items=MAX_REVIEW_THREAD_PAGE_ITEMS,
        max_items=MAX_REVIEW_THREADS,
    )
    if list(verification_threads) != list(threads):
        errors.append(
            "review-thread ordered content changed between primary and "
            "verification scans; evidence must be unavailable"
        )
    _validate_connection_stability(
        errors,
        label="review-thread",
        stability_value=stability,
        expected_connection=expected_connection,
        primary_pages=primary_pages,
        primary_projection=primary_projection,
        verification_pages=verification_pages,
        verification_projection=verification_projection,
    )


def _ci_rollup_identity_and_bucket(
    errors: list[str],
    entry: Mapping[str, Any],
    *,
    index: int,
) -> tuple[
    tuple[object, ...] | None,
    tuple[object, ...] | None,
    tuple[object, ...] | None,
    str | None,
]:
    location = f"CI statusCheckRollup[{index}]"
    typename = entry.get("__typename")
    if typename == "CheckRun":
        app = _mapping(entry.get("app"))
        database_id = entry.get("database_id")
        node_id = entry.get("node_id")
        name = entry.get("name")
        status = entry.get("status")
        conclusion = entry.get("conclusion")
        if (
            app is None
            or app.get("__typename") != "App"
            or not isinstance(app.get("node_id"), str)
            or GITHUB_NODE_ID_RE.fullmatch(app["node_id"]) is None
            or "database_id" not in app
            or not _is_nullable_positive_int(app.get("database_id"))
            or not isinstance(app.get("slug"), str)
            or GITHUB_APP_SLUG_RE.fullmatch(app["slug"]) is None
        ):
            errors.append(f"{location} has malformed GitHub App identity")
            identity = None
        elif (
            not isinstance(node_id, str)
            or GITHUB_NODE_ID_RE.fullmatch(node_id) is None
            or "database_id" not in entry
            or not _is_nullable_positive_int(database_id)
            or not isinstance(name, str)
            or not (1 <= len(name) <= 512)
        ):
            errors.append(f"{location} has malformed CheckRun identity")
            identity = None
        else:
            identity = (
                "CheckRun",
                app["node_id"],
                node_id,
            )
            provider = (
                "App",
                app["node_id"],
                app["database_id"],
                app["slug"],
            )
            object_identity = (
                "CheckRun",
                node_id,
                database_id,
                app["node_id"],
            )
        bucket = CI_GATE_BUCKETS_BY_TYPENAME["CheckRun"].get((status, conclusion))
        if bucket is None:
            errors.append(f"{location} status/conclusion combination is unknown")
        return (
            identity,
            provider if identity is not None else None,
            object_identity if identity is not None else None,
            bucket,
        )

    if typename == "StatusContext":
        creator = _mapping(entry.get("creator"))
        node_id = entry.get("node_id")
        context = entry.get("context")
        state = entry.get("state")
        if (
            creator is None
            or creator.get("__typename") not in GITHUB_ACTOR_TYPENAMES
            or not isinstance(creator.get("node_id"), str)
            or GITHUB_NODE_ID_RE.fullmatch(creator["node_id"]) is None
            or not isinstance(creator.get("login"), str)
            or GITHUB_LOGIN_RE.fullmatch(creator["login"]) is None
        ):
            errors.append(f"{location} has malformed creator identity")
            identity = None
        elif (
            not isinstance(node_id, str)
            or GITHUB_NODE_ID_RE.fullmatch(node_id) is None
            or not isinstance(context, str)
            or not 1 <= len(context) <= 512
        ):
            errors.append(f"{location} has malformed StatusContext identity")
            identity = None
        else:
            identity = (
                "StatusContext",
                creator["node_id"],
                node_id,
            )
            provider = (
                "Actor",
                creator["node_id"],
                creator["__typename"],
                creator["login"],
            )
        bucket = CI_GATE_BUCKETS_BY_TYPENAME["StatusContext"].get(state)
        if bucket is None:
            errors.append(f"{location} state is unknown")
        return identity, provider if identity is not None else None, None, bucket

    errors.append(f"{location} typename is unknown")
    return None, None, None, None


def semantic_errors(report: object) -> list[str]:
    """Return cross-field errors after the closed JSON Schema has passed."""

    errors: list[str] = []
    root = _mapping(report)
    if root is None:
        return ["report must be an object"]

    errors.extend(_read_only_delivery_errors(root.get("delivery_record")))
    report_token = _identifier(errors, root.get("report_id"), "report", "report_id")
    target = _mapping(root.get("target"))
    snapshot = _mapping(root.get("snapshot"))
    evidence = _mapping(root.get("evidence"))
    if target is None:
        errors.append("target must be an object")
    if snapshot is None:
        errors.append("snapshot must be an object")
    if evidence is None:
        errors.append("evidence must be an object")
    if target is None or snapshot is None or evidence is None:
        return errors

    target_token = _identifier(
        errors, target.get("binding_id"), "target", "target.binding_id"
    )
    snapshot_token = _identifier(
        errors, snapshot.get("binding_id"), "snapshot", "snapshot.binding_id"
    )
    observation_token = _identifier(
        errors, snapshot.get("snapshot_id"), "observation", "snapshot.snapshot_id"
    )
    tokens = [
        token
        for token in (
            report_token,
            target_token,
            snapshot_token,
            observation_token,
        )
        if token is not None
    ]
    if len(tokens) == 4 and len(set(tokens)) != 4:
        errors.append("report, target, snapshot, and observation IDs must be unique")

    report_id = root.get("report_id")
    target_binding = target.get("binding_id")
    snapshot_binding = snapshot.get("binding_id")
    snapshot_id = snapshot.get("snapshot_id")
    if target.get("report_binding") != report_id:
        errors.append("target.report_binding must equal report_id")
    if snapshot.get("report_binding") != report_id:
        errors.append("snapshot.report_binding must equal report_id")
    if snapshot.get("target_binding") != target_binding:
        errors.append("snapshot.target_binding must equal target.binding_id")

    provider = _mapping(target.get("provider"))
    repository = _mapping(target.get("repository"))
    head = _mapping(target.get("head"))
    if (
        provider is None
        or set(provider) != {"service", "host"}
        or provider.get("service") != "github"
        or not isinstance(provider.get("host"), str)
        or REPOSITORY_HOST_RE.fullmatch(provider["host"]) is None
    ):
        errors.append("target.provider must be the exact GitHub provider identity")
    if not _repository_identity_valid(repository):
        errors.append("target.repository must be an exact repository identity")
    elif provider is not None and provider.get("host") != repository.get("host"):
        errors.append("target.provider.host must equal target.repository.host")
    if (
        head is None
        or set(head) != {"repository", "ref", "oid"}
        or not _repository_identity_valid(head.get("repository"))
        or not isinstance(head.get("ref"), str)
        or not 1 <= len(head["ref"]) <= 1024
        or not _is_oid(head.get("oid"))
    ):
        errors.append("target.head must be an exact current-head identity")
    elif provider is not None:
        head_repository = _mapping(head.get("repository"))
        if head_repository is not None and provider.get("host") != head_repository.get(
            "host"
        ):
            errors.append("target head provider host is inconsistent")
    delivery = _mapping(root.get("delivery_record"))
    if (
        delivery is not None
        and head is not None
        and delivery.get("head_sha") != head.get("oid")
    ):
        errors.append("delivery_record.head_sha must bind the exact frozen target head")

    if "pull_request" in target:
        pull_request = _mapping(target.get("pull_request"))
        if not _repository_identity_valid(repository) or pull_request is None:
            errors.append(
                "target pull request URL requires structured repository and PR data"
            )
        else:
            host = repository.get("host")
            owner = repository.get("owner")
            name = repository.get("name")
            number = pull_request.get("number")
            if (
                set(pull_request) != {"node_id", "number", "url", "base_ref"}
                or not _is_github_node_id(pull_request.get("node_id"))
                or not _is_nonnegative_int(number)
                or number < 1
                or not isinstance(pull_request.get("base_ref"), str)
                or not 1 <= len(pull_request["base_ref"]) <= 1024
            ):
                errors.append(
                    "target pull request URL requires canonical repository components"
                )
            else:
                expected_url = f"https://{host}/{owner}/{name}/pull/{number}"
                if pull_request.get("url") != expected_url:
                    errors.append(
                        "target.pull_request.url must exactly match the canonical "
                        "repository PR URL"
                    )
            target_base = _mapping(target.get("base"))
            if target_base is not None and target_base.get("ref") != pull_request.get(
                "base_ref"
            ):
                errors.append(
                    "target.base.ref must exactly equal target.pull_request.base_ref"
                )

    evidence_records: dict[str, Mapping[str, Any]] = {}
    for field in EVIDENCE_NAMES:
        item = _mapping(evidence.get(field))
        if item is None:
            errors.append(f"evidence.{field} must be an object")
            continue
        evidence_records[field] = item
        if item.get("report_binding") != report_id:
            errors.append(f"evidence.{field}.report_binding must equal report_id")
        if item.get("target_binding") != target_binding:
            errors.append(
                f"evidence.{field}.target_binding must equal target.binding_id"
            )
        if item.get("snapshot_binding") != snapshot_binding:
            errors.append(
                f"evidence.{field}.snapshot_binding must equal snapshot.binding_id"
            )
        _observed_record(errors, item, f"evidence.{field}")

    if set(evidence_records) != set(EVIDENCE_NAMES):
        return errors
    sources = _sequence(snapshot.get("sources"))
    if sources is None:
        errors.append("snapshot.sources must be an array")
    elif (
        any(item.get("status") == "observed" for item in evidence_records.values())
        and not sources
    ):
        errors.append("observed evidence requires at least one snapshot source")
    if (
        sources is not None
        and (
            evidence_records["ci_status"].get("status") == "observed"
            or evidence_records["conversation_state"].get("status") == "observed"
        )
        and "github-graphql" not in sources
    ):
        errors.append(
            "observed paginated provider evidence requires github-graphql "
            "as a snapshot source"
        )

    non_observed = {
        external
        for field, external in EVIDENCE_NAMES.items()
        if evidence_records[field].get("status") != "observed"
    }
    unavailable = _sequence(root.get("unavailable_evidence"))
    if unavailable is None or set(unavailable) != non_observed:
        errors.append(
            "unavailable_evidence must exactly name every non-observed evidence kind"
        )
    blockers = _sequence(root.get("blockers"))
    blocker_names: list[object] = []
    if blockers is None:
        errors.append("blockers must be an array")
    else:
        for blocker in blockers:
            blocker_record = _mapping(blocker)
            blocker_names.append(
                blocker_record.get("evidence") if blocker_record is not None else None
            )
        if (
            len(blocker_names) != len(set(blocker_names))
            or set(blocker_names) != non_observed
        ):
            errors.append(
                "blockers must contain exactly one entry for each non-observed kind"
            )

    selection = evidence_records["pr_selection"]
    selection_record = _observed_record([], selection, "evidence.pr_selection")
    selection_outcome: object = None
    if selection_record is not None:
        selection_outcome = selection_record.get("outcome")
        method = selection_record.get("selection_method")
        count = selection_record.get("candidate_count")
        if method not in {"explicit", "unique-open-head"}:
            errors.append("selection_method is unknown")
        if not _is_nonnegative_int(count):
            errors.append("candidate_count must be a non-negative integer")
        elif selection_outcome == "selected" and count != 1:
            errors.append("selected PR evidence requires candidate_count == 1")
        elif selection_outcome == "no-match" and count != 0:
            errors.append("no-match PR evidence requires candidate_count == 0")
        elif selection_outcome == "ambiguous" and count < 2:
            errors.append("ambiguous PR evidence requires candidate_count >= 2")
        elif selection_outcome not in {"selected", "no-match", "ambiguous"}:
            errors.append("selection outcome is unknown")
        if method == "explicit" and selection_outcome == "ambiguous":
            errors.append("explicit PR selection cannot be ambiguous")
        _bind_observed_target_identity(
            errors,
            selection_record,
            target,
            location="PR selection",
            require_pull_request=selection_outcome == "selected",
        )

    terminal_state = root.get("terminal_state")
    target_state = target.get("state")
    downstream = (
        "pr_lifecycle",
        "ci_status",
        "conversation_state",
        "base_and_head",
    )
    if terminal_state == "pre-target":
        if target_state != "pre-target":
            errors.append("pre-target terminal requires a pre-target binding")
        if selection_outcome not in {"no-match", "ambiguous"}:
            errors.append("pre-target terminal requires a conclusive no-target result")
        if any(
            evidence_records[field].get("status") == "observed" for field in downstream
        ):
            errors.append(
                "pre-target terminal cannot contain target-scoped observations"
            )
    elif terminal_state == "pre-target-blocked":
        if target_state != "pre-target":
            errors.append("pre-target-blocked terminal requires a pre-target binding")
        if selection.get("status") == "observed":
            errors.append(
                "pre-target-blocked terminal requires unavailable or blocked selection"
            )
        if any(
            evidence_records[field].get("status") == "observed" for field in downstream
        ):
            errors.append(
                "pre-target-blocked terminal cannot contain target-scoped observations"
            )
    elif terminal_state == "target-resolution-blocked":
        if target_state != "pr-selected":
            errors.append(
                "target-resolution-blocked terminal requires a selected PR target"
            )
        if selection_outcome != "selected":
            errors.append(
                "target-resolution-blocked terminal requires selected PR evidence"
            )
        if evidence_records["base_and_head"].get("status") == "observed":
            errors.append(
                "target-resolution-blocked terminal requires non-observed base/head"
            )
    elif terminal_state == "target-snapshot":
        if target_state != "range-resolved":
            errors.append("target-snapshot terminal requires a resolved range target")
        if selection_outcome != "selected":
            errors.append("target-snapshot terminal requires selected PR evidence")
        if evidence_records["base_and_head"].get("status") != "observed":
            errors.append("target-snapshot terminal requires observed base/head")
    else:
        errors.append("terminal_state is unknown")

    lifecycle_record = _observed_record(
        [], evidence_records["pr_lifecycle"], "evidence.pr_lifecycle"
    )
    if lifecycle_record is not None:
        _bind_observed_target_identity(
            errors,
            lifecycle_record,
            target,
            location="PR lifecycle",
            require_pull_request=True,
        )
        lifecycle_tuple = (
            lifecycle_record.get("state"),
            lifecycle_record.get("merged"),
            lifecycle_record.get("merged_at"),
        )
        lifecycle_valid = (
            lifecycle_tuple == ("open", False, None)
            or lifecycle_tuple == ("closed", False, None)
            or (
                lifecycle_tuple[0] == "closed"
                and lifecycle_tuple[1] is True
                and isinstance(lifecycle_tuple[2], str)
            )
        )
        if not lifecycle_valid:
            errors.append("lifecycle state, merged, and merged_at contradict")

    ci_record = _observed_record(
        [], evidence_records["ci_status"], "evidence.ci_status"
    )
    if ci_record is not None:
        _bind_observed_target_identity(
            errors,
            ci_record,
            target,
            location="CI status",
            require_pull_request=True,
        )
        rollup = _sequence(ci_record.get("status_check_rollup"))
        if rollup is None:
            errors.append("CI statusCheckRollup must be an array")
        else:
            _validate_ci_pagination(
                errors,
                ci_record,
                rollup,
                snapshot_binding=snapshot_binding,
                snapshot_id=snapshot_id,
            )
            stable_identities: list[tuple[object, ...]] = []
            provider_bindings: dict[tuple[object, object], tuple[object, ...]] = {}
            app_database_bindings: dict[object, object] = {}
            check_run_bindings: dict[object, tuple[object, object]] = {}
            check_run_database_bindings: dict[object, object] = {}
            status_context_bindings: dict[
                object,
                tuple[object, object],
            ] = {}
            actual = {"success": 0, "failure": 0, "pending": 0, "cancelled": 0}
            for index, item in enumerate(rollup):
                entry = _mapping(item)
                if entry is None:
                    errors.append("each CI statusCheckRollup entry must be an object")
                    continue
                identity, provider, object_identity, bucket = (
                    _ci_rollup_identity_and_bucket(
                        errors,
                        entry,
                        index=index,
                    )
                )
                if identity is not None:
                    stable_identities.append(identity)
                if provider is not None:
                    provider_key = (provider[0], provider[1])
                    provider_value = provider[2:]
                    previous = provider_bindings.setdefault(
                        provider_key,
                        provider_value,
                    )
                    if previous != provider_value:
                        errors.append(
                            "CI statusCheckRollup provider identity is inconsistent"
                        )
                    if provider[0] == "App" and provider[2] is not None:
                        previous_node = app_database_bindings.setdefault(
                            provider[2],
                            provider[1],
                        )
                        if previous_node != provider[1]:
                            errors.append(
                                "CI GitHub App database ID maps to multiple Node IDs"
                            )
                if object_identity is not None:
                    node_id = object_identity[1]
                    database_id = object_identity[2]
                    app_node_id = object_identity[3]
                    previous_object = check_run_bindings.setdefault(
                        node_id,
                        (database_id, app_node_id),
                    )
                    if previous_object != (database_id, app_node_id):
                        errors.append(
                            "CI CheckRun Node ID maps to inconsistent object identity"
                        )
                    if database_id is not None:
                        previous_node = check_run_database_bindings.setdefault(
                            database_id,
                            node_id,
                        )
                        if previous_node != node_id:
                            errors.append(
                                "CI CheckRun database ID maps to multiple Node IDs"
                            )
                if entry.get("__typename") == "StatusContext":
                    creator = _mapping(entry.get("creator"))
                    node_id = entry.get("node_id")
                    context = entry.get("context")
                    if (
                        creator is not None
                        and _is_github_node_id(node_id)
                        and _is_github_node_id(creator.get("node_id"))
                        and isinstance(context, str)
                    ):
                        binding = (creator.get("node_id"), context)
                        previous_binding = status_context_bindings.setdefault(
                            node_id,
                            binding,
                        )
                        if previous_binding != binding:
                            errors.append(
                                "CI StatusContext Node ID maps to inconsistent "
                                "creator/context identity"
                            )
                if bucket is not None:
                    actual[bucket] += 1
            if len(stable_identities) != len(set(stable_identities)):
                errors.append("CI statusCheckRollup stable identities must be unique")
            reported = {
                "success": ci_record.get("successful"),
                "failure": ci_record.get("failed"),
                "pending": ci_record.get("pending"),
                "cancelled": ci_record.get("cancelled"),
            }
            if any(not _is_nonnegative_int(value) for value in reported.values()):
                errors.append("CI aggregate counts must be non-negative integers")
            elif reported != actual:
                errors.append("CI aggregate counts do not match statusCheckRollup")
            total = ci_record.get("total")
            if not _is_nonnegative_int(total) or total != len(rollup):
                errors.append("CI total does not match statusCheckRollup")
            expected_state = (
                "no-checks"
                if not rollup
                else "failure"
                if actual["failure"]
                else "pending"
                if actual["pending"]
                else "cancelled"
                if actual["cancelled"]
                else "success"
            )
            if ci_record.get("state") != expected_state:
                errors.append("CI aggregate state contradicts statusCheckRollup")

    conversation_record = _observed_record(
        [],
        evidence_records["conversation_state"],
        "evidence.conversation_state",
    )
    if conversation_record is not None:
        _bind_observed_target_identity(
            errors,
            conversation_record,
            target,
            location="conversation state",
            require_pull_request=True,
        )
        total_threads = conversation_record.get("total_threads")
        unresolved_threads = conversation_record.get("unresolved_threads")
        review_threads = _sequence(conversation_record.get("review_threads"))
        if not _is_nonnegative_int(total_threads) or not _is_nonnegative_int(
            unresolved_threads
        ):
            errors.append("conversation counts must be non-negative integers")
        if review_threads is None:
            errors.append("conversation review_threads must be an array")
        else:
            _validate_review_thread_pagination(
                errors,
                conversation_record,
                review_threads,
                snapshot_binding=snapshot_binding,
                snapshot_id=snapshot_id,
            )
            seen_thread_ids: set[str] = set()
            actual_unresolved = 0
            for index, item in enumerate(review_threads):
                thread = _mapping(item)
                if thread is None:
                    errors.append(f"review thread {index} must be an object")
                    continue
                node_id = thread.get("node_id")
                is_resolved = thread.get("is_resolved")
                if not _is_github_node_id(node_id):
                    errors.append(f"review thread {index} has an invalid Node ID")
                elif node_id in seen_thread_ids:
                    errors.append("review-thread Node IDs must be globally unique")
                else:
                    seen_thread_ids.add(node_id)
                if not isinstance(is_resolved, bool):
                    errors.append(f"review thread {index} is_resolved must be boolean")
                elif not is_resolved:
                    actual_unresolved += 1
            if _is_nonnegative_int(total_threads) and total_threads != len(
                review_threads
            ):
                errors.append("total_threads does not match the complete thread list")
            if (
                _is_nonnegative_int(unresolved_threads)
                and unresolved_threads != actual_unresolved
            ):
                errors.append(
                    "unresolved_threads does not match the complete thread list"
                )

    range_record = _observed_record(
        [], evidence_records["base_and_head"], "evidence.base_and_head"
    )
    if range_record is not None:
        target_base = _mapping(target.get("base"))
        target_head = _mapping(target.get("head"))
        observed_base_oid = range_record.get("observed_base_oid")
        observed_head_oid = range_record.get("observed_head_oid")
        endpoints_match = True
        if target_base is None or target_head is None:
            errors.append(
                "observed base/head evidence requires resolved target endpoints"
            )
            endpoints_match = False
        else:
            target_base_oid = target_base.get("oid")
            target_head_oid = target_head.get("oid")
            if not _is_oid(target_base_oid) or not _is_oid(observed_base_oid):
                errors.append("base endpoint OIDs must be full lowercase object IDs")
                endpoints_match = False
            elif observed_base_oid != target_base_oid:
                errors.append("observed_base_oid must exactly equal target.base.oid")
                endpoints_match = False
            if not _is_oid(target_head_oid) or not _is_oid(observed_head_oid):
                errors.append("head endpoint OIDs must be full lowercase object IDs")
                endpoints_match = False
            elif observed_head_oid != target_head_oid:
                errors.append("observed_head_oid must exactly equal target.head.oid")
                endpoints_match = False
        if endpoints_match:
            base_present = range_record.get("base_object_present")
            head_present = range_record.get("head_object_present")
            merge_base_count = range_record.get("merge_base_count")
            merge_base_oid = range_record.get("merge_base_oid")
            if not isinstance(base_present, bool) or not isinstance(head_present, bool):
                errors.append("endpoint object-presence fields must be booleans")
            if not _is_nonnegative_int(merge_base_count):
                errors.append("merge_base_count must be a non-negative integer")
            else:
                if (not base_present or not head_present) and (
                    merge_base_count != 0 or merge_base_oid is not None
                ):
                    errors.append(
                        "missing endpoint objects cannot have merge-base evidence"
                    )
                elif merge_base_count == 1 and not _is_oid(merge_base_oid):
                    errors.append("one merge base requires merge_base_oid")
                elif merge_base_count != 1 and merge_base_oid is not None:
                    errors.append("non-unique merge base must not claim merge_base_oid")

    return errors


def validate_semantics(report: object) -> None:
    """Raise ValueError when semantic or instance-binding validation fails."""

    errors = semantic_errors(report)
    if errors:
        raise ValueError("; ".join(errors))


def _secure_open_flags() -> int:
    required = ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
    values = [getattr(os, name, None) for name in required]
    if any(not isinstance(value, int) for value in values):
        raise OSError(errno.ENOTSUP, "required secure-open flags are unavailable")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _os_error_code(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno, "OS_ERROR")


def _file_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _validate_regular_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("report path must identify a regular file")
    if info.st_size < 0 or info.st_size > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")


def _read_descriptor_once(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while retained <= MAX_REPORT_BYTES:
        chunk = os.read(
            descriptor,
            min(READ_CHUNK_BYTES, MAX_REPORT_BYTES + 1 - retained),
        )
        if not chunk:
            break
        chunks.append(chunk)
        retained += len(chunk)
    if retained > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")
    return b"".join(chunks)


def _read_regular_path(path: str) -> bytes:
    """Retain bytes while proving path object identity and content stability.

    Object identity is device, inode, and file type. Content stability is exact
    size plus two identical complete reads. Permission bits, timestamps, and
    link count are outside these protected properties.
    """

    try:
        flags = _secure_open_flags()
    except OSError as exc:
        raise ValueError(
            f"secure report descriptor open is unavailable ({_os_error_code(exc)})"
        ) from exc
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError("report path is missing at descriptor admission") from exc
    except OSError as exc:
        raise ValueError(f"report path open failed ({_os_error_code(exc)})") from exc
    try:
        try:
            initial = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor admission failed ({_os_error_code(exc)})"
            ) from exc
        _validate_regular_file(initial)
        identity = _file_identity(initial)

        try:
            first = _read_descriptor_once(descriptor)
            after_first = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor first read failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(after_first) != identity:
            raise ValueError("report descriptor identity changed during first read")
        if after_first.st_size != initial.st_size or len(first) != initial.st_size:
            raise ValueError("report file size changed during first read")

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_descriptor_once(descriptor)
            final = os.fstat(descriptor)
        except OSError as exc:
            raise ValueError(
                f"report descriptor revalidation failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(final) != identity:
            raise ValueError(
                "report descriptor identity changed during content revalidation"
            )
        if final.st_size != initial.st_size or len(second) != initial.st_size:
            raise ValueError("report file size changed during content revalidation")
        if second != first:
            raise ValueError("report file content changed during validation")

        try:
            path_info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ValueError(
                "report path disappeared during final revalidation"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"report path final revalidation failed ({_os_error_code(exc)})"
            ) from exc
        if _file_identity(path_info) != identity:
            raise ValueError("report path identity changed during validation")
        if path_info.st_size != initial.st_size:
            raise ValueError("report path size changed during validation")
        return first
    finally:
        os.close(descriptor)


def _json_structure_preflight(text: str) -> None:
    depth = 0
    markers = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            markers += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("report JSON exceeds the nesting-depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("report JSON structure is malformed")
        elif character in ",:":
            markers += 1
        if markers > MAX_JSON_STRUCTURE_MARKERS:
            raise ValueError("report JSON exceeds the structure-node limit")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("report JSON contains a duplicate object key")
        result[key] = value
    return result


def _parse_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValueError("report JSON integer exceeds the digit limit")
    return int(value)


def _parse_float(value: str) -> float:
    if len(value) > MAX_NUMBER_CHARS:
        raise ValueError("report JSON number exceeds the length limit")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("report JSON number must be finite")
    return parsed


def _reject_nonfinite_constant(_value: str) -> None:
    raise ValueError("report JSON number must be finite")


def _validate_json_shape(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ValueError("report JSON root must be an object")

    nodes = 0
    stack: list[tuple[object, int]] = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("report JSON exceeds the nesting-depth limit")
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("report JSON exceeds the structure-node limit")
        if isinstance(value, dict):
            nodes += len(value)
            if nodes > MAX_JSON_NODES:
                raise ValueError("report JSON exceeds the structure-node limit")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="strict")
    _json_structure_preflight(text)
    payload = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite_constant,
        parse_float=_parse_float,
        parse_int=_parse_integer,
    )
    _validate_json_shape(payload)
    return payload


def _read_payload(path: str) -> object:
    """Read one bounded report.

    File paths use nonblocking descriptor admission and stable retained bytes.
    Standard input is byte-capped only; blocking and deadlines for stdin belong
    to the caller's transport.
    """

    if path == "-":
        raw = sys.stdin.buffer.read(MAX_REPORT_BYTES + 1)
    else:
        raw = _read_regular_path(path)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the 1 MiB validation ceiling")
    return _strict_json_object(raw)


def _safe_error_text(exc: BaseException) -> str:
    if isinstance(exc, MemoryError):
        return "validation resource limit exceeded"
    if isinstance(exc, UnicodeDecodeError):
        return "report is not valid UTF-8"
    if isinstance(exc, json.JSONDecodeError):
        return f"report is not valid JSON at line {exc.lineno}, column {exc.colno}"
    if isinstance(exc, RecursionError):
        return "report nesting exceeds the validation limit"
    if isinstance(exc, OSError):
        code = errno.errorcode.get(exc.errno, "OS_ERROR")
        return f"report input read failed ({code})"

    raw = str(exc)
    truncated = len(raw) > MAX_ERROR_CHARS
    sample = raw[:MAX_ERROR_CHARS]
    cleaned = "".join(
        " "
        if character.isspace() or unicodedata.category(character).startswith("C")
        else character
        for character in sample
    )
    cleaned = " ".join(cleaned.split()) or type(exc).__name__
    if truncated:
        cleaned = f"{cleaned[: MAX_ERROR_CHARS - 3]}..."
    return cleaned[:MAX_ERROR_CHARS]


def _emit_rejection(exc: BaseException) -> int:
    print(
        json.dumps(
            {
                "classification": "rejected",
                "error": _safe_error_text(exc),
            },
            sort_keys=True,
        )
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["new-bindings"]:
        try:
            bindings = new_bindings()
        except OSError as exc:
            return _emit_rejection(
                ValueError(f"report binding generation failed ({_os_error_code(exc)})")
            )
        except (
            MemoryError,
            RuntimeError,
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            return _emit_rejection(exc)
        print(json.dumps(bindings, sort_keys=True))
        return 0
    if len(args) == 2 and args[0] == "validate-semantics":
        try:
            payload = _read_payload(args[1])
            validate_semantics(payload)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            MemoryError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as exc:
            return _emit_rejection(exc)
        print(json.dumps({"classification": "accepted"}, sort_keys=True))
        return 0
    if len(args) == 2 and args[0] == "validate-delivery-handoff":
        try:
            payload = _read_payload(args[1])
            validate_delivery_handoff(payload)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            MemoryError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as exc:
            return _emit_rejection(exc)
        print(json.dumps({"classification": "accepted"}, sort_keys=True))
        return 0
    print(
        "usage: read_only_pr_report.py "
        "{new-bindings|validate-semantics <report.json|->|"
        "validate-delivery-handoff <delivery.json|->}",
        file=sys.stderr,
    )
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
