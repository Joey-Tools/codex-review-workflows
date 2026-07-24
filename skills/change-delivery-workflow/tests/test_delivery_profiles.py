from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import io
import json
import os
import runpy
import stat
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

SKILL_ROOT = Path(__file__).resolve().parents[1]
CHANGE_SKILL = SKILL_ROOT / "SKILL.md"
AGILE_SKILL = SKILL_ROOT.parent / "agile-delivery-workflow" / "SKILL.md"
VALIDATION_ENVIRONMENTS = SKILL_ROOT / "references" / "validation-environments.md"
DELIVERY_RESULT_SCHEMA = SKILL_ROOT / "references" / "delivery-result.schema.json"
PROFILE_SELECTION_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "profile-selection-cases.json"
)
FORMAL_REVIEW_TERMINAL_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "formal-review-terminal-cases.json"
)
LOCAL_MUTATION_CASES = SKILL_ROOT / "tests" / "fixtures" / "local-mutation-cases.json"
READ_ONLY_PR_PROBE_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "read-only-pr-probe-cases.json"
)
REVIEW_SKILL_ROOT = SKILL_ROOT.parent / "review-orchestration-playbook"
REVIEW_SKILL = REVIEW_SKILL_ROOT / "SKILL.md"
PR_READINESS = REVIEW_SKILL_ROOT / "references" / "pr-readiness.md"
READ_ONLY_PR_REPORT_SCHEMA = (
    REVIEW_SKILL_ROOT / "references" / "pr-readiness-read-only-report.schema.json"
)
READ_ONLY_PR_REPORT_RUNTIME = REVIEW_SKILL_ROOT / "scripts" / "read_only_pr_report.py"
READ_ONLY_PR_REPORT_RUNTIME_API = runpy.run_path(
    str(READ_ONLY_PR_REPORT_RUNTIME),
    run_name="read_only_pr_report_contract",
)
new_read_only_report_bindings = READ_ONLY_PR_REPORT_RUNTIME_API["new_bindings"]
validate_read_only_report_semantics = READ_ONLY_PR_REPORT_RUNTIME_API[
    "validate_semantics"
]
validate_delivery_handoff_semantics = READ_ONLY_PR_REPORT_RUNTIME_API[
    "validate_delivery_handoff"
]
READ_ONLY_DELIVERY_SUCCESS_MATRIX = READ_ONLY_PR_REPORT_RUNTIME_API[
    "READ_ONLY_DELIVERY_SUCCESS_MATRIX"
]
read_only_report_payload = READ_ONLY_PR_REPORT_RUNTIME_API["_read_payload"]
read_only_report_main = READ_ONLY_PR_REPORT_RUNTIME_API["main"]
READ_ONLY_PR_REPORT_GLOBALS = read_only_report_main.__globals__
READ_ONLY_REPORT_MAX_BYTES = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_REPORT_BYTES"]
READ_ONLY_REPORT_MAX_DEPTH = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_JSON_DEPTH"]
READ_ONLY_REPORT_MAX_NODES = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_JSON_NODES"]
READ_ONLY_REPORT_MAX_INTEGER_DIGITS = READ_ONLY_PR_REPORT_RUNTIME_API[
    "MAX_INTEGER_DIGITS"
]
READ_ONLY_REPORT_MAX_ERROR_CHARS = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_ERROR_CHARS"]

RESULT_FIELDS = {
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
PROFILES = {
    "focused-checkpoint",
    "local-gate",
    "pr-readiness-handoff",
}
CONSTRAINTS = {
    "local-only",
    "report-only",
    "probe-only",
    "read-only",
    "no-remote",
    "no-commit",
}
REMOTE_LIMITING_CONSTRAINTS = {
    "local-only",
    "report-only",
    "probe-only",
    "read-only",
    "no-remote",
}
REMOTE_READ_LIMITING_CONSTRAINTS = {"local-only"}
LOCAL_MUTATION_LIMITING_CONSTRAINTS = {
    "report-only",
    "probe-only",
    "read-only",
}
COMMIT_LIMITING_CONSTRAINTS = {
    "report-only",
    "probe-only",
    "read-only",
    "no-commit",
}
HANDOFF_PROFILES = {
    "none",
    "pr-readiness",
    "pr-readiness-read-only-probe",
}
TERMINAL_EVIDENCE_FIELDS = {
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
SUCCESS_REASONS = {
    "focused-checkpoint-complete",
    "focused-checkpoint-reviewed-complete",
    "focused-checkpoint-report",
    "focused-checkpoint-read-only-report",
    "focused-checkpoint-clean-range-report",
    "focused-checkpoint-read-only-clean-range-report",
    "local-gate-complete",
    "pr-readiness-handoff-ready",
    "pr-readiness-existing-range-handoff-ready",
    "pr-readiness-read-only-probe-ready",
    "pr-readiness-read-only-reviewed-probe-ready",
    "pr-readiness-read-only-gate-ready",
    "pr-readiness-read-only-uncommitted-probe-ready",
    "pr-readiness-read-only-existing-range-probe-ready",
    "uncommitted-checked-result",
    "read-only-checked-result",
    "clean-range-report",
    "read-only-clean-range-report",
}
BLOCKED_REASONS = {
    "implementation-blocked",
    "validation-blocked",
    "journal-blocked",
    "formal-review-blocked",
    "missing-committed-range",
    "review-findings",
    "signing-failed",
    "blocked-authorization",
    "blocked-input",
}
READ_ONLY_REPORT_FIELDS = {
    "schema_version",
    "terminal",
    "terminal_state",
    "report_id",
    "handoff_profile",
    "delivery_record",
    "target",
    "snapshot",
    "evidence",
    "unavailable_evidence",
    "blockers",
    "actions",
    "merge_ready",
    "next_handoff",
}
READ_ONLY_EVIDENCE_FIELDS = {
    "pr_selection",
    "pr_lifecycle",
    "ci_status",
    "conversation_state",
    "base_and_head",
}
READ_ONLY_ACTION_FIELDS = {
    "local_lanes_started",
    "secret_admission_started",
    "comments_posted",
    "waits_started",
    "cache_or_state_written",
    "local_mutation_performed",
    "remote_mutation_performed",
}
FIXTURE_HEAD_OID = "dddddddddddddddddddddddddddddddddddddddd"
ALTERNATE_HEAD_OID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
PAGE_DIGEST_DOMAIN = b"joey-tools:pr-readiness-page:v1\x00"


def success_evidence(
    local_gate: str,
    phase: str,
    committed_range: str,
    formal_review: str,
    signature: str,
    authorization: str,
    input_state: str,
) -> dict[str, str]:
    return {
        "local_gate": local_gate,
        "build": phase,
        "tests": phase,
        "docs": phase,
        "journal": phase,
        "committed_range": committed_range,
        "formal_review": formal_review,
        "signature": signature,
        "signature_verified_head_oid": (
            FIXTURE_HEAD_OID if signature == "verified" else None
        ),
        "authorization": authorization,
        "input": input_state,
    }


def success_terminal(
    *,
    profile: str,
    local_mutation: str,
    commit_mode: str,
    formal_review_required: bool,
    remote_mutation: str,
    terminal_evidence: dict[str, str],
    handoff: str = "none",
    handoff_profile: str = "none",
) -> dict[str, object]:
    return {
        "profile": profile,
        "local_mutation": local_mutation,
        "commit_mode": commit_mode,
        "formal_review_required": formal_review_required,
        "remote_mutation": remote_mutation,
        "terminal_evidence": terminal_evidence,
        "handoff": handoff,
        "handoff_profile": handoff_profile,
    }


# fmt: off
SUCCESS_ROWS = (
    ("focused-checkpoint-complete", "focused-checkpoint", "allowed", "allowed", False, "forbidden", "not-required", "satisfied", "present", "not-required", "verified", "not-required", "not-required", "none", "none"),
    ("focused-checkpoint-reviewed-complete", "focused-checkpoint", "allowed", "allowed", True, "forbidden", "not-required", "satisfied", "present", "clean", "verified", "not-required", "not-required", "none", "none"),
    ("focused-checkpoint-report", "focused-checkpoint", "allowed", "forbidden", False, "forbidden", "not-required", "satisfied", "missing", "not-required", "not-required", "not-required", "not-required", "none", "none"),
    ("focused-checkpoint-read-only-report", "focused-checkpoint", "forbidden", "forbidden", False, "forbidden", "not-required", "read-only-observed", "missing", "not-required", "not-required", "not-required", "not-required", "none", "none"),
    ("focused-checkpoint-clean-range-report", "focused-checkpoint", "allowed", "forbidden", True, "forbidden", "not-required", "satisfied", "present", "clean", "not-required", "not-required", "not-required", "none", "none"),
    ("focused-checkpoint-read-only-clean-range-report", "focused-checkpoint", "forbidden", "forbidden", True, "forbidden", "not-required", "read-only-observed", "present", "clean", "not-required", "not-required", "not-required", "none", "none"),
    ("local-gate-complete", "local-gate", "allowed", "allowed", True, "forbidden", "succeeded", "satisfied", "present", "clean", "verified", "not-required", "not-required", "none", "none"),
    ("uncommitted-checked-result", "local-gate", "allowed", "forbidden", False, "forbidden", "checked", "satisfied", "missing", "not-required", "not-required", "not-required", "not-required", "none", "none"),
    ("read-only-checked-result", "local-gate", "forbidden", "forbidden", False, "forbidden", "checked", "read-only-observed", "missing", "not-required", "not-required", "not-required", "not-required", "none", "none"),
    ("clean-range-report", "local-gate", "allowed", "forbidden", True, "forbidden", "checked", "satisfied", "present", "clean", "not-required", "not-required", "not-required", "none", "none"),
    ("read-only-clean-range-report", "local-gate", "forbidden", "forbidden", True, "forbidden", "checked", "read-only-observed", "present", "clean", "not-required", "not-required", "not-required", "none", "none"),
    ("pr-readiness-handoff-ready", "pr-readiness-handoff", "allowed", "allowed", True, "review-authorization-required", "succeeded", "satisfied", "present", "clean", "verified", "satisfied", "satisfied", "review-orchestration-playbook", "pr-readiness"),
    ("pr-readiness-existing-range-handoff-ready", "pr-readiness-handoff", "allowed", "forbidden", True, "review-authorization-required", "checked", "satisfied", "present", "clean", "verified", "satisfied", "satisfied", "review-orchestration-playbook", "pr-readiness"),
    ("pr-readiness-read-only-probe-ready", "local-gate", "forbidden", "forbidden", False, "forbidden", "checked", "read-only-observed", "missing", "not-required", "not-required", "not-required", "satisfied", "review-orchestration-playbook", "pr-readiness-read-only-probe"),
    ("pr-readiness-read-only-reviewed-probe-ready", "local-gate", "forbidden", "forbidden", True, "forbidden", "checked", "read-only-observed", "present", "clean", "verified", "not-required", "satisfied", "review-orchestration-playbook", "pr-readiness-read-only-probe"),
    ("pr-readiness-read-only-gate-ready", "local-gate", "allowed", "allowed", True, "forbidden", "succeeded", "satisfied", "present", "clean", "verified", "not-required", "satisfied", "review-orchestration-playbook", "pr-readiness-read-only-probe"),
    ("pr-readiness-read-only-uncommitted-probe-ready", "local-gate", "allowed", "forbidden", False, "forbidden", "checked", "satisfied", "missing", "not-required", "not-required", "not-required", "satisfied", "review-orchestration-playbook", "pr-readiness-read-only-probe"),
    ("pr-readiness-read-only-existing-range-probe-ready", "local-gate", "allowed", "forbidden", True, "forbidden", "checked", "satisfied", "present", "clean", "verified", "not-required", "satisfied", "review-orchestration-playbook", "pr-readiness-read-only-probe"),
)
# fmt: on
SUCCESS_MATRIX = {
    reason: success_terminal(
        profile=profile,
        local_mutation=local_mutation,
        commit_mode=commit_mode,
        formal_review_required=formal_review_required,
        remote_mutation=remote_mutation,
        terminal_evidence=success_evidence(
            local_gate,
            phase,
            committed_range,
            formal_review,
            signature,
            authorization,
            input_state,
        ),
        handoff=handoff,
        handoff_profile=handoff_profile,
    )
    for (
        reason,
        profile,
        local_mutation,
        commit_mode,
        formal_review_required,
        remote_mutation,
        local_gate,
        phase,
        committed_range,
        formal_review,
        signature,
        authorization,
        input_state,
        handoff,
        handoff_profile,
    ) in SUCCESS_ROWS
}
TERMINAL_EVIDENCE_VALUES = {
    "local_gate": {"succeeded", "checked", "blocked", "not-required"},
    "build": {"satisfied", "read-only-observed", "failed", "blocked"},
    "tests": {"satisfied", "read-only-observed", "failed", "blocked"},
    "docs": {"satisfied", "read-only-observed", "blocked"},
    "journal": {"satisfied", "read-only-observed", "blocked"},
    "committed_range": {"present", "missing", "not-required"},
    "formal_review": {
        "clean",
        "findings",
        "blocked",
        "not-started",
        "not-required",
    },
    "signature": {"verified", "failed", "not-required"},
    "authorization": {"satisfied", "blocked", "not-required"},
    "input": {"satisfied", "blocked", "not-required"},
}


def constraints_for_success(expected: dict[str, object]) -> list[str]:
    constraints: list[str] = []
    if expected["local_mutation"] == "forbidden":
        constraints.append("probe-only")
    elif expected["commit_mode"] == "forbidden":
        constraints.append("no-commit")
    if expected["handoff_profile"] == "pr-readiness-read-only-probe":
        constraints.append("no-remote")
    return constraints


def success_result(reason: str) -> dict[str, object]:
    expected = copy.deepcopy(SUCCESS_MATRIX[reason])
    return {
        "schema_version": 3,
        "constraints": constraints_for_success(expected),
        "head_sha": FIXTURE_HEAD_OID,
        "terminal_outcome": "succeeded",
        "terminal_reason": reason,
        **expected,
    }


def blocker_result(branch: dict[str, object]) -> dict[str, object]:
    properties = branch["properties"]
    if not isinstance(properties, dict):
        raise AssertionError("blocker row properties must be an object")
    result = success_result("pr-readiness-handoff-ready")
    for field in (
        "profile",
        "local_mutation",
        "commit_mode",
        "formal_review_required",
        "remote_mutation",
        "terminal_outcome",
        "terminal_reason",
        "handoff",
        "handoff_profile",
    ):
        field_schema = properties.get(field)
        if isinstance(field_schema, dict) and "const" in field_schema:
            result[field] = field_schema["const"]
    if result["local_mutation"] == "forbidden":
        result["constraints"] = ["read-only"]
    elif result["commit_mode"] == "forbidden":
        result["constraints"] = ["no-commit"]
    else:
        result["constraints"] = []
    if "remote_mutation" not in properties:
        result["remote_mutation"] = (
            "review-authorization-required"
            if result["profile"] == "pr-readiness-handoff"
            else "forbidden"
        )
    evidence_schema = properties["terminal_evidence"]
    if not isinstance(evidence_schema, dict):
        raise AssertionError("blocker row evidence must be an object")
    result["terminal_evidence"] = {
        field: (
            result["head_sha"]
            if field_schema.get("$ref") == "#/$defs/oid"
            else field_schema["const"]
        )
        for field, field_schema in evidence_schema["properties"].items()
    }
    return result


def check_run_rollup(
    *,
    database_id: int | None,
    name: str,
    status: str,
    conclusion: str | None,
    app_database_id: int | None = 15368,
    app_slug: str = "github-actions",
    node_id: str | None = None,
    app_node_id: str = "APP_15368",
) -> dict[str, object]:
    resolved_node_id = node_id or (
        f"CHECK_RUN_{database_id}"
        if database_id is not None
        else "CHECK_RUN_NO_DATABASE_ID"
    )
    return {
        "__typename": "CheckRun",
        "node_id": resolved_node_id,
        "database_id": database_id,
        "name": name,
        "app": {
            "__typename": "App",
            "node_id": app_node_id,
            "database_id": app_database_id,
            "slug": app_slug,
        },
        "status": status,
        "conclusion": conclusion,
    }


def status_context_rollup(
    *,
    context: str,
    state: str,
    creator_typename: str = "Bot",
    creator_node_id: str = "MDM6Qm90MTIzNDU2",
    creator_login: str = "legacy-ci[bot]",
    node_id: str = "STATUS_CONTEXT_REQUIRED",
) -> dict[str, object]:
    return {
        "__typename": "StatusContext",
        "node_id": node_id,
        "context": context,
        "creator": {
            "__typename": creator_typename,
            "node_id": creator_node_id,
            "login": creator_login,
        },
        "state": state,
    }


def canonical_page_digest(kind: str, payload: object) -> str:
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


def bind_ci_pagination(
    report: dict[str, object],
    observed: dict[str, object],
    *,
    page_size: int = 100,
) -> None:
    snapshot = report["snapshot"]
    if not isinstance(snapshot, dict):
        raise AssertionError("report snapshot must be an object")
    snapshot_binding = snapshot["binding_id"]
    snapshot_id = snapshot["snapshot_id"]
    target_identity = observed["target_identity"]
    if not isinstance(target_identity, dict):
        raise AssertionError("CI target identity must be an object")
    repository = target_identity["repository"]
    pull_request = target_identity["pull_request"]
    head = target_identity["head"]
    if not all(isinstance(item, dict) for item in (repository, pull_request, head)):
        raise AssertionError("CI target identity is incomplete")
    connection = {
        "provider": "github-graphql",
        "field": "commit.statusCheckRollup.contexts",
        "repository_node_id": repository["node_id"],
        "pull_request_node_id": pull_request["node_id"],
        "head_oid": head["oid"],
    }
    rollup = observed["status_check_rollup"]
    if not isinstance(rollup, list):
        raise AssertionError("CI rollup must be an array")
    chunks = [
        rollup[offset : offset + page_size]
        for offset in range(0, len(rollup), page_size)
    ] or [[]]
    pages = []
    previous_cursor: str | None = None
    for index, chunk in enumerate(chunks, start=1):
        end_cursor = None if not chunk else f"CI_CURSOR_{index}"
        page = {
            "connection": dict(connection),
            "snapshot_binding": snapshot_binding,
            "snapshot_id": snapshot_id,
            "page_index": index,
            "request_after": previous_cursor,
            "item_count": len(chunk),
            "server_total_count": len(rollup),
            "page_info": {
                "end_cursor": end_cursor,
                "has_next_page": index < len(chunks),
            },
        }
        page["content_sha256"] = canonical_page_digest(
            "ci-status",
            {
                "connection": connection,
                "snapshot_binding": snapshot_binding,
                "snapshot_id": snapshot_id,
                "server_total_count": len(rollup),
                "page_index": index,
                "request_after": previous_cursor,
                "item_count": len(chunk),
                "page_info": page["page_info"],
                "items": chunk,
            },
        )
        pages.append(page)
        previous_cursor = end_cursor
    observed["pagination"] = {
        "connection": connection,
        "server_total_count": len(rollup),
        "pages": pages,
    }


def bind_review_thread_pagination(
    report: dict[str, object],
    observed: dict[str, object],
    *,
    page_size: int = 100,
) -> None:
    snapshot = report["snapshot"]
    if not isinstance(snapshot, dict):
        raise AssertionError("report snapshot must be an object")
    snapshot_binding = snapshot["binding_id"]
    snapshot_id = snapshot["snapshot_id"]
    target_identity = observed["target_identity"]
    if not isinstance(target_identity, dict):
        raise AssertionError("conversation target identity must be an object")
    repository = target_identity["repository"]
    pull_request = target_identity["pull_request"]
    head = target_identity["head"]
    if not all(isinstance(item, dict) for item in (repository, pull_request, head)):
        raise AssertionError("conversation target identity is incomplete")
    connection = {
        "provider": "github-graphql",
        "field": "pullRequest.reviewThreads",
        "repository_node_id": repository["node_id"],
        "pull_request_node_id": pull_request["node_id"],
        "head_oid": head["oid"],
    }
    threads = observed["review_threads"]
    if not isinstance(threads, list):
        raise AssertionError("review_threads must be an array")
    chunks = [
        threads[offset : offset + page_size]
        for offset in range(0, len(threads), page_size)
    ] or [[]]
    pages = []
    previous_cursor: str | None = None
    for index, chunk in enumerate(chunks, start=1):
        end_cursor = None if not chunk else f"THREAD_CURSOR_{index}"
        page = {
            "connection": dict(connection),
            "snapshot_binding": snapshot_binding,
            "snapshot_id": snapshot_id,
            "page_index": index,
            "request_after": previous_cursor,
            "item_count": len(chunk),
            "server_total_count": len(threads),
            "page_info": {
                "end_cursor": end_cursor,
                "has_next_page": index < len(chunks),
            },
        }
        page["content_sha256"] = canonical_page_digest(
            "review-threads",
            {
                "connection": connection,
                "snapshot_binding": snapshot_binding,
                "snapshot_id": snapshot_id,
                "server_total_count": len(threads),
                "page_index": index,
                "request_after": previous_cursor,
                "item_count": len(chunk),
                "page_info": page["page_info"],
                "items": chunk,
            },
        )
        pages.append(page)
        previous_cursor = end_cursor
    observed["pagination"] = {
        "connection": connection,
        "server_total_count": len(threads),
        "pages": pages,
    }


def documented_profile_cases(skill: str) -> dict[str, tuple[str, str]]:
    cases: dict[str, tuple[str, str]] = {}
    for line in skill.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        prompt, profile, transition = cells
        cases[prompt.strip("`")] = (profile.strip("`"), transition)
    return cases


def profile_selection_cases() -> list[dict[str, object]]:
    payload = json.loads(PROFILE_SELECTION_CASES.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError("unexpected profile-selection fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError("profile-selection cases must be a list")
    return cases


def formal_review_terminal_cases() -> list[dict[str, object]]:
    payload = json.loads(FORMAL_REVIEW_TERMINAL_CASES.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError("unexpected formal-review terminal fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError("formal-review terminal cases must be a list")
    return cases


def fixture_cases(path: Path, label: str) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError(f"unexpected {label} fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError(f"{label} cases must be a list")
    return cases


def read_only_report_validator() -> Draft202012Validator:
    report_schema = json.loads(READ_ONLY_PR_REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(report_schema)
    return Draft202012Validator(report_schema)


def assert_valid_result_contract(result: object) -> None:
    if not isinstance(result, dict):
        raise AssertionError("delivery result must be an object")
    if set(result) != RESULT_FIELDS:
        raise AssertionError("delivery result fields do not match the closed contract")
    if result["schema_version"] != 3:
        raise AssertionError("unexpected delivery result schema version")
    if result["profile"] not in PROFILES:
        raise AssertionError("unknown delivery profile")
    head_sha = result["head_sha"]
    if (
        not isinstance(head_sha, str)
        or len(head_sha) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in head_sha)
    ):
        raise AssertionError("delivery result lacks a full lowercase head object ID")

    constraints = result["constraints"]
    if not isinstance(constraints, list):
        raise AssertionError("constraints must be a list")
    if len(constraints) != len(set(constraints)):
        raise AssertionError("constraints must be unique")
    if not set(constraints) <= CONSTRAINTS:
        raise AssertionError("unknown delivery constraint")

    commit_mode = result["commit_mode"]
    if commit_mode not in {"allowed", "forbidden"}:
        raise AssertionError("unknown commit mode")
    if not isinstance(result["formal_review_required"], bool):
        raise AssertionError("formal-review requirement must be boolean")
    if (
        result["profile"] == "local-gate"
        and commit_mode == "allowed"
        and result["formal_review_required"] is not True
    ):
        raise AssertionError("commit-allowed local gate bypassed formal review")
    remote_mutation = result["remote_mutation"]
    if remote_mutation not in {
        "forbidden",
        "review-authorization-required",
    }:
        raise AssertionError("unknown remote-mutation mode")
    handoff = result["handoff"]
    if handoff not in {"none", "review-orchestration-playbook"}:
        raise AssertionError("unknown handoff")
    outcome = result["terminal_outcome"]
    reason = result["terminal_reason"]
    evidence = result["terminal_evidence"]
    if not isinstance(evidence, dict) or set(evidence) != TERMINAL_EVIDENCE_FIELDS:
        raise AssertionError(
            "terminal evidence fields do not match the closed contract"
        )
    for field, values in TERMINAL_EVIDENCE_VALUES.items():
        if evidence[field] not in values:
            raise AssertionError(f"unknown terminal evidence value for {field}")
    verified_head_oid = evidence["signature_verified_head_oid"]
    if evidence["signature"] == "verified":
        if (
            not isinstance(verified_head_oid, str)
            or len(verified_head_oid) not in {40, 64}
            or any(
                character not in "0123456789abcdef" for character in verified_head_oid
            )
        ):
            raise AssertionError(
                "verified signature lacks a full lowercase head object ID"
            )
        if verified_head_oid != head_sha:
            raise AssertionError(
                "verified signature does not bind the exact delivery head"
            )
    elif verified_head_oid is not None:
        raise AssertionError(
            "non-verified signature retained a verified head object ID"
        )
    if outcome == "succeeded":
        expected_terminal = SUCCESS_MATRIX.get(reason)
        if expected_terminal is None:
            raise AssertionError("successful terminal used a blocker reason")
        expected_terminal = copy.deepcopy(expected_terminal)
        if evidence["signature"] == "verified":
            expected_terminal["terminal_evidence"]["signature_verified_head_oid"] = (
                verified_head_oid
            )
        actual_terminal = {
            field: result[field]
            for field in (
                "profile",
                "local_mutation",
                "commit_mode",
                "formal_review_required",
                "remote_mutation",
                "terminal_evidence",
                "handoff",
                "handoff_profile",
            )
        }
        if actual_terminal != expected_terminal:
            raise AssertionError(
                f"successful terminal contradicts terminal_reason {reason}"
            )
    elif outcome == "blocked":
        if reason not in BLOCKED_REASONS:
            raise AssertionError("blocked terminal used a success reason")
        if handoff != "none" or result["handoff_profile"] != "none":
            raise AssertionError("blocked terminal attempted a handoff")
    else:
        raise AssertionError("unknown terminal outcome")

    constraint_set = set(constraints)
    local_mutation = result["local_mutation"]
    if local_mutation not in {"allowed", "forbidden"}:
        raise AssertionError("unknown local-mutation mode")
    if constraint_set & LOCAL_MUTATION_LIMITING_CONSTRAINTS:
        if local_mutation != "forbidden":
            raise AssertionError("local-mutation-limiting constraint was discarded")
    elif local_mutation != "allowed":
        raise AssertionError(
            "local mutation was forbidden without a limiting constraint"
        )

    if constraint_set & COMMIT_LIMITING_CONSTRAINTS:
        if commit_mode != "forbidden":
            raise AssertionError("commit-limiting constraint was discarded")
    elif commit_mode != "allowed":
        raise AssertionError("commit was forbidden without a limiting constraint")
    if constraint_set & REMOTE_LIMITING_CONSTRAINTS:
        if result["profile"] == "pr-readiness-handoff":
            raise AssertionError(
                "remote-limiting constraint allowed mutable PR handoff"
            )
        if remote_mutation != "forbidden":
            raise AssertionError("remote-limiting constraint was discarded")
    if constraint_set & REMOTE_READ_LIMITING_CONSTRAINTS and handoff != "none":
        raise AssertionError("remote-read-limiting constraint allowed a handoff")

    handoff_profile = result["handoff_profile"]
    if handoff_profile not in HANDOFF_PROFILES:
        raise AssertionError("unknown handoff profile")
    if result["profile"] == "pr-readiness-handoff":
        if result["formal_review_required"] is not True:
            raise AssertionError("PR handoff bypassed required formal review")
        if remote_mutation != "review-authorization-required":
            raise AssertionError("PR handoff bypassed review authorization")
    elif remote_mutation != "forbidden":
        raise AssertionError("a local profile allowed unsupported remote mutation")

    if handoff_profile == "pr-readiness-read-only-probe":
        if result["profile"] != "local-gate":
            raise AssertionError("read-only PR probe did not use the local gate")
        if remote_mutation != "forbidden":
            raise AssertionError("read-only PR probe allowed remote mutation")
        if handoff != "review-orchestration-playbook":
            raise AssertionError("read-only PR probe did not route to review")
        if not constraint_set & (
            REMOTE_LIMITING_CONSTRAINTS - REMOTE_READ_LIMITING_CONSTRAINTS
        ):
            raise AssertionError("read-only PR probe lacks a mutation limit")
    elif handoff_profile == "pr-readiness":
        if result["profile"] != "pr-readiness-handoff":
            raise AssertionError("PR handoff profile used a local delivery profile")
        if handoff != "review-orchestration-playbook":
            raise AssertionError("PR handoff did not route to the review skill")
    elif handoff != "none" or handoff_profile != "none":
        raise AssertionError("a local profile attempted an unsupported handoff")

    blocker_evidence = {
        "missing-committed-range": ("committed_range", "missing"),
        "review-findings": ("formal_review", "findings"),
        "signing-failed": ("signature", "failed"),
        "blocked-authorization": ("authorization", "blocked"),
        "blocked-input": ("input", "blocked"),
    }
    if reason in blocker_evidence:
        field, expected = blocker_evidence[reason]
        if evidence[field] != expected:
            raise AssertionError(f"{reason} lacks matching terminal evidence")
    if reason == "review-findings" and (
        commit_mode != "forbidden"
        or result["formal_review_required"] is not True
        or evidence["committed_range"] != "present"
        or evidence["signature"] != "not-required"
    ):
        raise AssertionError(
            "review-findings is terminal only for a required no-commit review"
        )


def assert_read_only_report_contract(report: object) -> None:
    if not isinstance(report, dict) or set(report) != READ_ONLY_REPORT_FIELDS:
        raise AssertionError("read-only PR report fields do not match the contract")
    if report["schema_version"] != 7:
        raise AssertionError("unexpected read-only PR report schema version")
    if report["terminal"] != "pr-readiness-read-only-report":
        raise AssertionError("unexpected read-only PR report terminal")
    if report["handoff_profile"] != "pr-readiness-read-only-probe":
        raise AssertionError("unexpected read-only PR report handoff profile")
    assert_valid_result_contract(report["delivery_record"])
    if report["delivery_record"]["handoff_profile"] != report["handoff_profile"]:
        raise AssertionError("read-only PR report widened its delivery handoff")
    schema_errors = list(read_only_report_validator().iter_errors(report))
    if schema_errors:
        raise AssertionError(schema_errors[0].message)
    try:
        validate_read_only_report_semantics(report)
    except ValueError as exc:
        raise AssertionError(str(exc)) from exc
    actions = report["actions"]
    if not isinstance(actions, dict) or set(actions) != READ_ONLY_ACTION_FIELDS:
        raise AssertionError("read-only PR report actions are not closed")
    if any(actions.values()):
        raise AssertionError("read-only PR report recorded a forbidden action")
    if report["merge_ready"] is not False or report["next_handoff"] != "none":
        raise AssertionError("read-only PR report escaped its terminal boundary")


class DeliveryProfileContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.change = CHANGE_SKILL.read_text(encoding="utf-8")
        self.agile = AGILE_SKILL.read_text(encoding="utf-8")
        self.validation_environments = VALIDATION_ENVIRONMENTS.read_text(
            encoding="utf-8"
        )
        self.normalized_change = " ".join(self.change.split())
        self.normalized_agile = " ".join(self.agile.split())
        self.normalized_validation_environments = " ".join(
            self.validation_environments.split()
        )
        self.review = REVIEW_SKILL.read_text(encoding="utf-8")
        self.pr_readiness = PR_READINESS.read_text(encoding="utf-8")
        self.normalized_review = " ".join(self.review.split())
        self.normalized_pr_readiness = " ".join(self.pr_readiness.split())

    def test_one_active_entrypoint_declares_three_ordered_profiles(self) -> None:
        self.assertIn("only active delivery entrypoint", self.normalized_change)
        anchors = (
            "### `focused-checkpoint`",
            "### `local-gate`",
            "### `pr-readiness-handoff`",
        )
        positions = tuple(self.change.index(anchor) for anchor in anchors)
        self.assertEqual(positions, tuple(sorted(positions)))
        self.assertIn(
            "Do not downgrade it because a gate is slow",
            self.normalized_change,
        )
        self.assertIn(
            "do not silently promote a local checkpoint",
            self.normalized_change,
        )
        self.assertIn(
            "When a non-trivial delivery request is otherwise ambiguous, use `local-gate`",
            self.normalized_change,
        )

    def test_prompt_classification_uses_terminal_outcome_precedence(self) -> None:
        expected = {
            case["prompt"]: (
                case["result"]["profile"],
                case["transition"],
            )
            for case in profile_selection_cases()
        }
        self.assertEqual(documented_profile_cases(self.change), expected)
        for anchor in (
            "After applying hard constraints, choose by the remaining requested terminal outcome",
            "combined MVP-plus-PR request therefore selects `pr-readiness-handoff`",
            "combined MVP-plus-full-local-gate request similarly selects `local-gate`",
            "remote or full-gate work must wait for a later request",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_profiles_resolve_formal_review_requirement_deterministically(
        self,
    ) -> None:
        cases = {case["prompt"]: case["result"] for case in profile_selection_cases()}
        expected = {
            "Deliver a quick MVP and stop at a local checkpoint.": False,
            "Complete this non-trivial implementation locally.": True,
            "Probe local gate readiness, but do not commit.": False,
            "Implement and validate this locally, but do not commit.": False,
            "Run the full workflow with no remote work.": True,
            "Probe full workflow and PR readiness; do not make remote changes.": False,
            "Complete the full local workflow, then report PR readiness without remote mutations.": True,
            "Run the full workflow and open a PR.": True,
        }
        for prompt, formal_review_required in expected.items():
            with self.subTest(prompt=prompt):
                self.assertIs(
                    cases[prompt]["formal_review_required"],
                    formal_review_required,
                )

        validator = Draft202012Validator(
            json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        )
        for prompt in (
            "Run the full workflow and open a PR.",
            "Complete the full local workflow, then report PR readiness without remote mutations.",
        ):
            contradictory = copy.deepcopy(cases[prompt])
            contradictory["formal_review_required"] = not contradictory[
                "formal_review_required"
            ]
            with self.subTest(contradictory_prompt=prompt):
                self.assertTrue(list(validator.iter_errors(contradictory)))
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(contradictory)

        for anchor in (
            "Resolve `formal_review_required` once after the profile and hard constraints",
            "`pr-readiness-handoff` always resolves to `true`",
            "ordinary mutation-capable `local-gate` with commit mode `allowed` resolves to `true`",
            "constrained `local-gate` with commit mode `forbidden` resolves to `false`",
            "`focused-checkpoint` resolves to `false` by default",
            "may not downgrade either profile-mandated `true`",
            "preserve it unchanged across every handoff",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_constraint_precedes_every_checkpoint(self) -> None:
        mode_heading = self.change.index("## Resolve Hard Constraints First")
        profile_heading = self.change.index("## Choose The Profile")
        self.assertLess(mode_heading, profile_heading)
        for anchor in (
            "sets commit mode to `forbidden` for the whole run",
            "before any review checkpoint, anchor, or landing commit",
            "A delivery profile never overrides it",
            "leave Git history unchanged",
            "pre-existing exact committed range",
            "do not create an implicit checkpoint",
            "Under `report-only`, `probe-only`, `read-only`, or `no-commit`, do not create a checkpoint or anchor",
            "otherwise report the formal lane blocked",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_scope_constraints_precede_pr_signals_and_survive_handoff(
        self,
    ) -> None:
        cases = {case["prompt"]: case["result"] for case in profile_selection_cases()}
        constrained_expectations = {
            "Run the full workflow locally, report-only.": {
                "constraints": ["local-only", "report-only"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "none",
            },
            "Run the full workflow with no remote work.": {
                "constraints": ["no-remote"],
                "local_mutation": "allowed",
                "commit_mode": "allowed",
                "handoff_profile": "none",
            },
            "Review full-workflow readiness read-only.": {
                "constraints": ["read-only"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "none",
            },
            "Probe full workflow and PR readiness; do not make remote changes.": {
                "constraints": ["probe-only", "no-remote"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "pr-readiness-read-only-probe",
            },
        }
        for prompt, expected in constrained_expectations.items():
            with self.subTest(prompt=prompt):
                result = cases[prompt]
                self.assertEqual(result["profile"], "local-gate")
                self.assertEqual(result["constraints"], expected["constraints"])
                self.assertEqual(result["local_mutation"], expected["local_mutation"])
                self.assertEqual(result["commit_mode"], expected["commit_mode"])
                self.assertEqual(result["remote_mutation"], "forbidden")
                self.assertEqual(result["handoff_profile"], expected["handoff_profile"])
                expected_handoff = (
                    "review-orchestration-playbook"
                    if expected["handoff_profile"] == "pr-readiness-read-only-probe"
                    else "none"
                )
                self.assertEqual(result["handoff"], expected_handoff)

        positive = cases["Run the full workflow and open a PR."]
        self.assertEqual(positive["profile"], "pr-readiness-handoff")
        self.assertEqual(positive["constraints"], [])
        self.assertEqual(positive["local_mutation"], "allowed")
        self.assertEqual(
            positive["remote_mutation"],
            "review-authorization-required",
        )
        self.assertEqual(positive["handoff"], "review-orchestration-playbook")
        self.assertEqual(positive["handoff_profile"], "pr-readiness")

        for anchor in (
            "constraints are subtractive and take precedence over `full workflow`",
            "forbids `pr-readiness-handoff` and every remote mutation",
            "a downstream workflow may not reinterpret it",
            "hard constraint that forbids remote mutation always wins at this step",
            "Remote mutation being forbidden does not erase an explicitly requested read-only PR-readiness probe",
            "[delivery-result.schema.json](references/delivery-result.schema.json)",
            "Preserve these fields unchanged across any handoff",
            "Receivers must fail closed",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_read_only_constraints_short_circuit_all_local_mutation(self) -> None:
        profile_results = {
            case["prompt"]: case["result"] for case in profile_selection_cases()
        }
        cases = fixture_cases(LOCAL_MUTATION_CASES, "local-mutation")
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(prompt=case["prompt"]):
                expected = case["expected"]
                self.assertEqual(
                    profile_results[case["prompt"]]["local_mutation"],
                    "forbidden",
                )
                self.assertEqual(expected["local_mutation"], "forbidden")
                for action in (
                    "enter_implementation",
                    "write_journal",
                    "create_commit",
                    "generate_working_result_artifacts",
                    "run_mutating_or_cache_writing_validation",
                ):
                    self.assertFalse(expected[action])
                self.assertEqual(
                    expected["validation_mode"],
                    "read-only-subset",
                )

        for anchor in (
            "Resolve two independent mutation dimensions",
            "`local_mutation` is `forbidden`",
            "short-circuit the implementation and journal steps",
            "Do not edit source or documentation",
            "generate working-result artifacts",
            "validation known to create output, caches, or persistent state",
            "Run only the read-only validation subset",
            "Skip this entire step when `local_mutation` is `forbidden`",
            "Unknown mutation behavior is not read-only",
            "builds, tests, formatters, code generators, dependency resolution",
        ):
            self.assertIn(anchor, self.normalized_change)
        for anchor in (
            "parent workflow's `local_mutation` ceiling",
            "do not create an isolated worktree, cache, generated output, log, environment, or persistent state",
            "report unavailable single- or multi-version gates",
        ):
            self.assertIn(anchor, self.normalized_validation_environments)

    def test_no_commit_alone_keeps_local_mutation_available(self) -> None:
        result = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"]
            == "Implement and validate this locally, but do not commit."
        )
        self.assertEqual(result["constraints"], ["local-only", "no-commit"])
        self.assertEqual(result["local_mutation"], "allowed")
        self.assertEqual(result["commit_mode"], "forbidden")
        self.assertEqual(result["remote_mutation"], "forbidden")
        self.assertEqual(result["handoff"], "none")
        self.assertEqual(result["handoff_profile"], "none")

    def test_remote_mutation_limit_routes_explicit_read_only_pr_probe(self) -> None:
        cases = fixture_cases(READ_ONLY_PR_PROBE_CASES, "read-only-pr-probe")
        self.assertEqual(
            {case["name"] for case in cases},
            {
                "resolved-target-snapshot",
                "pre-target-no-match",
                "pre-target-selection-blocked",
                "selected-pr-base-head-blocked",
            },
        )
        case = next(
            case for case in cases if case["name"] == "resolved-target-snapshot"
        )
        selected = next(
            item["result"]
            for item in profile_selection_cases()
            if item["prompt"] == case["prompt"]
        )
        self.assertEqual(selected, case["input"])
        self.assertEqual(
            case["expected"]["allow"],
            [
                "pr-selection",
                "pr-lifecycle",
                "ci-status",
                "conversation-state",
                "base-and-head",
            ],
        )
        self.assertEqual(
            case["expected"]["forbid"],
            [
                "local-review-lanes",
                "secret-admission",
                "comments",
                "github-codex-request",
                "waits",
                "cache-or-state-writes",
                "branch-or-pr-metadata-changes",
                "fixes",
                "commits",
                "pushes",
            ],
        )
        self.assertEqual(
            case["expected"]["terminal"],
            "pr-readiness-read-only-report",
        )
        terminal_result = case["expected"]["terminal_result"]
        self.assertEqual(terminal_result["delivery_record"], case["input"])
        for fixture_case in cases:
            with self.subTest(name=fixture_case["name"]):
                assert_read_only_report_contract(
                    fixture_case["expected"]["terminal_result"]
                )
        for anchor in (
            "Remote mutation being forbidden does not erase",
            "`pr-readiness-read-only-probe`",
            "PR selection, lifecycle, CI, conversation, base, and head evidence",
            "comment, `@codex review` request, state-changing wait",
            "branch or PR metadata change, fix, commit, push",
            "not a fourth delivery profile",
            "must not start CI, a reviewer, a check",
            "must not persist an authentication refresh or cache",
            "terminal `pr-readiness-read-only-report`",
            "Never call this merge-ready",
            "receiver must preserve that read-only capability ceiling",
            "pr-readiness-read-only-report.schema.json",
            "fresh instance IDs",
            "real pre-target report",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_read_only_pr_probe_receiver_precedes_generic_review_and_is_closed(
        self,
    ) -> None:
        workflow = self.review.split("## Workflow", 1)[1]
        receiver = workflow.index("`handoff_profile: pr-readiness-read-only-probe`")
        generic_review = workflow.index("A review-only child")
        generic_pr = workflow.index("A PR/full-workflow request")
        self.assertLess(receiver, generic_review)
        self.assertLess(receiver, generic_pr)
        self.assertLess(
            self.pr_readiness.index(
                "## Read-Only Delivery Probe: Classify And Stop First"
            ),
            self.pr_readiness.index("## Authorization"),
        )

        for anchor in (
            "terminal evidence probe, not PR readiness",
            "Classify this structured handoff before every prose-based PR/review rule",
            "must not start a Codex or Claude local lane",
            "run secret admission or the low-level helper",
            "post a comment",
            "wait or poll",
            "write authentication/cache/state",
            "do not continue to steps 2-9",
            "invalid or widened record",
        ):
            self.assertIn(anchor, self.normalized_review)
        for anchor in (
            "First classify an inbound `pr-readiness-read-only-probe`",
            "Classify it before generic PR/full-workflow language",
            "Do not start any local Codex or Claude lane",
            "exact-secret admission",
            "GitHub Codex request",
            "poll, monitor, or wait",
            "persist authentication refreshes, caches, tool state, or connector state",
            "Then stop without another handoff",
            "never a named-review artifact",
            "pre-target-blocked",
            "target-resolution-blocked",
            "validate-semantics",
        ):
            self.assertIn(anchor, self.normalized_pr_readiness)

        schema = json.loads(READ_ONLY_PR_REPORT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(set(schema["required"]), READ_ONLY_REPORT_FIELDS)
        self.assertEqual(set(schema["properties"]), READ_ONLY_REPORT_FIELDS)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 7)
        self.assertEqual(
            set(schema["properties"]["terminal_state"]["enum"]),
            {
                "pre-target",
                "pre-target-blocked",
                "target-resolution-blocked",
                "target-snapshot",
            },
        )
        self.assertEqual(
            schema["properties"]["report_id"]["$ref"],
            "#/$defs/reportId",
        )
        self.assertEqual(schema["properties"]["target"]["$ref"], "#/$defs/target")
        self.assertEqual(
            schema["properties"]["snapshot"]["$ref"],
            "#/$defs/snapshot",
        )
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            schema["properties"]["delivery_record"]["$ref"],
            "#/$defs/readOnlyProbeDeliveryRecord",
        )
        delivery_contract = schema["$defs"]["readOnlyProbeDeliveryRecord"]
        self.assertEqual(
            delivery_contract["properties"]["handoff_profile"]["const"],
            "pr-readiness-read-only-probe",
        )
        self.assertEqual(
            delivery_contract["properties"]["terminal_outcome"]["const"],
            "succeeded",
        )
        self.assertEqual(
            set(delivery_contract["properties"]["terminal_reason"]["enum"]),
            set(READ_ONLY_DELIVERY_SUCCESS_MATRIX),
        )
        receiver_matrix = {}
        for branch in delivery_contract["allOf"][-1]["oneOf"]:
            properties = branch["properties"]
            reason = properties["terminal_reason"]["const"]
            evidence_properties = properties["terminal_evidence"]["properties"]
            evidence_matrix = {}
            for field in TERMINAL_EVIDENCE_FIELDS:
                field_schema = evidence_properties[field]
                evidence_matrix[field] = (
                    "required"
                    if field_schema.get("$ref") == "#/$defs/oid"
                    else field_schema["const"]
                )
            receiver_matrix[reason] = {
                "local_mutation": properties["local_mutation"]["const"],
                "commit_mode": properties["commit_mode"]["const"],
                "formal_review_required": properties["formal_review_required"]["const"],
                "terminal_evidence": evidence_matrix,
            }
        self.assertEqual(receiver_matrix, READ_ONLY_DELIVERY_SUCCESS_MATRIX)
        external_refs: list[str] = []

        def collect_external_refs(value: object) -> None:
            if isinstance(value, dict):
                reference = value.get("$ref")
                if isinstance(reference, str) and not reference.startswith("#/"):
                    external_refs.append(reference)
                for child in value.values():
                    collect_external_refs(child)
            elif isinstance(value, list):
                for child in value:
                    collect_external_refs(child)

        collect_external_refs(schema)
        self.assertEqual(external_refs, [])
        self.assertEqual(
            set(schema["properties"]["evidence"]["required"]),
            READ_ONLY_EVIDENCE_FIELDS,
        )
        evidence_definitions = {
            "pr_selection": "prSelectionEvidence",
            "pr_lifecycle": "prLifecycleEvidence",
            "ci_status": "ciStatusEvidence",
            "conversation_state": "conversationStateEvidence",
            "base_and_head": "baseAndHeadEvidence",
        }
        for field, definition in evidence_definitions.items():
            self.assertEqual(
                schema["properties"]["evidence"]["properties"][field]["$ref"],
                f"#/$defs/{definition}",
            )
            self.assertEqual(
                schema["$defs"][definition]["allOf"],
                [{"$ref": "#/$defs/nonemptyObservedEvidence"}],
            )
        ci_observation = schema["$defs"]["ciStatusEvidence"]["properties"]["observed"][
            "items"
        ]
        self.assertIn("target_identity", ci_observation["required"])
        self.assertIn("pagination", ci_observation["required"])
        self.assertIn("status_check_rollup", ci_observation["required"])
        self.assertEqual(
            ci_observation["properties"]["pagination"]["$ref"],
            "#/$defs/ciPaginationEvidence",
        )
        self.assertEqual(
            ci_observation["properties"]["status_check_rollup"]["maxItems"],
            1_000,
        )
        self.assertEqual(
            ci_observation["properties"]["status_check_rollup"]["items"]["$ref"],
            "#/$defs/statusCheckRollupEntry",
        )
        self.assertEqual(
            schema["$defs"]["ciPaginationEvidence"]["properties"]["server_total_count"][
                "maximum"
            ],
            1_000,
        )
        self.assertEqual(
            schema["$defs"]["ciPaginationEvidence"]["properties"]["pages"]["maxItems"],
            10,
        )
        self.assertEqual(
            schema["$defs"]["ciPaginationPage"]["properties"]["item_count"]["maximum"],
            100,
        )
        self.assertIn(
            "server_total_count",
            schema["$defs"]["ciPaginationPage"]["required"],
        )
        self.assertIn(
            "content_sha256",
            schema["$defs"]["ciPaginationPage"]["required"],
        )
        for definition in ("ciPaginationPage", "reviewThreadPaginationPage"):
            page_schema = schema["$defs"][definition]
            self.assertIn("snapshot_binding", page_schema["required"])
            self.assertIn("snapshot_id", page_schema["required"])
            self.assertEqual(
                page_schema["properties"]["snapshot_binding"]["$ref"],
                "#/$defs/snapshotId",
            )
            self.assertEqual(
                page_schema["properties"]["snapshot_id"]["$ref"],
                "#/$defs/observationId",
            )
        self.assertEqual(
            schema["$defs"]["ciPaginationPage"]["properties"]["content_sha256"][
                "pattern"
            ],
            "^[0-9a-f]{64}$",
        )
        self.assertEqual(
            schema["$defs"]["statusCheckRollupEntry"]["oneOf"],
            [
                {"$ref": "#/$defs/checkRunRollupEntry"},
                {"$ref": "#/$defs/statusContextRollupEntry"},
            ],
        )
        for definition in (
            "githubAppIdentity",
            "githubActorIdentity",
            "checkRunRollupEntry",
            "statusContextRollupEntry",
        ):
            self.assertIn("node_id", schema["$defs"][definition]["required"])
        self.assertEqual(
            set(
                schema["$defs"]["githubActorIdentity"]["properties"]["__typename"][
                    "enum"
                ]
            ),
            {
                "Bot",
                "EnterpriseUserAccount",
                "Mannequin",
                "Organization",
                "User",
            },
        )
        self.assertEqual(
            set(schema["$defs"]["checkRunRollupEntry"]["properties"]["status"]["enum"]),
            {
                "COMPLETED",
                "IN_PROGRESS",
                "PENDING",
                "QUEUED",
                "REQUESTED",
                "WAITING",
            },
        )
        self.assertEqual(
            set(
                schema["$defs"]["statusContextRollupEntry"]["properties"]["state"][
                    "enum"
                ]
            ),
            {"ERROR", "EXPECTED", "FAILURE", "PENDING", "SUCCESS"},
        )
        conversation_observation = schema["$defs"]["conversationStateEvidence"][
            "properties"
        ]["observed"]["items"]
        self.assertIn("review_threads", conversation_observation["required"])
        self.assertIn("pagination", conversation_observation["required"])
        self.assertEqual(
            conversation_observation["properties"]["review_threads"]["items"]["$ref"],
            "#/$defs/reviewThread",
        )
        self.assertEqual(
            conversation_observation["properties"]["pagination"]["$ref"],
            "#/$defs/reviewThreadPaginationEvidence",
        )
        self.assertEqual(
            schema["$defs"]["reviewThreadPaginationConnection"]["properties"]["field"][
                "const"
            ],
            "pullRequest.reviewThreads",
        )
        self.assertIn(
            "content_sha256",
            schema["$defs"]["reviewThreadPaginationPage"]["required"],
        )
        range_observation = schema["$defs"]["baseAndHeadEvidence"]["properties"][
            "observed"
        ]["items"]
        self.assertIn("observed_base_oid", range_observation["required"])
        self.assertIn("observed_head_oid", range_observation["required"])
        target = schema["$defs"]["target"]
        self.assertIn("provider", target["required"])
        self.assertIn("head", target["required"])
        self.assertIn("node_id", schema["$defs"]["repository"]["required"])
        self.assertIn("node_id", schema["$defs"]["pullRequest"]["required"])
        self.assertIn("base_ref", schema["$defs"]["pullRequest"]["required"])
        for definition in (
            "prLifecycleEvidence",
            "ciStatusEvidence",
            "conversationStateEvidence",
        ):
            observation = schema["$defs"][definition]["properties"]["observed"]["items"]
            self.assertIn("target_identity", observation["required"])
        self.assertEqual(
            set(schema["properties"]["actions"]["required"]),
            READ_ONLY_ACTION_FIELDS,
        )
        for field in READ_ONLY_ACTION_FIELDS:
            self.assertIs(
                schema["properties"]["actions"]["properties"][field]["const"],
                False,
            )
        self.assertIs(schema["properties"]["merge_ready"]["const"], False)
        self.assertEqual(schema["properties"]["next_handoff"]["const"], "none")

    def test_read_only_pr_report_schema_rejects_inconsistent_summaries(
        self,
    ) -> None:
        cases = {
            case["name"]: case
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        valid = copy.deepcopy(
            cases["resolved-target-snapshot"]["expected"]["terminal_result"]
        )
        validator = read_only_report_validator()
        for name, case in cases.items():
            with self.subTest(name=name):
                terminal_result = case["expected"]["terminal_result"]
                self.assertEqual(list(validator.iter_errors(terminal_result)), [])
                assert_read_only_report_contract(terminal_result)

        commit_allowed = copy.deepcopy(valid)
        commit_allowed["delivery_record"] = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"]
            == "Complete the full local workflow, then report PR readiness without remote mutations."
        )
        commit_allowed["delivery_record"]["terminal_evidence"][
            "signature_verified_head_oid"
        ] = commit_allowed["target"]["head"]["oid"]
        commit_allowed["delivery_record"]["head_sha"] = commit_allowed["target"][
            "head"
        ]["oid"]
        self.assertEqual(list(validator.iter_errors(commit_allowed)), [])
        assert_read_only_report_contract(commit_allowed)

        inconsistent: dict[str, dict[str, object]] = {}

        downgraded_commit_allowed = copy.deepcopy(commit_allowed)
        downgraded_commit_allowed["delivery_record"]["formal_review_required"] = False
        inconsistent["commit-allowed-local-gate-downgraded-review"] = (
            downgraded_commit_allowed
        )

        missing_unavailable = copy.deepcopy(valid)
        missing_unavailable["unavailable_evidence"].remove("ci-status")
        inconsistent["non-observed-without-unavailable-summary"] = missing_unavailable

        missing_blocker = copy.deepcopy(valid)
        missing_blocker["blockers"] = [
            blocker
            for blocker in missing_blocker["blockers"]
            if blocker["evidence"] != "ci-status"
        ]
        inconsistent["non-observed-without-blocker"] = missing_blocker

        observed_with_summaries = copy.deepcopy(valid)
        observed_with_summaries["evidence"]["ci_status"] = {
            "status": "observed",
            "report_binding": valid["report_id"],
            "target_binding": valid["target"]["binding_id"],
            "snapshot_binding": valid["snapshot"]["binding_id"],
            "observed": [
                {
                    "state": "success",
                    "total": 1,
                    "successful": 1,
                    "failed": 0,
                    "pending": 0,
                    "cancelled": 0,
                    "status_check_rollup": [
                        check_run_rollup(
                            database_id=2001,
                            name="tests",
                            status="COMPLETED",
                            conclusion="SUCCESS",
                        )
                    ],
                }
            ],
        }
        inconsistent["observed-with-unavailable-and-blocker"] = observed_with_summaries

        wrong_blocker_target = copy.deepcopy(valid)
        wrong_blocker_target["blockers"][0]["evidence"] = "pr-selection"
        inconsistent["blocker-targets-observed-evidence"] = wrong_blocker_target

        duplicate_blocker = copy.deepcopy(valid)
        duplicate_blocker["blockers"].append(
            {
                "evidence": "ci-status",
                "code": "second-ci-blocker",
                "detail": "A second blocker must not summarize the same evidence.",
            }
        )
        inconsistent["duplicate-blocker-for-one-evidence-kind"] = duplicate_blocker

        stale_snapshot = copy.deepcopy(valid)
        stale_snapshot["snapshot"]["freshness"] = "stale"
        inconsistent["stale-report-snapshot"] = stale_snapshot

        empty_observed = copy.deepcopy(valid)
        empty_observed["evidence"]["pr_selection"]["observed"] = []
        inconsistent["observed-status-without-record"] = empty_observed

        extra_observed_field = copy.deepcopy(valid)
        extra_observed_field["evidence"]["pr_lifecycle"]["observed"][0]["summary"] = (
            "open"
        )
        inconsistent["observed-record-with-free-form-field"] = extra_observed_field

        for name, candidate in inconsistent.items():
            with self.subTest(name=name):
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

        schema = validator.schema
        self.assertEqual(len(schema["allOf"]), len(READ_ONLY_EVIDENCE_FIELDS) + 2)
        blocker_schema = schema["properties"]["blockers"]["items"]
        self.assertEqual(
            set(blocker_schema["required"]),
            {"evidence", "code", "detail"},
        )
        self.assertEqual(
            set(schema["$defs"]["evidenceName"]["enum"]),
            {
                "pr-selection",
                "pr-lifecycle",
                "ci-status",
                "conversation-state",
                "base-and-head",
            },
        )

    def test_read_only_pr_report_binds_canonical_pr_url_to_target(self) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        valid = cases["resolved-target-snapshot"]
        validator = read_only_report_validator()
        canonical = "https://github.com/Joey-Tools/codex-review-workflows/pull/42"
        self.assertEqual(valid["target"]["pull_request"]["url"], canonical)
        self.assertEqual(list(validator.iter_errors(valid)), [])
        validate_read_only_report_semantics(valid)

        invalid_urls = {
            "userinfo": (
                "https://attacker@github.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "port": (
                "https://github.com:443/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "query": f"{canonical}?repository=other",
            "fragment": f"{canonical}#other",
            "percent-encoded-owner": (
                "https://github.com/%4aoey-Tools/codex-review-workflows/pull/42"
            ),
            "percent-encoded-slash": (
                "https://github.com/Joey-Tools%2Fother/codex-review-workflows/pull/42"
            ),
            "evil-prefix-host": (
                "https://evil-github.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "suffix-host": (
                "https://github.com.evil.example/"
                "Joey-Tools/codex-review-workflows/pull/42"
            ),
            "other-owner": (
                "https://github.com/Other-Owner/codex-review-workflows/pull/42"
            ),
            "other-repository": ("https://github.com/Joey-Tools/other/pull/42"),
            "other-number": (
                "https://github.com/Joey-Tools/codex-review-workflows/pull/43"
            ),
            "path-traversal": (
                "https://github.com/Joey-Tools/codex-review-workflows/../other/pull/42"
            ),
            "confusable-host": (
                "https://g\u0456thub.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "uppercase-host": (
                "https://GitHub.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "trailing-slash": f"{canonical}/",
        }
        for name, url in invalid_urls.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(valid)
                candidate["target"]["pull_request"]["url"] = url
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

    def test_read_only_pr_report_repository_components_are_canonical(
        self,
    ) -> None:
        valid = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "resolved-target-snapshot"
        )
        validator = read_only_report_validator()
        invalid_components = {
            ("host", "GitHub.com"),
            ("host", "github..com"),
            ("host", "-github.com"),
            ("host", "github.com-"),
            ("host", "github_com"),
            ("owner", "-Joey-Tools"),
            ("owner", "Joey--Tools"),
            ("owner", "Joey_Tools"),
            ("owner", "Joey.Tools"),
            ("owner", "Joey\u2010Tools"),
            ("name", ".."),
            ("name", "repo/name"),
            ("name", "repo%2Fname"),
            ("name", "r\u0435po"),
        }
        for field, value in invalid_components:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(valid)
                candidate["target"]["repository"][field] = value
                candidate["target"]["pull_request"]["url"] = (
                    f"https://{candidate['target']['repository']['host']}/"
                    f"{candidate['target']['repository']['owner']}/"
                    f"{candidate['target']['repository']['name']}/pull/42"
                )
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)

    def test_ci_rollup_requires_complete_identity_bound_pagination(self) -> None:
        base = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()

        multipage = copy.deepcopy(base)
        multipage_observed = multipage["evidence"]["ci_status"]["observed"][0]
        bind_ci_pagination(multipage, multipage_observed, page_size=1)
        self.assertEqual(list(validator.iter_errors(multipage)), [])
        validate_read_only_report_semantics(multipage)
        self.assertEqual(len(multipage_observed["pagination"]["pages"]), 2)
        self.assertIs(
            multipage_observed["pagination"]["pages"][-1]["page_info"]["has_next_page"],
            False,
        )

        no_checks = copy.deepcopy(base)
        no_checks_observed = no_checks["evidence"]["ci_status"]["observed"][0]
        no_checks_observed.update(
            {
                "state": "no-checks",
                "total": 0,
                "successful": 0,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [],
            }
        )
        bind_ci_pagination(no_checks, no_checks_observed)
        self.assertEqual(list(validator.iter_errors(no_checks)), [])
        validate_read_only_report_semantics(no_checks)

        for hidden_bucket in ("failure", "pending"):
            candidate = copy.deepcopy(base)
            observed = candidate["evidence"]["ci_status"]["observed"][0]
            observed.update(
                {
                    "state": "success",
                    "total": 1,
                    "successful": 1,
                    "failed": 0,
                    "pending": 0,
                    "cancelled": 0,
                    "status_check_rollup": [
                        check_run_rollup(
                            database_id=9001,
                            name="first-page-green",
                            status="COMPLETED",
                            conclusion="SUCCESS",
                        )
                    ],
                }
            )
            bind_ci_pagination(candidate, observed)
            connection = observed["pagination"]["connection"]
            first_page = observed["pagination"]["pages"][0]
            first_page["page_info"]["has_next_page"] = True
            observed["pagination"]["server_total_count"] = 2
            first_page["server_total_count"] = 2
            first_page["content_sha256"] = canonical_page_digest(
                "ci-status",
                {
                    "connection": connection,
                    "snapshot_binding": first_page["snapshot_binding"],
                    "snapshot_id": first_page["snapshot_id"],
                    "server_total_count": 2,
                    "page_index": 1,
                    "request_after": None,
                    "item_count": 1,
                    "page_info": first_page["page_info"],
                    "items": observed["status_check_rollup"],
                },
            )
            second_page = {
                "connection": copy.deepcopy(connection),
                "snapshot_binding": candidate["snapshot"]["binding_id"],
                "snapshot_id": candidate["snapshot"]["snapshot_id"],
                "page_index": 2,
                "request_after": first_page["page_info"]["end_cursor"],
                "item_count": 1,
                "server_total_count": 2,
                "page_info": {
                    "end_cursor": f"HIDDEN_{hidden_bucket.upper()}_CURSOR",
                    "has_next_page": False,
                },
            }
            second_page["content_sha256"] = canonical_page_digest(
                "ci-status",
                {
                    "connection": connection,
                    "snapshot_binding": second_page["snapshot_binding"],
                    "snapshot_id": second_page["snapshot_id"],
                    "server_total_count": 2,
                    "page_index": 2,
                    "request_after": second_page["request_after"],
                    "item_count": 1,
                    "page_info": second_page["page_info"],
                    "items": [],
                },
            )
            observed["pagination"]["pages"].append(second_page)
            with self.subTest(hidden_later_page=hidden_bucket):
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                with self.assertRaisesRegex(ValueError, "server totalCount"):
                    validate_read_only_report_semantics(candidate)

        count_mismatch = copy.deepcopy(base)
        observed = count_mismatch["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["server_total_count"] = 3
        self.assertEqual(list(validator.iter_errors(count_mismatch)), [])
        with self.assertRaisesRegex(ValueError, "item counts"):
            validate_read_only_report_semantics(count_mismatch)

        cursor_drift = copy.deepcopy(multipage)
        observed = cursor_drift["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["pages"][1]["request_after"] = "WRONG_CURSOR"
        self.assertEqual(list(validator.iter_errors(cursor_drift)), [])
        with self.assertRaisesRegex(ValueError, "request cursor drifted"):
            validate_read_only_report_semantics(cursor_drift)

        page_connection_drift = copy.deepcopy(multipage)
        observed = page_connection_drift["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["pages"][1]["connection"]["head_oid"] = "c" * 40
        self.assertEqual(list(validator.iter_errors(page_connection_drift)), [])
        with self.assertRaisesRegex(ValueError, "changed connection identity"):
            validate_read_only_report_semantics(page_connection_drift)

        for field, replacement in (
            ("repository_node_id", "REPO_OTHER"),
            ("pull_request_node_id", "PR_OTHER"),
            ("head_oid", "c" * 40),
        ):
            identity_drift = copy.deepcopy(base)
            observed = identity_drift["evidence"]["ci_status"]["observed"][0]
            observed["pagination"]["connection"][field] = replacement
            for page in observed["pagination"]["pages"]:
                page["connection"][field] = replacement
            with self.subTest(connection_identity=field):
                self.assertEqual(list(validator.iter_errors(identity_drift)), [])
                with self.assertRaisesRegex(ValueError, "exact PR head"):
                    validate_read_only_report_semantics(identity_drift)

        incomplete_final = copy.deepcopy(base)
        observed = incomplete_final["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["pages"][-1]["page_info"]["has_next_page"] = True
        self.assertEqual(list(validator.iter_errors(incomplete_final)), [])
        with self.assertRaisesRegex(ValueError, "final CI page"):
            validate_read_only_report_semantics(incomplete_final)

        content_drift = copy.deepcopy(base)
        observed = content_drift["evidence"]["ci_status"]["observed"][0]
        observed["status_check_rollup"][0]["name"] = "tampered-after-page-capture"
        self.assertEqual(list(validator.iter_errors(content_drift)), [])
        with self.assertRaisesRegex(ValueError, "content digest"):
            validate_read_only_report_semantics(content_drift)

        ordering_drift = copy.deepcopy(base)
        observed = ordering_drift["evidence"]["ci_status"]["observed"][0]
        observed["status_check_rollup"].reverse()
        self.assertEqual(list(validator.iter_errors(ordering_drift)), [])
        with self.assertRaisesRegex(ValueError, "ordered flat-rollup slice"):
            validate_read_only_report_semantics(ordering_drift)

        page_total_drift = copy.deepcopy(base)
        observed = page_total_drift["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["pages"][0]["server_total_count"] += 1
        self.assertEqual(list(validator.iter_errors(page_total_drift)), [])
        with self.assertRaisesRegex(ValueError, "mid-pagination total drift"):
            validate_read_only_report_semantics(page_total_drift)

        for field, replacement in (
            ("snapshot_binding", f"snapshot:{'e' * 32}"),
            ("snapshot_id", f"observation:{'f' * 32}"),
        ):
            snapshot_drift = copy.deepcopy(base)
            observed = snapshot_drift["evidence"]["ci_status"]["observed"][0]
            page = observed["pagination"]["pages"][0]
            page[field] = replacement
            page["content_sha256"] = canonical_page_digest(
                "ci-status",
                {
                    "connection": observed["pagination"]["connection"],
                    "snapshot_binding": page["snapshot_binding"],
                    "snapshot_id": page["snapshot_id"],
                    "server_total_count": observed["pagination"]["server_total_count"],
                    "page_index": page["page_index"],
                    "request_after": page["request_after"],
                    "item_count": page["item_count"],
                    "page_info": page["page_info"],
                    "items": observed["status_check_rollup"],
                },
            )
            with self.subTest(page_snapshot_identity=field):
                self.assertEqual(list(validator.iter_errors(snapshot_drift)), [])
                with self.assertRaisesRegex(
                    ValueError,
                    "changed report snapshot identity",
                ):
                    validate_read_only_report_semantics(snapshot_drift)

        beyond_legacy_truncation = copy.deepcopy(base)
        observed = beyond_legacy_truncation["evidence"]["ci_status"]["observed"][0]
        rollup = [
            check_run_rollup(
                database_id=10_000 + index,
                node_id=f"CHECK_RUN_COMPLETE_{index}",
                name=f"check-{index}",
                status="COMPLETED",
                conclusion="SUCCESS",
            )
            for index in range(257)
        ]
        observed.update(
            {
                "state": "success",
                "total": len(rollup),
                "successful": len(rollup),
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": rollup,
            }
        )
        bind_ci_pagination(beyond_legacy_truncation, observed)
        self.assertEqual(list(validator.iter_errors(beyond_legacy_truncation)), [])
        validate_read_only_report_semantics(beyond_legacy_truncation)

        over_cap = copy.deepcopy(base)
        observed = over_cap["evidence"]["ci_status"]["observed"][0]
        observed["pagination"]["server_total_count"] = 1_001
        self.assertTrue(list(validator.iter_errors(over_cap)))
        with self.assertRaisesRegex(ValueError, "bounded complete-rollup cap"):
            validate_read_only_report_semantics(over_cap)

    def test_review_threads_require_complete_identity_bound_pagination(
        self,
    ) -> None:
        base = copy.deepcopy(
            next(
                case["expected"]["terminal_result"]
                for case in fixture_cases(
                    READ_ONLY_PR_PROBE_CASES,
                    "read-only-pr-probe",
                )
                if case["name"] == "selected-pr-base-head-blocked"
            )
        )
        validator = read_only_report_validator()
        observed = base["evidence"]["conversation_state"]["observed"][0]
        threads = [
            {
                "node_id": f"REVIEW_THREAD_COMPLETE_{index}",
                "is_resolved": index != 100,
            }
            for index in range(101)
        ]
        observed.update(
            {
                "total_threads": len(threads),
                "unresolved_threads": 1,
                "review_threads": threads,
            }
        )
        bind_review_thread_pagination(base, observed)
        self.assertEqual(list(validator.iter_errors(base)), [])
        validate_read_only_report_semantics(base)
        self.assertEqual(len(observed["pagination"]["pages"]), 2)
        self.assertFalse(observed["review_threads"][-1]["is_resolved"])

        hidden_later_unresolved = copy.deepcopy(base)
        hidden = hidden_later_unresolved["evidence"]["conversation_state"]["observed"][
            0
        ]
        hidden["unresolved_threads"] = 0
        self.assertEqual(list(validator.iter_errors(hidden_later_unresolved)), [])
        with self.assertRaisesRegex(ValueError, "unresolved_threads"):
            validate_read_only_report_semantics(hidden_later_unresolved)

        incomplete = copy.deepcopy(base)
        incomplete_observed = incomplete["evidence"]["conversation_state"]["observed"][
            0
        ]
        incomplete_observed["pagination"]["pages"][-1]["page_info"]["has_next_page"] = (
            True
        )
        self.assertEqual(list(validator.iter_errors(incomplete)), [])
        with self.assertRaisesRegex(ValueError, "final review-thread page"):
            validate_read_only_report_semantics(incomplete)

        content_drift = copy.deepcopy(base)
        content_observed = content_drift["evidence"]["conversation_state"]["observed"][
            0
        ]
        content_observed["review_threads"][-1]["is_resolved"] = True
        content_observed["unresolved_threads"] = 0
        self.assertEqual(list(validator.iter_errors(content_drift)), [])
        with self.assertRaisesRegex(ValueError, "content digest"):
            validate_read_only_report_semantics(content_drift)

        total_drift = copy.deepcopy(base)
        total_observed = total_drift["evidence"]["conversation_state"]["observed"][0]
        total_observed["pagination"]["pages"][1]["server_total_count"] += 1
        self.assertEqual(list(validator.iter_errors(total_drift)), [])
        with self.assertRaisesRegex(ValueError, "mid-pagination total drift"):
            validate_read_only_report_semantics(total_drift)

        duplicate = copy.deepcopy(base)
        duplicate_observed = duplicate["evidence"]["conversation_state"]["observed"][0]
        duplicate_observed["review_threads"][1]["node_id"] = duplicate_observed[
            "review_threads"
        ][0]["node_id"]
        bind_review_thread_pagination(duplicate, duplicate_observed)
        self.assertTrue(list(validator.iter_errors(duplicate)))
        with self.assertRaisesRegex(ValueError, "globally unique"):
            validate_read_only_report_semantics(duplicate)

    def test_read_only_pr_report_preserves_and_maps_all_ci_provider_states(
        self,
    ) -> None:
        base = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()
        conclusion_buckets = {
            "SUCCESS": "success",
            "NEUTRAL": "success",
            "SKIPPED": "success",
            "FAILURE": "failure",
            "TIMED_OUT": "failure",
            "ACTION_REQUIRED": "failure",
            "STALE": "failure",
            "STARTUP_FAILURE": "failure",
            "CANCELLED": "cancelled",
        }
        for database_id, (conclusion, bucket) in enumerate(
            conclusion_buckets.items(),
            start=3001,
        ):
            with self.subTest(conclusion=conclusion):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": bucket,
                        "total": 1,
                        "successful": int(bucket == "success"),
                        "failed": int(bucket == "failure"),
                        "pending": 0,
                        "cancelled": int(bucket == "cancelled"),
                        "status_check_rollup": [
                            check_run_rollup(
                                database_id=database_id,
                                name="tests",
                                status="COMPLETED",
                                conclusion=conclusion,
                            )
                        ],
                    }
                )
                bind_ci_pagination(candidate, observed)
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                validate_read_only_report_semantics(candidate)
                self.assertEqual(
                    observed["status_check_rollup"][0]["conclusion"],
                    conclusion,
                )

        for status in (
            "QUEUED",
            "IN_PROGRESS",
            "REQUESTED",
            "WAITING",
            "PENDING",
        ):
            with self.subTest(status=status):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": "pending",
                        "total": 1,
                        "successful": 0,
                        "failed": 0,
                        "pending": 1,
                        "cancelled": 0,
                        "status_check_rollup": [
                            check_run_rollup(
                                database_id=4001,
                                name="tests",
                                status=status,
                                conclusion=None,
                            )
                        ],
                    }
                )
                bind_ci_pagination(candidate, observed)
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                validate_read_only_report_semantics(candidate)

        status_context_buckets = {
            "SUCCESS": "success",
            "FAILURE": "failure",
            "ERROR": "failure",
            "PENDING": "pending",
            "EXPECTED": "pending",
        }
        for state, bucket in status_context_buckets.items():
            with self.subTest(status_context_state=state):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": bucket,
                        "total": 1,
                        "successful": int(bucket == "success"),
                        "failed": int(bucket == "failure"),
                        "pending": int(bucket == "pending"),
                        "cancelled": 0,
                        "status_check_rollup": [
                            status_context_rollup(
                                context="required/legacy-commit-status",
                                state=state,
                            )
                        ],
                    }
                )
                bind_ci_pagination(candidate, observed)
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                validate_read_only_report_semantics(candidate)

        nullable_database_ids = copy.deepcopy(base)
        nullable_observed = nullable_database_ids["evidence"]["ci_status"]["observed"][
            0
        ]
        nullable_observed.update(
            {
                "state": "success",
                "total": 1,
                "successful": 1,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=None,
                        node_id="CHECK_RUN_NODE_ONLY",
                        name="node-only",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                        app_database_id=None,
                        app_node_id="APP_NODE_ONLY",
                        app_slug="node-only-provider",
                    )
                ],
            }
        )
        bind_ci_pagination(nullable_database_ids, nullable_observed)
        self.assertEqual(list(validator.iter_errors(nullable_database_ids)), [])
        validate_read_only_report_semantics(nullable_database_ids)

        mixed = copy.deepcopy(base)
        mixed_observed = mixed["evidence"]["ci_status"]["observed"][0]
        mixed_observed.update(
            {
                "state": "failure",
                "total": 4,
                "successful": 1,
                "failed": 1,
                "pending": 1,
                "cancelled": 1,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=5001,
                        name="required",
                        status="COMPLETED",
                        conclusion="NEUTRAL",
                    ),
                    check_run_rollup(
                        database_id=6001,
                        name="required",
                        status="COMPLETED",
                        conclusion="STALE",
                        app_database_id=40001,
                        app_slug="quality-gate",
                        app_node_id="APP_40001",
                    ),
                    status_context_rollup(
                        context="required",
                        state="EXPECTED",
                    ),
                    check_run_rollup(
                        database_id=5002,
                        name="e2e",
                        status="COMPLETED",
                        conclusion="CANCELLED",
                    ),
                ],
            }
        )
        bind_ci_pagination(mixed, mixed_observed)
        self.assertEqual(list(validator.iter_errors(mixed)), [])
        validate_read_only_report_semantics(mixed)

    def test_read_only_pr_report_ci_fails_closed_on_identity_or_state_drift(
        self,
    ) -> None:
        base = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()
        invalid_checks = {
            "unknown-typename": {
                "__typename": "WorkflowRun",
            },
            "unknown-check-run-status": check_run_rollup(
                database_id=7001,
                name="tests",
                status="UNKNOWN",
                conclusion=None,
            ),
            "unknown-completed-conclusion": check_run_rollup(
                database_id=7002,
                name="tests",
                status="COMPLETED",
                conclusion="UNKNOWN",
            ),
            "nonterminal-conclusion": check_run_rollup(
                database_id=7003,
                name="tests",
                status="IN_PROGRESS",
                conclusion="SUCCESS",
            ),
            "missing-completed-conclusion": check_run_rollup(
                database_id=7004,
                name="tests",
                status="COMPLETED",
                conclusion=None,
            ),
            "lowercase-provider-state": check_run_rollup(
                database_id=7005,
                name="tests",
                status="completed",
                conclusion="success",
            ),
            "unknown-status-context-state": status_context_rollup(
                context="required/legacy-commit-status",
                state="UNKNOWN",
            ),
        }
        missing_app_id = check_run_rollup(
            database_id=7006,
            name="tests",
            status="COMPLETED",
            conclusion="SUCCESS",
        )
        del missing_app_id["app"]["database_id"]
        invalid_checks["missing-app-database-id"] = missing_app_id
        missing_app_node_id = check_run_rollup(
            database_id=7007,
            name="tests",
            status="COMPLETED",
            conclusion="SUCCESS",
        )
        del missing_app_node_id["app"]["node_id"]
        invalid_checks["missing-app-node-id"] = missing_app_node_id
        missing_check_run_node_id = check_run_rollup(
            database_id=7008,
            name="tests",
            status="COMPLETED",
            conclusion="SUCCESS",
        )
        del missing_check_run_node_id["node_id"]
        invalid_checks["missing-check-run-node-id"] = missing_check_run_node_id
        malformed_app_slug = check_run_rollup(
            database_id=7009,
            name="tests",
            status="COMPLETED",
            conclusion="SUCCESS",
        )
        malformed_app_slug["app"]["slug"] = "GitHub Actions"
        invalid_checks["malformed-app-slug"] = malformed_app_slug
        missing_creator_node_id = status_context_rollup(
            context="required/legacy-commit-status",
            state="SUCCESS",
        )
        del missing_creator_node_id["creator"]["node_id"]
        invalid_checks["missing-creator-node-id"] = missing_creator_node_id
        missing_status_context_node_id = status_context_rollup(
            context="required/legacy-commit-status",
            state="SUCCESS",
        )
        del missing_status_context_node_id["node_id"]
        invalid_checks["missing-status-context-node-id"] = (
            missing_status_context_node_id
        )
        malformed_creator_type = status_context_rollup(
            context="required/legacy-commit-status",
            state="SUCCESS",
            creator_typename="Repository",
        )
        invalid_checks["malformed-creator-typename"] = malformed_creator_type

        for name, check in invalid_checks.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": "pending",
                        "total": 1,
                        "successful": 0,
                        "failed": 0,
                        "pending": 1,
                        "cancelled": 0,
                        "status_check_rollup": [check],
                    }
                )
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)

        duplicate_check_run_identity = copy.deepcopy(base)
        observed = duplicate_check_run_identity["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=8001,
                        name="lint",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                    check_run_rollup(
                        database_id=8001,
                        name="tests",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                ],
            }
        )
        self.assertEqual(
            list(validator.iter_errors(duplicate_check_run_identity)),
            [],
        )
        with self.assertRaisesRegex(ValueError, "stable identities"):
            validate_read_only_report_semantics(duplicate_check_run_identity)

        duplicate_status_context_identity = copy.deepcopy(base)
        observed = duplicate_status_context_identity["evidence"]["ci_status"][
            "observed"
        ][0]
        observed.update(
            {
                "state": "pending",
                "total": 2,
                "successful": 1,
                "failed": 0,
                "pending": 1,
                "cancelled": 0,
                "status_check_rollup": [
                    status_context_rollup(
                        context="required/legacy-commit-status",
                        state="SUCCESS",
                    ),
                    status_context_rollup(
                        context="required/legacy-commit-status",
                        state="EXPECTED",
                    ),
                ],
            }
        )
        self.assertEqual(
            list(validator.iter_errors(duplicate_status_context_identity)),
            [],
        )
        with self.assertRaisesRegex(ValueError, "stable identities"):
            validate_read_only_report_semantics(duplicate_status_context_identity)

        inconsistent_app_identity = copy.deepcopy(base)
        observed = inconsistent_app_identity["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=8101,
                        name="lint",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                    check_run_rollup(
                        database_id=8102,
                        name="tests",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                        app_slug="github-actions-renamed",
                    ),
                ],
            }
        )
        self.assertEqual(list(validator.iter_errors(inconsistent_app_identity)), [])
        with self.assertRaisesRegex(ValueError, "provider identity"):
            validate_read_only_report_semantics(inconsistent_app_identity)

        inconsistent_creator_identity = copy.deepcopy(base)
        observed = inconsistent_creator_identity["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    status_context_rollup(
                        context="required/lint",
                        state="SUCCESS",
                        node_id="STATUS_CONTEXT_LINT",
                    ),
                    status_context_rollup(
                        context="required/tests",
                        state="SUCCESS",
                        creator_login="renamed-ci[bot]",
                        node_id="STATUS_CONTEXT_TESTS",
                    ),
                ],
            }
        )
        self.assertEqual(
            list(validator.iter_errors(inconsistent_creator_identity)),
            [],
        )
        with self.assertRaisesRegex(ValueError, "provider identity"):
            validate_read_only_report_semantics(inconsistent_creator_identity)

        status_context_node_conflict = copy.deepcopy(base)
        observed = status_context_node_conflict["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    status_context_rollup(
                        context="required/lint",
                        state="SUCCESS",
                        creator_node_id="ACTOR_PRIMARY",
                        node_id="STATUS_CONTEXT_REUSED_NODE",
                    ),
                    status_context_rollup(
                        context="required/tests",
                        state="SUCCESS",
                        creator_node_id="ACTOR_SECONDARY",
                        creator_login="secondary-ci[bot]",
                        node_id="STATUS_CONTEXT_REUSED_NODE",
                    ),
                ],
            }
        )
        bind_ci_pagination(status_context_node_conflict, observed)
        self.assertEqual(list(validator.iter_errors(status_context_node_conflict)), [])
        with self.assertRaisesRegex(
            ValueError,
            "StatusContext Node ID maps to inconsistent creator/context identity",
        ):
            validate_read_only_report_semantics(status_context_node_conflict)

        app_database_collision = copy.deepcopy(base)
        observed = app_database_collision["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=8201,
                        node_id="CHECK_RUN_APP_A",
                        name="lint",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                        app_database_id=9901,
                        app_node_id="APP_NODE_A",
                        app_slug="provider-a",
                    ),
                    check_run_rollup(
                        database_id=8202,
                        node_id="CHECK_RUN_APP_B",
                        name="tests",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                        app_database_id=9901,
                        app_node_id="APP_NODE_B",
                        app_slug="provider-b",
                    ),
                ],
            }
        )
        self.assertEqual(list(validator.iter_errors(app_database_collision)), [])
        with self.assertRaisesRegex(ValueError, "App database ID"):
            validate_read_only_report_semantics(app_database_collision)

        check_run_database_collision = copy.deepcopy(base)
        observed = check_run_database_collision["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=8301,
                        node_id="CHECK_RUN_NODE_A",
                        name="lint",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                    check_run_rollup(
                        database_id=8301,
                        node_id="CHECK_RUN_NODE_B",
                        name="tests",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                ],
            }
        )
        self.assertEqual(
            list(validator.iter_errors(check_run_database_collision)),
            [],
        )
        with self.assertRaisesRegex(ValueError, "CheckRun database ID"):
            validate_read_only_report_semantics(check_run_database_collision)

        check_run_node_collision = copy.deepcopy(base)
        observed = check_run_node_collision["evidence"]["ci_status"]["observed"][0]
        observed.update(
            {
                "state": "success",
                "total": 2,
                "successful": 2,
                "failed": 0,
                "pending": 0,
                "cancelled": 0,
                "status_check_rollup": [
                    check_run_rollup(
                        database_id=8401,
                        node_id="CHECK_RUN_REUSED_NODE",
                        name="lint",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                    check_run_rollup(
                        database_id=8402,
                        node_id="CHECK_RUN_REUSED_NODE",
                        name="tests",
                        status="COMPLETED",
                        conclusion="SUCCESS",
                    ),
                ],
            }
        )
        self.assertEqual(list(validator.iter_errors(check_run_node_collision)), [])
        with self.assertRaisesRegex(ValueError, "CheckRun Node ID"):
            validate_read_only_report_semantics(check_run_node_collision)

    def test_read_only_pr_report_uses_real_staged_targets(self) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        no_match = cases["pre-target-no-match"]
        selection_blocked = cases["pre-target-selection-blocked"]
        range_blocked = cases["selected-pr-base-head-blocked"]

        self.assertEqual(no_match["target"]["state"], "pre-target")
        self.assertNotIn("pull_request", no_match["target"])
        self.assertNotIn("base", no_match["target"])
        self.assertIn("provider", no_match["target"])
        self.assertIn("repository", no_match["target"])
        self.assertIn("head", no_match["target"])
        self.assertEqual(selection_blocked["terminal_state"], "pre-target-blocked")
        self.assertNotIn("pull_request", selection_blocked["target"])
        self.assertNotIn("base", selection_blocked["target"])
        self.assertIn("head", selection_blocked["target"])
        self.assertEqual(
            range_blocked["terminal_state"],
            "target-resolution-blocked",
        )
        self.assertEqual(range_blocked["target"]["state"], "pr-selected")
        self.assertIn("pull_request", range_blocked["target"])
        self.assertNotIn("base", range_blocked["target"])
        self.assertIn("head", range_blocked["target"])

    def test_read_only_pr_report_binding_generator_is_instance_unique(self) -> None:
        first = new_read_only_report_bindings()
        second = new_read_only_report_bindings()
        self.assertEqual(
            set(first),
            {
                "report_id",
                "target_binding",
                "snapshot_binding",
                "snapshot_id",
            },
        )
        self.assertEqual(len(set(first.values())), 4)
        self.assertTrue(set(first.values()).isdisjoint(second.values()))
        for field, prefix in (
            ("report_id", "report:"),
            ("target_binding", "target:"),
            ("snapshot_binding", "snapshot:"),
            ("snapshot_id", "observation:"),
        ):
            with self.subTest(field=field):
                self.assertTrue(first[field].startswith(prefix))
                self.assertEqual(len(first[field]), len(prefix) + 32)

        repeated = "a" * 32
        runtime_secrets = new_read_only_report_bindings.__globals__["secrets"]
        with mock.patch.object(
            runtime_secrets,
            "token_hex",
            side_effect=[
                repeated,
                repeated,
                "b" * 32,
                "c" * 32,
                "d" * 32,
            ],
        ) as token_hex:
            collision_recovered = new_read_only_report_bindings()
        self.assertEqual(token_hex.call_count, 5)
        self.assertEqual(
            len({value.split(":", 1)[1] for value in collision_recovered.values()}),
            4,
        )
        binding_attempts = new_read_only_report_bindings.__globals__[
            "MAX_BINDING_ATTEMPTS"
        ]
        with mock.patch.object(
            runtime_secrets,
            "token_hex",
            return_value=repeated,
        ) as token_hex:
            with self.assertRaisesRegex(RuntimeError, "unique report bindings"):
                new_read_only_report_bindings()
        self.assertEqual(token_hex.call_count, binding_attempts + 1)

        with mock.patch.dict(
            READ_ONLY_PR_REPORT_GLOBALS,
            {
                "new_bindings": mock.Mock(
                    side_effect=OSError(
                        errno.EIO,
                        "entropy failure",
                        "untrusted\npath" * 1_000,
                    )
                )
            },
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                return_code = read_only_report_main(["new-bindings"])
        self.assertEqual(return_code, 2)
        rejection = json.loads(stdout.getvalue())
        self.assertEqual(rejection["classification"], "rejected")
        self.assertEqual(rejection["error"], "report binding generation failed (EIO)")

    def test_read_only_pr_report_path_reads_are_descriptor_safe(self) -> None:
        runtime_os = read_only_report_payload.__globals__["os"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "report.json"
            valid.write_bytes(b"{}")

            with mock.patch.object(runtime_os, "open", wraps=os.open) as open_mock:
                self.assertEqual(read_only_report_payload(str(valid)), {})
            flags = open_mock.call_args.args[1]
            for required_flag in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                self.assertEqual(flags & required_flag, required_flag)

            with mock.patch.object(runtime_os, "O_NOFOLLOW", None):
                with self.assertRaisesRegex(ValueError, "open is unavailable"):
                    read_only_report_payload(str(valid))

            missing = root / "missing.json"
            with self.assertRaisesRegex(ValueError, "missing at descriptor admission"):
                read_only_report_payload(str(missing))

            with mock.patch.object(
                runtime_os,
                "open",
                side_effect=PermissionError(
                    errno.EACCES,
                    "denied",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(ValueError, r"open failed \(EACCES\)"):
                    read_only_report_payload(str(valid))

            symlink = root / "report-link.json"
            symlink.symlink_to(valid)
            with self.assertRaisesRegex(ValueError, r"open failed \(ELOOP\)"):
                read_only_report_payload(str(symlink))

            fifo = root / "report.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_only_report_payload(str(fifo))

            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(READ_ONLY_REPORT_MAX_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                read_only_report_payload(str(oversized))

            with mock.patch.object(
                runtime_os,
                "read",
                side_effect=[b"{}", b"", b"[]", b""],
            ):
                with self.assertRaisesRegex(ValueError, "content changed"):
                    read_only_report_payload(str(valid))

            path_info = os.stat(valid, follow_symlinks=False)
            replaced_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino + 1,
                st_mode=path_info.st_mode,
                st_size=path_info.st_size,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=replaced_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path identity changed"):
                    read_only_report_payload(str(valid))

            nonregular_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino,
                st_mode=stat.S_IFIFO | 0o600,
                st_size=path_info.st_size,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=nonregular_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path identity changed"):
                    read_only_report_payload(str(valid))

            oversized_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino,
                st_mode=path_info.st_mode,
                st_size=READ_ONLY_REPORT_MAX_BYTES + 1,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=oversized_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path size changed"):
                    read_only_report_payload(str(valid))

            with mock.patch.object(
                runtime_os,
                "stat",
                side_effect=FileNotFoundError(
                    errno.ENOENT,
                    "gone",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(ValueError, "disappeared"):
                    read_only_report_payload(str(valid))

            with mock.patch.object(
                runtime_os,
                "stat",
                side_effect=PermissionError(
                    errno.EACCES,
                    "denied",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    r"final revalidation failed \(EACCES\)",
                ):
                    read_only_report_payload(str(valid))

        class FakeStdin:
            def __init__(self, payload: bytes) -> None:
                self.buffer = io.BytesIO(payload)

        runtime_sys = read_only_report_payload.__globals__["sys"]
        with mock.patch.object(
            runtime_sys,
            "stdin",
            FakeStdin(b"x" * (READ_ONLY_REPORT_MAX_BYTES + 1)),
        ):
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                read_only_report_payload("-")
        self.assertIn(
            "caller's transport",
            read_only_report_payload.__doc__ or "",
        )

    def test_read_only_pr_report_json_and_errors_are_bounded_and_strict(
        self,
    ) -> None:
        nested = (
            '{"value":' * (READ_ONLY_REPORT_MAX_DEPTH + 1)
            + "0"
            + "}" * (READ_ONLY_REPORT_MAX_DEPTH + 1)
        ).encode("utf-8")
        too_many_nodes = (
            '{"values":['
            + ",".join("0" for _ in range(READ_ONLY_REPORT_MAX_NODES))
            + "]}"
        ).encode("utf-8")
        invalid_payloads = {
            "invalid-utf8": b'{"value":"\xff"}',
            "malformed-json": b'{"value":',
            "duplicate-key": b'{"value":1,"value":2}',
            "nonfinite-constant": b'{"value":NaN}',
            "nonfinite-exponent": b'{"value":1e9999}',
            "non-object-root": b"[]",
            "oversized-integer": (
                b'{"value":' + b"9" * (READ_ONLY_REPORT_MAX_INTEGER_DIGITS + 1) + b"}"
            ),
            "excessive-depth": nested,
            "excessive-nodes": too_many_nodes,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in invalid_payloads.items():
                with self.subTest(payload=name):
                    path = root / f"{name}.json"
                    path.write_bytes(payload)
                    with self.assertRaises(
                        (
                            UnicodeDecodeError,
                            json.JSONDecodeError,
                            ValueError,
                        )
                    ):
                        read_only_report_payload(str(path))

        injected_errors: list[BaseException] = [
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
            json.JSONDecodeError("malformed", "", 0),
            RecursionError("nested\ninput"),
            ValueError("x" * 1_000 + "\n\x1b\u202e"),
            MemoryError("allocation failed"),
            OSError(
                errno.ENAMETOOLONG,
                "oversized path",
                "untrusted\npath" * 1_000,
            ),
        ]
        for injected in injected_errors:
            with self.subTest(error=type(injected).__name__):
                with mock.patch.dict(
                    READ_ONLY_PR_REPORT_GLOBALS,
                    {"_read_payload": mock.Mock(side_effect=injected)},
                ):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        return_code = read_only_report_main(
                            ["validate-semantics", "ignored"]
                        )
                self.assertEqual(return_code, 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["classification"], "rejected")
                self.assertLessEqual(
                    len(result["error"]),
                    READ_ONLY_REPORT_MAX_ERROR_CHARS,
                )
                self.assertFalse(
                    any(
                        unicodedata.category(character).startswith("C")
                        for character in result["error"]
                    )
                )

        for interrupt in (KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(interrupt=type(interrupt).__name__):
                with mock.patch.dict(
                    READ_ONLY_PR_REPORT_GLOBALS,
                    {"_read_payload": mock.Mock(side_effect=interrupt)},
                ):
                    with self.assertRaises(type(interrupt)):
                        read_only_report_main(["validate-semantics", "ignored"])

    def test_runtime_validator_rejects_splicing_and_cross_field_conflicts(
        self,
    ) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        resolved = cases["resolved-target-snapshot"]
        range_blocked = cases["selected-pr-base-head-blocked"]
        validator = read_only_report_validator()

        candidates: dict[str, tuple[dict[str, object], bool]] = {}

        spliced_evidence = copy.deepcopy(resolved)
        spliced_evidence["evidence"]["pr_lifecycle"] = copy.deepcopy(
            range_blocked["evidence"]["pr_lifecycle"]
        )
        candidates["cross-report-evidence-splice"] = (spliced_evidence, False)

        spliced_snapshot = copy.deepcopy(resolved)
        spliced_snapshot["snapshot"] = copy.deepcopy(range_blocked["snapshot"])
        candidates["cross-report-snapshot-splice"] = (spliced_snapshot, False)

        reused_instance_token = copy.deepcopy(resolved)
        reused_instance_token["snapshot"]["snapshot_id"] = (
            "observation:33333333333333333333333333333333"
        )
        candidates["reused-instance-token"] = (reused_instance_token, False)

        observed_without_source = copy.deepcopy(resolved)
        observed_without_source["snapshot"]["sources"] = []
        candidates["observed-evidence-without-source"] = (
            observed_without_source,
            True,
        )

        contradictory_lifecycle = copy.deepcopy(resolved)
        contradictory_lifecycle["evidence"]["pr_lifecycle"]["observed"][0].update(
            {
                "merged": True,
                "merged_at": "2026-07-24T06:04:00Z",
            }
        )
        candidates["open-and-merged-lifecycle"] = (
            contradictory_lifecycle,
            True,
        )

        contradictory_selection = copy.deepcopy(resolved)
        contradictory_selection["evidence"]["pr_selection"]["observed"][0][
            "candidate_count"
        ] = 2
        candidates["selected-with-two-candidates"] = (
            contradictory_selection,
            True,
        )

        explicit_ambiguity = copy.deepcopy(cases["pre-target-no-match"])
        explicit_ambiguity["evidence"]["pr_selection"]["observed"][0].update(
            {
                "selection_method": "explicit",
                "outcome": "ambiguous",
                "candidate_count": 2,
            }
        )
        candidates["explicit-selection-cannot-be-ambiguous"] = (
            explicit_ambiguity,
            True,
        )

        aggregate_mismatch = copy.deepcopy(range_blocked)
        aggregate_mismatch["evidence"]["ci_status"]["observed"][0]["successful"] = 2
        candidates["ci-counts-do-not-match-checks"] = (aggregate_mismatch, False)

        state_mismatch = copy.deepcopy(range_blocked)
        state_mismatch["evidence"]["ci_status"]["observed"][0]["state"] = "success"
        candidates["ci-state-does-not-match-checks"] = (state_mismatch, True)

        thread_mismatch = copy.deepcopy(range_blocked)
        thread_mismatch["evidence"]["conversation_state"]["observed"][0].update(
            {
                "total_threads": 1,
                "unresolved_threads": 2,
            }
        )
        candidates["unresolved-threads-exceed-total"] = (thread_mismatch, False)

        endpoint_mismatch = copy.deepcopy(resolved)
        endpoint_mismatch["evidence"]["base_and_head"]["observed"][0][
            "base_object_present"
        ] = False
        candidates["missing-base-with-merge-base"] = (endpoint_mismatch, True)

        for name, (candidate, schema_must_reject) in candidates.items():
            with self.subTest(name=name):
                schema_errors = list(validator.iter_errors(candidate))
                if schema_must_reject:
                    self.assertTrue(schema_errors)
                else:
                    self.assertEqual(schema_errors, [])
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

    def test_read_only_pr_report_rejects_target_identity_splicing(self) -> None:
        report = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()
        attacks: dict[str, dict[str, object]] = {}

        cross_pr = copy.deepcopy(report)
        cross_pr["evidence"]["pr_selection"]["observed"][0]["target_identity"][
            "pull_request"
        ]["node_id"] = "PR_OTHER_REPOSITORY_99"
        attacks["selection-cross-pr-node-id"] = cross_pr

        lifecycle_other_pr = copy.deepcopy(report)
        lifecycle_other_pr["evidence"]["pr_lifecycle"]["observed"][0][
            "target_identity"
        ]["pull_request"]["number"] = 99
        attacks["lifecycle-cross-pr-number"] = lifecycle_other_pr

        lifecycle_other_base_ref = copy.deepcopy(report)
        lifecycle_other_base_ref["evidence"]["pr_lifecycle"]["observed"][0][
            "target_identity"
        ]["pull_request"]["base_ref"] = "release"
        attacks["lifecycle-cross-base-ref"] = lifecycle_other_base_ref

        stale_green_ci = copy.deepcopy(report)
        stale_green_ci["evidence"]["ci_status"]["observed"][0]["target_identity"][
            "head"
        ]["oid"] = "d" * 40
        attacks["stale-green-ci-head"] = stale_green_ci

        conversation_head_race = copy.deepcopy(report)
        conversation_head_race["evidence"]["conversation_state"]["observed"][0][
            "target_identity"
        ]["head"]["ref"] = "codex/other-head"
        attacks["conversation-head-ref-race"] = conversation_head_race

        other_repository = copy.deepcopy(report)
        other_repository["evidence"]["ci_status"]["observed"][0]["target_identity"][
            "repository"
        ]["node_id"] = "REPO_OTHER"
        attacks["ci-cross-repository"] = other_repository

        other_provider = copy.deepcopy(report)
        other_provider["evidence"]["pr_selection"]["observed"][0]["target_identity"][
            "provider"
        ]["host"] = "ghe.example.com"
        attacks["selection-cross-provider"] = other_provider

        for name, candidate in attacks.items():
            with self.subTest(name=name):
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                with self.assertRaisesRegex(ValueError, "target_identity"):
                    validate_read_only_report_semantics(candidate)

    def test_read_only_pr_report_binds_endpoint_observation_to_target(self) -> None:
        resolved = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "resolved-target-snapshot"
        )
        validator = read_only_report_validator()

        swapped = copy.deepcopy(resolved)
        swapped_record = swapped["evidence"]["base_and_head"]["observed"][0]
        swapped_record["observed_base_oid"], swapped_record["observed_head_oid"] = (
            swapped_record["observed_head_oid"],
            swapped_record["observed_base_oid"],
        )

        other_report = copy.deepcopy(resolved)
        other_report["target"]["base"]["oid"] = "d" * 40
        other_report["target"]["head"]["oid"] = "e" * 40
        other_record = other_report["evidence"]["base_and_head"]["observed"][0]
        other_record["observed_base_oid"] = "d" * 40
        other_record["observed_head_oid"] = "e" * 40
        cross_report = copy.deepcopy(resolved)
        cross_report["evidence"]["base_and_head"]["observed"][0] = copy.deepcopy(
            other_record
        )

        stale_endpoint = copy.deepcopy(resolved)
        stale_endpoint["evidence"]["base_and_head"]["observed"][0][
            "observed_head_oid"
        ] = "d" * 40

        same_merge_base_different_head = copy.deepcopy(resolved)
        same_merge_base_different_head["target"]["head"]["oid"] = "d" * 40

        attacks = {
            "swapped-endpoints": swapped,
            "cross-report-endpoint-record": cross_report,
            "stale-observed-head": stale_endpoint,
            "same-merge-base-different-head": same_merge_base_different_head,
        }
        for name, candidate in attacks.items():
            with self.subTest(name=name):
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                with self.assertRaisesRegex(
                    ValueError,
                    r"(?:observed_.*_oid|target_identity\.head)",
                ):
                    validate_read_only_report_semantics(candidate)

        mismatched_base_ref = copy.deepcopy(resolved)
        mismatched_base_ref["target"]["base"]["ref"] = "release"
        self.assertEqual(list(validator.iter_errors(mismatched_base_ref)), [])
        with self.assertRaisesRegex(ValueError, r"target\.base\.ref"):
            validate_read_only_report_semantics(mismatched_base_ref)

        refreshed_head = copy.deepcopy(resolved)
        refreshed_head["target"]["head"]["oid"] = "d" * 40
        refreshed_head["delivery_record"]["head_sha"] = "d" * 40
        refreshed_head["evidence"]["base_and_head"]["observed"][0][
            "observed_head_oid"
        ] = "d" * 40
        for field in ("pr_selection", "pr_lifecycle"):
            refreshed_head["evidence"][field]["observed"][0]["target_identity"]["head"][
                "oid"
            ] = "d" * 40
        self.assertEqual(list(validator.iter_errors(refreshed_head)), [])
        validate_read_only_report_semantics(refreshed_head)

    def test_delivery_result_schema_is_closed_and_fixture_cases_conform(
        self,
    ) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(set(schema["required"]), RESULT_FIELDS)
        self.assertEqual(set(schema["properties"]), RESULT_FIELDS)
        self.assertFalse(schema["additionalProperties"])
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        self.assertEqual(
            set(schema["properties"]["profile"]["enum"]),
            PROFILES,
        )
        self.assertEqual(
            set(schema["properties"]["constraints"]["items"]["enum"]),
            CONSTRAINTS,
        )
        self.assertEqual(schema["properties"]["head_sha"]["$ref"], "#/$defs/oid")
        self.assertEqual(schema["properties"]["schema_version"]["const"], 3)
        self.assertEqual(
            set(schema["properties"]["terminal_outcome"]["enum"]),
            {"succeeded", "blocked"},
        )
        self.assertEqual(
            set(schema["properties"]["terminal_reason"]["enum"]),
            SUCCESS_REASONS | BLOCKED_REASONS,
        )
        self.assertEqual(
            set(schema["properties"]["terminal_evidence"]["required"]),
            TERMINAL_EVIDENCE_FIELDS,
        )
        self.assertFalse(
            schema["properties"]["terminal_evidence"]["additionalProperties"]
        )

        constraints_by_enum = {
            frozenset(rule["if"]["properties"]["constraints"]["contains"]["enum"]): rule
            for rule in schema["allOf"]
            if "constraints" in rule["if"]["properties"]
            and "enum" in rule["if"]["properties"]["constraints"]["contains"]
        }
        local_mutation_constraint = constraints_by_enum[
            frozenset(LOCAL_MUTATION_LIMITING_CONSTRAINTS)
        ]
        commit_constraint = constraints_by_enum[frozenset(COMMIT_LIMITING_CONSTRAINTS)]
        remote_constraint = constraints_by_enum[frozenset(REMOTE_LIMITING_CONSTRAINTS)]
        local_gate_formal_review_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"].get("profile", {}).get("const") == "local-gate"
            and rule["if"]["properties"].get("commit_mode", {}).get("const")
            == "allowed"
        )
        profile_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"].get("profile", {}).get("const")
            == "pr-readiness-handoff"
            and "terminal_outcome" not in rule["if"]["properties"]
        )
        local_only_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"]
            .get("constraints", {})
            .get("contains", {})
            .get("const")
            == "local-only"
        )
        blocked_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"].get("terminal_outcome", {}).get("const")
            == "blocked"
        )
        successful_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"].get("terminal_outcome", {}).get("const")
            == "succeeded"
        )
        read_only_handoff_constraint = next(
            rule
            for rule in schema["allOf"]
            if rule["if"]["properties"].get("handoff_profile", {}).get("const")
            == "pr-readiness-read-only-probe"
        )
        self.assertEqual(
            set(
                local_mutation_constraint["if"]["properties"]["constraints"][
                    "contains"
                ]["enum"]
            ),
            LOCAL_MUTATION_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            local_mutation_constraint["then"]["properties"]["local_mutation"]["const"],
            "forbidden",
        )
        self.assertEqual(
            local_mutation_constraint["else"]["properties"]["local_mutation"]["const"],
            "allowed",
        )
        self.assertEqual(
            set(
                remote_constraint["if"]["properties"]["constraints"]["contains"]["enum"]
            ),
            REMOTE_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            set(
                commit_constraint["if"]["properties"]["constraints"]["contains"]["enum"]
            ),
            COMMIT_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            commit_constraint["then"]["properties"]["commit_mode"]["const"],
            "forbidden",
        )
        self.assertEqual(
            commit_constraint["else"]["properties"]["commit_mode"]["const"],
            "allowed",
        )
        self.assertEqual(
            local_gate_formal_review_constraint["if"]["properties"]["profile"]["const"],
            "local-gate",
        )
        self.assertEqual(
            local_gate_formal_review_constraint["if"]["properties"]["commit_mode"][
                "const"
            ],
            "allowed",
        )
        self.assertIs(
            local_gate_formal_review_constraint["then"]["properties"][
                "formal_review_required"
            ]["const"],
            True,
        )
        self.assertEqual(
            profile_constraint["if"]["properties"]["profile"]["const"],
            "pr-readiness-handoff",
        )
        self.assertEqual(
            profile_constraint["then"]["properties"]["remote_mutation"]["const"],
            "review-authorization-required",
        )
        self.assertNotIn("handoff", profile_constraint["then"]["properties"])
        self.assertNotIn(
            "handoff_profile",
            profile_constraint["then"]["properties"],
        )
        self.assertIs(
            profile_constraint["then"]["properties"]["formal_review_required"]["const"],
            True,
        )
        self.assertEqual(
            successful_constraint["then"]["$ref"],
            "#/$defs/successTerminalMatrix",
        )
        self.assertEqual(
            profile_constraint["else"]["properties"]["remote_mutation"]["const"],
            "forbidden",
        )
        self.assertEqual(
            local_only_constraint["then"]["properties"]["handoff"]["const"],
            "none",
        )
        self.assertEqual(
            local_only_constraint["then"]["properties"]["handoff_profile"]["const"],
            "none",
        )
        self.assertEqual(
            blocked_constraint["then"]["properties"]["handoff"]["const"],
            "none",
        )
        self.assertEqual(
            blocked_constraint["then"]["properties"]["handoff_profile"]["const"],
            "none",
        )
        self.assertEqual(
            set(blocked_constraint["then"]["properties"]["terminal_reason"]["enum"]),
            BLOCKED_REASONS,
        )
        self.assertEqual(
            set(
                read_only_handoff_constraint["then"]["properties"]["constraints"][
                    "contains"
                ]["enum"]
            ),
            REMOTE_LIMITING_CONSTRAINTS - REMOTE_READ_LIMITING_CONSTRAINTS,
        )
        schema_success_matrix = {}
        for branch in schema["$defs"]["successTerminalMatrix"]["oneOf"]:
            properties = branch["properties"]
            reason = properties["terminal_reason"]["const"]
            self.assertEqual(branch["title"], reason)
            self.assertEqual(properties["terminal_outcome"]["const"], "succeeded")
            evidence_properties = properties["terminal_evidence"]["properties"]
            schema_evidence = {
                field: (
                    FIXTURE_HEAD_OID
                    if evidence_properties[field].get("$ref") == "#/$defs/oid"
                    else evidence_properties[field]["const"]
                )
                for field in TERMINAL_EVIDENCE_FIELDS
            }
            schema_success_matrix[reason] = {
                field: (
                    schema_evidence
                    if field == "terminal_evidence"
                    else properties[field]["const"]
                )
                for field in SUCCESS_MATRIX[reason]
            }
        self.assertEqual(schema_success_matrix, SUCCESS_MATRIX)

        for case in profile_selection_cases():
            with self.subTest(prompt=case["prompt"]):
                assert_valid_result_contract(case["result"])
                self.assertEqual(list(validator.iter_errors(case["result"])), [])

    def test_success_reason_matrix_rejects_every_cross_product(self) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        top_level_values = {
            "profile": PROFILES,
            "local_mutation": {"allowed", "forbidden"},
            "commit_mode": {"allowed", "forbidden"},
            "formal_review_required": {True, False},
            "remote_mutation": {
                "forbidden",
                "review-authorization-required",
            },
            "handoff": {"none", "review-orchestration-playbook"},
            "handoff_profile": HANDOFF_PROFILES,
        }

        def assert_rejected(candidate: dict[str, object]) -> None:
            self.assertTrue(list(validator.iter_errors(candidate)))
            with self.assertRaises(AssertionError):
                assert_valid_result_contract(candidate)

        for reason in sorted(SUCCESS_MATRIX):
            valid = success_result(reason)
            with self.subTest(reason=reason, mutation="valid"):
                self.assertEqual(list(validator.iter_errors(valid)), [])
                assert_valid_result_contract(valid)
                self.assertTrue(
                    set(valid["terminal_evidence"].values()).isdisjoint(
                        {"blocked", "failed", "findings", "not-started"}
                    )
                )

            for field, values in top_level_values.items():
                for alternative in values - {valid[field]}:
                    with self.subTest(
                        reason=reason,
                        mutation=field,
                        alternative=alternative,
                    ):
                        candidate = copy.deepcopy(valid)
                        candidate[field] = alternative
                        assert_rejected(candidate)

            for field, values in TERMINAL_EVIDENCE_VALUES.items():
                for alternative in values - {valid["terminal_evidence"][field]}:
                    with self.subTest(
                        reason=reason,
                        mutation=f"terminal_evidence.{field}",
                        alternative=alternative,
                    ):
                        candidate = copy.deepcopy(valid)
                        candidate["terminal_evidence"][field] = alternative
                        assert_rejected(candidate)

            for alternative_reason in SUCCESS_REASONS - {reason}:
                with self.subTest(
                    reason=reason,
                    mutation="terminal_reason",
                    alternative=alternative_reason,
                ):
                    candidate = copy.deepcopy(valid)
                    candidate["terminal_reason"] = alternative_reason
                    assert_rejected(candidate)

            missing_evidence = copy.deepcopy(valid)
            del missing_evidence["terminal_evidence"]["journal"]
            assert_rejected(missing_evidence)
            extra_evidence = copy.deepcopy(valid)
            extra_evidence["terminal_evidence"]["summary"] = "looks good"
            assert_rejected(extra_evidence)

    def test_read_only_receiver_enforces_each_success_reason_matrix(self) -> None:
        base_report = copy.deepcopy(
            next(
                case["expected"]["terminal_result"]
                for case in fixture_cases(
                    READ_ONLY_PR_PROBE_CASES,
                    "read-only-pr-probe",
                )
                if case["name"] == "resolved-target-snapshot"
            )
        )
        validator = read_only_report_validator()
        read_only_reasons = set(READ_ONLY_DELIVERY_SUCCESS_MATRIX)
        for reason in sorted(read_only_reasons):
            report = copy.deepcopy(base_report)
            report["delivery_record"] = success_result(reason)
            report["delivery_record"]["head_sha"] = report["target"]["head"]["oid"]
            if (
                report["delivery_record"]["terminal_evidence"]["signature"]
                == "verified"
            ):
                report["delivery_record"]["terminal_evidence"][
                    "signature_verified_head_oid"
                ] = report["target"]["head"]["oid"]
            with self.subTest(reason=reason, mutation="valid"):
                self.assertEqual(list(validator.iter_errors(report)), [])
                validate_read_only_report_semantics(report)

            for alternative_reason in read_only_reasons - {reason}:
                candidate = copy.deepcopy(report)
                candidate["delivery_record"]["terminal_reason"] = alternative_reason
                with self.subTest(
                    reason=reason,
                    mutation="terminal_reason",
                    alternative=alternative_reason,
                ):
                    self.assertTrue(list(validator.iter_errors(candidate)))
                    with self.assertRaises(ValueError):
                        validate_read_only_report_semantics(candidate)

            for field, values in TERMINAL_EVIDENCE_VALUES.items():
                current = report["delivery_record"]["terminal_evidence"][field]
                for alternative in values - {current}:
                    candidate = copy.deepcopy(report)
                    candidate["delivery_record"]["terminal_evidence"][field] = (
                        alternative
                    )
                    with self.subTest(
                        reason=reason,
                        mutation=f"terminal_evidence.{field}",
                        alternative=alternative,
                    ):
                        self.assertTrue(list(validator.iter_errors(candidate)))
                        with self.assertRaises(ValueError):
                            validate_read_only_report_semantics(candidate)

    def test_ordinary_pr_readiness_receiver_requires_exact_delivery_head(
        self,
    ) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for reason in (
            "pr-readiness-handoff-ready",
            "pr-readiness-existing-range-handoff-ready",
        ):
            valid = success_result(reason)
            with self.subTest(reason=reason, mode="valid"):
                self.assertEqual(list(validator.iter_errors(valid)), [])
                validate_delivery_handoff_semantics(valid)

            for alternate_head in ("e" * 40, "f" * 64):
                candidate = copy.deepcopy(valid)
                candidate["terminal_evidence"]["signature_verified_head_oid"] = (
                    alternate_head
                )
                with self.subTest(
                    reason=reason,
                    mode="different-valid-oid",
                    alternate_head=alternate_head,
                ):
                    self.assertEqual(list(validator.iter_errors(candidate)), [])
                    with self.assertRaisesRegex(
                        ValueError,
                        "delivery_record.head_sha",
                    ):
                        validate_delivery_handoff_semantics(candidate)

        accepted = success_result("pr-readiness-handoff-ready")
        with mock.patch.dict(
            READ_ONLY_PR_REPORT_GLOBALS,
            {"_read_payload": mock.Mock(return_value=accepted)},
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                return_code = read_only_report_main(
                    ["validate-delivery-handoff", "ignored"]
                )
        self.assertEqual(return_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"classification": "accepted"},
        )

    def test_pr_readiness_blockers_preserve_profile_without_handoff(self) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        ready = copy.deepcopy(
            next(
                case["result"]
                for case in profile_selection_cases()
                if case["result"]["profile"] == "pr-readiness-handoff"
            )
        )
        incomplete_success = copy.deepcopy(ready)
        incomplete_success.update(
            {
                "terminal_reason": "local-gate-complete",
                "handoff": "none",
                "handoff_profile": "none",
            }
        )
        self.assertTrue(list(validator.iter_errors(incomplete_success)))
        with self.assertRaises(AssertionError):
            assert_valid_result_contract(incomplete_success)

        blocker_branches = schema["$defs"]["blockedTerminalMatrix"]["oneOf"]
        self.assertEqual(
            {
                branch["properties"]["terminal_reason"]["const"]
                for branch in blocker_branches
            },
            BLOCKED_REASONS,
        )
        for index, branch in enumerate(blocker_branches):
            properties = branch["properties"]
            reason = properties["terminal_reason"]["const"]
            with self.subTest(reason=reason, row=index):
                blocked = blocker_result(branch)
                self.assertEqual(list(validator.iter_errors(blocked)), [])
                assert_valid_result_contract(blocked)
                self.assertEqual(
                    blocked["profile"],
                    properties.get("profile", {}).get(
                        "const",
                        "pr-readiness-handoff",
                    ),
                )

                widened = copy.deepcopy(blocked)
                widened["handoff"] = "review-orchestration-playbook"
                widened["handoff_profile"] = "pr-readiness"
                self.assertTrue(list(validator.iter_errors(widened)))
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(widened)

        allowed_findings = copy.deepcopy(ready)
        allowed_findings.update(
            {
                "terminal_outcome": "blocked",
                "terminal_reason": "review-findings",
                "handoff": "none",
                "handoff_profile": "none",
            }
        )
        allowed_findings["terminal_evidence"]["formal_review"] = "findings"
        self.assertTrue(list(validator.iter_errors(allowed_findings)))
        with self.assertRaisesRegex(
            AssertionError,
            "terminal only for a required no-commit review",
        ):
            assert_valid_result_contract(allowed_findings)

    def test_blocker_matrix_closes_each_mutation_and_commit_path(self) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        branches = schema["$defs"]["blockedTerminalMatrix"]["oneOf"]
        self.assertEqual(
            len({branch["title"] for branch in branches}),
            len(branches),
        )

        paths_by_reason: dict[str, set[tuple[str, str]]] = {}
        for branch in branches:
            properties = branch["properties"]
            reason = properties["terminal_reason"]["const"]
            path = (
                properties["local_mutation"]["const"],
                properties["commit_mode"]["const"],
            )
            paths_by_reason.setdefault(reason, set()).add(path)

            valid = blocker_result(branch)
            self.assertEqual(list(validator.iter_errors(valid)), [])
            assert_valid_result_contract(valid)

            for field, alternative in (
                (
                    "local_mutation",
                    "forbidden" if valid["local_mutation"] == "allowed" else "allowed",
                ),
                (
                    "commit_mode",
                    "forbidden" if valid["commit_mode"] == "allowed" else "allowed",
                ),
            ):
                candidate = copy.deepcopy(valid)
                candidate[field] = alternative
                with self.subTest(
                    title=branch["title"],
                    mutation=field,
                    alternative=alternative,
                ):
                    self.assertTrue(list(validator.iter_errors(candidate)))

            if valid["commit_mode"] == "forbidden":
                fake_success = copy.deepcopy(valid)
                fake_success["terminal_evidence"]["local_gate"] = "succeeded"
                with self.subTest(
                    title=branch["title"],
                    mutation="fake-succeeded-local-gate",
                ):
                    self.assertTrue(list(validator.iter_errors(fake_success)))
            if valid["local_mutation"] == "forbidden":
                for phase in ("build", "tests", "docs", "journal"):
                    self.assertEqual(
                        valid["terminal_evidence"][phase],
                        "read-only-observed",
                    )

        mutable_commit = ("allowed", "allowed")
        no_commit = ("allowed", "forbidden")
        read_only = ("forbidden", "forbidden")
        self.assertEqual(
            paths_by_reason["missing-committed-range"],
            {no_commit, read_only},
        )
        self.assertEqual(
            paths_by_reason["review-findings"],
            {no_commit, read_only},
        )
        for reason in (
            "formal-review-blocked",
            "signing-failed",
            "blocked-authorization",
            "blocked-input",
        ):
            self.assertEqual(
                paths_by_reason[reason],
                {mutable_commit, no_commit, read_only},
            )

    def test_read_only_receiver_rejects_non_ready_delivery_terminal(self) -> None:
        report = copy.deepcopy(
            next(
                case["expected"]["terminal_result"]
                for case in fixture_cases(
                    READ_ONLY_PR_PROBE_CASES,
                    "read-only-pr-probe",
                )
                if case["name"] == "resolved-target-snapshot"
            )
        )
        delivery = report["delivery_record"]
        delivery.update(
            {
                "terminal_outcome": "blocked",
                "terminal_reason": "blocked-input",
                "handoff": "none",
                "handoff_profile": "none",
            }
        )
        delivery["terminal_evidence"]["input"] = "blocked"
        validator = read_only_report_validator()
        self.assertTrue(list(validator.iter_errors(report)))
        with self.assertRaisesRegex(ValueError, "succeeded delivery terminal"):
            validate_read_only_report_semantics(report)

        malformed = copy.deepcopy(report)
        malformed["delivery_record"]["constraints"] = [{}]
        with self.assertRaisesRegex(ValueError, "constraints are malformed"):
            validate_read_only_report_semantics(malformed)

        local_only = copy.deepcopy(
            next(
                case["expected"]["terminal_result"]
                for case in fixture_cases(
                    READ_ONLY_PR_PROBE_CASES,
                    "read-only-pr-probe",
                )
                if case["name"] == "resolved-target-snapshot"
            )
        )
        local_only["delivery_record"]["constraints"].append("local-only")
        self.assertTrue(list(validator.iter_errors(local_only)))
        with self.assertRaisesRegex(ValueError, "local-only delivery"):
            validate_read_only_report_semantics(local_only)

        legacy_delivery = copy.deepcopy(local_only)
        legacy_delivery["delivery_record"]["constraints"].remove("local-only")
        legacy_delivery["delivery_record"]["schema_version"] = 2
        self.assertTrue(list(validator.iter_errors(legacy_delivery)))
        with self.assertRaisesRegex(ValueError, "schema_version must be 3"):
            validate_read_only_report_semantics(legacy_delivery)

        legacy_report = copy.deepcopy(local_only)
        legacy_report["delivery_record"]["constraints"].remove("local-only")
        legacy_report["schema_version"] = 6
        self.assertTrue(list(validator.iter_errors(legacy_report)))

    def test_blocked_reason_matrix_rejects_contradictory_evidence(self) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        alternatives: dict[str, object] = {
            "local_gate": "succeeded",
            "build": "read-only-observed",
            "tests": "read-only-observed",
            "docs": "read-only-observed",
            "journal": "read-only-observed",
            "committed_range": "not-required",
            "formal_review": "clean",
            "signature": "failed",
            "signature_verified_head_oid": FIXTURE_HEAD_OID,
            "authorization": "blocked",
            "input": "blocked",
        }
        target_reasons = {
            "implementation-blocked",
            "validation-blocked",
            "journal-blocked",
            "formal-review-blocked",
        }
        branches = [
            branch
            for branch in schema["$defs"]["blockedTerminalMatrix"]["oneOf"]
            if branch["properties"]["terminal_reason"]["const"] in target_reasons
        ]
        self.assertEqual(
            {branch["properties"]["terminal_reason"]["const"] for branch in branches},
            target_reasons,
        )
        for index, branch in enumerate(branches):
            properties = branch["properties"]
            reason = properties["terminal_reason"]["const"]
            valid = blocker_result(branch)
            self.assertEqual(list(validator.iter_errors(valid)), [])
            for field, current in valid["terminal_evidence"].items():
                replacement = alternatives[field]
                if replacement == current:
                    replacement = (
                        None
                        if field == "signature_verified_head_oid"
                        else {
                            "local_gate": "checked",
                            "build": "blocked",
                            "tests": "blocked",
                            "docs": "blocked",
                            "journal": "blocked",
                            "committed_range": "missing",
                            "formal_review": "not-started",
                            "signature": "not-required",
                            "authorization": "not-required",
                            "input": "not-required",
                        }[field]
                    )
                candidate = copy.deepcopy(valid)
                candidate["terminal_evidence"][field] = replacement
                with self.subTest(reason=reason, row=index, field=field):
                    self.assertTrue(list(validator.iter_errors(candidate)))

    def test_constrained_result_cannot_be_reinterpreted_downstream(self) -> None:
        constrained = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"] == "Run the full workflow locally, report-only."
        )
        invalid_results = []

        missing_constraints = dict(constrained)
        del missing_constraints["constraints"]
        invalid_results.append(missing_constraints)

        unknown_field = dict(constrained)
        unknown_field["remote_authorized"] = True
        invalid_results.append(unknown_field)

        widened_profile = dict(constrained)
        widened_profile["profile"] = "pr-readiness-handoff"
        invalid_results.append(widened_profile)

        widened_handoff = dict(constrained)
        widened_handoff["remote_mutation"] = "review-authorization-required"
        widened_handoff["handoff"] = "review-orchestration-playbook"
        widened_handoff["handoff_profile"] = "pr-readiness"
        invalid_results.append(widened_handoff)

        for result in invalid_results:
            with self.subTest(result=result):
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(result)

    def test_journal_gate_does_not_force_first_time_adoption(self) -> None:
        for anchor in (
            "repository already adopted the convention",
            "repository policy requires it",
            "task truly crosses a session or PR handoff",
            "existing tracking product is needed for durable recovery",
            "Do not introduce tracking into an unadopted repository",
            "ordinary implementation, test, and review phases",
            "short `focused-checkpoint`",
            "First-time setup still needs an explicit product or recovery need",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_checkpoints_and_landing_commits_are_automatic_and_signed(self) -> None:
        for anchor in (
            "create a signed local checkpoint automatically",
            "create a signed landing commit automatically",
            "`report-only`, `probe-only`, `read-only`, or `no-commit`",
            "do not ask again merely to commit",
            "git commit -S",
            "Treat a signing failure as a blocker",
            "Never silently create an unsigned fallback commit",
        ):
            self.assertIn(anchor, self.normalized_change)
        self.assertIn(
            "does not push without separate authorization",
            self.normalized_change,
        )
        self.assertIn(
            "Do not automatically push, open a PR",
            self.normalized_change,
        )

    def test_allowed_review_fixes_require_a_new_frozen_range(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        loop = cases["existing-committed-range-commit-allowed-review-findings"]
        self.assertEqual(
            loop["expected"],
            {
                "apply_fixes": True,
                "rerun_validation": True,
                "rerun_journal_gate": True,
                "create_new_signed_head": True,
                "invalidate_reviewed_range": "base_sha..old_head_sha",
                "review_new_exact_range": True,
                "terminal": None,
            },
        )
        anchors = (
            "exact frozen range",
            "branch on the resolved `commit_mode`",
            "If commit mode is `allowed`",
            "rerun affected validation and journal work",
            "create a new signed review checkpoint",
            "creates a new head and invalidates every review result",
            "review the new exact range",
            "latest reviewed head is clean under an allowed commit mode",
        )
        positions = tuple(self.normalized_change.index(anchor) for anchor in anchors)
        self.assertEqual(positions, tuple(sorted(positions)))

    def test_no_commit_review_findings_preserve_range_and_stop(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["existing-committed-range-no-commit-review-findings"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": "base_sha..head_sha",
                "formal_review_required": True,
                "review_outcome": "findings",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "apply_fixes": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "preserve_committed_range": "base_sha..head_sha",
                "handoff": False,
                "terminal": "review-findings-blocker",
            },
        )
        for anchor in (
            "If commit mode is `forbidden`",
            "do not apply fixes or create or require a new head, checkpoint, anchor, or commit",
            "Preserve the exact existing committed range",
            "report the unresolved findings as a blocker, and stop",
            "Only a later authorization may begin a new mutation-capable run",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_clean_no_commit_review_reports_without_inducing_commit(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["existing-committed-range-no-commit-review-clean"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": "base_sha..head_sha",
                "formal_review_required": True,
                "review_outcome": "clean",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "preserve_committed_range": "base_sha..head_sha",
                "next_step": "profile-terminal",
                "terminal": "clean-range-report",
            },
        )
        for anchor in (
            "Report the exact clean range, bypass the signed-commit step",
            "Do not create, require, amend, or relabel a commit",
            "clean review under forbidden commit mode is complete evidence",
            "Enter this step only when commit mode is `allowed`",
            "bypass this step without asking for or implying commit authorization",
            "clean pre-existing reviewed range is reported directly",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_existing_range_pr_handoff_requires_exact_signature(
        self,
    ) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        verified = cases["existing-range-pr-handoff-no-commit-verified-signature"]
        self.assertTrue(verified["expected"]["read_only_signature_verification"])
        self.assertEqual(verified["expected"]["signature"], "verified")
        self.assertEqual(
            verified["expected"]["signature_verified_head_oid"],
            verified["input"]["frozen_head_oid"],
        )
        self.assertTrue(verified["expected"]["handoff"])
        for name in (
            "existing-range-pr-handoff-no-commit-unsigned",
            "existing-range-pr-handoff-no-commit-unverifiable",
        ):
            with self.subTest(name=name):
                case = cases[name]
                self.assertEqual(case["expected"]["signature"], "failed")
                self.assertFalse(case["expected"]["handoff"])
                self.assertEqual(case["expected"]["terminal"], "signing-failed")

        handoff = success_result("pr-readiness-existing-range-handoff-ready")
        self.assertEqual(handoff["terminal_evidence"]["signature"], "verified")
        self.assertEqual(
            handoff["terminal_evidence"]["signature_verified_head_oid"],
            handoff["head_sha"],
        )
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        validate_delivery_handoff_semantics(handoff)
        for replacement in (None, "f" * 39, "F" * 40):
            candidate = copy.deepcopy(handoff)
            candidate["terminal_evidence"]["signature_verified_head_oid"] = replacement
            with self.subTest(replacement=replacement):
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(candidate)
                with self.assertRaises(ValueError):
                    validate_delivery_handoff_semantics(candidate)

        for replacement in ("e" * 40, "f" * 64):
            candidate = copy.deepcopy(handoff)
            candidate["terminal_evidence"]["signature_verified_head_oid"] = replacement
            with self.subTest(valid_but_different_oid=replacement):
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                with self.assertRaisesRegex(
                    AssertionError,
                    "exact delivery head",
                ):
                    assert_valid_result_contract(candidate)
                with self.assertRaisesRegex(
                    ValueError,
                    "delivery_record.head_sha",
                ):
                    validate_delivery_handoff_semantics(candidate)

        sha256_handoff = copy.deepcopy(handoff)
        sha256_handoff["head_sha"] = "a" * 64
        sha256_handoff["terminal_evidence"]["signature_verified_head_oid"] = "a" * 64
        self.assertEqual(list(validator.iter_errors(sha256_handoff)), [])
        assert_valid_result_contract(sha256_handoff)
        validate_delivery_handoff_semantics(sha256_handoff)

        report = copy.deepcopy(
            next(
                case["expected"]["terminal_result"]
                for case in fixture_cases(
                    READ_ONLY_PR_PROBE_CASES,
                    "read-only-pr-probe",
                )
                if case["name"] == "resolved-target-snapshot"
            )
        )
        report["delivery_record"] = success_result(
            "pr-readiness-read-only-existing-range-probe-ready"
        )
        report["delivery_record"]["head_sha"] = report["target"]["head"]["oid"]
        report["delivery_record"]["terminal_evidence"][
            "signature_verified_head_oid"
        ] = "c" * 40
        self.assertEqual(
            list(read_only_report_validator().iter_errors(report)),
            [],
        )
        with self.assertRaisesRegex(ValueError, "delivery_record.head_sha"):
            validate_read_only_report_semantics(report)

        for anchor in (
            "read-only signature verification",
            "`signature_verified_head_oid`",
            "exact frozen head",
            "unsigned or unverifiable",
            "stop with `signing-failed`",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_missing_range_no_commit_blocks_without_inducing_commit(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["missing-committed-range-no-commit-formal-review-required"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": None,
                "formal_review_required": True,
                "review_outcome": "not-started",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "start_formal_review": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "handoff": False,
                "terminal": "missing-committed-range-blocker",
            },
        )
        for anchor in (
            "Report `missing-committed-range` as a blocker and stop",
            "Do not create or require a checkpoint, anchor, or commit to start review",
            "missing exact range or review findings under forbidden commit mode is a terminal blocker",
            "Do not continue to a profile handoff from either blocker",
            "a missing range, findings, signing failure, authorization blocker, or input blocker stops before handoff",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_without_required_review_reports_checked_result(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["uncommitted-no-commit-formal-review-not-required"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": None,
                "formal_review_required": False,
                "review_outcome": "not-required",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "start_formal_review": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "report_exact_validations": True,
                "missing_committed_range_blocker": False,
                "handoff": False,
                "terminal": "uncommitted-checked-result",
            },
        )
        for anchor in (
            "blocker only when formal review is required",
            "When formal review is not required",
            "report the uncommitted checked result and exact validations directly",
            "without inventing a missing-range blocker or review handoff",
            "`false` | `forbidden`",
            "Do not invent a missing-range blocker",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_clean_review_checkpoint_is_the_landing_without_history_churn(
        self,
    ) -> None:
        for anchor in (
            "latest clean reviewed checkpoint is the profile's landing commit",
            "do not create an empty commit",
            "amend, squash, or rewrite history",
            "Reuse the latest clean signed review checkpoint",
            "Never manufacture an empty commit",
            "implicit history rewrite",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_multi_version_validation_is_delegated_and_isolated(self) -> None:
        self.assertIn(
            "[validation-environments.md](references/validation-environments.md)",
            self.change,
        )
        for anchor in (
            "CI matrix",
            "supported-version set",
            "canonical version ordering",
            "minimum supported version or CI matrix does not by itself require",
            "explicitly requires local multi-version validation",
            "change targets cross-version compatibility",
            "version-selection config or pin",
            "installed inventory",
            "highest compatible installed version",
            "finite, non-empty, duplicate-free",
            "Do not compare or merge lower-priority declarations",
            "independent worktree, cache, and state roots",
            "fixed ports",
            "persistent machine-level state",
        ):
            self.assertIn(anchor, self.normalized_validation_environments)

    def test_thin_orchestrator_does_not_duplicate_review_state_machines(self) -> None:
        self.assertIn(
            "hand the exact frozen range to the authoritative `$review-orchestration-playbook`",
            self.normalized_change,
        )
        self.assertIn(
            "Do not copy the review skill's materialization, provider, PR-state, or evidence rules",
            self.normalized_change,
        )
        for duplicated_literal in (
            "materialize-worktree",
            "validate-worktree",
            "chatgpt-codex-connector",
            "chatgpt-codex-connector[bot]",
            "Claude Code",
            "2.1.212",
            ">=2.1.211,<3.0.0",
            "baseRefOid",
            "triple-inconclusive",
            "scope-mismatch",
            "base-changed-same-head",
            "pr-lifecycle-unverified",
            "selected-pr-closed",
            "selected-pr-merged",
            "GIT_CONFIG_NOSYSTEM",
        ):
            with self.subTest(duplicated_literal=duplicated_literal):
                self.assertNotIn(duplicated_literal, self.normalized_change)

    def test_retired_agile_skill_is_only_a_compatibility_alias(self) -> None:
        self.assertIn("retired as an independent workflow", self.agile)
        self.assertIn(
            "[$change-delivery-workflow](../change-delivery-workflow/SKILL.md)",
            self.agile,
        )
        for source, target in (
            ("`MVP`", "`focused-checkpoint`"),
            ("full local gate", "`local-gate`"),
            ("merge-ready", "`pr-readiness-handoff`"),
        ):
            source_position = self.agile.index(source)
            self.assertGreater(
                self.agile.index(target, source_position),
                source_position,
            )
        self.assertIn("active delivery skill is authoritative", self.agile)
        self.assertNotIn("## Workflow", self.agile)
        self.assertNotIn("Create the MVP checkpoint", self.agile)


if __name__ == "__main__":
    unittest.main()
