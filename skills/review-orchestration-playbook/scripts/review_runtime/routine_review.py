"""Parent-side review disposition and dependency-based local revalidation.

Inputs are observations made by the orchestrator, never reviewer self-attestation.
This module does not execute a reviewer or prove a sandbox boundary.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import PurePosixPath
from typing import Any, Sequence

MAX_INPUT_BYTES = 2 * 1024 * 1024
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _boolean(record: dict[str, Any], key: str) -> bool:
    value = record[key]
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


def _scope(record: dict[str, Any]) -> None:
    for key in ("base_sha", "head_sha"):
        if not isinstance(record.get(key), str) or not OID.fullmatch(record[key]):
            raise ValueError(f"{key} must be a full lowercase object ID")
    if len(record["base_sha"]) != len(record["head_sha"]):
        raise ValueError("scope endpoints must use the same object format")


def _paths(record: dict[str, Any], key: str) -> set[str]:
    value = record[key]
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a path array")
    result: set[str] = set()
    for path in value:
        if (
            not isinstance(path, str)
            or not path
            or "\x00" in path
            or PurePosixPath(path).is_absolute()
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise ValueError(f"{key} must contain repository-relative leaf paths")
        path.encode("utf-8", errors="strict")
        result.add(path)
    return result


def classify(record: dict[str, Any]) -> dict[str, Any]:
    """Keep source conclusions separate from execution and acceptance."""
    _scope(record)
    code = record["code_outcome"]
    if code not in ("clean", "findings", "incomplete"):
        raise ValueError("unsupported code_outcome")
    flags = {
        key: _boolean(record, key)
        for key in (
            "terminal_received",
            "scope_complete",
            "boundary_intact",
            "source_unchanged",
            "evidence_complete",
            "unresolved_execution_error",
        )
    }
    diagnostics = record.get("diagnostics", [])
    if not isinstance(diagnostics, list) or any(
        not isinstance(item, str) for item in diagnostics
    ):
        raise ValueError("diagnostics must be a string array")
    if not flags["boundary_intact"] or not flags["source_unchanged"]:
        execution = "invalid"
    elif (
        not flags["terminal_received"]
        or not flags["evidence_complete"]
        or flags["unresolved_execution_error"]
    ):
        execution = "incomplete"
    else:
        execution = "complete-with-warnings" if diagnostics else "complete"
    accepted = (
        execution in ("complete", "complete-with-warnings")
        and flags["scope_complete"]
        and code == "clean"
    )
    return {
        "base_sha": record["base_sha"],
        "head_sha": record["head_sha"],
        "code_outcome": code,
        "execution_status": execution,
        "scope_complete": flags["scope_complete"],
        "accepted": accepted,
        "diagnostics": diagnostics,
    }


def revalidation_plan(record: dict[str, Any]) -> dict[str, Any]:
    """Plan reuse of a local unit; never issue new-head review approval."""
    _scope(record)
    reviewed = _paths(record, "reviewed_paths")
    dependencies = _paths(record, "dependency_paths")
    changed = _paths(record, "changed_paths")
    if not reviewed:
        raise ValueError("reviewed_paths must not be empty")
    prior_clean = _boolean(record, "prior_clean")
    complete = _boolean(record, "dependencies_complete")
    base_same = _boolean(record, "base_unchanged")
    control_same = _boolean(record, "control_policy_unchanged")
    intersects = sorted(changed & (reviewed | dependencies))
    reusable = prior_clean and complete and base_same and control_same and not intersects
    if not prior_clean:
        reason = "prior-unit-not-clean"
    elif not complete:
        reason = "dependency-coverage-unknown"
    elif not base_same or not control_same:
        reason = "scope-or-control-changed"
    elif intersects:
        reason = "affected-paths"
    else:
        reason = "dependencies-unchanged"
    return {
        "base_sha": record["base_sha"],
        "head_sha": record["head_sha"],
        "action": "retain-unit-evidence" if reusable else "review-unit",
        "reason": reason,
        "affected_paths": intersects,
        "current_head_integration_required": True,
        "current_head_approved": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("classify", "revalidate"))
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("parent record exceeds the 2 MiB input limit")
        record = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(record, dict):
            raise ValueError("parent record must be an object")
        result = classify(record) if args.operation == "classify" else revalidation_plan(record)
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

