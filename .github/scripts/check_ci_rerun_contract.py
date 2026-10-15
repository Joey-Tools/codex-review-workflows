"""Check the reviewed CI declaration's schema and exact workflow byte binding.

This is a local consistency check, not an Actions mutation or approval helper.
An independently trusted, merged declaration and live operator preflight remain
necessary; candidate code cannot establish its own repeat-safety authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


MAX_BYTES = 1024 * 1024
FIXED_FIELDS = {
    "schema": "joey-tools-ci-rerun-v1",
    "repository": "Joey-Tools/codex-review-workflows",
    "workflow_path": ".github/workflows/ci.yml",
    "operation": "existing-run-rerun-failed-jobs",
    "repeat_safety": "reentrant",
    "authority": "manual-diagnostic-only",
    "maximum_run_attempt": 2,
}
JOB_TIMEOUTS = {
    "platform_tests": 60,
    "broker_reproducibility": 15,
    "independent_supervisor_tests": 15,
    "readonly_install_supervisor_tests": 20,
    "test": 5,
}


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate contract key")
        result[key] = value
    return result


def check_contract(raw: bytes, workflow: bytes) -> dict[str, object]:
    """Bind a reviewed declaration to bytes, without inferring execution safety."""
    if len(raw) > MAX_BYTES or len(workflow) > MAX_BYTES:
        raise ValueError("contract or workflow exceeds byte limit")
    contract = json.loads(raw, object_pairs_hook=unique_object)
    fields = set(FIXED_FIELDS) | {"workflow_sha256", "job_timeout_minutes"}
    if type(contract) is not dict or set(contract) != fields:
        raise ValueError("unexpected contract fields")
    for key, expected in FIXED_FIELDS.items():
        if type(contract[key]) is not type(expected) or contract[key] != expected:
            raise ValueError(f"unsupported contract field: {key}")
    jobs = contract["job_timeout_minutes"]
    if (
        type(jobs) is not dict
        or set(jobs) != set(JOB_TIMEOUTS)
        or any(type(jobs[key]) is not int or jobs[key] != limit
               for key, limit in JOB_TIMEOUTS.items())
    ):
        raise ValueError("unsupported job budget")
    digest = contract["workflow_sha256"]
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid workflow digest")
    if hashlib.sha256(workflow).hexdigest() != digest:
        raise ValueError("workflow changed; review repeat safety and update the declaration")
    return {
        "schema": contract["schema"],
        "workflow_sha256": digest,
        "workflow_binding": "matched",
        "mutation_authorized": False,
        "automatic_recovery_authority": False,
    }


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds byte limit")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[2],
        help="repository root to check (read-only)",
    )
    args = parser.parse_args()
    try:
        result = check_contract(
            read_bounded(args.repo / ".github/ci-rerun-contract.json"),
            read_bounded(args.repo / ".github/workflows/ci.yml"),
        )
    except (OSError, ValueError, RecursionError) as error:
        print(f"CI rerun contract check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
