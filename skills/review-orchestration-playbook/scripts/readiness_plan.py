"""Plan PR-readiness evidence invalidation and merge constraints.

This module is deliberately a pure, read-only classifier. Its output is not a
PR-ready verdict and does not acquire GitHub evidence or authorize mutations.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import Any


_CHANGE_KEYS = frozenset(
    ("head", "base_ref", "base_tip", "merge_base", "merge_group")
)
_DEPENDENCIES = frozenset(
    ("head", "base_ref", "base_tip", "merge_base", "merge_group", "local_range")
)
_EVIDENCE_KINDS = frozenset(("readiness", "head_only_provider"))
_PROOFS = frozenset(
    (
        "none",
        "expected_base_precondition",
        "repository_exact_base_guard",
        "monotonic_range_contraction",
        "strict_queue_full_gate_binding",
    )
)
_HEAD_BINDINGS = frozenset(
    ("match-head-commit", "persistent-queue-merge-async-sha", "none")
)


class PlanInputError(ValueError):
    """The input is incomplete or outside the closed planning contract."""


def _closed_object(value: Any, *, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PlanInputError(f"{label} must contain exactly: {', '.join(sorted(keys))}")
    return value


def _boolean(value: Any, *, label: str) -> bool:
    if type(value) is not bool:
        raise PlanInputError(f"{label} must be boolean")
    return value


def _merge_constraints(profile: str, merge: Mapping[str, Any]) -> dict[str, Any]:
    common_keys = {"operation", "head_binding", "admin_bypass_requested"}
    strict_keys = {
        "base_proof",
        "strict_freshness",
        "complete_bypass_audit",
        "configured_bypass",
        "actor_inventory_complete",
        "same_ref_fast_forward_only",
        "no_delete",
        "exact_base_ref",
        "merge_base_equals_reviewed_base",
    }
    queue_keys = {
        "all_invalidated_gates_on_required_merge_group",
        "non_bypassed_completion_hold",
        "queue_bypass_rules",
    }
    operation = merge.get("operation") if isinstance(merge, dict) else None
    if operation not in ("direct", "merge_queue"):
        raise PlanInputError("merge.operation must be direct or merge_queue")
    keys = common_keys | (strict_keys if profile == "strict" else set())
    if operation == "merge_queue":
        keys |= queue_keys
    _closed_object(merge, keys=keys, label="merge")
    if (
        not isinstance(merge["head_binding"], str)
        or merge["head_binding"] not in _HEAD_BINDINGS
    ):
        raise PlanInputError("merge.head_binding is unknown")
    expected_binding = (
        "persistent-queue-merge-async-sha"
        if merge["operation"] == "merge_queue"
        else "match-head-commit"
    )
    if merge["head_binding"] not in (expected_binding, "none"):
        raise PlanInputError(
            "merge.head_binding does not match merge.operation"
        )
    if profile == "strict" and merge["base_proof"] == "strict_queue_full_gate_binding":
        if merge["operation"] != "merge_queue":
            raise PlanInputError(
                "strict_queue_full_gate_binding requires merge_queue operation"
            )
    elif (
        profile == "strict"
        and merge["operation"] == "merge_queue"
        and merge["base_proof"] not in ("none", "strict_queue_full_gate_binding")
    ):
        raise PlanInputError(
            "direct strict base proof cannot satisfy merge_queue operation"
        )
    if profile == "strict" and (
        not isinstance(merge["base_proof"], str)
        or merge["base_proof"] not in _PROOFS
    ):
        raise PlanInputError("merge.base_proof is unknown")
    booleans = keys - {
        "operation",
        "head_binding",
        "base_proof",
        "queue_bypass_rules",
    }
    for key in booleans:
        _boolean(merge[key], label=f"merge.{key}")
    if merge["operation"] == "merge_queue":
        if merge["queue_bypass_rules"] is not None:
            _boolean(merge["queue_bypass_rules"], label="merge.queue_bypass_rules")

    reasons: list[str] = []
    if merge["head_binding"] == "none":
        reasons.append("exact_reviewed_head_not_server_bound")
    if merge["admin_bypass_requested"]:
        reasons.append("admin_bypass_forbidden")
    if merge["operation"] == "merge_queue" and merge["queue_bypass_rules"] is not False:
        reasons.append("queue_bypass_rules_not_proven_false")

    if profile == "strict":
        if not merge["complete_bypass_audit"]:
            reasons.append("complete_bypass_audit_missing")
        if merge["configured_bypass"]:
            reasons.append("configured_bypass_present")
        proof = merge["base_proof"]
        if proof == "expected_base_precondition":
            pass
        elif proof == "repository_exact_base_guard":
            if not merge["actor_inventory_complete"]:
                reasons.append("actor_inventory_incomplete")
        elif proof == "monotonic_range_contraction":
            required = (
                "strict_freshness",
                "actor_inventory_complete",
                "same_ref_fast_forward_only",
                "no_delete",
                "exact_base_ref",
                "merge_base_equals_reviewed_base",
            )
            for key in required:
                if not merge[key]:
                    reasons.append(f"{key}_unproved")
        elif proof == "strict_queue_full_gate_binding":
            if not merge["actor_inventory_complete"]:
                reasons.append("actor_inventory_complete_unproved")
            if not (
                merge["all_invalidated_gates_on_required_merge_group"]
                or merge["non_bypassed_completion_hold"]
            ):
                reasons.append("strict_queue_gate_contract_unproved")
        else:
            reasons.append("strict_base_proof_missing")

    queue_binding = merge["operation"] == "merge_queue"
    return {
        "constraint_status": "satisfied" if not reasons else "blocked",
        "operation": merge["operation"],
        "profile": profile,
        "reasons": reasons,
        "residual_base_race": profile == "routine",
        "head_binding_type": (
            "persistent_queue_merge_async_sha"
            if queue_binding and merge["head_binding"] != "none"
            else "direct_match_head_commit"
            if not queue_binding and merge["head_binding"] == "match-head-commit"
            else "missing"
        ),
        "required_head_binding": (
            "PUT /repos/<owner>/<repo>/pulls/<number>/merge-async "
            '{"sha":"<exact-reviewed-head>","merge_action":"merge_queue",'
            '"bypass_rules":false}'
            if queue_binding
            else "--match-head-commit <exact-reviewed-head>"
        ),
        "admin_bypass_allowed": False,
    }


def build_plan(payload: Any) -> dict[str, Any]:
    """Return an evidence-revalidation plan, never a merge-ready verdict."""
    root = _closed_object(
        payload,
        keys={"profile", "changes", "evidence", "merge"},
        label="input",
    )
    profile = root["profile"]
    if profile not in ("routine", "strict"):
        raise PlanInputError("profile must be routine or strict")

    changes = _closed_object(
        root["changes"], keys=set(_CHANGE_KEYS), label="changes"
    )
    changed = {
        key for key in _CHANGE_KEYS if _boolean(changes[key], label=f"changes.{key}")
    }
    evidence = root["evidence"]
    if not isinstance(evidence, list):
        raise PlanInputError("evidence must be an array")

    invalidated: dict[str, list[str]] = {}
    preserved: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(evidence):
        record = _closed_object(
            item,
            keys={"id", "kind", "depends_on"},
            label=f"evidence[{index}]",
        )
        identity = record["id"]
        if not isinstance(identity, str) or not identity or identity in seen:
            raise PlanInputError(f"evidence[{index}].id must be unique non-empty text")
        seen.add(identity)
        kind = record["kind"]
        if not isinstance(kind, str) or kind not in _EVIDENCE_KINDS:
            raise PlanInputError(f"evidence[{index}].kind is unknown")
        dependencies = record["depends_on"]
        if not isinstance(dependencies, list) or any(
            not isinstance(dependency, str) or dependency not in _DEPENDENCIES
            for dependency in dependencies
        ):
            raise PlanInputError(f"evidence[{index}].depends_on is invalid")
        if len(set(dependencies)) != len(dependencies):
            raise PlanInputError(f"evidence[{index}].depends_on contains duplicates")
        if not dependencies:
            raise PlanInputError(f"evidence[{index}].depends_on cannot be empty")
        if kind == "head_only_provider" and dependencies != ["head"]:
            raise PlanInputError(
                f"evidence[{index}] head-only provider must depend exactly on head"
            )

        reasons = set(dependencies) & changed
        if "head" in changed and "local_range" in dependencies:
            reasons.add("head")
        if "merge_base" in changed and "local_range" in dependencies:
            reasons.add("merge_base")
        base_changed = bool(changed & {"base_ref", "base_tip", "merge_base"})
        if profile == "strict" and base_changed and kind == "readiness":
            reasons.add("strict_base_profile")
        if reasons:
            invalidated[identity] = sorted(reasons)
        else:
            preserved.append(identity)

    merge = _merge_constraints(profile, root["merge"])
    queue_binding = root["merge"]["operation"] == "merge_queue"
    if not queue_binding and (
        "merge_group" in changed
        or any("merge_group" in item["depends_on"] for item in evidence)
    ):
        raise PlanInputError("merge_group changes and evidence require merge_queue operation")
    base_changed = bool(changed & {"base_ref", "base_tip", "merge_base"})
    merge_group_changed = "merge_group" in changed
    if not queue_binding:
        queue_enrollment_action = "not_applicable"
    elif root["merge"]["head_binding"] == "none":
        queue_enrollment_action = "blocked_missing_persistent_head_binding"
    elif "head" in changed:
        queue_enrollment_action = "cancel_and_reenroll_after_head_change"
    elif profile == "strict" and base_changed:
        queue_enrollment_action = "cancel_and_reenroll_after_strict_base_rerun"
    elif "base_ref" in changed:
        queue_enrollment_action = "cancel_and_reenroll_after_base_retarget"
    elif root["merge"]["queue_bypass_rules"] is not False:
        queue_enrollment_action = "blocked_queue_bypass_rules_enabled_or_unknown"
    elif base_changed or merge_group_changed:
        if not invalidated or root["merge"]["all_invalidated_gates_on_required_merge_group"] or root["merge"]["non_bypassed_completion_hold"]:
            queue_enrollment_action = "retain_across_merge_group_rebuild"
        else:
            queue_enrollment_action = "cancel_and_reenroll_after_affected_evidence_revalidation"
    else:
        queue_enrollment_action = "retain_if_exact_head_binding_remains_current"
    if (
        queue_binding
        and merge["constraint_status"] != "satisfied"
        and not queue_enrollment_action.startswith("cancel_")
    ):
        queue_enrollment_action = "cancel_and_reenroll_after_merge_constraints_reacquired"

    global_invalidations = []
    if changed:
        global_invalidations.extend(
            ("pr_scope_and_final_reread", "readiness_decision")
        )
    if changed & {"base_ref", "base_tip", "merge_base"}:
        global_invalidations.append("merge_policy_snapshot")
    if queue_binding and changed:
        global_invalidations.append("current_merge_group_checks")

    return {
        "planning_only": True,
        "readiness_verdict": "not-evaluated",
        "profile": profile,
        "invalidated_evidence": invalidated,
        "preserved_evidence": sorted(preserved),
        "global_invalidations": global_invalidations,
        "merge_constraints": merge,
        "queue_enrollment_action": queue_enrollment_action,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="-", help="JSON file path or - for stdin")
    args = parser.parse_args()
    try:
        if args.input == "-":
            payload = json.load(sys.stdin)
        else:
            with open(args.input, encoding="utf-8") as source:
                payload = json.load(source)
        result = build_plan(payload)
    except (OSError, json.JSONDecodeError, PlanInputError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
