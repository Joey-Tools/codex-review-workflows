from __future__ import annotations

import copy
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from readiness_plan import PlanInputError, build_plan  # noqa: E402


def _payload() -> dict[str, object]:
    return {
        "profile": "routine",
        "changes": {
            "head": False,
            "base_ref": False,
            "base_tip": False,
            "merge_base": False,
            "merge_group": False,
        },
        "evidence": [
            {
                "id": "provider",
                "kind": "head_only_provider",
                "depends_on": ["head"],
            },
            {
                "id": "range_review",
                "kind": "readiness",
                "depends_on": ["head", "local_range"],
            },
            {
                "id": "base_sensitive_test",
                "kind": "readiness",
                "depends_on": ["head", "base_tip"],
            },
            {
                "id": "head_check",
                "kind": "readiness",
                "depends_on": ["head"],
            },
            {
                "id": "base_branch_rule",
                "kind": "readiness",
                "depends_on": ["base_ref"],
            },
        ],
        "merge": {
            "operation": "direct",
            "head_binding": "match-head-commit",
            "admin_bypass_requested": False,
        },
    }


def _strict_profile(payload: dict[str, object]) -> None:
    payload["profile"] = "strict"
    payload["merge"].update(  # type: ignore[union-attr]
        {
            "base_proof": "none",
            "strict_freshness": False,
            "complete_bypass_audit": False,
            "configured_bypass": False,
            "actor_inventory_complete": False,
            "same_ref_fast_forward_only": False,
            "no_delete": False,
            "exact_base_ref": False,
            "merge_base_equals_reviewed_base": False,
        }
    )
    if payload["merge"]["operation"] == "merge_queue":  # type: ignore[index]
        _queue_profile(payload)


def _queue_profile(
    payload: dict[str, object],
    *,
    bypass_rules: bool | None = False,
    required_group: bool = False,
    completion_hold: bool = False,
) -> None:
    payload["merge"].update(  # type: ignore[union-attr]
        {
            "operation": "merge_queue",
            "head_binding": "persistent-queue-merge-async-sha",
            "all_invalidated_gates_on_required_merge_group": required_group,
            "non_bypassed_completion_hold": completion_hold,
            "queue_bypass_rules": bypass_rules,
        }
    )


class ReadinessPlanTests(unittest.TestCase):
    def test_documented_queue_actions_match_reachable_behavior(self) -> None:
        reference = (SCRIPTS.parent / "references" / "pr-readiness.md").read_text()
        action_contract = reference.split("Its `queue_enrollment_action` is one of", 1)[1].split("The caller must inspect", 1)[0]
        documented = set(re.findall(r"`([^`]+)`", action_contract))
        observed = {build_plan(_payload())["queue_enrollment_action"]}
        for strict, change, minimal_evidence in (
            (False, None, False),
            (False, "base_tip", True),
            (False, "base_ref", False),
            (False, "head", False),
            (True, "base_tip", False),
            (False, "base_tip", False),
            (True, None, False),
        ):
            with self.subTest(strict=strict, change=change, minimal=minimal_evidence):
                payload = _payload()
                _queue_profile(payload)
                if strict:
                    _strict_profile(payload)
                if change:
                    payload["changes"][change] = True  # type: ignore[index]
                if minimal_evidence:
                    payload["evidence"] = [{"id": "provider", "kind": "head_only_provider", "depends_on": ["head"]}]
                action = build_plan(payload)["queue_enrollment_action"]
                self.assertIn(action, documented)
                observed.add(action)
        covered_queue = _payload()
        _queue_profile(covered_queue, required_group=True)
        covered_queue["changes"]["base_tip"] = True  # type: ignore[index]
        observed.add(build_plan(covered_queue)["queue_enrollment_action"])
        self.assertEqual(documented, observed)

    def test_base_tip_change_rechecks_only_dependent_evidence_by_default(self) -> None:
        payload = _payload()
        payload["changes"]["base_tip"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(result["readiness_verdict"], "not-evaluated")
        self.assertEqual(
            result["invalidated_evidence"],
            {"base_sensitive_test": ["base_tip"]},
        )
        self.assertEqual(
            result["preserved_evidence"],
            ["base_branch_rule", "head_check", "provider", "range_review"],
        )
        self.assertEqual(
            result["global_invalidations"],
            [
                "pr_scope_and_final_reread",
                "readiness_decision",
                "merge_policy_snapshot",
            ],
        )
        self.assertTrue(result["merge_constraints"]["residual_base_race"])

    def test_base_ref_retarget_invalidates_ref_dependent_evidence(self) -> None:
        payload = _payload()
        payload["changes"]["base_ref"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["invalidated_evidence"], {"base_branch_rule": ["base_ref"]}
        )
        self.assertIn("provider", result["preserved_evidence"])
        self.assertIn("range_review", result["preserved_evidence"])

    def test_merge_base_change_invalidates_local_range_but_reuses_head_lane(self) -> None:
        payload = _payload()
        payload["changes"]["merge_base"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["invalidated_evidence"],
            {"range_review": ["merge_base"]},
        )
        self.assertIn("provider", result["preserved_evidence"])
        self.assertIn("head_check", result["preserved_evidence"])

    def test_head_change_invalidates_head_bound_review_and_evidence(self) -> None:
        payload = _payload()
        payload["changes"]["head"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["invalidated_evidence"],
            {
                "base_sensitive_test": ["head"],
                "head_check": ["head"],
                "provider": ["head"],
                "range_review": ["head"],
            },
        )

    def test_strict_profile_keeps_full_base_invalidation_and_head_only_reuse(self) -> None:
        payload = _payload()
        _strict_profile(payload)
        payload["changes"]["base_tip"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            set(result["invalidated_evidence"]),
            {"base_branch_rule", "base_sensitive_test", "head_check", "range_review"},
        )
        self.assertEqual(result["preserved_evidence"], ["provider"])

    def test_routine_merge_uses_exact_head_without_base_audit_or_admin_bypass(self) -> None:
        payload = _payload()

        result = build_plan(payload)

        self.assertEqual(
            result["merge_constraints"]["constraint_status"], "satisfied"
        )
        self.assertEqual(
            result["merge_constraints"]["required_head_binding"],
            "--match-head-commit <exact-reviewed-head>",
        )
        self.assertEqual(
            result["merge_constraints"]["head_binding_type"],
            "direct_match_head_commit",
        )
        self.assertFalse(result["merge_constraints"]["admin_bypass_allowed"])
        self.assertTrue(result["merge_constraints"]["residual_base_race"])
        payload["merge"]["configured_bypass"] = False  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(payload)

    def test_queue_binding_survives_routine_base_rebuild_but_strict_reenrolls(self) -> None:
        payload = _payload()
        _queue_profile(payload, required_group=True)
        payload["evidence"] = [  # type: ignore[assignment]
            item for item in payload["evidence"]
            if item["id"] == "provider" or item["id"] == "head_check"
        ]
        payload["changes"]["base_tip"] = True  # type: ignore[index]

        routine = build_plan(payload)

        self.assertEqual(
            routine["merge_constraints"]["constraint_status"], "satisfied"
        )
        self.assertEqual(
            routine["merge_constraints"]["head_binding_type"],
            "persistent_queue_merge_async_sha",
        )
        self.assertEqual(routine["merge_constraints"]["operation"], "merge_queue")
        self.assertIn("merge-async", routine["merge_constraints"]["required_head_binding"])
        self.assertIn('"bypass_rules":false', routine["merge_constraints"]["required_head_binding"])
        self.assertEqual(
            routine["queue_enrollment_action"], "retain_across_merge_group_rebuild"
        )
        self.assertIn("current_merge_group_checks", routine["global_invalidations"])

        routine_retarget = copy.deepcopy(payload)
        routine_retarget["changes"]["base_ref"] = True  # type: ignore[index]
        self.assertEqual(
            build_plan(routine_retarget)["queue_enrollment_action"],
            "cancel_and_reenroll_after_base_retarget",
        )

        routine_head_change = copy.deepcopy(payload)
        routine_head_change["changes"]["base_tip"] = False  # type: ignore[index]
        routine_head_change["changes"]["head"] = True  # type: ignore[index]
        self.assertEqual(
            build_plan(routine_head_change)["queue_enrollment_action"],
            "cancel_and_reenroll_after_head_change",
        )

        _strict_profile(payload)
        payload["merge"]["all_invalidated_gates_on_required_merge_group"] = True  # type: ignore[index]
        strict = build_plan(payload)
        self.assertEqual(
            strict["queue_enrollment_action"],
            "cancel_and_reenroll_after_strict_base_rerun",
        )

        payload["changes"]["head"] = True  # type: ignore[index]
        head_change = build_plan(payload)
        self.assertEqual(
            head_change["queue_enrollment_action"],
            "cancel_and_reenroll_after_head_change",
        )

    def test_queue_rebuild_requires_non_bypassed_request_details(self) -> None:
        for bypass_rules in (True, None):
            with self.subTest(bypass_rules=bypass_rules):
                payload = _payload()
                _queue_profile(payload, bypass_rules=bypass_rules)
                payload["changes"]["base_tip"] = True  # type: ignore[index]
                result = build_plan(payload)
                self.assertEqual(result["merge_constraints"]["constraint_status"], "blocked")
                self.assertIn(
                    "queue_bypass_rules_not_proven_false",
                    result["merge_constraints"]["reasons"],
                )
                self.assertEqual(
                    result["queue_enrollment_action"],
                    "cancel_and_reenroll_after_merge_constraints_reacquired",
                )

        payload = _payload()
        _queue_profile(payload, bypass_rules=False)
        payload["changes"]["base_tip"] = True  # type: ignore[index]
        self.assertEqual(
            build_plan(payload)["queue_enrollment_action"],
            "cancel_and_reenroll_after_affected_evidence_revalidation",
        )

    def test_queue_retention_requires_satisfied_merge_constraints(self) -> None:
        unchanged = _payload()
        _queue_profile(unchanged)
        self.assertEqual(
            build_plan(unchanged)["queue_enrollment_action"],
            "retain_if_exact_head_binding_remains_current",
        )

        for bypass_rules in (True, None):
            with self.subTest(routine_bypass_rules=bypass_rules):
                blocked = _payload()
                _queue_profile(blocked, bypass_rules=bypass_rules)
                result = build_plan(blocked)
                self.assertEqual(result["merge_constraints"]["constraint_status"], "blocked")
                self.assertEqual(
                    result["queue_enrollment_action"],
                    "cancel_and_reenroll_after_merge_constraints_reacquired",
                )

        missing_head_binding = _payload()
        _queue_profile(missing_head_binding)
        missing_head_binding["merge"]["head_binding"] = "none"  # type: ignore[index]
        result = build_plan(missing_head_binding)
        self.assertEqual(result["merge_constraints"]["constraint_status"], "blocked")
        self.assertEqual(
            result["queue_enrollment_action"],
            "cancel_and_reenroll_after_merge_constraints_reacquired",
        )

        strict_missing_proof = _payload()
        _queue_profile(strict_missing_proof)
        _strict_profile(strict_missing_proof)
        result = build_plan(strict_missing_proof)
        self.assertEqual(result["merge_constraints"]["constraint_status"], "blocked")
        self.assertIn("complete_bypass_audit_missing", result["merge_constraints"]["reasons"])
        self.assertIn("strict_base_proof_missing", result["merge_constraints"]["reasons"])
        self.assertEqual(
            result["queue_enrollment_action"],
            "cancel_and_reenroll_after_merge_constraints_reacquired",
        )

        strict_with_held_gate_but_bypass = _payload()
        _queue_profile(strict_with_held_gate_but_bypass, completion_hold=True)
        _strict_profile(strict_with_held_gate_but_bypass)
        strict_with_held_gate_but_bypass["merge"]["complete_bypass_audit"] = True  # type: ignore[index]
        strict_with_held_gate_but_bypass["merge"]["actor_inventory_complete"] = True  # type: ignore[index]
        strict_with_held_gate_but_bypass["merge"]["base_proof"] = "strict_queue_full_gate_binding"  # type: ignore[index]
        strict_with_held_gate_but_bypass["merge"]["non_bypassed_completion_hold"] = True  # type: ignore[index]
        strict_with_held_gate_but_bypass["merge"]["configured_bypass"] = True  # type: ignore[index]
        strict_with_held_gate_but_bypass["evidence"].append(  # type: ignore[union-attr]
            {"id": "group-gate", "kind": "readiness", "depends_on": ["merge_group"]}
        )
        strict_with_held_gate_but_bypass["changes"]["merge_group"] = True  # type: ignore[index]
        result = build_plan(strict_with_held_gate_but_bypass)
        self.assertEqual(result["merge_constraints"]["constraint_status"], "blocked")
        self.assertIn("configured_bypass_present", result["merge_constraints"]["reasons"])
        self.assertEqual(
            result["queue_enrollment_action"],
            "cancel_and_reenroll_after_merge_constraints_reacquired",
        )

        direct = _payload()
        _strict_profile(direct)
        self.assertEqual(build_plan(direct)["queue_enrollment_action"], "not_applicable")

    def test_queue_rebuild_retains_only_when_invalidated_gates_are_covered(self) -> None:
        for evidence in ("base_sensitive_test",):
            for required_group, completion_hold in ((True, False), (False, True)):
                with self.subTest(required_group=required_group, hold=completion_hold):
                    payload = _payload()
                    _queue_profile(
                        payload,
                        required_group=required_group,
                        completion_hold=completion_hold,
                    )
                    payload["changes"]["base_tip"] = True  # type: ignore[index]
                    self.assertIn(
                        evidence,
                        build_plan(payload)["invalidated_evidence"],
                    )
                    self.assertEqual(
                        build_plan(payload)["queue_enrollment_action"],
                        "retain_across_merge_group_rebuild",
                    )

        no_out_of_band = _payload()
        _queue_profile(no_out_of_band)
        no_out_of_band["evidence"] = [  # type: ignore[assignment]
            item for item in no_out_of_band["evidence"] if item["id"] == "provider"
        ]
        no_out_of_band["changes"]["base_tip"] = True  # type: ignore[index]
        self.assertEqual(
            build_plan(no_out_of_band)["queue_enrollment_action"],
            "cancel_and_reenroll_after_global_gate_revalidation",
        )

    def test_global_gates_block_uncovered_empty_or_head_only_queue_retention(self) -> None:
        for dimension in ("base_tip", "merge_base", "merge_group"):
            for evidence in (
                [],
                [{"id": "provider", "kind": "head_only_provider", "depends_on": ["head"]}],
            ):
                with self.subTest(dimension=dimension, evidence=evidence):
                    payload = _payload()
                    _queue_profile(payload)
                    payload["evidence"] = copy.deepcopy(evidence)
                    payload["changes"][dimension] = True  # type: ignore[index]

                    result = build_plan(payload)

                    self.assertEqual(result["invalidated_evidence"], {})
                    self.assertTrue(result["global_invalidations"])
                    self.assertEqual(
                        result["queue_enrollment_action"],
                        "cancel_and_reenroll_after_global_gate_revalidation",
                    )

        for dimension in ("base_tip", "merge_base", "merge_group"):
            for required_group, completion_hold in ((True, False), (False, True)):
                with self.subTest(
                    dimension=dimension,
                    required_group=required_group,
                    completion_hold=completion_hold,
                ):
                    payload = _payload()
                    _queue_profile(
                        payload,
                        required_group=required_group,
                        completion_hold=completion_hold,
                    )
                    payload["evidence"] = [
                        {"id": "provider", "kind": "head_only_provider", "depends_on": ["head"]}
                    ]
                    payload["changes"][dimension] = True  # type: ignore[index]

                    result = build_plan(payload)

                    self.assertTrue(result["global_invalidations"])
                    self.assertEqual(
                        result["queue_enrollment_action"],
                        "retain_across_merge_group_rebuild",
                    )

        direct = _payload()
        direct["changes"]["base_tip"] = True  # type: ignore[index]
        result = build_plan(direct)
        self.assertIn("pr_scope_and_final_reread", result["global_invalidations"])
        self.assertEqual(result["queue_enrollment_action"], "not_applicable")

    def test_strict_queue_retarget_uses_full_strict_action_and_head_wins(self) -> None:
        payload = _payload()
        _queue_profile(payload, required_group=True)
        _strict_profile(payload)
        payload["merge"]["all_invalidated_gates_on_required_merge_group"] = True  # type: ignore[index]
        payload["merge"]["complete_bypass_audit"] = True  # type: ignore[index]
        payload["merge"]["actor_inventory_complete"] = True  # type: ignore[index]
        payload["merge"]["base_proof"] = "strict_queue_full_gate_binding"  # type: ignore[index]
        payload["changes"]["base_ref"] = True  # type: ignore[index]
        strict_retarget = build_plan(payload)
        self.assertEqual(strict_retarget["merge_constraints"]["constraint_status"], "satisfied")
        self.assertEqual(
            strict_retarget["queue_enrollment_action"],
            "cancel_and_reenroll_after_strict_base_rerun",
        )

        payload["changes"]["head"] = True  # type: ignore[index]
        self.assertEqual(
            build_plan(payload)["queue_enrollment_action"],
            "cancel_and_reenroll_after_head_change",
        )

    def test_merge_group_change_invalidates_group_evidence_without_base_change(self) -> None:
        payload = _payload()
        _queue_profile(payload)
        payload["evidence"].append(  # type: ignore[union-attr]
            {
                "id": "old-merge-group-check",
                "kind": "readiness",
                "depends_on": ["merge_group"],
            }
        )
        payload["changes"]["merge_group"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["invalidated_evidence"],
            {"old-merge-group-check": ["merge_group"]},
        )
        self.assertIn("provider", result["preserved_evidence"])
        self.assertIn("head_check", result["preserved_evidence"])
        self.assertIn("current_merge_group_checks", result["global_invalidations"])
        self.assertEqual(
            result["queue_enrollment_action"],
            "cancel_and_reenroll_after_affected_evidence_revalidation",
        )

        no_group_sensitive = _payload()
        _queue_profile(no_group_sensitive)
        no_group_sensitive["changes"]["merge_group"] = True  # type: ignore[index]
        no_group_plan = build_plan(no_group_sensitive)
        self.assertEqual(no_group_plan["invalidated_evidence"], {})
        self.assertIn(
            "current_merge_group_checks", no_group_plan["global_invalidations"]
        )
        self.assertEqual(
            no_group_plan["queue_enrollment_action"],
            "cancel_and_reenroll_after_global_gate_revalidation",
        )

    def test_merge_group_sensitive_queue_gates_need_coverage_or_hold(self) -> None:
        for required_group, completion_hold in ((True, False), (False, True)):
            with self.subTest(required_group=required_group, hold=completion_hold):
                payload = _payload()
                _queue_profile(
                    payload,
                    required_group=required_group,
                    completion_hold=completion_hold,
                )
                payload["evidence"].append(  # type: ignore[union-attr]
                    {
                        "id": "group-bound-validation",
                        "kind": "readiness",
                        "depends_on": ["merge_group"],
                    }
                )
                payload["changes"]["merge_group"] = True  # type: ignore[index]

                result = build_plan(payload)

                self.assertEqual(
                    result["queue_enrollment_action"],
                    "retain_across_merge_group_rebuild",
                )

        strict = _payload()
        _queue_profile(strict)
        _strict_profile(strict)
        strict["merge"]["complete_bypass_audit"] = True  # type: ignore[index]
        strict["merge"]["actor_inventory_complete"] = True  # type: ignore[index]
        strict["merge"]["base_proof"] = "strict_queue_full_gate_binding"  # type: ignore[index]
        strict["evidence"].append(  # type: ignore[union-attr]
            {
                "id": "group-bound-validation",
                "kind": "readiness",
                "depends_on": ["merge_group"],
            }
        )
        strict["changes"]["merge_group"] = True  # type: ignore[index]
        unheld = build_plan(strict)
        self.assertEqual(unheld["merge_constraints"]["constraint_status"], "blocked")
        self.assertEqual(
            unheld["queue_enrollment_action"],
            "cancel_and_reenroll_after_affected_evidence_revalidation",
        )
        strict["merge"]["non_bypassed_completion_hold"] = True  # type: ignore[index]
        strict_result = build_plan(strict)
        self.assertEqual(
            strict_result["merge_constraints"]["constraint_status"], "satisfied"
        )
        self.assertEqual(
            strict_result["queue_enrollment_action"],
            "retain_across_merge_group_rebuild",
        )

    def test_merge_group_change_is_queue_specific(self) -> None:
        payload = _payload()
        payload["changes"]["merge_group"] = True  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(payload)

        evidence_only = _payload()
        evidence_only["evidence"].append(  # type: ignore[union-attr]
            {
                "id": "group-bound-validation",
                "kind": "readiness",
                "depends_on": ["merge_group"],
            }
        )
        with self.assertRaises(PlanInputError):
            build_plan(evidence_only)

    def test_head_change_invalidates_positive_results_not_applicable_findings(self) -> None:
        payload = _payload()
        payload["changes"]["head"] = True  # type: ignore[index]
        result = build_plan(payload)
        self.assertEqual(result["readiness_verdict"], "not-evaluated")
        self.assertEqual(
            set(result["invalidated_evidence"]),
            {"base_sensitive_test", "head_check", "provider", "range_review"},
        )

        negative_in_positive_array = _payload()
        negative_in_positive_array["evidence"].append(  # type: ignore[union-attr]
            {"id": "unresolved-finding", "kind": "negative_provider_finding", "depends_on": ["head"]}
        )
        with self.assertRaises(PlanInputError):
            build_plan(negative_in_positive_array)

    def test_direct_and_queue_operations_reject_wrong_or_missing_head_binding(self) -> None:
        for operation, wrong_binding in (
            ("direct", "persistent-queue-merge-async-sha"),
            ("merge_queue", "match-head-commit"),
        ):
            with self.subTest(operation=operation, case="wrong"):
                payload = _payload()
                if operation == "merge_queue":
                    _queue_profile(payload)
                payload["merge"]["operation"] = operation  # type: ignore[index]
                payload["merge"]["head_binding"] = wrong_binding  # type: ignore[index]
                with self.assertRaisesRegex(PlanInputError, "does not match"):
                    build_plan(payload)

            with self.subTest(operation=operation, case="missing"):
                payload = _payload()
                if operation == "merge_queue":
                    _queue_profile(payload)
                else:
                    payload["merge"]["operation"] = operation  # type: ignore[index]
                payload["merge"]["head_binding"] = "none"  # type: ignore[index]
                constraints = build_plan(payload)["merge_constraints"]
                self.assertEqual(constraints["constraint_status"], "blocked")
                self.assertIn(
                    "exact_reviewed_head_not_server_bound", constraints["reasons"]
                )
                if operation == "merge_queue":
                    self.assertEqual(
                        build_plan(payload)["queue_enrollment_action"],
                        "cancel_and_reenroll_after_merge_constraints_reacquired",
                    )

            with self.subTest(operation=operation, case="omitted"):
                payload = _payload()
                if operation == "merge_queue":
                    _queue_profile(payload)
                else:
                    payload["merge"]["operation"] = operation  # type: ignore[index]
                del payload["merge"]["head_binding"]  # type: ignore[index]
                with self.assertRaises(PlanInputError):
                    build_plan(payload)

    def test_strict_queue_requires_queue_specific_full_gate_proof(self) -> None:
        payload = _payload()
        payload["merge"]["operation"] = "merge_queue"  # type: ignore[index]
        _strict_profile(payload)
        payload["merge"]["head_binding"] = "persistent-queue-merge-async-sha"  # type: ignore[index]
        payload["merge"]["base_proof"] = "strict_queue_full_gate_binding"  # type: ignore[index]
        payload["merge"]["complete_bypass_audit"] = True  # type: ignore[index]
        payload["merge"]["actor_inventory_complete"] = True  # type: ignore[index]
        payload["merge"]["all_invalidated_gates_on_required_merge_group"] = True  # type: ignore[index]
        payload["changes"]["base_tip"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["merge_constraints"]["constraint_status"], "satisfied"
        )
        self.assertEqual(
            result["queue_enrollment_action"],
            "cancel_and_reenroll_after_strict_base_rerun",
        )

        payload["merge"]["all_invalidated_gates_on_required_merge_group"] = False  # type: ignore[index]
        blocked = build_plan(payload)
        self.assertEqual(blocked["merge_constraints"]["constraint_status"], "blocked")
        self.assertIn(
            "strict_queue_gate_contract_unproved",
            blocked["merge_constraints"]["reasons"],
        )

        payload["merge"]["non_bypassed_completion_hold"] = True  # type: ignore[index]
        held = build_plan(payload)
        self.assertEqual(held["merge_constraints"]["constraint_status"], "satisfied")

        payload["merge"]["operation"] = "direct"  # type: ignore[index]
        payload["merge"]["head_binding"] = "match-head-commit"  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(payload)

        direct = _payload()
        _strict_profile(direct)
        direct["merge"]["base_proof"] = "strict_queue_full_gate_binding"  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(direct)

        queue_with_direct_proof = _payload()
        queue_with_direct_proof["merge"]["operation"] = "merge_queue"  # type: ignore[index]
        _strict_profile(queue_with_direct_proof)
        queue_with_direct_proof["merge"]["head_binding"] = "persistent-queue-merge-async-sha"  # type: ignore[index]
        queue_with_direct_proof["merge"]["base_proof"] = "monotonic_range_contraction"  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(queue_with_direct_proof)

    def test_strict_merge_requires_complete_base_proof_and_bypass_audit(self) -> None:
        payload = _payload()
        _strict_profile(payload)
        payload["merge"]["base_proof"] = "monotonic_range_contraction"  # type: ignore[index]
        payload["merge"]["strict_freshness"] = True  # type: ignore[index]
        payload["merge"]["complete_bypass_audit"] = True  # type: ignore[index]
        payload["merge"]["actor_inventory_complete"] = True  # type: ignore[index]
        payload["merge"]["same_ref_fast_forward_only"] = True  # type: ignore[index]
        payload["merge"]["no_delete"] = True  # type: ignore[index]
        payload["merge"]["exact_base_ref"] = True  # type: ignore[index]
        payload["merge"]["merge_base_equals_reviewed_base"] = True  # type: ignore[index]

        result = build_plan(payload)

        self.assertEqual(
            result["merge_constraints"]["constraint_status"], "satisfied"
        )

        payload["merge"]["actor_inventory_complete"] = False  # type: ignore[index]
        missing_actor_audit = build_plan(payload)
        self.assertEqual(
            missing_actor_audit["merge_constraints"]["constraint_status"], "blocked"
        )
        self.assertIn(
            "actor_inventory_complete_unproved",
            missing_actor_audit["merge_constraints"]["reasons"],
        )

        payload["merge"]["configured_bypass"] = True  # type: ignore[index]
        blocked = build_plan(payload)
        self.assertEqual(blocked["merge_constraints"]["constraint_status"], "blocked")
        self.assertIn(
            "configured_bypass_present", blocked["merge_constraints"]["reasons"]
        )

    def test_admin_bypass_and_missing_exact_head_binding_block_both_profiles(self) -> None:
        for profile in ("routine", "strict"):
            with self.subTest(profile=profile):
                payload = _payload()
                if profile == "strict":
                    _strict_profile(payload)
                else:
                    payload["profile"] = profile
                payload["merge"]["admin_bypass_requested"] = True  # type: ignore[index]
                payload["merge"]["head_binding"] = "none"  # type: ignore[index]

                constraints = build_plan(payload)["merge_constraints"]

                self.assertEqual(constraints["constraint_status"], "blocked")
                self.assertIn("admin_bypass_forbidden", constraints["reasons"])
                self.assertIn(
                    "exact_reviewed_head_not_server_bound", constraints["reasons"]
                )

    def test_missing_unknown_and_duplicate_fields_fail_closed(self) -> None:
        mutations = []
        missing = _payload()
        del missing["changes"]["base_tip"]  # type: ignore[index]
        mutations.append(missing)
        unknown = _payload()
        unknown["unexpected"] = True
        mutations.append(unknown)
        missing_operation = _payload()
        del missing_operation["merge"]["operation"]  # type: ignore[index]
        mutations.append(missing_operation)
        unknown_operation = _payload()
        unknown_operation["merge"]["operation"] = "auto_merge"  # type: ignore[index]
        mutations.append(unknown_operation)
        invalid_binding_type = _payload()
        invalid_binding_type["merge"]["head_binding"] = []  # type: ignore[index]
        mutations.append(invalid_binding_type)
        bad_dependency = _payload()
        bad_dependency["evidence"][0]["depends_on"] = ["unknown"]  # type: ignore[index]
        mutations.append(bad_dependency)
        missing_dependencies = _payload()
        missing_dependencies["evidence"][0]["depends_on"] = []  # type: ignore[index]
        mutations.append(missing_dependencies)
        head_provider_missing_head = _payload()
        head_provider_missing_head["evidence"][0]["depends_on"] = ["base_tip"]  # type: ignore[index]
        mutations.append(head_provider_missing_head)
        head_provider_extra_dependency = _payload()
        head_provider_extra_dependency["evidence"][0]["depends_on"] = [
            "head",
            "base_tip",
        ]  # type: ignore[index]
        mutations.append(head_provider_extra_dependency)
        bad_kind = _payload()
        bad_kind["evidence"][0]["kind"] = []  # type: ignore[index]
        mutations.append(bad_kind)
        bad_proof = _payload()
        _strict_profile(bad_proof)
        bad_proof["merge"]["base_proof"] = []  # type: ignore[index]
        mutations.append(bad_proof)
        missing_strict_audit = _payload()
        _strict_profile(missing_strict_audit)
        del missing_strict_audit["merge"]["complete_bypass_audit"]  # type: ignore[index]
        mutations.append(missing_strict_audit)
        duplicate = _payload()
        duplicate["evidence"].append(copy.deepcopy(duplicate["evidence"][0]))  # type: ignore[union-attr]
        mutations.append(duplicate)

        for payload in mutations:
            with self.subTest(payload=payload):
                with self.assertRaises(PlanInputError):
                    build_plan(payload)

    def test_json_cli_emits_a_plan_and_rejects_incomplete_input(self) -> None:
        command = [sys.executable, "-B", str(SCRIPTS / "readiness_plan.py")]
        completed = subprocess.run(
            command,
            input=json.dumps(_payload()),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["planning_only"])

        incomplete = _payload()
        del incomplete["changes"]["base_tip"]  # type: ignore[index]
        rejected = subprocess.run(
            command,
            input=json.dumps(incomplete),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("changes must contain exactly", rejected.stderr)

    def test_json_cli_rejects_duplicate_keys_from_stdin_and_file(self) -> None:
        command = [sys.executable, "-B", str(SCRIPTS / "readiness_plan.py")]
        payload = _payload()
        _queue_profile(payload)
        valid = json.dumps(payload, separators=(",", ":"))
        duplicate_inputs = {
            "root_key": valid.replace(
                '"profile":"routine"',
                '"profile":"routine","profile":"routine"',
                1,
            ),
            "evidence_duplicate_id": valid.replace(
                '"id":"provider"', '"id":"provider","id":"provider"', 1
            ),
            "evidence_duplicate_dependencies": valid.replace(
                '"depends_on":["head"]',
                '"depends_on":["head"],"depends_on":["head"]',
                1,
            ),
            "nested_change_true_then_false": valid.replace(
                '"head":false', '"head":true,"head":false', 1
            ),
            "nested_change_false_then_true": valid.replace(
                '"head":false', '"head":false,"head":true', 1
            ),
            "bypass_false_then_true": valid.replace(
                '"queue_bypass_rules":false',
                '"queue_bypass_rules":false,"queue_bypass_rules":true',
                1,
            ),
            "bypass_true_then_false": valid.replace(
                '"queue_bypass_rules":false',
                '"queue_bypass_rules":true,"queue_bypass_rules":false',
                1,
            ),
        }
        self.assertTrue(all(text != valid for text in duplicate_inputs.values()))

        with tempfile.TemporaryDirectory(prefix="readiness-plan-duplicate-") as temporary:
            input_path = pathlib.Path(temporary) / "input.json"
            for input_kind in ("stdin", "file"):
                valid_command = command
                if input_kind == "file":
                    input_path.write_text(valid, encoding="utf-8")
                    valid_command = [*command, "--input", str(input_path)]
                valid_result = subprocess.run(
                    valid_command,
                    input=valid if input_kind == "stdin" else None,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(valid_result.returncode, 0, valid_result.stderr)
                self.assertTrue(json.loads(valid_result.stdout)["planning_only"])

                for label, duplicate_text in duplicate_inputs.items():
                    with self.subTest(input_kind=input_kind, duplicate=label):
                        if input_kind == "file":
                            input_path.write_text(duplicate_text, encoding="utf-8")
                            duplicate_command = [*command, "--input", str(input_path)]
                            stdin_text = None
                        else:
                            duplicate_command = command
                            stdin_text = duplicate_text
                        rejected = subprocess.run(
                            duplicate_command,
                            input=stdin_text,
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(rejected.returncode, 2)
                        self.assertEqual(rejected.stdout, "")
                        self.assertIn("duplicate JSON object key", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
