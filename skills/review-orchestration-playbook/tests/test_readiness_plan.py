from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
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


class ReadinessPlanTests(unittest.TestCase):
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
        self.assertFalse(result["merge_constraints"]["admin_bypass_allowed"])
        self.assertTrue(result["merge_constraints"]["residual_base_race"])
        payload["merge"]["configured_bypass"] = False  # type: ignore[index]
        with self.assertRaises(PlanInputError):
            build_plan(payload)

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


if __name__ == "__main__":
    unittest.main()
