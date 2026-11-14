from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.review_result import classify_review_result  # noqa: E402
from review_runtime.routine_review import classify, revalidation_plan  # noqa: E402


class ReviewResultDispositionTest(unittest.TestCase):
    def assertDisposition(
        self,
        raw_result: str,
        content_assessment: str,
        *,
        outcome: str,
        presentation: str,
    ) -> None:
        disposition = classify_review_result(
            raw_result,
            content_assessment=content_assessment,
        )
        self.assertEqual(disposition.raw_result, raw_result)
        self.assertEqual(disposition.review_outcome, outcome)
        self.assertEqual(disposition.presentation, presentation)

    def test_exact_and_outer_ascii_whitespace_sentinel_are_canonical_clean(
        self,
    ) -> None:
        for raw_result in (
            "No findings.",
            " \t\r\nNo findings.\r\n\v\f ",
        ):
            with self.subTest(raw_result=raw_result):
                self.assertDisposition(
                    raw_result,
                    "summary-only",
                    outcome="clean",
                    presentation="canonical-clean",
                )

    def test_crlf_positive_coverage_summary_is_extended_clean(self) -> None:
        self.assertDisposition(
            "Reviewed the changed error paths and focused tests.\r\nNo findings.\r\n",
            "summary-only",
            outcome="clean",
            presentation="extended-clean",
        )

    def test_actionable_finding_overrides_terminal_clean_sentinel(self) -> None:
        self.assertDisposition(
            "[P1] Retry state can be lost; persist it before return.\nNo findings.",
            "actionable-findings",
            outcome="findings",
            presentation="contradictory",
        )

    def test_uncertain_prefix_makes_terminal_sentinel_ambiguous(self) -> None:
        self.assertDisposition(
            "I could not confirm the cleanup behavior.\nNo findings.",
            "undetermined",
            outcome="undetermined",
            presentation="ambiguous",
        )

    def test_actionable_findings_without_sentinel_are_findings(self) -> None:
        self.assertDisposition(
            "[P2] The fallback skips validation on retry.",
            "actionable-findings",
            outcome="findings",
            presentation="findings",
        )

    def test_inline_quoted_and_nonfinal_sentinels_are_nonconforming(self) -> None:
        for raw_result in (
            "Summary: No findings.",
            '"No findings."',
            "> No findings.",
            "No findings.\nCoverage was not confirmed.",
        ):
            with self.subTest(raw_result=raw_result):
                self.assertDisposition(
                    raw_result,
                    "undetermined",
                    outcome="undetermined",
                    presentation="nonconforming",
                )

    def test_repeated_sentinel_is_not_a_clean_presentation(self) -> None:
        self.assertDisposition(
            "No findings.\nNo findings.",
            "summary-only",
            outcome="undetermined",
            presentation="nonconforming",
        )

    def test_unicode_separator_and_whitespace_are_not_ascii_trimmed(self) -> None:
        for raw_result in (
            "Coverage checked.\u2028No findings.",
            "\u00a0No findings.\u00a0",
        ):
            with self.subTest(raw_result=raw_result):
                self.assertDisposition(
                    raw_result,
                    "summary-only",
                    outcome="undetermined",
                    presentation="nonconforming",
                )

    def test_blank_result_is_rejected(self) -> None:
        for raw_result in ("", " \t\r\n\v\f"):
            with self.subTest(raw_result=raw_result):
                with self.assertRaises(ValueError):
                    classify_review_result(
                        raw_result,
                        content_assessment="undetermined",
                    )

    def test_unknown_assessment_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            classify_review_result(
                "No findings.",
                content_assessment="clean",  # type: ignore[arg-type]
            )

    def test_cli_preserves_exact_utf8_result_and_emits_disposition(self) -> None:
        raw_result = b"Reviewed the changed paths.\r\nNo findings.\r\n"
        completed = subprocess.run(
            (
                sys.executable,
                str(SCRIPTS / "review_runtime/review_result.py"),
                "--content-assessment",
                "summary-only",
            ),
            check=False,
            input=raw_result,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        disposition = json.loads(completed.stdout)
        self.assertEqual(disposition["raw_result"], raw_result.decode("utf-8"))
        self.assertEqual(disposition["review_outcome"], "clean")
        self.assertEqual(disposition["presentation"], "extended-clean")

    def test_cli_rejects_invalid_utf8(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                str(SCRIPTS / "review_runtime/review_result.py"),
                "--content-assessment",
                "undetermined",
            ),
            check=False,
            input=b"\xff",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"raw_result must be valid UTF-8", completed.stderr)



def assessment() -> dict:
    return {
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "code_outcome": "clean",
        "terminal_received": True,
        "scope_complete": True,
        "boundary_intact": True,
        "source_unchanged": True,
        "evidence_complete": True,
        "unresolved_execution_error": False,
        "diagnostics": [],
    }


def unit() -> dict:
    return {
        "base_sha": "a" * 40,
        "head_sha": "c" * 40,
        "reviewed_paths": ["src/client.cpp"],
        "dependency_paths": ["include/session.h", "AGENTS.md"],
        "changed_paths": ["docs/example.md"],
        "prior_clean": True,
        "dependencies_complete": True,
        "base_unchanged": True,
        "control_policy_unchanged": True,
    }


class RoutineReviewTest(unittest.TestCase):
    def test_recovered_read_and_transport_warnings_preserve_clean_review(self) -> None:
        record = assessment()
        record["diagnostics"] = [
            "Initial grep syntax failed; corrected query returned complete context.",
            "Stream reconnected; complete terminal message was retained.",
            "Equivalent read-only command form independently checked by parent.",
        ]
        result = classify(record)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["execution_status"], "complete-with-warnings")

    def test_real_evidence_gap_or_failed_transport_cannot_pass(self) -> None:
        for key, value in (
            ("terminal_received", False),
            ("scope_complete", False),
            ("evidence_complete", False),
            ("unresolved_execution_error", True),
        ):
            with self.subTest(key=key):
                record = assessment()
                record[key] = value
                self.assertFalse(classify(record)["accepted"])

    def test_source_replacement_and_boundary_failure_remain_invalid(self) -> None:
        for key in ("boundary_intact", "source_unchanged"):
            with self.subTest(key=key):
                record = assessment()
                record[key] = False
                result = classify(record)
                self.assertFalse(result["accepted"])
                self.assertEqual(result["execution_status"], "invalid")

    def test_findings_survive_an_incomplete_execution(self) -> None:
        record = assessment()
        record.update(code_outcome="findings", scope_complete=False, evidence_complete=False)
        result = classify(record)
        self.assertEqual(result["code_outcome"], "findings")
        self.assertEqual(result["execution_status"], "incomplete")
        self.assertFalse(result["accepted"])

    def test_no_findings_on_partial_scope_is_not_approval(self) -> None:
        record = assessment()
        record.update(code_outcome="incomplete", scope_complete=False)
        self.assertFalse(classify(record)["accepted"])

    def test_parent_records_are_not_mutated(self) -> None:
        for function, record in ((classify, assessment()), (revalidation_plan, unit())):
            before = copy.deepcopy(record)
            function(record)
            self.assertEqual(record, before)

    def test_unrelated_documentation_change_retains_unit_only(self) -> None:
        result = revalidation_plan(unit())
        self.assertEqual(result["action"], "retain-unit-evidence")
        self.assertTrue(result["current_head_integration_required"])
        self.assertFalse(result["current_head_approved"])

    def test_source_dependency_and_convention_changes_require_review(self) -> None:
        for path in ("src/client.cpp", "include/session.h", "AGENTS.md"):
            with self.subTest(path=path):
                record = unit()
                record["changed_paths"] = [path]
                result = revalidation_plan(record)
                self.assertEqual(result["action"], "review-unit")
                self.assertEqual(result["affected_paths"], [path])

    def test_rename_accounts_for_removed_and_added_names(self) -> None:
        record = unit()
        record["changed_paths"] = ["src/client.cpp", "src/client_mac.cpp"]
        self.assertEqual(revalidation_plan(record)["action"], "review-unit")

    def test_unknown_dependencies_changed_base_or_policy_force_review(self) -> None:
        for key in (
            "prior_clean", "dependencies_complete", "base_unchanged", "control_policy_unchanged"
        ):
            with self.subTest(key=key):
                record = unit()
                record[key] = False
                self.assertEqual(revalidation_plan(record)["action"], "review-unit")

    def test_sha256_object_ids_are_supported(self) -> None:
        record = assessment()
        record.update(base_sha="a" * 64, head_sha="b" * 64)
        self.assertTrue(classify(record)["accepted"])

    def test_invalid_scope_or_boolean_is_rejected(self) -> None:
        for key, value in (("head_sha", "HEAD"), ("scope_complete", 1), ("boundary_intact", "true")):
            with self.subTest(key=key):
                record = assessment()
                record[key] = value
                with self.assertRaises(ValueError):
                    classify(record)

    def test_invalid_dependency_paths_cannot_enable_reuse(self) -> None:
        for path in ("/etc/config", "../src/client.cpp", "src//client.cpp", "src/./client.cpp"):
            with self.subTest(path=path):
                record = unit()
                record["dependency_paths"] = [path]
                with self.assertRaises(ValueError):
                    revalidation_plan(record)

    def test_real_cli_uses_parent_input_and_returns_separate_dispositions(self) -> None:
        script = SCRIPTS / "review_runtime" / "routine_review.py"
        for operation, record in (("classify", assessment()), ("revalidate", unit())):
            with self.subTest(operation=operation):
                result = subprocess.run(
                    [sys.executable, "-B", str(script), operation],
                    input=json.dumps(record).encode(),
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                output = json.loads(result.stdout)
                if operation == "classify":
                    self.assertTrue(output["accepted"])
                else:
                    self.assertFalse(output["current_head_approved"])


if __name__ == "__main__":
    unittest.main()
