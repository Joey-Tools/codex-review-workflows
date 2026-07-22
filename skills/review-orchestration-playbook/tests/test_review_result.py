from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.review_result import classify_review_result  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
