from __future__ import annotations

import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.review_result import classify_review_result  # noqa: E402
from review_runtime import routine_review  # noqa: E402
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
    def test_snapshot_disposition_cannot_claim_commit_or_merge_approval(self) -> None:
        record = assessment()
        record.update(scope_kind="snapshot", source_head_sha=record.pop("head_sha"), snapshot_id="c" * 64)
        result = classify(record)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["merge_approval"])
        self.assertNotIn("head_sha", result)
        with self.assertRaises(ValueError):
            revalidation_plan(record)
        record["head_sha"] = record["source_head_sha"]
        with self.assertRaises(ValueError):
            classify(record)

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


@unittest.skipUnless(os.name == "posix", "snapshot traversal requires POSIX no-follow opens")
class RoutineSnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "src").mkdir()
        self.path = self.source / "src/client.py"
        self.path.write_bytes(b"final worktree bytes\n")
        self.output = self.root / "snapshot"
        self.record = {
            "base_sha": "a" * 40, "source_head_sha": "b" * 40,
            "paths": ["src/client.py"], "deleted_paths": ["src/deleted.py"],
        }

    def capture(self):
        return routine_review.capture_snapshot(self.record, self.source, self.output)

    def test_snapshot_retains_final_bytes_and_explicit_deletions_without_git_writes(self) -> None:
        self.source.joinpath("untracked-private.txt").write_bytes(b"excluded")
        receipt = self.capture()
        self.path.write_bytes(b"later edit\n")
        result = routine_review.validate_snapshot(self.output, receipt["snapshot_id"])
        self.assertTrue(result["snapshot_valid"])
        self.assertFalse(result["merge_approval"])
        self.assertEqual((self.output / "files/src/client.py").read_bytes(), b"final worktree bytes\n")
        self.assertFalse((self.output / "files/untracked-private.txt").exists())
        self.assertFalse((self.source / ".git").exists())

    def test_changed_content_or_mode_invalidates_snapshot(self) -> None:
        receipt = self.capture()
        target = self.output / "files/src/client.py"
        target.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "content mismatch"):
            routine_review.validate_snapshot(self.output, receipt["snapshot_id"])
        target.chmod(0o600)
        target.write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "content mismatch"):
            routine_review.validate_snapshot(self.output, receipt["snapshot_id"])

    def test_real_staged_unstaged_and_selected_new_files_leave_source_git_unchanged(self) -> None:
        def git(*args):
            return subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
                 "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-C", str(self.source), *args],
                check=True, capture_output=True, timeout=10,
            ).stdout

        git("init", "-q")
        git("add", ".")
        git("commit", "-qm", "baseline")
        head = git("rev-parse", "HEAD").decode().strip()
        self.path.write_bytes(b"staged")
        git("add", "src/client.py")
        self.path.write_bytes(b"final unstaged")
        new = self.source / "selected-new.bin"
        new.write_bytes(b"\x00\xff\n")
        new.chmod(0o700)
        self.record.update(base_sha=head, source_head_sha=head, paths=["src/client.py", new.name])
        before_status = git("status", "--porcelain=v1")
        before_index = (self.source / ".git/index").read_bytes()
        receipt = self.capture()
        routine_review.validate_snapshot(self.output, receipt["snapshot_id"])
        self.assertEqual((self.output / "files/src/client.py").read_bytes(), b"final unstaged")
        self.assertEqual((self.output / "files/selected-new.bin").read_bytes(), b"\x00\xff\n")
        self.assertEqual((self.source / ".git/index").read_bytes(), before_index)
        self.assertEqual(git("rev-parse", "HEAD").decode().strip(), head)
        self.assertEqual(git("status", "--porcelain=v1"), before_status)

    def test_manifest_cannot_replace_parent_owned_identity(self) -> None:
        receipt = self.capture()
        with self.assertRaisesRegex(ValueError, "parent-owned identity"):
            routine_review.validate_snapshot(self.output, "0" * 64)
        receipt["source_head_sha"] = "c" * 40
        (self.output / "snapshot.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            routine_review.validate_snapshot(self.output, receipt["snapshot_id"])

    def test_metadata_churn_is_benign_but_content_change_during_capture_fails(self) -> None:
        original = routine_review._read_snapshot_path
        reads = 0

        def changing_read(*arguments):
            nonlocal reads
            result = original(*arguments)
            reads += 1
            if reads == 1:
                os.utime(self.path, None)
                (self.source / "src/unrelated").touch()
                replacement = self.source / "src/replacement"
                replacement.write_bytes(result[0])
                replacement.replace(self.path)
            return result

        with mock.patch.object(routine_review, "_read_snapshot_path", side_effect=changing_read):
            receipt = self.capture()
        routine_review.validate_snapshot(self.output, receipt["snapshot_id"])
        self.output = self.root / "changed-snapshot"
        reads = 0

        def mutated_read(*arguments):
            nonlocal reads
            result = original(*arguments)
            reads += 1
            if reads == 1:
                self.path.write_bytes(b"changed while capturing\n")
            return result

        with mock.patch.object(routine_review, "_read_snapshot_path", side_effect=mutated_read):
            with self.assertRaisesRegex(ValueError, "content changed"):
                self.capture()
        self.assertFalse((self.output / "snapshot.json").exists())

    def test_missing_and_unreadable_files_are_not_deletions(self) -> None:
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.capture()
        self.output = self.root / "unreadable-snapshot"
        self.path.write_bytes(b"content")
        with mock.patch.object(routine_review, "_read_snapshot_path", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                self.capture()

    def test_symlink_and_fifo_are_rejected_without_following_or_blocking(self) -> None:
        private = self.root / "private"
        private.write_bytes(b"excluded")
        self.path.unlink()
        self.path.symlink_to(private)
        with self.assertRaises(OSError):
            self.capture()
        self.path.unlink()
        os.mkfifo(self.path)
        self.output = self.root / "fifo-snapshot"
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.capture()

    def test_unsafe_paths_existing_output_and_in_source_output_are_rejected(self) -> None:
        for path in ("../private", "/private", ".git/config", "src//client.py"):
            with self.subTest(path=path):
                record = {**self.record, "paths": [path]}
                with self.assertRaises(ValueError):
                    routine_review.capture_snapshot(record, self.source, self.output)
        with self.assertRaises(ValueError):
            routine_review.capture_snapshot(self.record, self.source, self.source / "snapshot")
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.capture()

    def test_present_deletion_capacity_stop_and_parent_symlink_remain_incomplete(self) -> None:
        deleted = self.source / "src/deleted.py"
        deleted.write_bytes(b"still present")
        with self.assertRaisesRegex(ValueError, "deletion is present"):
            self.capture()
        deleted.unlink()
        self.output = self.root / "capacity-stop"
        with mock.patch.object(routine_review, "SNAPSHOT_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "capacity"):
                self.capture()
        self.assertFalse((self.output / "snapshot.json").exists())
        self.output = self.root / "parent-symlink"
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "private").write_bytes(b"excluded")
        (self.source / "linked").symlink_to(outside, target_is_directory=True)
        self.record["paths"] = ["linked/private"]
        with self.assertRaises(OSError):
            self.capture()

    def test_real_cli_captures_and_validates_selected_scope(self) -> None:
        script = SCRIPTS / "review_runtime/routine_review.py"
        captured = subprocess.run(
            [sys.executable, str(script), "snapshot", "--source", str(self.source), "--output", str(self.output)],
            input=json.dumps(self.record), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(captured.returncode, 0, captured.stderr)
        receipt = json.loads(captured.stdout)
        validated = subprocess.run(
            [sys.executable, str(script), "validate-snapshot", "--output", str(self.output),
             "--snapshot-id", receipt["snapshot_id"]],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertTrue(json.loads(validated.stdout)["snapshot_valid"])


if __name__ == "__main__":
    unittest.main()
