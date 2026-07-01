from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import ReviewError  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    _file_secret_rule,
    _sensitive_path_rule,
    cleanup_workspace,
    prepare_workspace,
    validate_external_workspace,
)


def git(repo: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


class WorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        subprocess.run(
            ("git", "init", "-b", "master", str(self.repo)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(self.repo, "config", "user.name", "Review Test")
        git(self.repo, "config", "user.email", "review@example.com")
        git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text(
            "example.txt filter=evil diff=evil\n",
            encoding="utf-8",
        )
        (self.repo / "example.txt").write_text("one\n", encoding="utf-8")
        git(self.repo, "add", ".gitignore", ".gitattributes", "example.txt")
        git(self.repo, "commit", "-m", "Initial")
        self.base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("one\ntwo\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Update")
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.reviews = []

    def tearDown(self) -> None:
        for review in self.reviews:
            if review.workspace_root.exists():
                cleanup_workspace(review, keep_container=False)
        self.temporary.cleanup()

    def test_prepare_materializes_frozen_range_and_local_control_files(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)

        self.assertEqual(review.base_ref, self.base)
        self.assertEqual(review.head_ref, self.head)
        self.assertEqual(review.diff_file.parent.name, ".codex-review")
        self.assertEqual(review.prompt_file.parent, review.diff_file.parent)
        self.assertIn("+two", review.diff_file.read_text(encoding="utf-8"))
        prompt = review.prompt_file.read_text(encoding="utf-8")
        self.assertIn(f"{self.base}..{self.head}", prompt)
        self.assertNotIn("Source repository:", prompt)
        self.assertFalse((review.workspace_root / ".git").exists())
        self.assertEqual(review.container_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (review.workspace_root / "example.txt").read_text(encoding="utf-8"),
            "one\ntwo\n",
        )

        cleanup_workspace(review, keep_container=False)
        self.assertFalse(review.container_dir.exists())

    def test_prompt_override_replaces_only_review_scope_placeholders(self) -> None:
        template = pathlib.Path(self.temporary.name) / "prompt.txt"
        template.write_text(
            "Workspace={workspace}\nDiff={diff_file}\nRange={review_range}\n",
            encoding="utf-8",
        )
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            prompt_override=template,
        )
        self.reviews.append(review)
        prompt = review.prompt_file.read_text(encoding="utf-8")
        self.assertIn(str(review.workspace_root), prompt)
        self.assertIn(str(review.diff_file), prompt)
        self.assertIn(f"{self.base}..{self.head}", prompt)

    def test_invalid_ref_fails_before_creating_a_review_container(self) -> None:
        with self.assertRaises(ReviewError):
            prepare_workspace(
                repo=self.repo,
                base_ref="missing-ref",
                head_ref=self.head,
            )
        review_root = self.repo / ".codex-tmp"
        self.assertFalse(review_root.exists())

    def test_keyboard_interrupt_cleans_partial_review_container(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_sanitized_git_view",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        review_root = self.repo / ".codex-tmp"
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_review_root_symlink_is_rejected_without_writing_outside_repo(self) -> None:
        outside = pathlib.Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.repo / ".codex-tmp").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ReviewError, "not a symlink"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_reserved_control_path_in_base_is_rejected(self) -> None:
        control = self.repo / ".codex-review"
        control.mkdir()
        (control / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        git(self.repo, "add", ".codex-review/tracked.txt")
        git(self.repo, "commit", "-m", "Add reserved path")
        reserved_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "-r", ".codex-review")
        git(self.repo, "commit", "-m", "Remove reserved path")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(ReviewError, "frozen base uses the reserved"):
            prepare_workspace(
                repo=self.repo,
                base_ref=reserved_base,
                head_ref=clean_head,
            )

    def test_external_workspace_rejects_symlinks_that_escape_frozen_root(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        (review.workspace_root / "escape").symlink_to(self.repo / "example.txt")
        with self.assertRaises(ReviewError):
            validate_external_workspace(review)

    def test_deleted_binary_secret_is_detected_from_base_blob(self) -> None:
        secret = ("sk-" + "A" * 40).encode()
        binary = self.repo / "opaque.bin"
        binary.write_bytes(b"\0binary\0" + secret + b"\0")
        git(self.repo, "add", "opaque.bin")
        git(self.repo, "commit", "-m", "Add binary credential")
        secret_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "opaque.bin")
        git(self.repo, "commit", "-m", "Remove binary credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=secret_base,
            head_ref=clean_head,
        )
        self.reviews.append(review)
        findings = (
            review.workspace_root / ".codex-review/changed-blob-findings.z"
        ).read_bytes()
        self.assertNotIn(secret, findings)
        with self.assertRaisesRegex(ReviewError, "opaque.bin.*base-blob"):
            validate_external_workspace(review)

    def test_oauth_refresh_token_is_detected_in_head_content(self) -> None:
        credential = pathlib.Path(self.temporary.name) / "oauth.json"
        credential.write_text(
            '{"refresh_token": "1//oauth-refresh-credential-value"}\n',
            encoding="utf-8",
        )
        self.assertEqual(_file_secret_rule(credential), "generic-secret-assignment")

    def test_deleted_oauth_refresh_token_is_detected_from_base_blob(self) -> None:
        credential = self.repo / "oauth.json"
        credential.write_text(
            '{"refresh_token": "1//oauth-refresh-credential-value"}\n',
            encoding="utf-8",
        )
        git(self.repo, "add", "oauth.json")
        git(self.repo, "commit", "-m", "Add OAuth credential")
        credential_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "oauth.json")
        git(self.repo, "commit", "-m", "Remove OAuth credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=credential_base,
            head_ref=clean_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(ReviewError, "oauth.json.*base-blob"):
            validate_external_workspace(review)

    def test_function_call_assignment_is_not_treated_as_literal_secret(self) -> None:
        source = pathlib.Path(self.temporary.name) / "source.py"
        source.write_text(
            "password = load_password_from_keyring()\n",
            encoding="utf-8",
        )
        self.assertIsNone(_file_secret_rule(source))

    def test_all_env_suffix_files_are_sensitive_paths(self) -> None:
        self.assertEqual(_sensitive_path_rule("config.env"), "environment-file")
        self.assertEqual(_sensitive_path_rule("deploy/prod.env"), "environment-file")
        self.assertIsNone(_sensitive_path_rule(".env.example"))

    def test_nested_oauth_token_file_is_a_sensitive_path(self) -> None:
        self.assertEqual(
            _sensitive_path_rule("fixtures/google/token.json"),
            "credential-path",
        )

    def test_snapshot_does_not_execute_repo_hooks_filters_or_external_diff(
        self,
    ) -> None:
        marker_root = pathlib.Path(self.temporary.name) / "markers"
        marker_root.mkdir()
        hooks_dir = pathlib.Path(self.temporary.name) / "hooks"
        hooks_dir.mkdir()
        hook_marker = marker_root / "hook"
        filter_marker = marker_root / "filter"
        diff_marker = marker_root / "diff"

        hook = hooks_dir / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{hook_marker}'\n", encoding="utf-8")
        hook.chmod(0o755)
        filter_script = pathlib.Path(self.temporary.name) / "filter.sh"
        filter_script.write_text(
            f"#!/bin/sh\ntouch '{filter_marker}'\ncat\n",
            encoding="utf-8",
        )
        filter_script.chmod(0o755)
        diff_script = pathlib.Path(self.temporary.name) / "diff.sh"
        diff_script.write_text(
            f"#!/bin/sh\ntouch '{diff_marker}'\n",
            encoding="utf-8",
        )
        diff_script.chmod(0o755)

        git(self.repo, "config", "core.hooksPath", str(hooks_dir))
        git(self.repo, "config", "filter.evil.smudge", str(filter_script))
        git(self.repo, "config", "diff.external", str(diff_script))
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        self.assertFalse(hook_marker.exists())
        self.assertFalse(filter_marker.exists())
        self.assertFalse(diff_marker.exists())

    def test_snapshot_uses_raw_blobs_despite_archive_export_attributes(self) -> None:
        attributes = self.repo / ".gitattributes"
        attributes.write_text(
            attributes.read_text(encoding="utf-8")
            + "hidden.txt export-ignore\n"
            + "substituted.txt export-subst\n",
            encoding="utf-8",
        )
        (self.repo / "hidden.txt").write_text("still tracked\n", encoding="utf-8")
        raw_substitution = "$Format:%H$\n"
        (self.repo / "substituted.txt").write_text(
            raw_substitution,
            encoding="utf-8",
        )
        git(
            self.repo,
            "add",
            ".gitattributes",
            "hidden.txt",
            "substituted.txt",
        )
        git(self.repo, "commit", "-m", "Add export attributes")
        export_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=export_head,
        )
        self.reviews.append(review)
        self.assertEqual(
            (review.workspace_root / "hidden.txt").read_text(encoding="utf-8"),
            "still tracked\n",
        )
        self.assertEqual(
            (review.workspace_root / "substituted.txt").read_text(encoding="utf-8"),
            raw_substitution,
        )

    def test_prepare_supports_sha256_repositories(self) -> None:
        sha256_repo = pathlib.Path(self.temporary.name) / "sha256-repo"
        subprocess.run(
            (
                "git",
                "init",
                "--object-format=sha256",
                "-b",
                "master",
                str(sha256_repo),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(sha256_repo, "config", "user.name", "Review Test")
        git(sha256_repo, "config", "user.email", "review@example.com")
        git(sha256_repo, "config", "commit.gpgsign", "false")
        (sha256_repo / ".gitignore").write_text(
            ".codex-tmp/\n",
            encoding="utf-8",
        )
        content = sha256_repo / "content.txt"
        content.write_text("base\n", encoding="utf-8")
        git(sha256_repo, "add", ".gitignore", "content.txt")
        git(sha256_repo, "commit", "-m", "Initial")
        base = git(sha256_repo, "rev-parse", "HEAD")
        content.write_text("base\nhead\n", encoding="utf-8")
        git(sha256_repo, "add", "content.txt")
        git(sha256_repo, "commit", "-m", "Update")
        head = git(sha256_repo, "rev-parse", "HEAD")
        self.assertEqual(len(head), 64)

        review = prepare_workspace(
            repo=sha256_repo,
            base_ref=base,
            head_ref=head,
        )
        self.reviews.append(review)
        self.assertEqual(review.head_ref, head)
        self.assertEqual(
            (review.workspace_root / "content.txt").read_text(encoding="utf-8"),
            "base\nhead\n",
        )
        self.assertIn("+head", review.diff_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
