from __future__ import annotations

import errno
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import workspace as workspace_runtime  # noqa: E402
from review_runtime.common import ForwardedSignal, ReviewError  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    _file_secret_rule,
    _parse_tree_record,
    _sensitive_path_rule,
    _value_secret_rule,
    cleanup_workspace,
    prepare_workspace as _prepare_workspace,
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


def oauth_refresh_credential() -> str:
    return "1//" + "".join(("oauth", "-refresh", "-credential", "-value"))


def prepare_workspace(**kwargs):
    captured = []
    review = _prepare_workspace(ownership_handoff=captured.append, **kwargs)
    if captured != [review]:
        raise AssertionError("workspace ownership was not handed off exactly once")
    return review


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

    def test_git_environment_disables_lazy_fetch_and_prompts(self) -> None:
        environment = workspace_runtime._git_environment()

        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_ASKPASS"], "/usr/bin/false")
        self.assertEqual(environment["SSH_ASKPASS"], "/usr/bin/false")

    def test_partial_clone_missing_blob_fails_without_transport(self) -> None:
        git(self.repo, "config", "uploadpack.allowFilter", "true")
        partial = pathlib.Path(self.temporary.name) / "partial"
        subprocess.run(
            (
                "git",
                "-c",
                "protocol.file.allow=always",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                self.repo.as_uri(),
                str(partial),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        blob = git(self.repo, "rev-parse", f"{self.head}:example.txt")
        missing = subprocess.run(
            ("git", "-C", str(partial), "cat-file", "-e", blob),
            check=False,
            env=workspace_runtime._git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(missing.returncode, 0)

        marker = pathlib.Path(self.temporary.name) / "transport-called"
        upload_pack = pathlib.Path(self.temporary.name) / "upload-pack"
        upload_pack.write_text(
            f"#!/bin/sh\ntouch '{marker}'\nexit 1\n",
            encoding="utf-8",
        )
        upload_pack.chmod(0o755)
        git(partial, "config", "remote.origin.uploadpack", str(upload_pack))

        transport_environment = dict(os.environ)
        transport_environment.pop("GIT_NO_LAZY_FETCH", None)
        transport_attempt = subprocess.run(
            ("git", "-C", str(partial), "cat-file", "-e", blob),
            check=False,
            env=transport_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(transport_attempt.returncode, 0)
        self.assertTrue(marker.exists())
        marker.unlink()

        with self.assertRaisesRegex(ReviewError, "unexpected git cat-file"):
            prepare_workspace(
                repo=partial,
                base_ref=self.base,
                head_ref=self.head,
        )

        self.assertFalse(marker.exists())
        self.assertEqual(
            list((partial / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

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

    def test_prompt_override_replacement_is_single_pass(self) -> None:
        renamed_repo = self.repo.with_name("repo-{diff_file}")
        self.repo.rename(renamed_repo)
        self.repo = renamed_repo
        template = pathlib.Path(self.temporary.name) / "single-pass-prompt.txt"
        template.write_text(
            "Workspace={workspace}\nDiff={diff_file}\n",
            encoding="utf-8",
        )

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            prompt_override=template,
        )
        self.reviews.append(review)

        self.assertEqual(
            review.prompt_file.read_text(encoding="utf-8"),
            f"Workspace={review.workspace_root}\nDiff={review.diff_file}\n",
        )

    def test_prompt_override_rejects_oversized_template(self) -> None:
        template = pathlib.Path(self.temporary.name) / "oversized-prompt.txt"
        template.write_bytes(b"x" * 9)
        with (
            mock.patch.object(workspace_runtime, "MAX_REVIEW_PROMPT_BYTES", 8),
            self.assertRaisesRegex(ReviewError, "review prompt exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                prompt_override=template,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_prompt_override_rejects_oversized_rendered_prompt(self) -> None:
        template = pathlib.Path(self.temporary.name) / "expanded-prompt.txt"
        template.write_text("{workspace}", encoding="utf-8")
        with (
            mock.patch.object(workspace_runtime, "MAX_REVIEW_PROMPT_BYTES", 32),
            self.assertRaisesRegex(ReviewError, "review prompt exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                prompt_override=template,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_tree_record_diagnostics_redact_secret_paths_and_payloads(self) -> None:
        secret = "AKIA" + "A" * 16
        malformed = f"malformed-{secret}".encode()
        with self.assertRaises(ReviewError) as malformed_error:
            _parse_tree_record(malformed)
        self.assertNotIn(secret, str(malformed_error.exception))

        reserved = f"100644 blob {'a' * 40}\t.git/{secret}".encode()
        with self.assertRaises(ReviewError) as reserved_error:
            _parse_tree_record(reserved)
        self.assertIn("<redacted snapshot path>", str(reserved_error.exception))
        self.assertNotIn(secret, str(reserved_error.exception))

        unsafe = b"100644 blob " + b"b" * 40 + b"\tline\n\x1b\xff/.."
        with self.assertRaises(ReviewError) as unsafe_error:
            _parse_tree_record(unsafe)
        diagnostic = str(unsafe_error.exception)
        self.assertNotIn("\n", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertIn("\\x0a", diagnostic)
        self.assertIn("\\x1b", diagnostic)
        self.assertIn("\\udcff", diagnostic)
        diagnostic.encode("utf-8")

    def test_aws_secret_key_matches_nonword_terminal_characters(self) -> None:
        for terminal in b"/+=":
            with self.subTest(terminal=chr(terminal)):
                value = b"A" * 39 + bytes([terminal])
                self.assertEqual(
                    _value_secret_rule(b"aws_secret_access_key=" + value),
                    "aws-secret-key",
                )
                self.assertIsNone(
                    _value_secret_rule(b"aws_secret_access_key=" + value + b"A")
                )

    def test_pgp_private_key_marker_is_rejected(self) -> None:
        marker = b"-----BEGIN PGP PRIVATE" + b" KEY BLOCK-----"

        self.assertEqual(_value_secret_rule(marker), "pgp-private-key")

    def test_placeholder_secret_requires_a_complete_placeholder_value(self) -> None:
        self.assertIsNone(
            _value_secret_rule(b'password = "example-test-secret"')
        )
        self.assertIsNone(
            _value_secret_rule(b'password = "${DATABASE_PASSWORD}"')
        )
        self.assertIsNone(
            _value_secret_rule(b'password = "<DATABASE_PASSWORD>"')
        )
        self.assertIsNone(
            _value_secret_rule(b'OPENAI_API_KEY = "parent-only-secret"')
        )

        credential = "".join(("example-", "ProdSecret", "ABC123!"))
        self.assertEqual(
            _value_secret_rule(f'password = "{credential}"'.encode()),
            "generic-secret-assignment",
        )

    def test_unquoted_secret_accepts_common_password_punctuation(self) -> None:
        credentials = (
            "".join(("StrongPass", "123456")),
            "".join(("StrongProductionPass", "123456!")),
            "".join(("StrongProductionPass", "123456@corp")),
            "".join(("Pass1234", "#Word5678")),
            "".join(("Pass1234", ";Word5678")),
            "".join(("0123456789abcdef", "0123456789abcdef")),
            "".join(("12345678", "90123456")),
            "".join(("deadbeef", "deadbeef", "deadbeef", "deadbeef")),
            "".join(("alphabetagamma", "deltaepsilonzeta")),
        )
        for credential in credentials:
            with self.subTest(credential=credential):
                payload = b"password: " + credential.encode()
                self.assertEqual(
                    _value_secret_rule(payload),
                    "generic-secret-assignment",
                )
        self.assertIsNone(
            _value_secret_rule(b"password: example-test-secret # placeholder")
        )

    def test_oversized_secret_assignments_fail_closed(self) -> None:
        alpha_secret = b"A" * 513
        hex_secret = b"deadbeef" * 65
        numeric_secret = b"1" * 513
        payloads = (
            b'password="' + alpha_secret + b'"',
            b"password=" + alpha_secret,
            b"password=" + hex_secret,
            b"password=" + numeric_secret,
        )
        for payload in payloads:
            with self.subTest(payload_length=len(payload)):
                self.assertEqual(
                    _value_secret_rule(payload),
                    "generic-secret-assignment",
                )

    def test_snapshot_rejects_oversized_single_blob_before_materializing(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_BLOB_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "per-file review limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_reserved_path_preflight_rejects_oversized_tree_metadata(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_TREE_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen base tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_reserved_path_preflight_rejects_excessive_tree_entries(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "frozen base tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_recursive_tree_metadata(self) -> None:
        with (
            mock.patch.object(
                workspace_runtime,
                "_commit_uses_reserved_control_path",
                return_value=False,
            ),
            mock.patch.object(workspace_runtime, "MAX_TREE_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen Git tree metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_total_before_materializing(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_SNAPSHOT_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "total review snapshot limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_generated_diff(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_DIFF_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen review diff exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_changed_path_metadata(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "frozen changed paths exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_excessive_changed_path_entries(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "frozen changed paths exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_changed_blob_metadata(self) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_METADATA_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "changed blob metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_excessive_changed_blob_entries(self) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_ENTRIES", 0),
            self.assertRaisesRegex(ReviewError, "changed blob metadata exceeds"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_snapshot_rejects_oversized_changed_blob_scan(self) -> None:
        with (
            mock.patch.object(workspace_runtime, "MAX_CHANGED_BLOB_SCAN_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "total review scan limit"),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_materialization_os_error_redacts_secret_path(self) -> None:
        secret = "AKIA" + "B" * 16
        (self.repo / secret).write_text("secret-shaped path\n", encoding="utf-8")
        git(self.repo, "add", secret)
        git(self.repo, "commit", "-m", "Add secret-shaped path")
        self.head = git(self.repo, "rev-parse", "HEAD")
        materialize_blob = workspace_runtime._materialize_blob

        def fail_secret_path(**kwargs):
            if kwargs["destination"].name == secret:
                raise OSError(errno.ENAMETOOLONG, f"path too long: {secret}")
            return materialize_blob(**kwargs)

        with (
            mock.patch.object(
                workspace_runtime,
                "_materialize_blob",
                side_effect=fail_secret_path,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertIn("<redacted snapshot path>", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_invalid_ref_fails_before_creating_a_review_container(self) -> None:
        with self.assertRaises(ReviewError):
            prepare_workspace(
                repo=self.repo,
                base_ref="missing-ref",
                head_ref=self.head,
            )
        review_root = self.repo / ".codex-tmp"
        self.assertFalse(review_root.exists())

    def test_diverged_range_reports_merge_base_before_creating_container(self) -> None:
        git(self.repo, "switch", "-c", "diverged", self.base)
        (self.repo / "side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "side.txt")
        git(self.repo, "commit", "-m", "Diverge")
        diverged = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            rf"not an ancestor.*merge base {self.base}",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=diverged,
                head_ref=self.head,
            )
        self.assertFalse((self.repo / ".codex-tmp").exists())

    def test_ancestor_check_ignores_local_replace_refs(self) -> None:
        git(self.repo, "switch", "-c", "replace-diverged", self.base)
        (self.repo / "replace-side.txt").write_text("side\n", encoding="utf-8")
        git(self.repo, "add", "replace-side.txt")
        git(self.repo, "commit", "-m", "Replace diverge")
        diverged = git(self.repo, "rev-parse", "HEAD")
        head_tree = git(self.repo, "rev-parse", f"{self.head}^{{tree}}")
        replacement = git(
            self.repo,
            "commit-tree",
            head_tree,
            "-p",
            diverged,
            "-m",
            "Replacement head",
        )
        git(self.repo, "replace", self.head, replacement)

        self.assertEqual(
            git(
                self.repo,
                "merge-base",
                "--is-ancestor",
                diverged,
                self.head,
            ),
            "",
        )
        with self.assertRaisesRegex(ReviewError, "not an ancestor"):
            prepare_workspace(
                repo=self.repo,
                base_ref=diverged,
                head_ref=self.head,
            )
        self.assertFalse((self.repo / ".codex-tmp").exists())

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

    def test_prepare_cleanup_failure_reports_retained_container(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_sanitized_git_view",
                side_effect=RuntimeError("prepare failed"),
            ),
            mock.patch(
                "review_runtime.workspace.shutil.rmtree",
                side_effect=PermissionError("permission denied"),
            ),
            self.assertRaisesRegex(
                ReviewError,
                r"evidence retained at .*isolated-review.*permission denied",
            ),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        review_root = self.repo / ".codex-tmp"
        self.assertEqual(len(list(review_root.glob("isolated-review-*"))), 1)

    def test_container_handoff_signal_cleans_private_snapshot(self) -> None:
        restore_calls = 0

        def interrupt_first_restore(_mask):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                raise ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch(
                "review_runtime.workspace.restore_signal_mask",
                side_effect=interrupt_first_restore,
            ),
            self.assertRaises(ForwardedSignal),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        review_root = self.repo / ".codex-tmp"
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

    def test_completed_workspace_is_owned_before_handoff_signal(self) -> None:
        restore_calls = 0
        captured = []

        def interrupt_ownership_restore(_mask):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 2:
                raise ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch(
                "review_runtime.workspace.restore_signal_mask",
                side_effect=interrupt_ownership_restore,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
            )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0].workspace_root.exists())
        cleanup_workspace(captured[0], keep_container=False)

    def test_partial_snapshot_cleanup_reports_second_signal(self) -> None:
        with (
            mock.patch(
                "review_runtime.workspace._create_sanitized_git_view",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch(
                "review_runtime.workspace.block_forwarded_signals",
                side_effect=({signal.SIGTERM}, {signal.SIGTERM}),
            ),
            mock.patch(
                "review_runtime.workspace.consume_pending_forwarded_signal",
                return_value=signal.SIGQUIT,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertEqual(raised.exception.signum, signal.SIGQUIT)
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

    def test_group_writable_review_root_is_rejected(self) -> None:
        review_root = self.repo / ".codex-tmp"
        review_root.mkdir(mode=0o700)
        review_root.chmod(0o770)

        with self.assertRaisesRegex(ReviewError, "group or other writable"):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(list(review_root.iterdir()), [])

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

    def test_protected_review_path_symlink_is_rejected(self) -> None:
        (self.repo / ".agents").symlink_to(".codex-review")
        git(self.repo, "add", ".agents")
        git(self.repo, "commit", "-m", "Add protected path alias")
        alias_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            "symlink for protected top-level path .agents",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=alias_head,
            )

        review_root = self.repo / ".codex-tmp"
        self.assertEqual(list(review_root.glob("isolated-review-*")), [])

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

    def test_escaping_secret_symlink_target_is_redacted(self) -> None:
        secret = "sk-" + "A" * 40
        (self.repo / "artifact").symlink_to(pathlib.Path("../..") / secret)
        git(self.repo, "add", "artifact")
        git(self.repo, "commit", "-m", "Add escaping secret-shaped symlink")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            r"artifact -> <redacted symlink target>",
        ) as raised:
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=secret_head,
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_unchanged_sensitive_path_symlink_blocks_external_review(self) -> None:
        (self.repo / "public.txt").write_text("ordinary content\n", encoding="utf-8")
        credentials = self.repo / "fixtures"
        credentials.mkdir()
        (credentials / ".netrc").symlink_to("../public.txt")
        git(self.repo, "add", "public.txt", "fixtures/.netrc")
        git(self.repo, "commit", "-m", "Add credential-shaped symlink")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(ReviewError, r"fixtures/\.netrc.*credential-path"):
            validate_external_workspace(review)

    def test_unchanged_secret_in_path_name_blocks_external_review(self) -> None:
        secret = "sk-" + "A" * 40
        secret_path = self.repo / "fixtures" / secret
        secret_path.parent.mkdir()
        secret_path.write_text("ordinary content\n", encoding="utf-8")
        git(self.repo, "add", str(secret_path.relative_to(self.repo)))
        git(self.repo, "commit", "-m", "Add secret-shaped path")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(
            ReviewError,
            r"<redacted snapshot path>.*openai-key.*path-name",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_secret_in_sensitive_changed_path_is_redacted(self) -> None:
        secret = "sk-" + "A" * 40
        secret_path = self.repo / secret / ".netrc"
        secret_path.parent.mkdir()
        secret_path.write_text("ordinary content\n", encoding="utf-8")
        git(self.repo, "add", str(secret_path.relative_to(self.repo)))
        git(self.repo, "commit", "-m", "Add secret-bearing credential path")
        secret_head = git(self.repo, "rev-parse", "HEAD")
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=secret_head,
        )
        self.reviews.append(review)

        with self.assertRaisesRegex(
            ReviewError,
            r"<redacted changed path>.*openai-key.*changed-path-name",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_unchanged_secret_in_symlink_target_blocks_external_review(self) -> None:
        secret = "sk-" + "A" * 40
        (self.repo / "artifact").symlink_to(secret)
        git(self.repo, "add", "artifact")
        git(self.repo, "commit", "-m", "Add secret-shaped symlink target")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=sensitive_base,
            head_ref=unrelated_head,
        )
        self.reviews.append(review)
        with self.assertRaisesRegex(
            ReviewError,
            r"artifact -> <redacted symlink target>.*openai-key.*symlink-target",
        ) as raised:
            validate_external_workspace(review)
        self.assertNotIn(secret, str(raised.exception))

    def test_secret_findings_escape_control_characters_in_snapshot_paths(self) -> None:
        secret = "AKIA" + "C" * 16
        file_name = "file\n\x1bname"
        symlink_name = "link\n\x1bname"
        (self.repo / file_name).write_text(secret + "\n", encoding="utf-8")
        (self.repo / symlink_name).symlink_to("sk-" + "D" * 40)
        git(self.repo, "add", file_name, symlink_name)
        git(self.repo, "commit", "-m", "Add control-character secret paths")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=secret_head,
        )
        self.reviews.append(review)

        with self.assertRaises(ReviewError) as raised:
            validate_external_workspace(review)

        diagnostic = str(raised.exception)
        self.assertNotIn("\n", diagnostic)
        self.assertNotIn("\x1b", diagnostic)
        self.assertIn("file\\x0a\\x1bname (aws-access-key)", diagnostic)
        self.assertIn(
            "link\\x0a\\x1bname -> <redacted symlink target>",
            diagnostic,
        )

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
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_file_secret_rule(credential), "generic-secret-assignment")

    def test_deleted_oauth_refresh_token_is_detected_from_base_blob(self) -> None:
        credential = self.repo / "oauth.json"
        credential.write_text(
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n",
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
