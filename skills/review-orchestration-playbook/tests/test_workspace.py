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
    symlink_target_stays_within_workspace,
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


def unregistered_generic_credential() -> bytes:
    return b"".join((b"Critical", b"Credential", b"Alpha", b"9!"))


def second_unregistered_generic_credential() -> bytes:
    return b"".join((b"Critical", b"Credential", b"Bravo", b"8!"))


def unregistered_jwt_credential() -> bytes:
    return b".".join((b"eyJ" + b"A" * 12, b"B" * 16, b"C" * 16))


def unregistered_provider_credential() -> bytes:
    return b"".join((b"sk", b"-", b"P" * 40))


def unregistered_private_key() -> bytes:
    label = b"".join((b"PRIVATE", b" KEY"))
    return b"".join(
        (
            b"-----BEGIN ",
            label,
            b"-----\n",
            b"Q" * 64,
            b"\n-----END ",
            label,
            b"-----",
        )
    )


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

    def commit_bytes(self, relative: str, payload: bytes, message: str) -> str:
        destination = self.repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        git(self.repo, "add", relative)
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def remove_and_commit(self, relative: str, message: str) -> str:
        git(self.repo, "rm", relative)
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def prepare_range(self, base_ref: str, head_ref: str):
        review = prepare_workspace(
            repo=self.repo,
            base_ref=base_ref,
            head_ref=head_ref,
        )
        self.reviews.append(review)
        return review

    def assert_control_evidence_omits(
        self,
        review,
        raw_value: bytes,
    ) -> None:
        control_dir = review.workspace_root / ".codex-review"
        artifacts = [
            path
            for path in control_dir.rglob("*")
            if path.is_file() and path != review.diff_file
        ]
        artifacts.extend(
            path for path in review.container_dir.iterdir() if path.is_file()
        )
        self.assertTrue(artifacts)
        for artifact in artifacts:
            with self.subTest(control_artifact=artifact.name):
                self.assertNotIn(raw_value, artifact.read_bytes())

    def assert_diff_retains_raw_deletion(self, review, raw_value: bytes) -> None:
        diff = review.diff_file.read_bytes()
        deleted_lines = [line for line in diff.splitlines() if line.startswith(b"-")]
        for line in raw_value.splitlines():
            self.assertTrue(
                any(line in deleted_line for deleted_line in deleted_lines),
                f"raw deletion line is absent from review.diff: {line!r}",
            )
        self.assertNotIn(b"<redacted", diff)

    def assert_external_review_blocked(
        self,
        *,
        base_ref: str,
        head_ref: str,
        rule: str,
    ) -> None:
        try:
            review = self.prepare_range(base_ref, head_ref)
        except ReviewError as error:
            self.assertRegex(str(error), rule)
            return
        with self.assertRaisesRegex(ReviewError, rule):
            validate_external_workspace(review)

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
        self.assertIn("Primary diff file: .codex-review/review.diff", prompt)
        self.assertIn("If `Read` is the only file tool", prompt)
        self.assertNotIn(str(review.workspace_root), prompt)
        self.assertNotIn("Source repository:", prompt)
        self.assertFalse((review.workspace_root / ".git").exists())
        self.assertEqual(review.container_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (review.workspace_root / "example.txt").read_text(encoding="utf-8"),
            "one\ntwo\n",
        )

        cleanup_workspace(review, keep_container=False)
        self.assertFalse(review.container_dir.exists())

    def test_prepare_uses_private_control_modes_under_permissive_umask(self) -> None:
        for mask in (0o002, 0o000):
            with self.subTest(mask=oct(mask)):
                previous = os.umask(mask)
                try:
                    review = prepare_workspace(
                        repo=self.repo,
                        base_ref=self.base,
                        head_ref=self.head,
                    )
                finally:
                    os.umask(previous)
                self.reviews.append(review)

                control_dir = review.workspace_root / ".codex-review"
                self.assertEqual(review.container_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(control_dir.stat().st_mode & 0o777, 0o700)
                for name in workspace_runtime.CONTROL_ARTIFACT_SPECS:
                    self.assertEqual(
                        (control_dir / name).stat().st_mode & 0o777,
                        0o600,
                        name,
                    )
                for name in (
                    workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME,
                    workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
                    workspace_runtime.PRIVATE_CHANGED_PATHS_NAME,
                ):
                    self.assertEqual(
                        (review.container_dir / name).stat().st_mode & 0o777,
                        0o600,
                        name,
                    )
                self.assertEqual(
                    (review.workspace_root / "example.txt").stat().st_mode & 0o777,
                    0o644,
                )
                validate_external_workspace(review)

    def test_external_workspace_rejects_group_writable_control_artifact(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        changed_paths = (
            review.workspace_root
            / ".codex-review"
            / workspace_runtime.CHANGED_PATH_DIGESTS_NAME
        )
        changed_paths.chmod(0o660)

        with self.assertRaisesRegex(ReviewError, "group or other writable"):
            validate_external_workspace(review)

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

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_prompt_override_rejects_symlink_hardlink_fifo_and_writable_file(
        self,
    ) -> None:
        root = pathlib.Path(self.temporary.name)
        target = root / "prompt-target.txt"
        target.write_text("Review {review_range}\n", encoding="utf-8")
        target.chmod(0o600)
        symlink = root / "prompt-symlink.txt"
        symlink.symlink_to(target)
        hardlink = root / "prompt-hardlink.txt"
        os.link(target, hardlink)
        fifo = root / "prompt.fifo"
        os.mkfifo(fifo, mode=0o600)
        writable = root / "prompt-writable.txt"
        writable.write_text("Review {review_range}\n", encoding="utf-8")
        writable.chmod(0o620)

        for label, candidate in (
            ("symlink", symlink),
            ("hardlink", hardlink),
            ("fifo", fifo),
            ("writable", writable),
        ):
            with self.subTest(file_type=label), self.assertRaises(ReviewError):
                prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_override=candidate,
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

    def test_aws_secret_key_rejects_extended_terminal_values(self) -> None:
        for terminal in b"/+=":
            with self.subTest(terminal=chr(terminal)):
                value = b"A" * 39 + bytes([terminal])
                self.assertEqual(
                    _value_secret_rule(b"aws_secret_access_key=" + value),
                    "aws-secret-key",
                )
                self.assertEqual(
                    _value_secret_rule(b"aws_secret_access_key=" + value + b"A"),
                    "generic-secret-assignment",
                )

    def test_pgp_private_key_marker_is_rejected(self) -> None:
        marker = b"-----BEGIN PGP PRIVATE" + b" KEY BLOCK-----"

        self.assertEqual(_value_secret_rule(marker), "pgp-private-key")

    def test_placeholder_secret_requires_a_complete_placeholder_value(self) -> None:
        self.assertIsNone(_value_secret_rule(b'password = "example-test-secret"'))
        self.assertIsNone(_value_secret_rule(b'password = "${DATABASE_PASSWORD}"'))
        self.assertIsNone(_value_secret_rule(b'password = "<DATABASE_PASSWORD>"'))
        self.assertIsNone(_value_secret_rule(b'OPENAI_API_KEY = "parent-only-secret"'))

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
        placeholder = b"".join((b"example-", b"test-", b"secret"))
        self.assertIsNone(_value_secret_rule(b"password: " + placeholder))
        self.assertIsNone(
            _value_secret_rule(b"password: example-test-secret # placeholder")
        )
        self.assertEqual(
            _value_secret_rule(
                b"password: "
                + placeholder
                + b" # fixture\n  ActualOpaqueSecretA9Z8Y7\n"
            ),
            "generic-secret-assignment",
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
            mock.patch.object(
                workspace_runtime,
                "_reject_legacy_values_in_frozen_tree_paths",
                return_value=None,
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
            kwargs["private_destination"].touch()

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
            kwargs["private_destination"].touch()

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

    def test_partial_cleanup_removes_private_artifacts_when_rmtree_fails(self) -> None:
        container = pathlib.Path(self.temporary.name) / "partial-container"
        container.mkdir(mode=0o700)
        private_paths = container / workspace_runtime.PRIVATE_CHANGED_PATHS_NAME
        private_manifest = container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        private_paths.write_bytes(b"private-path\x00")
        private_manifest.write_bytes(b"private-manifest")

        with mock.patch.object(
            workspace_runtime.shutil,
            "rmtree",
            side_effect=PermissionError("permission denied"),
        ) as remove_tree:
            cleanup_error = workspace_runtime._remove_partial_container(container)

        self.assertIn("permission denied", cleanup_error or "")
        remove_tree.assert_called_once_with(container.name, dir_fd=mock.ANY)
        self.assertTrue(container.exists())
        self.assertFalse(private_paths.exists())
        self.assertFalse(private_manifest.exists())

        symlink_target = pathlib.Path(self.temporary.name) / "symlink-target"
        symlink_target.mkdir()
        target_private_paths = (
            symlink_target / workspace_runtime.PRIVATE_CHANGED_PATHS_NAME
        )
        target_private_paths.write_bytes(b"outside\x00")
        target_private_manifest = (
            symlink_target / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        target_private_manifest.write_bytes(b"outside-manifest")
        symlink_container = pathlib.Path(self.temporary.name) / "container-link"
        symlink_container.symlink_to(symlink_target, target_is_directory=True)

        symlink_error = workspace_runtime.remove_private_review_artifacts(
            symlink_container
        )

        self.assertIsNotNone(symlink_error)
        self.assertTrue(target_private_paths.exists())
        self.assertTrue(target_private_manifest.exists())

        private_paths.write_bytes(b"private-path\x00")
        private_manifest.write_bytes(b"private-manifest")
        real_unlink = os.unlink

        def fail_first_unlink(path, *args, **kwargs):
            if path == workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME:
                raise PermissionError("manifest unlink denied")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "unlink",
            side_effect=fail_first_unlink,
        ):
            first_unlink_error = workspace_runtime.remove_private_review_artifacts(
                container
            )

        self.assertIn("manifest unlink denied", first_unlink_error or "")
        self.assertTrue(private_manifest.exists())
        self.assertFalse(private_paths.exists())

        private_manifest.unlink()
        private_manifest.mkdir()
        nested_private = private_manifest / "nested.txt"
        nested_private.write_text("do not recurse\n", encoding="utf-8")
        private_paths.write_bytes(b"private-path\x00")

        directory_artifact_error = workspace_runtime.remove_private_review_artifacts(
            container
        )

        self.assertIsNotNone(directory_artifact_error)
        self.assertTrue(nested_private.exists())
        self.assertFalse(private_paths.exists())

        missing_parent_error = workspace_runtime.remove_private_review_artifacts(
            pathlib.Path(self.temporary.name) / "missing-parent/isolated-review-missing"
        )
        self.assertIn("parent is missing", missing_parent_error or "")

        source_root = pathlib.Path(self.temporary.name) / "symlink-source"
        source_root.mkdir()
        review_root = source_root / ".codex-tmp"
        review_root.mkdir(mode=0o700)
        original_container = review_root / "isolated-review-original"
        original_container.mkdir(mode=0o700)
        original_private = (
            original_container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        original_private.write_bytes(b"original")
        moved_review_root = source_root / ".codex-tmp-original"
        review_root.rename(moved_review_root)
        outside_root = pathlib.Path(self.temporary.name) / "outside-review-root"
        outside_root.mkdir(mode=0o700)
        outside_container = outside_root / original_container.name
        outside_container.mkdir(mode=0o700)
        outside_workspace = outside_container / "workspace"
        outside_workspace.mkdir(mode=0o700)
        outside_victim = outside_workspace / "victim.txt"
        outside_victim.write_text("outside\n", encoding="utf-8")
        outside_private = (
            outside_container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        outside_private.write_bytes(b"outside")
        review_root.symlink_to(outside_root, target_is_directory=True)

        swapped_parent_error = workspace_runtime.remove_private_review_artifacts(
            original_container
        )

        self.assertIsNotNone(swapped_parent_error)
        self.assertTrue(outside_private.exists())
        self.assertTrue(
            (
                moved_review_root
                / original_container.name
                / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
            ).exists()
        )

        swapped_review = workspace_runtime.ReviewWorkspace(
            source_root=source_root,
            container_dir=original_container,
            workspace_root=original_container / "workspace",
            base_ref=self.base,
            head_ref=self.head,
            diff_file=original_container / "workspace/.codex-review/review.diff",
            prompt_file=original_container / "workspace/.codex-review/review.prompt",
        )
        swapped_cleanup_error = workspace_runtime.cleanup_workspace(
            swapped_review,
            keep_container=False,
        )
        partial_cleanup_error = workspace_runtime._remove_partial_container(
            original_container
        )

        self.assertIsNotNone(swapped_cleanup_error)
        self.assertIsNotNone(partial_cleanup_error)
        self.assertTrue(outside_victim.exists())
        self.assertTrue(outside_private.exists())

    def test_cleanup_does_not_scrub_forged_external_container(self) -> None:
        external_container = pathlib.Path(self.temporary.name) / "external-container"
        external_container.mkdir(mode=0o700)
        private_artifacts = tuple(
            external_container / name
            for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
        )
        for path in private_artifacts:
            path.write_bytes(b"outside")
        forged = workspace_runtime.ReviewWorkspace(
            source_root=self.repo,
            container_dir=external_container,
            workspace_root=external_container / "workspace",
            base_ref=self.base,
            head_ref=self.head,
            diff_file=external_container / "review.diff",
            prompt_file=external_container / "review.prompt",
        )

        with self.assertRaises(ReviewError):
            workspace_runtime.cleanup_workspace(forged, keep_container=True)

        self.assertTrue(all(path.exists() for path in private_artifacts))

        with (
            mock.patch.object(
                workspace_runtime,
                "validate_workspace_layout",
                return_value=None,
            ),
            self.assertRaisesRegex(ReviewError, "not lexically bound"),
        ):
            workspace_runtime.cleanup_workspace(forged, keep_container=True)

        self.assertTrue(all(path.exists() for path in private_artifacts))

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

    def test_frozen_tree_rejects_sandbox_authentication_symlink(self) -> None:
        (self.repo / "leak").symlink_to("/config/.credentials.json")
        git(self.repo, "add", "leak")
        git(self.repo, "commit", "-m", "Add sandbox authentication symlink")
        link_head = git(self.repo, "rev-parse", "HEAD")

        with self.assertRaisesRegex(
            ReviewError,
            "frozen Git tree symlink escapes workspace",
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=link_head,
            )

    def test_symlink_target_boundary_rejects_magic_and_transient_escape(self) -> None:
        cases = (
            (pathlib.PurePosixPath("leak"), "/proc/self/environ", False),
            (pathlib.PurePosixPath("leak"), "/proc/self/fd/3", False),
            (
                pathlib.PurePosixPath("a/x"),
                "../../workspace/file",
                False,
            ),
            (pathlib.PurePosixPath("a/x"), "../README.md", True),
            (pathlib.PurePosixPath("a/x"), "missing.md", True),
        )

        for link, target, expected in cases:
            with self.subTest(link=link, target=target):
                self.assertEqual(
                    symlink_target_stays_within_workspace(link, target),
                    expected,
                )

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

        with self.assertRaisesRegex(ReviewError, "openai-key") as raised:
            prepare_workspace(
                repo=self.repo,
                base_ref=sensitive_base,
                head_ref=unrelated_head,
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_secret_findings_escape_control_characters_in_snapshot_paths(self) -> None:
        secret = "AKIA" + "C" * 16
        file_name = "file\n\x1bname"
        symlink_name = "link\n\x1bname"
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Prepare clean review range")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=clean_head,
        )
        self.reviews.append(review)
        (review.workspace_root / file_name).write_text(
            secret + "\n",
            encoding="utf-8",
        )
        (review.workspace_root / symlink_name).symlink_to("sk-" + "D" * 40)

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

    def test_deleted_binary_secret_is_allowed_without_control_evidence_leak(
        self,
    ) -> None:
        secret = unregistered_provider_credential()
        binary = self.repo / "opaque.bin"
        binary.write_bytes(b"\0binary\0" + secret + b"\0")
        git(self.repo, "add", "opaque.bin")
        git(self.repo, "commit", "-m", "Add binary credential")
        secret_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "opaque.bin")
        git(self.repo, "commit", "-m", "Remove binary credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(secret_base, clean_head)
        validate_external_workspace(review)

        diff = review.diff_file.read_bytes()
        self.assertIn(b"GIT binary patch", diff)
        self.assert_control_evidence_omits(review, secret)

    def test_oauth_refresh_token_is_detected_in_head_content(self) -> None:
        credential = pathlib.Path(self.temporary.name) / "oauth.json"
        credential.write_text(
            json.dumps({"refresh_token": oauth_refresh_credential()}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_file_secret_rule(credential), "generic-secret-assignment")

    def test_deleted_oauth_refresh_token_is_allowed_without_control_evidence_leak(
        self,
    ) -> None:
        credential = self.repo / "oauth.json"
        raw_credential = oauth_refresh_credential()
        credential.write_text(
            json.dumps({"refresh_token": raw_credential}) + "\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "oauth.json")
        git(self.repo, "commit", "-m", "Add OAuth credential")
        credential_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "oauth.json")
        git(self.repo, "commit", "-m", "Remove OAuth credential")
        clean_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(credential_base, clean_head)
        validate_external_workspace(review)

        raw_value = raw_credential.encode()
        self.assert_diff_retains_raw_deletion(review, raw_value)
        self.assert_control_evidence_omits(review, raw_value)

    def test_unregistered_secret_reductions_are_allowed(self) -> None:
        fixtures = (
            (
                "generic",
                unregistered_generic_credential(),
                lambda value: b'password = "' + value + b'"\n',
            ),
            (
                "jwt",
                unregistered_jwt_credential(),
                lambda value: value + b"\n",
            ),
            (
                "provider",
                unregistered_provider_credential(),
                lambda value: value + b"\n",
            ),
            (
                "private-key",
                unregistered_private_key(),
                lambda value: value + b"\n",
            ),
        )

        for name, raw_value, render in fixtures:
            relative = f"secret-reduction-{name}.txt"
            with self.subTest(secret_kind=name, transition="one-to-zero"):
                one_base = self.commit_bytes(
                    relative,
                    render(raw_value),
                    f"Add one {name} credential",
                )
                zero_head = self.remove_and_commit(
                    relative,
                    f"Remove one {name} credential",
                )
                review = self.prepare_range(one_base, zero_head)
                validate_external_workspace(review)
                self.assert_diff_retains_raw_deletion(review, raw_value)
                self.assert_control_evidence_omits(review, raw_value)

            with self.subTest(secret_kind=name, transition="two-to-one"):
                two_base = self.commit_bytes(
                    relative,
                    render(raw_value) * 2,
                    f"Add two {name} credentials",
                )
                one_head = self.commit_bytes(
                    relative,
                    render(raw_value),
                    f"Reduce {name} credential count",
                )
                review = self.prepare_range(two_base, one_head)
                validate_external_workspace(review)
                self.assert_diff_retains_raw_deletion(review, raw_value)
                self.assert_control_evidence_omits(review, raw_value)
                self.remove_and_commit(
                    relative,
                    f"Clean up remaining {name} credential",
                )

    def test_unregistered_secret_addition_is_blocked(self) -> None:
        raw_value = unregistered_generic_credential()
        added_head = self.commit_bytes(
            "added-secret.txt",
            b'password = "' + raw_value + b'"\n',
            "Add unregistered credential",
        )

        self.assert_external_review_blocked(
            base_ref=self.head,
            head_ref=added_head,
            rule="generic-secret-assignment",
        )

    def test_unchanged_unregistered_secret_with_unrelated_change_is_blocked(
        self,
    ) -> None:
        raw_value = unregistered_generic_credential()
        secret_base = self.commit_bytes(
            "retained-secret.txt",
            b'password = "' + raw_value + b'"\n',
            "Add retained credential",
        )
        unrelated_head = self.commit_bytes(
            "unrelated.txt",
            b"unrelated change\n",
            "Make unrelated change",
        )

        self.assert_external_review_blocked(
            base_ref=secret_base,
            head_ref=unrelated_head,
            rule="generic-secret-assignment",
        )

    def test_moved_unregistered_secret_is_blocked(self) -> None:
        raw_value = unregistered_generic_credential()
        old_path = "old-secret.txt"
        new_path = "new-secret.txt"
        secret_base = self.commit_bytes(
            old_path,
            b'password = "' + raw_value + b'"\n',
            "Add credential before move",
        )
        git(self.repo, "mv", old_path, new_path)
        git(self.repo, "commit", "-m", "Move credential")
        moved_head = git(self.repo, "rev-parse", "HEAD")

        self.assert_external_review_blocked(
            base_ref=secret_base,
            head_ref=moved_head,
            rule="generic-secret-assignment",
        )

    def test_copied_unregistered_secret_count_increase_is_blocked(self) -> None:
        raw_value = unregistered_generic_credential()
        rendered = b'password = "' + raw_value + b'"\n'
        secret_base = self.commit_bytes(
            "source-secret.txt",
            rendered,
            "Add source credential",
        )
        copied_head = self.commit_bytes(
            "copied-secret.txt",
            rendered,
            "Copy credential",
        )

        self.assert_external_review_blocked(
            base_ref=secret_base,
            head_ref=copied_head,
            rule="generic-secret-assignment",
        )

    def test_replacing_two_secret_occurrences_with_a_new_secret_is_blocked(
        self,
    ) -> None:
        first = unregistered_generic_credential()
        second = second_unregistered_generic_credential()
        first_rendered = b'password = "' + first + b'"\n'
        secret_base = self.commit_bytes(
            "replaced-secret.txt",
            first_rendered * 2,
            "Add repeated credential",
        )
        replaced_head = self.commit_bytes(
            "replaced-secret.txt",
            b'password = "' + second + b'"\n',
            "Replace credential",
        )

        self.assert_external_review_blocked(
            base_ref=secret_base,
            head_ref=replaced_head,
            rule="generic-secret-assignment",
        )

    def test_deleted_credential_path_is_allowed(self) -> None:
        credential_base = self.commit_bytes(
            "fixtures/.netrc",
            b"machine example.invalid login reviewer\n",
            "Add credential-shaped path",
        )
        clean_head = self.remove_and_commit(
            "fixtures/.netrc",
            "Remove credential-shaped path",
        )

        review = self.prepare_range(credential_base, clean_head)
        validate_external_workspace(review)
        self.assertIn(b"fixtures/.netrc", review.diff_file.read_bytes())

    def test_new_and_retained_credential_paths_are_blocked(self) -> None:
        added_head = self.commit_bytes(
            "fixtures/.netrc",
            b"machine example.invalid login reviewer\n",
            "Add credential-shaped path",
        )
        with self.subTest(transition="new-sensitive-path"):
            self.assert_external_review_blocked(
                base_ref=self.head,
                head_ref=added_head,
                rule="credential-path",
            )

        retained_head = self.commit_bytes(
            "unrelated-path-change.txt",
            b"unrelated change\n",
            "Make unrelated change with retained credential path",
        )
        with self.subTest(transition="retained-sensitive-path"):
            self.assert_external_review_blocked(
                base_ref=added_head,
                head_ref=retained_head,
                rule="credential-path",
            )

    def test_non_extractable_secret_deletions_fail_closed(self) -> None:
        oversized_provider = b"".join((b"sk", b"-", b"O" * 513))
        private_key_label = b"".join((b"PRIVATE", b" KEY"))
        incomplete_private_key = b"".join(
            (
                b"-----BEGIN ",
                private_key_label,
                b"-----\n",
                b"R" * 64,
                b"\n",
            )
        )
        fixtures = (
            ("oversized-provider", oversized_provider, "openai-key"),
            ("incomplete-private-key", incomplete_private_key, "private-key"),
        )

        for name, raw_value, rule in fixtures:
            with self.subTest(secret_kind=name):
                relative = f"non-extractable-{name}.txt"
                secret_base = self.commit_bytes(
                    relative,
                    raw_value,
                    f"Add {name} credential",
                )
                clean_head = self.remove_and_commit(
                    relative,
                    f"Remove {name} credential",
                )
                self.assert_external_review_blocked(
                    base_ref=secret_base,
                    head_ref=clean_head,
                    rule=rule,
                )

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
