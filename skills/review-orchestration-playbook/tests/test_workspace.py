from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import synthetic_tokens as synthetic_tokens_runtime  # noqa: E402
from review_runtime import workspace as workspace_runtime  # noqa: E402
from review_runtime.common import ForwardedSignal, ReviewError  # noqa: E402
from review_runtime.synthetic_tokens import (  # noqa: E402
    LegacyExemption,
    LegacyToken,
    SyntheticTokenCatalog,
)
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


def cleanup_evidence(
    container: pathlib.Path,
) -> workspace_runtime.PrivateCleanupEvidence:
    container_status = os.lstat(container)
    artifacts = {}
    for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES:
        path = container / name
        if path.is_file() and not path.is_symlink():
            status = os.lstat(path)
            artifacts[name] = workspace_runtime.CleanupIdentity(
                device=status.st_dev,
                inode=status.st_ino,
            )
    return workspace_runtime.PrivateCleanupEvidence(
        container=workspace_runtime.CleanupIdentity(
            device=container_status.st_dev,
            inode=container_status.st_ino,
        ),
        artifacts=artifacts,
    )


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

    def test_secret_admission_runs_without_materializing_or_reviewing(self) -> None:
        repository_entries = tuple(sorted(path.name for path in self.repo.iterdir()))
        with (
            mock.patch.object(
                workspace_runtime, "_materialize_frozen_tree"
            ) as materialize,
            mock.patch.object(workspace_runtime, "_write_frozen_diff") as write_diff,
            mock.patch.object(workspace_runtime, "build_review_prompt") as build_prompt,
        ):
            exit_code, summary = workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(summary["status"], "clean")
        self.assertEqual(summary["review_contract"], "admission-only-no-reviewer")
        self.assertFalse(summary["reviewer_started"])
        self.assertEqual(summary["review_range"], f"{self.base}..{self.head}")
        materialize.assert_not_called()
        write_diff.assert_not_called()
        build_prompt.assert_not_called()
        self.assertEqual(
            tuple(sorted(path.name for path in self.repo.iterdir())),
            repository_entries,
        )

    def test_secret_admission_reports_growth_and_scan_uncertainty(self) -> None:
        added_secret_head = self.commit_bytes(
            "credential.txt",
            b"password: " + unregistered_generic_credential() + b"\n",
            "Add credential",
        )
        exit_code, violation = workspace_runtime.secret_admission(
            repo=self.repo,
            base_ref=self.head,
            head_ref=added_secret_head,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(violation["status"], "violations")
        self.assertFalse(violation["reviewer_started"])
        self.assertTrue(violation["secret_delta"]["violations"])

        with mock.patch.object(
            workspace_runtime,
            "_secret_count_manifests",
            side_effect=ReviewError("scan failed"),
        ):
            exit_code, inconclusive = workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )
        self.assertEqual(exit_code, 75)
        self.assertEqual(inconclusive["status"], "inconclusive")
        self.assertEqual(inconclusive["failure_class"], "exact-value-scan-incomplete")
        self.assertFalse(inconclusive["reviewer_started"])

    def test_secret_admission_preserves_violation_when_locations_fail(self) -> None:
        added_secret_head = self.commit_bytes(
            "credential.txt",
            b"password: " + unregistered_generic_credential() + b"\n",
            "Add credential",
        )
        with mock.patch.object(
            workspace_runtime,
            "_secret_delta_addition_locations",
            side_effect=OSError("location scan failed"),
        ):
            exit_code, summary = workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.head,
                head_ref=added_secret_head,
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(summary["status"], "violations")
        self.assertEqual(summary["secret_delta"]["location_status"], "inconclusive")
        self.assertTrue(summary["secret_delta"]["violations"])

    def test_secret_admission_cleanup_failure_never_erases_violations(self) -> None:
        added_secret_head = self.commit_bytes(
            "credential.txt",
            b"password: " + unregistered_generic_credential() + b"\n",
            "Add credential",
        )
        real_container = tempfile.TemporaryDirectory()
        self.addCleanup(real_container.cleanup)
        temporary = mock.Mock()
        temporary.name = real_container.name
        temporary.cleanup.side_effect = OSError("cleanup failed")
        with mock.patch.object(
            workspace_runtime.tempfile,
            "TemporaryDirectory",
            return_value=temporary,
        ):
            exit_code, summary = workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.head,
                head_ref=added_secret_head,
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(summary["status"], "violations")
        self.assertTrue(summary["secret_delta"]["violations"])
        self.assertEqual(summary["temporary_cleanup_status"], "inconclusive")
        self.assertEqual(
            summary["temporary_cleanup_failure_class"],
            "temporary-cleanup-incomplete",
        )

    def test_secret_admission_clean_cleanup_failure_is_inconclusive(self) -> None:
        real_container = tempfile.TemporaryDirectory()
        self.addCleanup(real_container.cleanup)
        temporary = mock.Mock()
        temporary.name = real_container.name
        temporary.cleanup.side_effect = OSError("cleanup failed")
        with mock.patch.object(
            workspace_runtime.tempfile,
            "TemporaryDirectory",
            return_value=temporary,
        ):
            exit_code, summary = workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        self.assertEqual(exit_code, 75)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["failure_class"], "temporary-cleanup-incomplete")
        self.assertEqual(summary["temporary_cleanup_status"], "inconclusive")

    def test_secret_admission_catalog_io_error_is_an_input_error(self) -> None:
        with (
            mock.patch.object(
                workspace_runtime,
                "load_catalog",
                side_effect=OSError("catalog read failed"),
            ),
            self.assertRaisesRegex(
                ReviewError,
                "direct secret-admission input or policy could not be read",
            ),
        ):
            workspace_runtime.secret_admission(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

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

    def catalog_with_legacy_values(
        self,
        values: tuple[bytes, ...],
        *,
        rule: str,
    ) -> SyntheticTokenCatalog:
        base_catalog = workspace_runtime.load_catalog()
        exemption = LegacyExemption(
            identifier="test-legacy-exemption",
            repository="example/repository",
            verified_master_tip=self.base,
            match="non-increasing-global-count",
            values=tuple(
                LegacyToken(
                    identifier=f"test-legacy-{index:03d}",
                    rule=rule,
                    value=value,
                    containing_commit=self.base,
                    source_occurrences=1,
                )
                for index, value in enumerate(values)
            ),
        )
        return SyntheticTokenCatalog(
            schema_version=base_catalog.schema_version,
            pool_version=base_catalog.pool_version,
            authoring_tokens=base_catalog.authoring_tokens,
            legacy_exemptions=(exemption,),
        )

    def encoded_file_catalog_with_legacy_values(
        self,
        values: tuple[bytes, ...],
        *,
        rule: str,
    ) -> bytes:
        payload = json.loads(
            synthetic_tokens_runtime.CATALOG_PATH.read_text(encoding="utf-8")
        )
        payload["legacy_exemptions"] = [
            {
                "id": "x",
                "match": "non-increasing-global-count",
                "repository": "e/p",
                "values": [
                    {
                        "containing_commit": "b" * 40,
                        "id": f"t{index}",
                        "rule": rule,
                        "source_occurrences": 1,
                        "value_base64": base64.b64encode(value).decode("ascii"),
                    }
                    for index, value in enumerate(values)
                ],
                "verified_master_tip": "a" * 40,
            }
        ]
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def maximal_file_backed_legacy_catalog(
        self,
        *,
        rule: str,
        compact_values: bool = False,
    ) -> tuple[tuple[bytes, ...], SyntheticTokenCatalog]:
        if compact_values:
            candidate_values = tuple(
                b"S" * 11 + f"{index:05d}".encode("ascii")
                for index in range(workspace_runtime.MAX_SYNTHETIC_EVIDENCE_ENTRIES)
            )
        else:
            candidate_values = tuple(
                b"sk-" + b"P" * 36 + f"{index:04d}".encode("ascii")
                for index in range(workspace_runtime.MAX_SYNTHETIC_EVIDENCE_ENTRIES)
            )
        lower_bound = 0
        upper_bound = len(candidate_values)
        while lower_bound < upper_bound:
            midpoint = (lower_bound + upper_bound + 1) // 2
            encoded_candidate = self.encoded_file_catalog_with_legacy_values(
                candidate_values[:midpoint],
                rule=rule,
            )
            if len(encoded_candidate) <= synthetic_tokens_runtime.MAX_CATALOG_BYTES:
                lower_bound = midpoint
            else:
                upper_bound = midpoint - 1
        values = candidate_values[:lower_bound]
        encoded_catalog = self.encoded_file_catalog_with_legacy_values(
            values,
            rule=rule,
        )
        self.assertGreater(
            len(values),
            workspace_runtime.MAX_SECRET_REDUCTION_CANDIDATES,
        )
        self.assertLessEqual(
            len(encoded_catalog),
            synthetic_tokens_runtime.MAX_CATALOG_BYTES,
        )
        self.assertLess(len(values), len(candidate_values))
        self.assertGreater(
            len(
                self.encoded_file_catalog_with_legacy_values(
                    candidate_values[: len(values) + 1],
                    rule=rule,
                )
            ),
            synthetic_tokens_runtime.MAX_CATALOG_BYTES,
        )
        return values, synthetic_tokens_runtime.parse_catalog_bytes(encoded_catalog)

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

    def assert_secret_delta_status(self, review, expected: str) -> dict:
        evidence = validate_external_workspace(review)
        secret_delta = evidence["secret_delta"]
        self.assertEqual(secret_delta["status"], expected)
        self.assertIn(
            secret_delta["location_status"],
            {"complete", "inconclusive"},
        )
        return secret_delta

    def assert_secret_violation(
        self,
        review,
        raw_value: bytes,
        *,
        base_count: int,
        head_count: int,
    ) -> dict:
        secret_delta = self.assert_secret_delta_status(review, "violations")
        matching = [
            violation
            for violation in secret_delta["violations"]
            if violation["value_sha256"] == hashlib.sha256(raw_value).hexdigest()
        ]
        self.assertEqual(len(matching), 1)
        violation = matching[0]
        self.assertEqual(violation["base_count"], base_count)
        self.assertEqual(violation["head_count"], head_count)
        self.assertEqual(violation["delta"], head_count - base_count)
        return violation

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

    def test_prepare_keeps_tracked_review_context_and_excludes_untracked_files(
        self,
    ) -> None:
        tracked_context = {
            ".env": "tracked root environment context\n",
            "config/prod.env": "tracked nested environment context\n",
            ".agents/AGENTS.md": "tracked agent context\n",
            ".codex/skills/example/SKILL.md": "tracked Codex context\n",
        }
        for relative, content in tracked_context.items():
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        git(self.repo, "add", *tracked_context)
        git(self.repo, "commit", "-m", "Add tracked review context")
        context_head = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "untracked-private-sentinel.txt").write_text(
            "must stay outside the frozen review workspace\n",
            encoding="utf-8",
        )

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.head,
            head_ref=context_head,
        )
        self.reviews.append(review)

        for relative, content in tracked_context.items():
            self.assertEqual(
                (review.workspace_root / relative).read_text(encoding="utf-8"),
                content,
            )
        self.assertFalse(
            (review.workspace_root / "untracked-private-sentinel.txt").exists()
        )
        self.assertFalse((review.workspace_root / ".git").exists())

    def test_changed_path_proof_preserves_both_sides_of_rename(self) -> None:
        git(self.repo, "mv", "example.txt", "renamed.txt")
        git(self.repo, "commit", "-m", "Rename example")
        renamed_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(self.head, renamed_head)
        private_records = (
            (review.container_dir / workspace_runtime.PRIVATE_CHANGED_PATHS_NAME)
            .read_bytes()
            .split(b"\0")
        )

        self.assertIn(
            workspace_runtime.CHANGED_PATH_BASE_ONLY_TAG + b"example.txt",
            private_records,
        )
        self.assertIn(
            workspace_runtime.CHANGED_PATH_HEAD_TAG + b"renamed.txt",
            private_records,
        )

    def test_prepare_rejects_lfs_pointer_after_attributes_are_deleted(self) -> None:
        git(self.repo, "rm", ".gitattributes")
        oid = "a" * 64
        (self.repo / "asset.bin").write_text(
            f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 1\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "asset.bin")
        git(self.repo, "commit", "-m", "Add direct LFS pointer")
        self.head = git(self.repo, "rev-parse", "HEAD")
        handoffs = []

        with self.assertRaisesRegex(
            ReviewError,
            r"blocked-checkout-lfs-pointer: review_status=not-run: .*asset\.bin",
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=handoffs.append,
            )

        self.assertEqual(handoffs, [])
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_prepare_materializes_blob_at_lfs_pointer_cutoff(self) -> None:
        git(self.repo, "rm", ".gitattributes")
        oid = "a" * 64
        canonical = (
            f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 1\n"
        ).encode("ascii")
        payload = canonical + (b" " * (1024 - len(canonical)))
        self.assertEqual(len(payload), workspace_runtime.GIT_LFS_POINTER_MAX_BYTES)
        (self.repo / "asset.bin").write_bytes(payload)
        git(self.repo, "add", "asset.bin")
        git(self.repo, "commit", "-m", "Add cutoff-sized pointer-like blob")
        self.head = git(self.repo, "rev-parse", "HEAD")

        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)

        self.assertEqual((review.workspace_root / "asset.bin").read_bytes(), payload)

    def test_prepare_uses_private_control_modes_under_permissive_umask(self) -> None:
        nested_file = self.repo / "nested" / "deeper" / "payload.txt"
        nested_file.parent.mkdir(parents=True)
        nested_file.write_text("nested\n", encoding="utf-8")
        git(self.repo, "add", str(nested_file.relative_to(self.repo)))
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},nested/vendor/external",
        )
        git(self.repo, "commit", "-m", "Add nested frozen tree entries")
        self.head = git(self.repo, "rev-parse", "HEAD")

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
                self.assertEqual(review.workspace_root.stat().st_mode & 0o777, 0o755)
                for directory in (
                    review.workspace_root / "nested",
                    review.workspace_root / "nested" / "deeper",
                    review.workspace_root / "nested" / "vendor",
                    review.workspace_root / "nested" / "vendor" / "external",
                ):
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
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
                self.assertIsNone(cleanup_workspace(review, keep_container=False))
                self.assertFalse(review.container_dir.exists())

    def test_bound_file_creators_force_owner_mode_under_restrictive_umask(
        self,
    ) -> None:
        review = self.prepare_range(self.base, self.head)
        lock_path = review.container_dir / "cleanup.lock"
        lock_path.unlink(missing_ok=True)
        lock_handle, lock_error = workspace_runtime.open_bound_review_lock(
            review.container_dir,
            expected=review.private_cleanup,
            name="cleanup.lock",
        )
        self.assertIsNone(lock_error)
        self.assertIsNotNone(lock_handle)
        assert lock_handle is not None
        private_path = review.container_dir / "restrictive-umask-private.bin"
        control_state = workspace_runtime._load_control_artifact_state(
            container_dir=review.container_dir
        )
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        container_descriptor = os.open(review.container_dir, directory_flags)
        previous_umask = os.umask(0o777)
        try:
            with workspace_runtime._open_new_private_binary(private_path) as handle:
                handle.write(b"private artifact\n")
            self.assertIsNone(
                workspace_runtime.write_bound_review_text(
                    review.container_dir,
                    expected=review.private_cleanup,
                    name="runner-error.txt",
                    text="runtime artifact\n",
                )
            )
            workspace_runtime._write_control_artifact_state_at(
                container_descriptor,
                control_state,
            )
            self.assertIsNone(lock_handle.open_compatibility_lock("cleanup.lock"))
        finally:
            os.umask(previous_umask)
            os.close(container_descriptor)
            lock_handle.close()

        for artifact in (
            private_path,
            review.container_dir / "runner-error.txt",
            review.container_dir / workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
            lock_path,
        ):
            with self.subTest(artifact=artifact.name):
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

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

    def test_external_workspace_requires_private_artifact_mode_0600(self) -> None:
        for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES:
            with self.subTest(name=name):
                review = prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                )
                artifact = review.container_dir / name
                artifact.chmod(0o644)

                with self.assertRaisesRegex(ReviewError, "must have mode 0600"):
                    validate_external_workspace(review)

                self.assertIsNone(cleanup_workspace(review, keep_container=False))
                self.assertFalse(review.container_dir.exists())

    def test_external_workspace_attests_exact_primary_diff(self) -> None:
        review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )
        self.reviews.append(review)
        diff_bytes = review.diff_file.read_bytes()

        evidence = validate_external_workspace(review)

        manifest = json.loads(
            (
                review.workspace_root
                / ".codex-review"
                / workspace_runtime.SYNTHETIC_MANIFEST_NAME
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["schema_version"], 5)
        self.assertEqual(
            set(manifest["secret_delta"]),
            {"limitations", "location_status", "status", "violations"},
        )
        self.assertEqual(
            evidence["primary_diff"],
            {
                "path": ".codex-review/review.diff",
                "sha256": hashlib.sha256(diff_bytes).hexdigest(),
                "size": len(diff_bytes),
            },
        )
        encoded_evidence = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(str(review.workspace_root), encoded_evidence)
        self.assertNotIn("+two", encoded_evidence)
        self.assertEqual(
            workspace_runtime.build_preflight_evidence(review, evidence)["status"],
            "review workspace containment and integrity checks passed",
        )

        tampered_diff = bytearray(diff_bytes)
        tampered_diff[0] ^= 1
        review.diff_file.write_bytes(tampered_diff)
        with self.assertRaisesRegex(
            ReviewError,
            "does not match helper-private control state",
        ):
            validate_external_workspace(review)

    def test_preflight_serialization_has_a_separate_pretty_json_bound(self) -> None:
        def exact_value(target_size: int, *, pretty: bool) -> dict[str, str]:
            value = {"padding": ""}
            if pretty:
                empty = json.dumps(value, indent=2, sort_keys=True) + "\n"
            else:
                empty = json.dumps(value, separators=(",", ":"), sort_keys=True)
            value["padding"] = "x" * (target_size - len(empty.encode("utf-8")))
            return value

        compact_limit = workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES
        compact = exact_value(compact_limit, pretty=False)
        self.assertEqual(
            len(workspace_runtime._encode_synthetic_evidence_json(compact)),
            compact_limit,
        )
        with self.assertRaisesRegex(ReviewError, "synthetic-token preflight evidence"):
            workspace_runtime._encode_synthetic_evidence_json(
                exact_value(compact_limit + 1, pretty=False)
            )

        pretty_limit = workspace_runtime.MAX_PREFLIGHT_JSON_BYTES
        pretty = exact_value(pretty_limit, pretty=True)
        self.assertEqual(
            len(workspace_runtime.encode_preflight_json(pretty).encode("utf-8")),
            pretty_limit,
        )
        adaptive = exact_value(pretty_limit + 1, pretty=True)
        adaptive_encoded = workspace_runtime.encode_preflight_json(adaptive)
        self.assertLessEqual(len(adaptive_encoded.encode("utf-8")), pretty_limit)
        self.assertEqual(json.loads(adaptive_encoded), adaptive)
        with self.assertRaisesRegex(ReviewError, "serialized preflight evidence"):
            workspace_runtime.encode_preflight_json(
                exact_value(pretty_limit + 1, pretty=False)
            )

    def test_bounded_json_reader_rejects_growth_past_limit(self) -> None:
        limit = workspace_runtime.MAX_PREFLIGHT_JSON_BYTES
        path = pathlib.Path(self.temporary.name) / "growing.json"
        empty = json.dumps({"padding": ""}, sort_keys=True)
        value = {"padding": "x" * (limit - len(empty.encode("utf-8")))}
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")
        self.assertEqual(len(encoded), limit)
        path.write_bytes(encoded)
        original_read = workspace_runtime._DigestingReader.read
        grew = False

        def grow_before_first_read(reader, size=-1):
            nonlocal grew
            if not grew:
                with path.open("ab") as handle:
                    handle.write(b"x")
                grew = True
            return original_read(reader, size)

        with mock.patch.object(
            workspace_runtime._DigestingReader,
            "read",
            new=grow_before_first_read,
        ):
            with self.assertRaisesRegex(ReviewError, "exceeds its review size limit"):
                workspace_runtime._read_bounded_json(
                    path,
                    label="growing evidence",
                    max_bytes=limit,
                )

    def test_bounded_json_reader_enforces_explicit_depth_limit(self) -> None:
        path = pathlib.Path(self.temporary.name) / "nested.json"

        def nested(depth: int) -> dict[str, object]:
            value: object = None
            for _ in range(depth):
                value = [value]
            return {"padding": value}

        path.write_text(
            json.dumps(nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH)),
            encoding="utf-8",
        )
        self.assertEqual(
            workspace_runtime._read_bounded_json(path, label="nested evidence"),
            nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH),
        )

        path.write_text(
            json.dumps(nested(workspace_runtime.MAX_BOUNDED_JSON_DEPTH + 1)),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewError,
            "nested evidence exceeds the JSON nesting depth limit",
        ):
            workspace_runtime._read_bounded_json(path, label="nested evidence")

    def test_descriptor_relative_json_reader_honors_caller_bound(self) -> None:
        directory = pathlib.Path(self.temporary.name) / "descriptor-json"
        directory.mkdir()
        path = directory / "evidence.json"
        value = {"padding": "x" * workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES}
        encoded = json.dumps(value).encode("utf-8")
        path.write_bytes(encoded)
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            with self.assertRaisesRegex(ReviewError, "exceeds its review size limit"):
                workspace_runtime._read_bounded_json_at(
                    descriptor,
                    path.name,
                    label="descriptor evidence",
                )
            self.assertEqual(
                workspace_runtime._read_bounded_json_at(
                    descriptor,
                    path.name,
                    label="descriptor evidence",
                    max_bytes=len(encoded),
                ),
                value,
            )
        finally:
            os.close(descriptor)

    def test_descriptor_relative_json_reader_keeps_strict_json_checks(self) -> None:
        directory = pathlib.Path(self.temporary.name) / "strict-descriptor-json"
        directory.mkdir()
        path = directory / "evidence.json"
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            path.write_text('{"outer":{"key":1,"key":2}}', encoding="utf-8")
            with self.assertRaisesRegex(ReviewError, "duplicate key"):
                workspace_runtime._read_bounded_json_at(
                    descriptor,
                    path.name,
                    label="descriptor evidence",
                )

            nested: object = None
            for _ in range(workspace_runtime.MAX_BOUNDED_JSON_DEPTH + 1):
                nested = [nested]
            path.write_text(json.dumps({"padding": nested}), encoding="utf-8")
            with self.assertRaisesRegex(ReviewError, "nesting depth limit"):
                workspace_runtime._read_bounded_json_at(
                    descriptor,
                    path.name,
                    label="descriptor evidence",
                )
        finally:
            os.close(descriptor)

    def test_secret_delta_summary_accepts_only_valid_status_combinations(
        self,
    ) -> None:
        violation = {
            "additions": [
                {
                    "line": 3,
                    "occurrence_count": 1,
                    "path": "example.txt",
                    "surface": "blob",
                }
            ],
            "base_count": 1,
            "delta": 1,
            "head_count": 2,
            "omitted_addition_location_count": 0,
            "rules": ["generic-secret-assignment"],
            "value_length": 16,
            "value_sha256": "a" * 64,
        }
        valid = (
            {
                "limitations": [],
                "location_status": "complete",
                "status": "clean",
                "violations": [],
            },
            {
                "limitations": [],
                "location_status": "complete",
                "status": "violations",
                "violations": [violation],
            },
            {
                "limitations": [],
                "location_status": "inconclusive",
                "status": "violations",
                "violations": [violation],
            },
            {
                "failure_class": "secret-count-incomplete",
                "limitations": [],
                "location_status": "inconclusive",
                "status": "inconclusive",
                "violations": [],
            },
        )
        for summary in valid:
            with self.subTest(summary=summary["status"]):
                self.assertEqual(
                    workspace_runtime.validate_secret_delta_summary(summary),
                    summary,
                )

        invalid = (
            {**valid[0], "location_status": "inconclusive"},
            {**valid[0], "failure_class": "unexpected"},
            {**valid[1], "violations": []},
            {**valid[1], "failure_class": "unexpected"},
            {**valid[3], "location_status": "complete"},
            {**valid[3], "failure_class": "INVALID"},
            {**valid[3], "violations": [violation]},
        )
        for summary in invalid:
            with self.subTest(summary=summary):
                with self.assertRaisesRegex(ReviewError, "state is invalid"):
                    workspace_runtime.validate_secret_delta_summary(summary)

    def test_secret_delta_summary_bounds_violation_structure(self) -> None:
        def violation(digest: str, additions: list[dict[str, object]]):
            return {
                "additions": additions,
                "base_count": 0,
                "delta": 1,
                "head_count": 1,
                "omitted_addition_location_count": 0,
                "rules": ["generic-secret-assignment"],
                "value_length": 16,
                "value_sha256": digest,
            }

        addition = {
            "line": None,
            "occurrence_count": 1,
            "path": "example.bin",
            "surface": "binary",
        }
        too_many = workspace_runtime.MAX_SECRET_DELTA_ADDITION_LOCATIONS
        oversized_location_set = violation(
            "a" * 64,
            [dict(addition) for _ in range(too_many)],
        )
        oversized_location_set["delta"] = too_many
        oversized_location_set["head_count"] = too_many
        summary = {
            "limitations": [],
            "location_status": "inconclusive",
            "status": "violations",
            "violations": [
                oversized_location_set,
                violation("b" * 64, [dict(addition)]),
            ],
        }
        with self.assertRaisesRegex(ReviewError, "too many addition locations"):
            workspace_runtime.validate_secret_delta_summary(summary)

        malformed = dict(violation("c" * 64, [dict(addition)]))
        malformed["delta"] = 2
        summary["violations"] = [malformed]
        with self.assertRaisesRegex(ReviewError, "violation is inconsistent"):
            workspace_runtime.validate_secret_delta_summary(summary)

        excessive_addition = dict(addition)
        excessive_addition["occurrence_count"] = 2
        summary["violations"] = [violation("c" * 64, [excessive_addition])]
        with self.assertRaisesRegex(ReviewError, "addition evidence is inconsistent"):
            workspace_runtime.validate_secret_delta_summary(summary)

        summary["location_status"] = "complete"
        summary["violations"] = [violation("c" * 64, [])]
        with self.assertRaisesRegex(ReviewError, "addition evidence is inconsistent"):
            workspace_runtime.validate_secret_delta_summary(summary)
        summary["location_status"] = "inconclusive"

        unhashable_rules = dict(violation("d" * 64, [dict(addition)]))
        unhashable_rules["rules"] = [{}, "generic-secret-assignment"]
        summary["violations"] = [unhashable_rules]
        with self.assertRaisesRegex(ReviewError, "violation is inconsistent"):
            workspace_runtime.validate_secret_delta_summary(summary)

        unhashable_surface = dict(addition)
        unhashable_surface["surface"] = []
        summary["violations"] = [violation("e" * 64, [unhashable_surface])]
        with self.assertRaisesRegex(ReviewError, "addition is inconsistent"):
            workspace_runtime.validate_secret_delta_summary(summary)

        bounded_violations = [
            violation(
                hashlib.sha256(f"violation-{index}".encode("ascii")).hexdigest(),
                [],
            )
            for index in range(workspace_runtime.MAX_SYNTHETIC_EVIDENCE_ENTRIES)
        ]
        bounded_summary = {
            "limitations": [],
            "location_status": "inconclusive",
            "status": "violations",
            "violations": bounded_violations,
        }
        self.assertEqual(
            workspace_runtime.validate_secret_delta_summary(bounded_summary),
            bounded_summary,
        )
        bounded_manifest = {
            "base_ref": "1" * 40,
            "catalog_schema_version": 1,
            "entries": [
                {
                    "base_count": 0,
                    "exemption_id": "x",
                    "head_count": 1,
                    "rule": "generic-secret-assignment",
                    "token_id": f"t{index}",
                    "value_length": 16,
                    "value_sha256": violation_entry["value_sha256"],
                }
                for index, violation_entry in enumerate(bounded_violations)
            ],
            "head_ref": "2" * 40,
            "pool_version": "test",
            "schema_version": workspace_runtime.SYNTHETIC_MANIFEST_SCHEMA_VERSION,
            "secret_delta": bounded_summary,
            "secret_reductions": [],
            "selected_exemptions": ["x"],
        }
        public_shard, private_shard = workspace_runtime._shard_catalog_count_manifest(
            bounded_manifest
        )
        self.assertLessEqual(
            len(
                workspace_runtime._bounded_json_bytes(
                    public_shard,
                    label="test public synthetic secret manifest shard",
                )
            ),
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        self.assertLessEqual(
            len(
                workspace_runtime._bounded_json_bytes(
                    private_shard,
                    label="test private synthetic secret manifest shard",
                )
            ),
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        merged_manifest, was_sharded, raw_reduction_values = (
            workspace_runtime._merge_secret_count_manifest_shards(
                public_shard,
                private_shard,
            )
        )
        self.assertTrue(was_sharded)
        self.assertEqual(raw_reduction_values, [])
        self.assertEqual(merged_manifest["entries"], [])
        self.assertEqual(merged_manifest["secret_delta"]["status"], "violations")
        self.assertEqual(
            len(merged_manifest["secret_delta"]["violations"]),
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_ENTRIES,
        )
        workspace_runtime.validate_secret_delta_summary(merged_manifest["secret_delta"])
        complete_preflight = {
            "primary_diff": {
                "path": ".codex-review/review.diff",
                "sha256": "0" * 64,
                "size": 0,
            },
            "private_artifacts": "removed",
            "review_range": f"{'1' * 40}..{'2' * 40}",
            "scope": "frozen tracked workspace, diff, and review prompt",
            "secret_delta": bounded_summary,
            "status": "review workspace containment and integrity checks passed",
            "synthetic_tokens": {
                "accepted": [],
                "catalog_schema_version": 1,
                "legacy_counts": [],
                "pool_version": "test",
                "secret_reductions": [],
            },
        }
        pretty_preflight = (
            json.dumps(complete_preflight, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertGreater(
            len(pretty_preflight),
            workspace_runtime.MAX_PREFLIGHT_JSON_BYTES,
        )
        encoded_preflight = workspace_runtime.encode_preflight_json(
            complete_preflight
        ).encode("utf-8")
        self.assertLessEqual(
            len(encoded_preflight),
            workspace_runtime.MAX_PREFLIGHT_JSON_BYTES,
        )
        parsed_preflight = json.loads(encoded_preflight)
        self.assertEqual(parsed_preflight["secret_delta"]["status"], "violations")
        self.assertEqual(
            len(parsed_preflight["secret_delta"]["violations"]),
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_ENTRIES,
        )
        bounded_summary["violations"] = bounded_violations + [violation("f" * 64, [])]
        with self.assertRaisesRegex(ReviewError, "secret-delta is invalid"):
            workspace_runtime.validate_secret_delta_summary(bounded_summary)

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
            mock.patch.object(
                workspace_runtime,
                "_secret_count_manifests",
                return_value=({}, {}, ()),
            ),
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
            mock.patch.object(
                workspace_runtime,
                "_secret_count_manifests",
                return_value=({}, {}, ()),
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

    def test_oversized_changed_blob_finding_metadata_does_not_block_validation(
        self,
    ) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()
            status = kwargs["private_destination"].stat()
            self.assertEqual(
                kwargs["private_expected_identity"],
                workspace_runtime.CleanupIdentity(
                    device=status.st_dev,
                    inode=status.st_ino,
                ),
            )

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_METADATA_BYTES", 1),
        ):
            review = self.prepare_range(
                base_ref=self.base,
                head_ref=self.head,
            )
        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["location_status"], "complete")
        self.assertIn(b"+two", review.diff_file.read_bytes())

    def test_excessive_changed_blob_finding_entries_do_not_block_validation(
        self,
    ) -> None:
        def write_empty_changed_paths(**kwargs) -> None:
            kwargs["destination"].touch()
            status = kwargs["private_destination"].stat()
            self.assertEqual(
                kwargs["private_expected_identity"],
                workspace_runtime.CleanupIdentity(
                    device=status.st_dev,
                    inode=status.st_ino,
                ),
            )

        with (
            mock.patch.object(
                workspace_runtime,
                "_write_frozen_changed_paths",
                side_effect=write_empty_changed_paths,
            ),
            mock.patch.object(workspace_runtime, "MAX_CHANGED_ENTRIES", 0),
        ):
            review = self.prepare_range(
                base_ref=self.base,
                head_ref=self.head,
            )
        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["location_status"], "complete")
        self.assertIn(b"+two", review.diff_file.read_bytes())

    def test_oversized_changed_blob_scan_marks_secret_delta_inconclusive(self) -> None:
        with mock.patch.object(
            workspace_runtime,
            "MAX_CHANGED_BLOB_SCAN_BYTES",
            1,
        ):
            review = self.prepare_range(
                base_ref=self.base,
                head_ref=self.head,
            )
        secret_delta = self.assert_secret_delta_status(review, "inconclusive")
        self.assertEqual(
            secret_delta["failure_class"],
            "exact-value-scan-incomplete",
        )
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        self.assertIn(b"+two", review.diff_file.read_bytes())

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
                "review_runtime.workspace._remove_open_directory_contents",
                return_value=["permission denied"],
            ),
            self.assertRaisesRegex(
                ReviewError,
                r"evidence may remain near .*isolated-review.*permission denied",
            ),
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
            )

        review_root = self.repo / ".codex-tmp"
        self.assertEqual(len(list(review_root.glob("isolated-review-*"))), 1)

    def test_keep_container_cleanup_retry_rejects_workspace_quarantine(self) -> None:
        review = self.prepare_range(self.base, self.head)

        with mock.patch.object(
            workspace_runtime,
            "_remove_open_directory_contents",
            return_value=["permission denied"],
        ):
            first_error = cleanup_workspace(review, keep_container=True)

        self.assertIn("permission denied", first_error or "")
        quarantines = list(
            review.container_dir.glob(
                f"{workspace_runtime.REVIEW_CLEANUP_QUARANTINE_PREFIX}*"
            )
        )
        self.assertEqual(len(quarantines), 1)
        self.assertTrue(quarantines[0].is_dir())
        self.assertFalse(review.workspace_root.exists())

        retry_error = cleanup_workspace(review, keep_container=True)

        self.assertIn(
            "pre-existing review cleanup quarantine requires manual recovery",
            retry_error or "",
        )
        self.assertTrue(quarantines[0].exists())

    def test_full_cleanup_quarantines_container_before_retiring_protocol(self) -> None:
        review = self.prepare_range(self.base, self.head)
        marker = review.container_dir / workspace_runtime.REVIEW_STATE_MARKER_NAME
        marker.write_text("recovery marker\n", encoding="utf-8")
        cleanup_lock_path = (
            review.container_dir / workspace_runtime.REVIEW_CLEANUP_LOCK_NAME
        )
        runner_lock_path = (
            review.container_dir / workspace_runtime.REVIEW_RUNNER_LOCK_NAME
        )
        cleanup_lock_path.touch()
        runner_lock_path.touch()
        cleanup_lock_handle = cleanup_lock_path.open("r+b")
        runner_lock_handle = runner_lock_path.open("r+b")
        fcntl.flock(cleanup_lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(runner_lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        cleanup_events = []
        real_quarantine = workspace_runtime._quarantine_cleanup_entry
        real_fsync = os.fsync
        real_rmdir = os.rmdir
        parent_metadata = review.container_dir.parent.stat()
        parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)

        def record_parent_fsync(descriptor):
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == parent_identity:
                cleanup_events.append("parent-fsync")
            real_fsync(descriptor)

        def record_container_rmdir(path, *, dir_fd=None):
            if dir_fd is not None and str(path).startswith(
                workspace_runtime.REVIEW_CLEANUP_QUARANTINE_PREFIX
            ):
                metadata = os.fstat(dir_fd)
                if (metadata.st_dev, metadata.st_ino) == parent_identity:
                    cleanup_events.append("container-rmdir")
            real_rmdir(path, dir_fd=dir_fd)

        def record_final_entry(parent_descriptor, entry_name, metadata, **kwargs):
            label = kwargs.get("label")
            if label == "private artifact container":
                self.assertFalse(review.workspace_root.exists())
                self.assertTrue(marker.is_file())
                self.assertTrue(cleanup_lock_path.is_file())
                self.assertTrue(runner_lock_path.is_file())
                for lock_path, held_handle in (
                    (cleanup_lock_path, cleanup_lock_handle),
                    (runner_lock_path, runner_lock_handle),
                ):
                    with lock_path.open("a+b") as probe:
                        self.assertEqual(
                            (
                                os.fstat(held_handle.fileno()).st_dev,
                                os.fstat(held_handle.fileno()).st_ino,
                            ),
                            (os.lstat(lock_path).st_dev, os.lstat(lock_path).st_ino),
                        )
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(
                                probe.fileno(),
                                fcntl.LOCK_EX | fcntl.LOCK_NB,
                            )
                cleanup_events.append("container-quarantined")
            elif label == "final review cleanup entry":
                self.assertFalse(review.container_dir.exists())
                cleanup_events.append(entry_name)
            return real_quarantine(
                parent_descriptor,
                entry_name,
                metadata,
                **kwargs,
            )

        try:
            with (
                mock.patch.object(
                    workspace_runtime,
                    "_quarantine_cleanup_entry",
                    side_effect=record_final_entry,
                ),
                mock.patch.object(
                    workspace_runtime.os,
                    "fsync",
                    side_effect=record_parent_fsync,
                ),
                mock.patch.object(
                    workspace_runtime.os,
                    "rmdir",
                    side_effect=record_container_rmdir,
                ),
            ):
                cleanup_error = cleanup_workspace(review, keep_container=False)
        finally:
            cleanup_lock_handle.close()
            runner_lock_handle.close()

        self.assertIsNone(cleanup_error)
        self.assertEqual(
            cleanup_events,
            [
                "container-quarantined",
                "parent-fsync",
                workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
                workspace_runtime.REVIEW_CLEANUP_LOCK_NAME,
                workspace_runtime.REVIEW_RUNNER_LOCK_NAME,
                workspace_runtime.REVIEW_STATE_MARKER_NAME,
                "container-rmdir",
                "parent-fsync",
            ],
        )
        self.assertFalse(review.container_dir.exists())

    def test_full_cleanup_preserves_protocol_when_parent_quarantine_sync_fails(
        self,
    ) -> None:
        review = self.prepare_range(self.base, self.head)
        protocol_names = (
            workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
            workspace_runtime.REVIEW_CLEANUP_LOCK_NAME,
            workspace_runtime.REVIEW_RUNNER_LOCK_NAME,
            workspace_runtime.REVIEW_STATE_MARKER_NAME,
        )
        for name in protocol_names[1:]:
            (review.container_dir / name).touch()
        real_fsync = os.fsync
        parent_metadata = review.container_dir.parent.stat()
        parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)

        def fail_parent_fsync(descriptor):
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == parent_identity:
                raise OSError("injected parent quarantine sync failure")
            real_fsync(descriptor)

        with mock.patch.object(
            workspace_runtime.os,
            "fsync",
            side_effect=fail_parent_fsync,
        ):
            cleanup_error = cleanup_workspace(review, keep_container=False)

        self.assertIn("parent after quarantine", cleanup_error or "")
        self.assertIn("quarantine retained", cleanup_error or "")
        self.assertFalse(review.container_dir.exists())
        quarantines = list(
            review.container_dir.parent.glob(
                f"{workspace_runtime.REVIEW_CLEANUP_QUARANTINE_PREFIX}*"
            )
        )
        self.assertEqual(len(quarantines), 1)
        for name in protocol_names:
            self.assertTrue((quarantines[0] / name).is_file(), name)
        self.assertIsNone(
            workspace_runtime._remove_review_container_tree(
                quarantines[0],
                expected=review.private_cleanup,
                use_control_state=True,
            )
        )

    def test_full_cleanup_reports_unconfirmed_final_parent_sync(self) -> None:
        review = self.prepare_range(self.base, self.head)
        parent_metadata = review.container_dir.parent.stat()
        parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
        real_fsync = os.fsync
        parent_syncs = 0

        def fail_second_parent_fsync(descriptor):
            nonlocal parent_syncs
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == parent_identity:
                parent_syncs += 1
                if parent_syncs == 2:
                    raise OSError("injected final parent sync failure")
            real_fsync(descriptor)

        with mock.patch.object(
            workspace_runtime.os,
            "fsync",
            side_effect=fail_second_parent_fsync,
        ):
            cleanup_error = cleanup_workspace(review, keep_container=False)

        self.assertEqual(parent_syncs, 2)
        self.assertIn("durable removal is unconfirmed", cleanup_error or "")
        self.assertFalse(review.container_dir.exists())
        self.assertEqual(
            list(
                review.container_dir.parent.glob(
                    f"{workspace_runtime.REVIEW_CLEANUP_QUARANTINE_PREFIX}*"
                )
            ),
            [],
        )

    def test_full_cleanup_preserves_protocol_when_container_quarantine_fails(
        self,
    ) -> None:
        review = self.prepare_range(self.base, self.head)
        protocol_names = (
            workspace_runtime.REVIEW_CLEANUP_LOCK_NAME,
            workspace_runtime.REVIEW_RUNNER_LOCK_NAME,
            workspace_runtime.REVIEW_STATE_MARKER_NAME,
        )
        for name in protocol_names:
            (review.container_dir / name).touch()
        real_quarantine = workspace_runtime._quarantine_cleanup_entry

        def fail_container_quarantine(
            parent_descriptor,
            entry_name,
            metadata,
            **kwargs,
        ):
            if kwargs.get("label") == "private artifact container":
                return None, None, ["cannot quarantine private artifact container"]
            return real_quarantine(
                parent_descriptor,
                entry_name,
                metadata,
                **kwargs,
            )

        with mock.patch.object(
            workspace_runtime,
            "_quarantine_cleanup_entry",
            side_effect=fail_container_quarantine,
        ):
            cleanup_error = cleanup_workspace(review, keep_container=False)

        self.assertEqual(
            cleanup_error,
            "cannot quarantine private artifact container",
        )
        self.assertTrue(review.container_dir.is_dir())
        self.assertFalse(review.workspace_root.exists())
        for name in (
            workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
            *protocol_names,
        ):
            self.assertTrue((review.container_dir / name).is_file())

    def test_partial_cleanup_removes_private_artifacts_when_rmtree_fails(self) -> None:
        container = pathlib.Path(self.temporary.name) / "partial-container"
        container.mkdir(mode=0o700)
        private_paths = container / workspace_runtime.PRIVATE_CHANGED_PATHS_NAME
        private_manifest = container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        private_paths.write_bytes(b"private-path\x00")
        private_manifest.write_bytes(b"private-manifest")
        expected_cleanup = cleanup_evidence(container)

        with mock.patch.object(
            workspace_runtime,
            "_remove_open_directory_contents",
            return_value=["permission denied"],
        ) as remove_contents:
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn("permission denied", cleanup_error or "")
        remove_contents.assert_called_once_with(
            mock.ANY,
            depth=0,
            excluded_entry_names=frozenset(
                (
                    *workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES,
                    workspace_runtime.REVIEW_CLEANUP_LOCK_NAME,
                    workspace_runtime.REVIEW_RUNNER_LOCK_NAME,
                    workspace_runtime.REVIEW_STATE_MARKER_NAME,
                )
            ),
        )
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
            symlink_container,
            expected=cleanup_evidence(symlink_target),
        )

        self.assertIsNotNone(symlink_error)
        self.assertTrue(target_private_paths.exists())
        self.assertTrue(target_private_manifest.exists())

        private_paths.write_bytes(b"private-path\x00")
        private_manifest.write_bytes(b"private-manifest")
        expected_cleanup = cleanup_evidence(container)
        real_unlink = os.unlink
        failed_private_unlink = False

        def fail_first_unlink(path, *args, **kwargs):
            nonlocal failed_private_unlink
            if (
                not failed_private_unlink
                and isinstance(path, str)
                and path.startswith(".codex-review-cleanup-")
            ):
                failed_private_unlink = True
                raise PermissionError("manifest unlink denied")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "unlink",
            side_effect=fail_first_unlink,
        ):
            first_unlink_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn("manifest unlink denied", first_unlink_error or "")
        self.assertFalse(private_manifest.exists())
        self.assertFalse(private_paths.exists())
        retained_manifest = next(container.glob(".codex-review-cleanup-*"))
        self.assertEqual(retained_manifest.read_bytes(), b"private-manifest")

        retained_manifest.unlink()
        private_manifest.mkdir()
        nested_private = private_manifest / "nested.txt"
        nested_private.write_text("do not recurse\n", encoding="utf-8")
        private_paths.write_bytes(b"private-path\x00")
        expected_cleanup = cleanup_evidence(container)

        directory_artifact_error = workspace_runtime._remove_partial_container(
            container,
            expected=expected_cleanup,
        )

        self.assertIsNotNone(directory_artifact_error)
        self.assertTrue(nested_private.exists())
        self.assertFalse(private_paths.exists())

        missing_parent_error = workspace_runtime.remove_private_review_artifacts(
            pathlib.Path(self.temporary.name)
            / "missing-parent/isolated-review-missing",
            expected=expected_cleanup,
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
        original_cleanup = cleanup_evidence(original_container)
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
            original_container,
            expected=original_cleanup,
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
            private_cleanup=original_cleanup,
        )
        swapped_cleanup_error = workspace_runtime.cleanup_workspace(
            swapped_review,
            keep_container=False,
        )
        partial_cleanup_error = workspace_runtime._remove_partial_container(
            original_container,
            expected=original_cleanup,
        )

        self.assertIsNotNone(swapped_cleanup_error)
        self.assertIsNotNone(partial_cleanup_error)
        self.assertTrue(outside_victim.exists())
        self.assertTrue(outside_private.exists())

    def test_partial_cleanup_keeps_a_failed_private_unlink_in_quarantine(
        self,
    ) -> None:
        container = pathlib.Path(self.temporary.name) / "private-unlink-container"
        container.mkdir(mode=0o700)
        private_manifest = container / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        private_manifest.write_bytes(b"private")
        expected_cleanup = cleanup_evidence(container)
        ordinary = container / "ordinary.txt"
        ordinary.write_text("ordinary\n", encoding="utf-8")
        real_unlink = os.unlink
        failed_private_unlink = False

        def fail_private_unlink(path, *args, **kwargs):
            nonlocal failed_private_unlink
            if (
                not failed_private_unlink
                and isinstance(path, str)
                and path.startswith(".codex-review-cleanup-")
            ):
                failed_private_unlink = True
                raise PermissionError("private unlink denied")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "unlink",
            side_effect=fail_private_unlink,
        ):
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn("private unlink denied", cleanup_error or "")
        self.assertFalse(private_manifest.exists())
        self.assertTrue(ordinary.exists())
        retained = list(container.glob(".codex-review-cleanup-*"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"private")

    def test_cleanup_does_not_remove_a_replacement_container(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        moved_container = container.with_name(container.name + "-moved")
        replacement_victim = container / "victim.txt"
        real_rename = os.rename
        swapped = False

        def swap_before_quarantine(source, destination, *args, **kwargs):
            nonlocal swapped
            if not swapped and source == container.name:
                real_rename(
                    source,
                    moved_container.name,
                    *args,
                    **kwargs,
                )
                container.mkdir(mode=0o700)
                replacement_victim.write_text("replacement\n", encoding="utf-8")
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "rename",
            side_effect=swap_before_quarantine,
        ):
            cleanup_error = workspace_runtime.cleanup_workspace(
                review,
                keep_container=False,
            )

        self.assertIn(
            "private artifact container changed before removal",
            cleanup_error or "",
        )
        self.assertTrue(swapped)
        self.assertTrue(moved_container.exists())
        self.assertEqual(list(moved_container.iterdir()), [])
        quarantines = list(container.parent.glob(".codex-review-cleanup-*/victim.txt"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")

    def test_private_cleanup_rejects_container_replaced_before_cleanup(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        moved_container = container.with_name(container.name + "-moved-before-cleanup")
        container.rename(moved_container)
        container.mkdir(mode=0o700)
        replacement = container / "replacement.txt"
        replacement.write_text("replacement\n", encoding="utf-8")

        cleanup_error = workspace_runtime.remove_private_review_artifacts(
            container,
            expected=review.private_cleanup,
        )

        self.assertIn("does not match preparation identity", cleanup_error or "")
        self.assertTrue(replacement.exists())
        self.assertTrue(
            all(
                (moved_container / name).exists()
                for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
            )
        )

    def test_bound_cleanup_lock_rejects_compatibility_symlink_leaf(self) -> None:
        review = self.prepare_range(self.base, self.head)
        victim = review.container_dir / "lock-victim"
        victim.write_text("keep me\n", encoding="utf-8")
        lock_path = review.container_dir / "cleanup.lock"
        lock_path.unlink(missing_ok=True)
        lock_path.symlink_to(victim.name)

        handle, lock_error = workspace_runtime.open_bound_review_lock(
            review.container_dir,
            expected=review.private_cleanup,
            name="cleanup.lock",
        )

        self.assertIsNone(lock_error)
        self.assertIsNotNone(handle)
        if handle is not None:
            compatibility_error = handle.open_compatibility_lock("cleanup.lock")
            self.assertIn(
                "cannot securely open review runtime compatibility lock",
                compatibility_error or "",
            )
            handle.close()
        self.assertTrue(lock_path.is_symlink())
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")

    def test_bound_cleanup_lock_uses_open_container_after_path_swap(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        moved_container = container.with_name(f"{container.name}-moved-lock-open")
        sentinel = container / "replacement"
        real_dup = workspace_runtime.os.dup
        swapped = False

        def swap_before_lock_dup(descriptor: int) -> int:
            nonlocal swapped
            if not swapped:
                container.rename(moved_container)
                container.mkdir(mode=0o700)
                sentinel.write_text("keep me\n", encoding="utf-8")
                swapped = True
            return real_dup(descriptor)

        handle = None
        try:
            with mock.patch.object(
                workspace_runtime.os,
                "dup",
                side_effect=swap_before_lock_dup,
            ):
                handle, lock_error = workspace_runtime.open_bound_review_lock(
                    container,
                    expected=review.private_cleanup,
                    name="cleanup.lock",
                )

            self.assertIsNone(lock_error)
            self.assertIsNotNone(handle)
            if handle is not None:
                self.assertIsNone(handle.open_compatibility_lock("cleanup.lock"))
            self.assertTrue(swapped)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep me\n")
            self.assertFalse((container / "cleanup.lock").exists())
            self.assertTrue((moved_container / "cleanup.lock").is_file())
        finally:
            if handle is not None:
                handle.close()
            if container.is_dir():
                sentinel.unlink(missing_ok=True)
                container.rmdir()
            if moved_container.is_dir():
                moved_container.rename(container)

    def test_private_cleanup_rejects_container_moved_before_cleanup(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        moved_container = container.with_name(container.name + "-moved-missing")
        container.rename(moved_container)

        try:
            cleanup_error = workspace_runtime.remove_private_review_artifacts(
                container,
                expected=review.private_cleanup,
            )

            self.assertIn("private artifact container is missing", cleanup_error or "")
            self.assertFalse(container.exists())
            self.assertTrue(
                all(
                    (moved_container / name).exists()
                    for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
                )
            )
        finally:
            moved_cleanup_error = workspace_runtime._remove_review_container_tree(
                moved_container,
                expected=review.private_cleanup,
                use_control_state=True,
            )
            self.assertIsNone(moved_cleanup_error)

    def test_private_cleanup_receipts_distinguish_removed_from_moved(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        moved_name = workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        moved = container / f"{moved_name}.moved"
        original = container / moved_name
        original.rename(moved)
        replacement = container / moved_name
        replacement.write_bytes(b"replacement")
        other_name = workspace_runtime.PRIVATE_CHANGED_PATHS_NAME

        first_error = workspace_runtime.remove_private_review_artifacts(
            container,
            expected=review.private_cleanup,
        )

        self.assertIn("does not match preparation identity", first_error or "")
        self.assertEqual(replacement.read_bytes(), b"replacement")
        self.assertTrue(moved.exists())
        self.assertFalse((container / other_name).exists())
        cleanup_state = workspace_runtime._load_control_artifact_state(
            container_dir=container
        )
        self.assertEqual(cleanup_state.private_artifacts_removed, {other_name})

        replacement.unlink()
        moved.rename(original)
        self.assertIsNone(
            workspace_runtime.remove_private_review_artifacts(
                container,
                expected=review.private_cleanup,
            )
        )
        final_state = workspace_runtime._load_control_artifact_state(
            container_dir=container
        )
        self.assertEqual(
            final_state.private_artifacts_removed,
            frozenset(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
        )
        self.assertIsNone(
            workspace_runtime.remove_private_review_artifacts(
                container,
                expected=review.private_cleanup,
            )
        )

    def test_private_cleanup_continues_after_removal_receipt_failure(self) -> None:
        review = self.prepare_range(self.base, self.head)
        container = review.container_dir
        failed_name, recorded_name = workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
        failed_path = container / failed_name
        recorded_path = container / recorded_name
        real_record_removal = workspace_runtime._record_private_artifact_removal_at
        receipt_attempts = []

        def fail_first_receipt(
            container_descriptor: int,
            *,
            expected: workspace_runtime.PrivateCleanupEvidence,
            artifact_name: str,
        ) -> None:
            receipt_attempts.append(artifact_name)
            if artifact_name == failed_name:
                raise ReviewError("receipt write denied")
            real_record_removal(
                container_descriptor,
                expected=expected,
                artifact_name=artifact_name,
            )

        with mock.patch.object(
            workspace_runtime,
            "_record_private_artifact_removal_at",
            side_effect=fail_first_receipt,
        ):
            cleanup_error = workspace_runtime.remove_private_review_artifacts(
                container,
                expected=review.private_cleanup,
            )

        self.assertIn("receipt write denied", cleanup_error or "")
        self.assertEqual(receipt_attempts, [failed_name, recorded_name])
        self.assertFalse(failed_path.exists())
        self.assertFalse(recorded_path.exists())
        cleanup_state = workspace_runtime._load_control_artifact_state(
            container_dir=container
        )
        self.assertEqual(cleanup_state.private_artifacts_removed, {recorded_name})

        retry_error = workspace_runtime.remove_private_review_artifacts(
            container,
            expected=review.private_cleanup,
        )

        self.assertIn(
            f"{failed_name}: expected helper-private artifact is missing",
            retry_error or "",
        )
        retry_state = workspace_runtime._load_control_artifact_state(
            container_dir=container
        )
        self.assertEqual(retry_state.private_artifacts_removed, {recorded_name})

    def test_removed_private_name_reappearance_is_preserved(self) -> None:
        review = self.prepare_range(self.base, self.head)
        self.assertIsNone(
            workspace_runtime.remove_private_review_artifacts(
                review.container_dir,
                expected=review.private_cleanup,
            )
        )
        name = workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        replacement = review.container_dir / name
        replacement.write_bytes(b"replacement")

        cleanup_error = workspace_runtime.remove_private_review_artifacts(
            review.container_dir,
            expected=review.private_cleanup,
        )

        self.assertIn("reappeared after its recorded removal", cleanup_error or "")
        self.assertEqual(replacement.read_bytes(), b"replacement")

    def test_partial_cleanup_preserves_a_replacement_file(self) -> None:
        container = pathlib.Path(self.temporary.name) / "file-race-container"
        container.mkdir(mode=0o700)
        target = container / "target.txt"
        target.write_text("original\n", encoding="utf-8")
        moved_target = container / "target-moved.txt"
        expected_cleanup = cleanup_evidence(container)
        real_rename = os.rename
        swapped = False

        def swap_before_quarantine(source, destination, *args, **kwargs):
            nonlocal swapped
            if not swapped and source == target.name:
                real_rename(source, moved_target.name, *args, **kwargs)
                target.write_text("replacement\n", encoding="utf-8")
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "rename",
            side_effect=swap_before_quarantine,
        ):
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn(
            "review cleanup entry changed before removal", cleanup_error or ""
        )
        self.assertTrue(swapped)
        self.assertEqual(moved_target.read_text(encoding="utf-8"), "original\n")
        quarantines = list(container.glob(".codex-review-cleanup-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")

        retry_error = workspace_runtime._remove_partial_container(
            container,
            expected=expected_cleanup,
        )

        self.assertIn(
            "pre-existing review cleanup quarantine requires manual recovery",
            retry_error or "",
        )
        self.assertTrue(quarantines[0].exists())
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")

    def test_partial_cleanup_preserves_a_replacement_nested_directory(self) -> None:
        container = pathlib.Path(self.temporary.name) / "directory-race-container"
        container.mkdir(mode=0o700)
        nested = container / "nested"
        nested.mkdir()
        (nested / "original.txt").write_text("original\n", encoding="utf-8")
        moved_nested = container / "nested-moved"
        expected_cleanup = cleanup_evidence(container)
        real_rename = os.rename
        swapped = False

        def swap_before_quarantine(source, destination, *args, **kwargs):
            nonlocal swapped
            if not swapped and source == nested.name:
                real_rename(source, moved_nested.name, *args, **kwargs)
                nested.mkdir()
                (nested / "victim.txt").write_text(
                    "replacement\n",
                    encoding="utf-8",
                )
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "rename",
            side_effect=swap_before_quarantine,
        ):
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn(
            "review cleanup directory entry changed before removal",
            cleanup_error or "",
        )
        self.assertTrue(swapped)
        self.assertEqual(
            (moved_nested / "original.txt").read_text(encoding="utf-8"),
            "original\n",
        )
        quarantines = list(container.glob(".codex-review-cleanup-*/victim.txt"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")

        retry_error = workspace_runtime._remove_partial_container(
            container,
            expected=expected_cleanup,
        )

        self.assertIn(
            "pre-existing review cleanup quarantine requires manual recovery",
            retry_error or "",
        )
        self.assertTrue(quarantines[0].exists())
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")

    def test_partial_cleanup_does_not_enter_a_mountpoint_like_directory(self) -> None:
        container = pathlib.Path(self.temporary.name) / "mount-boundary-container"
        container.mkdir(mode=0o700)
        nested = container / "nested"
        nested.mkdir()
        victim = nested / "victim.txt"
        victim.write_text("retained\n", encoding="utf-8")
        expected_cleanup = cleanup_evidence(container)
        real_rename = os.rename

        def reject_mountpoint_rename(source, destination, *args, **kwargs):
            if source == nested.name:
                raise OSError(errno.EBUSY, "Device or resource busy")
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "rename",
            side_effect=reject_mountpoint_rename,
        ):
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn(
            "cannot quarantine review cleanup directory entry",
            cleanup_error or "",
        )
        self.assertEqual(victim.read_text(encoding="utf-8"), "retained\n")
        self.assertEqual(list(container.glob(".codex-review-cleanup-*")), [])

    def test_partial_cleanup_bounds_depth_and_still_scrubs_private_files(
        self,
    ) -> None:
        container = pathlib.Path(self.temporary.name) / "deep-container"
        container.mkdir(mode=0o700)
        nested = container
        for index in range(6):
            nested = nested / f"d{index}"
            nested.mkdir()
        deep_victim = nested / "victim.txt"
        deep_victim.write_text("retained\n", encoding="utf-8")
        private_artifacts = tuple(
            container / name for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
        )
        for path in private_artifacts:
            path.write_bytes(b"private")
        expected_cleanup = cleanup_evidence(container)

        with mock.patch.object(
            workspace_runtime,
            "MAX_REVIEW_CLEANUP_DEPTH",
            4,
        ):
            cleanup_error = workspace_runtime._remove_partial_container(
                container,
                expected=expected_cleanup,
            )

        self.assertIn("directory depth exceeds the safety limit", cleanup_error or "")
        self.assertTrue(container.exists())
        self.assertFalse(deep_victim.exists())
        retained_victims = list(container.rglob("victim.txt"))
        self.assertEqual(len(retained_victims), 1)
        self.assertEqual(
            retained_victims[0].read_text(encoding="utf-8"),
            "retained\n",
        )
        self.assertTrue(all(not path.exists() for path in private_artifacts))

    def test_partial_cleanup_unlinks_nested_symlink_without_following_it(self) -> None:
        outside = pathlib.Path(self.temporary.name) / "outside"
        outside.mkdir()
        outside_victim = outside / "victim.txt"
        outside_victim.write_text("outside\n", encoding="utf-8")
        container = pathlib.Path(self.temporary.name) / "symlink-tree-container"
        container.mkdir(mode=0o700)
        nested = container / "nested"
        nested.mkdir()
        (nested / "outside-link").symlink_to(outside, target_is_directory=True)
        expected_cleanup = cleanup_evidence(container)

        cleanup_error = workspace_runtime._remove_partial_container(
            container,
            expected=expected_cleanup,
        )

        self.assertIsNone(cleanup_error)
        self.assertFalse(container.exists())
        self.assertTrue(outside_victim.exists())

    def test_retained_cleanup_does_not_remove_a_replacement_workspace(self) -> None:
        review = self.prepare_range(self.base, self.head)
        workspace_root = review.workspace_root
        moved_workspace = workspace_root.with_name("workspace-moved")
        replacement_victim = workspace_root / "victim.txt"
        private_artifacts = tuple(
            review.container_dir / name
            for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
        )
        real_rename = os.rename
        swapped = False

        def swap_before_quarantine(source, destination, *args, **kwargs):
            nonlocal swapped
            if not swapped and source == workspace_root.name:
                real_rename(
                    source,
                    moved_workspace.name,
                    *args,
                    **kwargs,
                )
                workspace_root.mkdir(mode=0o700)
                replacement_victim.write_text("replacement\n", encoding="utf-8")
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            workspace_runtime.os,
            "rename",
            side_effect=swap_before_quarantine,
        ):
            cleanup_error = workspace_runtime.cleanup_workspace(
                review,
                keep_container=True,
            )

        self.reviews.remove(review)
        self.assertIn("review workspace changed before removal", cleanup_error or "")
        self.assertTrue(swapped)
        self.assertTrue(moved_workspace.exists())
        self.assertTrue(
            (
                moved_workspace / review.diff_file.relative_to(review.workspace_root)
            ).exists()
        )
        quarantines = list(
            review.container_dir.glob(".codex-review-cleanup-*/victim.txt")
        )
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_text(encoding="utf-8"), "replacement\n")
        self.assertTrue(all(not path.exists() for path in private_artifacts))

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
            private_cleanup=cleanup_evidence(external_container),
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

    def test_preparation_cleanup_handoff_precedes_private_bytes(self) -> None:
        handoff_sizes: list[int] = []

        def capture_handoff(
            container: pathlib.Path,
            evidence: workspace_runtime.PrivateCleanupEvidence,
        ) -> None:
            self.assertEqual(
                set(evidence.artifacts),
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            self.assertFalse((container / "workspace").exists())
            self.assertEqual(
                {path.name for path in container.iterdir()},
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES:
                path = container / name
                metadata = path.stat()
                self.assertEqual(metadata.st_size, 0)
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_nlink, 1)
                self.assertEqual(metadata.st_uid, os.geteuid())
                self.assertEqual(
                    evidence.artifacts[name],
                    workspace_runtime.CleanupIdentity(
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                    ),
                )
            handoff_sizes.append(len(evidence.artifacts))

        review = _prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
            ownership_handoff=lambda prepared: self.reviews.append(prepared),
            preparation_cleanup_handoff=capture_handoff,
        )

        self.assertEqual(handoff_sizes, [2])
        self.assertEqual(self.reviews, [review])
        self.assertTrue(
            all(
                (review.container_dir / name).stat().st_size > 0
                for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
            )
        )

    def test_preparation_handoff_failure_leaves_no_sensitive_workspace(self) -> None:
        def reject_handoff(
            container: pathlib.Path,
            evidence: workspace_runtime.PrivateCleanupEvidence,
        ) -> None:
            self.assertEqual(
                set(evidence.artifacts),
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            self.assertFalse((container / "workspace").exists())
            self.assertTrue(
                all(
                    (container / name).stat().st_size == 0
                    for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
                )
            )
            raise ReviewError("preparation marker failed")

        with self.assertRaisesRegex(ReviewError, "preparation marker failed"):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=lambda _prepared: self.fail(
                    "ownership must not transfer"
                ),
                preparation_cleanup_handoff=reject_handoff,
            )

        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_prepared_private_writer_does_not_truncate_replacements(self) -> None:
        container = pathlib.Path(self.temporary.name) / "prepared-private"
        container.mkdir(mode=0o700)
        name = workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        path = container / name
        original = container / f"{name}.original"
        path.write_bytes(b"")
        path.chmod(0o600)
        metadata = path.stat()
        expected = workspace_runtime.CleanupIdentity(
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        parent_descriptor = os.open(
            container,
            workspace_runtime._private_cleanup_directory_flags(),
        )
        try:
            for replacement_bytes in (b"", b"replacement must remain"):
                with self.subTest(replacement_bytes=replacement_bytes):
                    path.rename(original)
                    path.write_bytes(replacement_bytes)
                    path.chmod(0o600)
                    with self.assertRaisesRegex(
                        ReviewError,
                        "does not match its preparation identity|is not empty",
                    ):
                        with workspace_runtime._open_prepared_private_binary(
                            path,
                            expected_identity=expected,
                            parent_descriptor=parent_descriptor,
                        ) as handle:
                            handle.write(b"sensitive bytes")
                    self.assertEqual(path.read_bytes(), replacement_bytes)
                    path.unlink()
                    original.rename(path)
        finally:
            os.close(parent_descriptor)

    def test_prepared_private_writer_uses_existing_nonblocking_file(self) -> None:
        container = pathlib.Path(self.temporary.name) / "prepared-private-flags"
        container.mkdir(mode=0o700)
        name = workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        path = container / name
        path.write_bytes(b"")
        path.chmod(0o600)
        metadata = path.stat()
        expected = workspace_runtime.CleanupIdentity(
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        parent_descriptor = os.open(
            container,
            workspace_runtime._private_cleanup_directory_flags(),
        )
        real_open = os.open
        observed_flags: list[int] = []

        def capture_open(target, flags, *args, **kwargs):
            if target == name and kwargs.get("dir_fd") == parent_descriptor:
                observed_flags.append(flags)
            return real_open(target, flags, *args, **kwargs)

        try:
            with mock.patch.object(
                workspace_runtime.os,
                "open",
                side_effect=capture_open,
            ):
                with workspace_runtime._open_prepared_private_binary(
                    path,
                    expected_identity=expected,
                    parent_descriptor=parent_descriptor,
                ) as handle:
                    handle.write(b"payload")
        finally:
            os.close(parent_descriptor)

        self.assertEqual(len(observed_flags), 1)
        flags = observed_flags[0]
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertTrue(flags & os.O_NONBLOCK)
        self.assertFalse(flags & (os.O_CREAT | os.O_EXCL | os.O_TRUNC))

    def test_prepared_private_writer_rechecks_path_after_write(self) -> None:
        container = pathlib.Path(self.temporary.name) / "prepared-private-race"
        container.mkdir(mode=0o700)
        name = workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
        path = container / name
        moved = container / f"{name}.moved"
        path.write_bytes(b"")
        path.chmod(0o600)
        metadata = path.stat()
        expected = workspace_runtime.CleanupIdentity(
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        parent_descriptor = os.open(
            container,
            workspace_runtime._private_cleanup_directory_flags(),
        )
        real_fsync = os.fsync
        swapped = False

        def swap_after_private_write(descriptor: int) -> None:
            nonlocal swapped
            real_fsync(descriptor)
            current = os.fstat(descriptor)
            if (
                not swapped
                and workspace_runtime._cleanup_identity_evidence(current) == expected
            ):
                path.rename(moved)
                path.write_bytes(b"replacement must remain")
                path.chmod(0o600)
                swapped = True

        try:
            with (
                mock.patch.object(
                    workspace_runtime.os,
                    "fsync",
                    side_effect=swap_after_private_write,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "does not match its preparation identity|is not empty",
                ),
            ):
                with workspace_runtime._open_prepared_private_binary(
                    path,
                    expected_identity=expected,
                    parent_descriptor=parent_descriptor,
                ) as handle:
                    handle.write(b"sensitive bytes")
        finally:
            os.close(parent_descriptor)

        self.assertTrue(swapped)
        self.assertEqual(path.read_bytes(), b"replacement must remain")
        self.assertEqual(moved.read_bytes(), b"sensitive bytes")

    def test_container_directory_entries_are_durable_before_handoff(self) -> None:
        self.assertFalse((self.repo / ".codex-tmp").exists())
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        events: list[str] = []
        captured = []
        real_fsync = os.fsync

        def record_directory_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if stat.S_ISDIR(metadata.st_mode):
                if identity == source_identity:
                    events.append("source-root-fsync")
                else:
                    review_root = self.repo / ".codex-tmp"
                    if review_root.is_dir():
                        root_metadata = review_root.stat()
                        if identity == (root_metadata.st_dev, root_metadata.st_ino):
                            events.append("review-root-fsync")
                        else:
                            for container in review_root.glob("isolated-review-*"):
                                container_metadata = container.stat()
                                if identity == (
                                    container_metadata.st_dev,
                                    container_metadata.st_ino,
                                ):
                                    events.append("container-fsync")
                                    break
            elif stat.S_ISREG(metadata.st_mode):
                review_root = self.repo / ".codex-tmp"
                for container in review_root.glob("isolated-review-*"):
                    for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES:
                        path = container / name
                        if path.is_file():
                            path_metadata = path.stat()
                            if identity == (
                                path_metadata.st_dev,
                                path_metadata.st_ino,
                            ):
                                events.append(f"private-slot-fsync:{name}")
                                break
            real_fsync(descriptor)

        def capture_handoff(
            _container: pathlib.Path,
            evidence: workspace_runtime.PrivateCleanupEvidence,
        ) -> None:
            self.assertEqual(
                set(evidence.artifacts),
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            events.append("preparation-handoff")
            self.assertEqual(
                events,
                [
                    "source-root-fsync",
                    "review-root-fsync",
                    *(
                        f"private-slot-fsync:{name}"
                        for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
                    ),
                    "container-fsync",
                    "preparation-handoff",
                ],
            )

        with mock.patch.object(
            workspace_runtime.os,
            "fsync",
            side_effect=record_directory_fsync,
        ):
            review = _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
                preparation_cleanup_handoff=capture_handoff,
            )

        self.reviews.append(review)
        self.assertEqual(captured, [review])

    def test_review_root_creation_race_fsyncs_source_before_handoff(self) -> None:
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        real_stat = os.stat
        real_mkdir = os.mkdir
        real_fsync = os.fsync
        initial_missing_injected = False
        racing_create_injected = False
        events: list[str] = []
        captured = []

        def race_stat(
            path: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal initial_missing_injected
            if (
                not initial_missing_injected
                and path == ".codex-tmp"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                initial_missing_injected = True
                raise FileNotFoundError(
                    errno.ENOENT,
                    os.strerror(errno.ENOENT),
                    ".codex-tmp",
                )
            return real_stat(path, *args, **kwargs)

        def race_mkdir(
            path: os.PathLike[str] | str,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal racing_create_injected
            if (
                path == ".codex-tmp"
                and dir_fd is not None
                and not racing_create_injected
            ):
                real_mkdir(path, mode=mode, dir_fd=dir_fd)
                racing_create_injected = True
                raise FileExistsError(
                    errno.EEXIST,
                    os.strerror(errno.EEXIST),
                    ".codex-tmp",
                )
            real_mkdir(path, mode=mode, dir_fd=dir_fd)

        def record_directory_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if identity == source_identity:
                events.append("source-root-fsync")
            else:
                review_root = self.repo / ".codex-tmp"
                if review_root.is_dir():
                    root_metadata = real_stat(review_root)
                    if identity == (root_metadata.st_dev, root_metadata.st_ino):
                        events.append("review-root-fsync")
            real_fsync(descriptor)

        def capture_handoff(
            container: pathlib.Path,
            evidence: workspace_runtime.PrivateCleanupEvidence,
        ) -> None:
            self.assertEqual(
                set(evidence.artifacts),
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            self.assertFalse((container / "workspace").exists())
            events.append("preparation-handoff")
            self.assertEqual(
                events,
                [
                    "source-root-fsync",
                    "review-root-fsync",
                    "preparation-handoff",
                ],
            )

        with (
            mock.patch.object(
                workspace_runtime.os,
                "stat",
                side_effect=race_stat,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "mkdir",
                side_effect=race_mkdir,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "fsync",
                side_effect=record_directory_fsync,
            ),
        ):
            review = _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
                preparation_cleanup_handoff=capture_handoff,
            )

        self.reviews.append(review)
        self.assertTrue(initial_missing_injected)
        self.assertTrue(racing_create_injected)
        self.assertEqual(captured, [review])

    def test_review_root_creation_race_fsync_failure_fails_closed(self) -> None:
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        real_stat = os.stat
        real_mkdir = os.mkdir
        real_fsync = os.fsync
        initial_missing_injected = False
        racing_create_injected = False
        handoff = mock.Mock()

        def race_stat(
            path: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal initial_missing_injected
            if (
                not initial_missing_injected
                and path == ".codex-tmp"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                initial_missing_injected = True
                raise FileNotFoundError(
                    errno.ENOENT,
                    os.strerror(errno.ENOENT),
                    ".codex-tmp",
                )
            return real_stat(path, *args, **kwargs)

        def race_mkdir(
            path: os.PathLike[str] | str,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal racing_create_injected
            if (
                path == ".codex-tmp"
                and dir_fd is not None
                and not racing_create_injected
            ):
                real_mkdir(path, mode=mode, dir_fd=dir_fd)
                racing_create_injected = True
                raise FileExistsError(
                    errno.EEXIST,
                    os.strerror(errno.EEXIST),
                    ".codex-tmp",
                )
            real_mkdir(path, mode=mode, dir_fd=dir_fd)

        def fail_source_root_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                raise OSError("source root fsync denied after creation race")
            real_fsync(descriptor)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "stat",
                side_effect=race_stat,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "mkdir",
                side_effect=race_mkdir,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "fsync",
                side_effect=fail_source_root_fsync,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "cannot persist the repository review-root directory entry",
            ),
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=mock.Mock(),
                preparation_cleanup_handoff=handoff,
            )

        self.assertTrue(initial_missing_injected)
        self.assertTrue(racing_create_injected)
        handoff.assert_not_called()
        review_root = self.repo / ".codex-tmp"
        self.assertTrue(review_root.is_dir())
        self.assertEqual(list(review_root.iterdir()), [])

    def test_existing_review_root_does_not_fsync_source_root(self) -> None:
        review_root = self.repo / ".codex-tmp"
        review_root.mkdir(mode=0o700)
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        review_root_identity = (
            review_root.stat().st_dev,
            review_root.stat().st_ino,
        )
        events: list[str] = []
        captured = []
        real_fsync = os.fsync

        def record_directory_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if stat.S_ISDIR(metadata.st_mode):
                if identity == source_identity:
                    events.append("unexpected-source-root-fsync")
                elif identity == review_root_identity:
                    events.append("review-root-fsync")
            real_fsync(descriptor)

        def capture_handoff(
            container: pathlib.Path,
            evidence: workspace_runtime.PrivateCleanupEvidence,
        ) -> None:
            self.assertEqual(
                set(evidence.artifacts),
                set(workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES),
            )
            self.assertFalse((container / "workspace").exists())
            events.append("preparation-handoff")
            self.assertEqual(
                events,
                ["review-root-fsync", "preparation-handoff"],
            )

        with mock.patch.object(
            workspace_runtime.os,
            "fsync",
            side_effect=record_directory_fsync,
        ):
            review = _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
                preparation_cleanup_handoff=capture_handoff,
            )

        self.reviews.append(review)
        self.assertEqual(captured, [review])
        self.assertNotIn("unexpected-source-root-fsync", events)

    def test_existing_review_root_allows_shared_source_owner(self) -> None:
        review_root = self.repo / ".codex-tmp"
        review_root.mkdir(mode=0o700)
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        foreign_uid = os.geteuid() + 1
        real_lstat = os.lstat
        real_fstat = os.fstat
        captured = []

        def with_foreign_owner(metadata: os.stat_result) -> os.stat_result:
            fields = list(metadata)
            fields[4] = foreign_uid
            return os.stat_result(fields)

        def foreign_source_lstat(
            path: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            metadata = real_lstat(path, *args, **kwargs)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                return with_foreign_owner(metadata)
            return metadata

        def foreign_source_fstat(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                return with_foreign_owner(metadata)
            return metadata

        with (
            mock.patch.object(
                workspace_runtime.os,
                "lstat",
                side_effect=foreign_source_lstat,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "fstat",
                side_effect=foreign_source_fstat,
            ),
        ):
            review = _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=captured.append,
            )

        self.reviews.append(review)
        self.assertEqual(captured, [review])

    def test_shared_source_owner_cannot_create_review_root(self) -> None:
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        foreign_uid = os.geteuid() + 1
        real_lstat = os.lstat
        real_fstat = os.fstat
        handoff = mock.Mock()

        def with_foreign_owner(metadata: os.stat_result) -> os.stat_result:
            fields = list(metadata)
            fields[4] = foreign_uid
            return os.stat_result(fields)

        def foreign_source_lstat(
            path: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            metadata = real_lstat(path, *args, **kwargs)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                return with_foreign_owner(metadata)
            return metadata

        def foreign_source_fstat(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                return with_foreign_owner(metadata)
            return metadata

        with (
            mock.patch.object(
                workspace_runtime.os,
                "lstat",
                side_effect=foreign_source_lstat,
            ),
            mock.patch.object(
                workspace_runtime.os,
                "fstat",
                side_effect=foreign_source_fstat,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "must be owned by the current user to create the review root",
            ),
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=handoff,
            )

        handoff.assert_not_called()
        self.assertFalse((self.repo / ".codex-tmp").exists())

    def test_new_review_root_fsync_failure_precedes_handoff(self) -> None:
        handoff = mock.Mock()
        source_identity = (
            self.repo.stat().st_dev,
            self.repo.stat().st_ino,
        )
        real_fsync = os.fsync

        def fail_source_root_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == source_identity:
                raise OSError("source root fsync denied")
            real_fsync(descriptor)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "fsync",
                side_effect=fail_source_root_fsync,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "cannot persist the repository review-root directory entry",
            ),
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.base,
                head_ref=self.head,
                ownership_handoff=mock.Mock(),
                preparation_cleanup_handoff=handoff,
            )

        handoff.assert_not_called()
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_container_parent_fsync_failure_precedes_private_bytes(self) -> None:
        marker = b"PRIVATE_PATH_FSYNC_FAILURE_MARKER_29871"
        failed_head = self.commit_bytes(
            marker.decode("ascii") + ".txt",
            b"ordinary payload\n",
            "Add fsync failure marker path",
        )
        handoff = mock.Mock()
        real_fsync = os.fsync
        observed_container = False

        def fail_review_root_fsync(descriptor: int) -> None:
            nonlocal observed_container
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                real_fsync(descriptor)
                return
            review_root = self.repo / ".codex-tmp"
            if review_root.is_dir():
                root_metadata = review_root.stat()
                if (metadata.st_dev, metadata.st_ino) == (
                    root_metadata.st_dev,
                    root_metadata.st_ino,
                ):
                    if observed_container:
                        real_fsync(descriptor)
                        return
                    containers = list(review_root.glob("isolated-review-*"))
                    self.assertEqual(len(containers), 1)
                    observed_container = True
                    self.assertFalse(
                        any(
                            (containers[0] / name).exists()
                            for name in workspace_runtime.PRIVATE_HELPER_ARTIFACT_NAMES
                        )
                    )
                    for path in containers[0].rglob("*"):
                        if path.is_file():
                            self.assertNotIn(marker, path.read_bytes())
                    raise OSError("review root fsync denied")
            real_fsync(descriptor)

        with (
            mock.patch.object(
                workspace_runtime.os,
                "fsync",
                side_effect=fail_review_root_fsync,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "cannot persist the private review container directory entry",
            ),
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=failed_head,
                ownership_handoff=mock.Mock(),
                preparation_cleanup_handoff=handoff,
            )

        self.assertTrue(observed_container)
        handoff.assert_not_called()
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_private_slot_persistence_failure_precedes_handoff(self) -> None:
        for failure_point in ("second-slot", "container"):
            with self.subTest(failure_point=failure_point):
                preparation_handoff = mock.Mock()
                ownership_handoff = mock.Mock()
                real_fsync = os.fsync
                regular_fsyncs = 0
                failed = False

                def fail_selected_fsync(descriptor: int) -> None:
                    nonlocal failed, regular_fsyncs
                    metadata = os.fstat(descriptor)
                    if stat.S_ISREG(metadata.st_mode):
                        regular_fsyncs += 1
                        if (
                            not failed
                            and failure_point == "second-slot"
                            and regular_fsyncs == 2
                        ):
                            failed = True
                            raise OSError("private slot fsync denied")
                    elif stat.S_ISDIR(metadata.st_mode) and not failed:
                        review_root = self.repo / ".codex-tmp"
                        for container in review_root.glob("isolated-review-*"):
                            container_metadata = container.stat()
                            if failure_point == "container" and (
                                metadata.st_dev,
                                metadata.st_ino,
                            ) == (
                                container_metadata.st_dev,
                                container_metadata.st_ino,
                            ):
                                failed = True
                                raise OSError("private container fsync denied")
                    real_fsync(descriptor)

                with (
                    mock.patch.object(
                        workspace_runtime.os,
                        "fsync",
                        side_effect=fail_selected_fsync,
                    ),
                    self.assertRaisesRegex((OSError, ReviewError), "fsync denied"),
                ):
                    _prepare_workspace(
                        repo=self.repo,
                        base_ref=self.base,
                        head_ref=self.head,
                        ownership_handoff=ownership_handoff,
                        preparation_cleanup_handoff=preparation_handoff,
                    )

                self.assertTrue(failed)
                preparation_handoff.assert_not_called()
                ownership_handoff.assert_not_called()
                self.assertEqual(
                    list((self.repo / ".codex-tmp").glob("isolated-review-*")),
                    [],
                )

    def test_completed_workspace_is_owned_before_handoff_signal(self) -> None:
        restore_calls = 0
        captured = []

        def interrupt_ownership_restore(_mask):
            nonlocal restore_calls
            restore_calls += 1
            if captured:
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
                side_effect=lambda: {signal.SIGTERM},
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

    def test_head_cleanup_quarantine_namespace_is_rejected(self) -> None:
        marker = "private-marker"
        reserved_path = f"nested/.codex-review-cleanup-{marker}/tracked.txt"
        reserved_head = self.commit_bytes(
            reserved_path,
            b"tracked\n",
            "Add reserved cleanup quarantine path",
        )

        with self.assertRaisesRegex(
            ReviewError,
            "frozen head uses a reserved review cleanup quarantine path component",
        ) as raised:
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=reserved_head,
            )
        self.assertNotIn(marker, str(raised.exception))
        self.assertNotIn(reserved_path, str(raised.exception))
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
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

    def test_frozen_tree_depth_matches_cleanup_safety_boundary(self) -> None:
        accepted_relative = "/".join(["d"] * 254 + ["accepted.txt"])
        accepted_head = self.commit_bytes(
            accepted_relative,
            b"accepted\n",
            "Add deepest cleanable frozen path",
        )

        review = self.prepare_range(self.head, accepted_head)
        self.assertEqual(
            (review.workspace_root / accepted_relative).read_bytes(),
            b"accepted\n",
        )
        self.assertIsNone(cleanup_workspace(review, keep_container=False))
        self.assertFalse(review.container_dir.exists())

        rejected_relative = "/".join(["d"] * 255 + ["rejected.txt"])
        rejected_head = self.commit_bytes(
            rejected_relative,
            b"rejected\n",
            "Add frozen path beyond cleanup depth",
        )
        captured = []

        with self.assertRaisesRegex(
            ReviewError,
            "frozen Git tree path depth exceeds the review cleanup safety limit",
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=accepted_head,
                head_ref=rejected_head,
                ownership_handoff=captured.append,
            )

        self.assertEqual(captured, [])
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_gitlink_depth_accounts_for_materialized_directory(self) -> None:
        accepted_relative = "nested/deeper/accepted.txt"
        accepted_head = self.commit_bytes(
            accepted_relative,
            b"accepted\n",
            "Add cleanable blob path",
        )
        with mock.patch.object(
            workspace_runtime,
            "MAX_REVIEW_CLEANUP_DEPTH",
            4,
        ):
            review = self.prepare_range(self.head, accepted_head)
            self.assertIsNone(cleanup_workspace(review, keep_container=False))

        rejected_gitlink = "nested/deeper/external"
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},{rejected_gitlink}",
        )
        git(self.repo, "commit", "-m", "Add gitlink beyond cleanup depth")
        rejected_head = git(self.repo, "rev-parse", "HEAD")
        captured = []

        with (
            mock.patch.object(
                workspace_runtime,
                "MAX_REVIEW_CLEANUP_DEPTH",
                4,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "frozen Git tree path depth exceeds the review cleanup safety limit",
            ),
        ):
            _prepare_workspace(
                repo=self.repo,
                base_ref=accepted_head,
                head_ref=rejected_head,
                ownership_handoff=captured.append,
            )

        self.assertEqual(captured, [])
        self.assertEqual(
            list((self.repo / ".codex-tmp").glob("isolated-review-*")),
            [],
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

    def test_external_workspace_rejects_injected_cleanup_quarantine_path(
        self,
    ) -> None:
        review = self.prepare_range(self.base, self.head)
        marker = "post-prepare-marker"
        injected = review.workspace_root / f".codex-review-cleanup-{marker}"
        injected.write_text("injected\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(
                ReviewError,
                "external review snapshot uses a reserved review cleanup "
                "quarantine path component",
            ) as raised:
                validate_external_workspace(review)
            self.assertNotIn(marker, str(raised.exception))
        finally:
            injected.unlink()

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

        with (
            mock.patch.object(
                workspace_runtime,
                "_secret_count_manifests",
                return_value=({}, {}, ()),
            ),
            self.assertRaisesRegex(
                ReviewError,
                r"artifact -> <redacted symlink target>",
            ) as raised,
        ):
            prepare_workspace(
                repo=self.repo,
                base_ref=self.head,
                head_ref=secret_head,
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_unchanged_sensitive_path_symlink_is_available_to_reviewer(self) -> None:
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
        secret_delta = self.assert_secret_delta_status(review, "clean")

        self.assertEqual(secret_delta["violations"], [])
        self.assertTrue((review.workspace_root / "fixtures/.netrc").is_symlink())
        self.assertEqual(
            os.readlink(review.workspace_root / "fixtures/.netrc"),
            "../public.txt",
        )

    def test_unchanged_secret_in_path_name_is_available_to_reviewer(self) -> None:
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
        secret_delta = self.assert_secret_delta_status(review, "clean")

        self.assertEqual(secret_delta["violations"], [])
        self.assertEqual(
            (review.workspace_root / "fixtures" / secret).read_text(encoding="utf-8"),
            "ordinary content\n",
        )

    def test_secret_in_sensitive_changed_path_is_raw_with_violation_evidence(
        self,
    ) -> None:
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

        secret_delta = self.assert_secret_delta_status(review, "violations")
        self.assertEqual(secret_delta["location_status"], "complete")
        self.assertEqual(len(secret_delta["violations"]), 1)
        violation = secret_delta["violations"][0]
        self.assertEqual(
            (violation["base_count"], violation["head_count"], violation["delta"]),
            (0, 1, 1),
        )
        self.assertEqual(violation["additions"][0]["surface"], "path")
        self.assertEqual(violation["additions"][0]["path"], f"{secret}/.netrc")
        self.assertEqual(
            (review.workspace_root / secret / ".netrc").read_text(encoding="utf-8"),
            "ordinary content\n",
        )
        self.assertIn(secret.encode(), review.diff_file.read_bytes())

    def test_unchanged_secret_in_symlink_target_is_available_to_reviewer(self) -> None:
        secret = "sk-" + "A" * 40
        (self.repo / "artifact").symlink_to(secret)
        git(self.repo, "add", "artifact")
        git(self.repo, "commit", "-m", "Add secret-shaped symlink target")
        sensitive_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("three\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated content")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(sensitive_base, unrelated_head)
        secret_delta = self.assert_secret_delta_status(review, "clean")

        self.assertEqual(secret_delta["violations"], [])
        self.assertEqual(os.readlink(review.workspace_root / "artifact"), secret)

    def test_secret_content_in_control_character_paths_remains_raw(self) -> None:
        file_secret = "AKIA" + "C" * 16
        link_secret = "sk-" + "D" * 40
        file_name = "file\n\x1bname"
        symlink_name = "link\n\x1bname"
        (self.repo / file_name).write_text(file_secret + "\n", encoding="utf-8")
        (self.repo / symlink_name).symlink_to(link_secret)
        git(self.repo, "add", file_name, symlink_name)
        git(self.repo, "commit", "-m", "Add raw tracked secret content")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(self.head, secret_head)
        secret_delta = self.assert_secret_delta_status(review, "violations")

        self.assertEqual(secret_delta["location_status"], "complete")
        self.assertEqual(
            (review.workspace_root / file_name).read_text(encoding="utf-8"),
            file_secret + "\n",
        )
        self.assertEqual(
            os.readlink(review.workspace_root / symlink_name),
            link_secret,
        )
        diff = review.diff_file.read_bytes()
        self.assertIn(file_secret.encode(), diff)
        self.assertIn(link_secret.encode(), diff)
        self.assertNotIn(b"<redacted", diff)

    def test_secret_addition_in_non_utf8_path_has_reversible_location(self) -> None:
        raw_value = unregistered_generic_credential()
        raw_path = b"non-utf8-\xff-secret.txt"
        relative = os.fsdecode(raw_path)
        payload = b'password = "' + raw_value + b'"\n'
        destination = self.repo / relative
        try:
            destination.write_bytes(payload)
        except OSError as error:
            if error.errno not in {errno.EILSEQ, errno.EINVAL, errno.EPERM}:
                raise
            self.skipTest("filesystem rejects non-UTF-8 path names")
        git(self.repo, "add", relative)
        git(self.repo, "commit", "-m", "Add credential under non-UTF-8 path")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(self.head, secret_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=0,
            head_count=1,
        )

        self.assertEqual(violation["additions"][0]["surface"], "blob")
        self.assertEqual(
            os.fsencode(violation["additions"][0]["path"]),
            raw_path,
        )
        self.assertEqual(
            (review.workspace_root / relative).read_bytes(),
            payload,
        )
        self.assertIn(raw_value, review.diff_file.read_bytes())
        self.assert_control_evidence_omits(review, raw_value)

        manifest_payload = (
            review.workspace_root
            / ".codex-review"
            / workspace_runtime.SYNTHETIC_MANIFEST_NAME
        ).read_bytes()
        self.assertNotIn(b"\xff", manifest_payload)
        self.assertIn(b"non-utf8-\\udcff-secret.txt", manifest_payload)

    def test_non_utf8_path_evidence_serialization_is_reversible(self) -> None:
        raw_path = b"non-utf8-\xff-secret.txt"
        path = os.fsdecode(raw_path)
        evidence = {
            "secret_delta": {
                "violations": [
                    {
                        "additions": [
                            {
                                "line": 1,
                                "occurrence_count": 1,
                                "path": path,
                                "surface": "blob",
                            }
                        ]
                    }
                ]
            }
        }

        encoded = workspace_runtime._bounded_json_bytes(
            evidence,
            label="test evidence",
        )
        decoded_path = json.loads(encoded)["secret_delta"]["violations"][0][
            "additions"
        ][0]["path"]

        self.assertEqual(os.fsencode(decoded_path), raw_path)
        self.assertNotIn(b"\xff", encoded)
        self.assertIn(b"non-utf8-\\udcff-secret.txt", encoded)
        with self.assertRaisesRegex(ReviewError, "contains an invalid string"):
            list(workspace_runtime._iter_evidence_strings("\ud800"))

        raw_value = unregistered_generic_credential()
        descriptor = workspace_runtime._secret_reduction_descriptor(
            raw_value,
            {"generic-secret-assignment"},
        )
        leaking_path = os.fsdecode(b"non-utf8-\xff-" + raw_value)
        with self.assertRaisesRegex(ReviewError, "would expose a raw synthetic value"):
            workspace_runtime._bounded_json_bytes(
                {"path": leaking_path},
                label="test evidence",
                accepted_values=(descriptor,),
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

    def test_binary_secret_growth_reports_only_the_new_occurrence(self) -> None:
        secret = unregistered_provider_credential()
        base_payload = b"\0binary\0" + secret + b"\0"
        head_payload = base_payload + secret + b"\0"
        secret_base = self.commit_bytes(
            "growing-opaque.bin",
            base_payload,
            "Add one binary credential",
        )
        secret_head = self.commit_bytes(
            "growing-opaque.bin",
            head_payload,
            "Add a second binary credential",
        )

        review = self.prepare_range(secret_base, secret_head)
        violation = self.assert_secret_violation(
            review,
            secret,
            base_count=1,
            head_count=2,
        )

        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": None,
                    "occurrence_count": 1,
                    "path": "growing-opaque.bin",
                    "surface": "binary",
                }
            ],
        )
        self.assertEqual(
            (review.workspace_root / "growing-opaque.bin").read_bytes(),
            head_payload,
        )

    def test_symlink_target_secret_growth_reports_only_the_new_occurrence(
        self,
    ) -> None:
        secret = "sk-" + "I" * 40
        link_path = self.repo / "growing-link"
        base_target = f"{secret}/target"
        head_target = f"{secret}/{secret}/target"
        link_path.symlink_to(base_target)
        git(self.repo, "add", "growing-link")
        git(self.repo, "commit", "-m", "Add one symlink credential")
        secret_base = git(self.repo, "rev-parse", "HEAD")
        link_path.unlink()
        link_path.symlink_to(head_target)
        git(self.repo, "add", "growing-link")
        git(self.repo, "commit", "-m", "Add a second symlink credential")
        secret_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(secret_base, secret_head)
        violation = self.assert_secret_violation(
            review,
            secret.encode("ascii"),
            base_count=1,
            head_count=2,
        )

        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": 1,
                    "occurrence_count": 1,
                    "path": "growing-link",
                    "surface": "symlink-target",
                }
            ],
        )
        self.assertEqual(
            os.readlink(review.workspace_root / "growing-link"), head_target
        )

    def test_ambiguous_replaced_secret_line_marks_locations_inconclusive(
        self,
    ) -> None:
        secret = "sk-" + "J" * 40
        secret_base = self.commit_bytes(
            "ambiguous.txt",
            f"key={secret} old\n".encode("ascii"),
            "Add one text credential",
        )
        secret_head = self.commit_bytes(
            "ambiguous.txt",
            (f"key={secret} edited\nsecond={secret}\n").encode("ascii"),
            "Edit one credential line and add another",
        )

        review = self.prepare_range(secret_base, secret_head)
        secret_delta = self.assert_secret_delta_status(review, "violations")
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        matching = [
            violation
            for violation in secret_delta["violations"]
            if violation["value_sha256"]
            == hashlib.sha256(secret.encode("ascii")).hexdigest()
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(
            (
                matching[0]["base_count"],
                matching[0]["head_count"],
                matching[0]["delta"],
                matching[0]["additions"],
            ),
            (1, 2, 1, []),
        )

    def test_replaced_multiline_match_cannot_mask_cross_boundary_addition(
        self,
    ) -> None:
        secret = b"CriticalCredential\nAlpha9!"
        self.commit_bytes(
            "multiline-seed.txt",
            b'password = """CriticalCredential\nAlpha9!"""\n',
            "Add an exact multiline credential seed",
        )
        secret_base = self.commit_bytes(
            "cross-boundary.txt",
            b"old=CriticalCredential\nAlpha9! old\nAlpha9! stable\n",
            "Add one multiline credential",
        )
        secret_head = self.commit_bytes(
            "cross-boundary.txt",
            (
                b"edited=CriticalCredential\n"
                b"Alpha9! edited\n"
                b"note=CriticalCredential\n"
                b"Alpha9! stable\n"
            ),
            "Retain one credential and add a cross-boundary copy",
        )

        review = self.prepare_range(secret_base, secret_head)
        violation = self.assert_secret_violation(
            review,
            secret,
            base_count=2,
            head_count=3,
        )
        self.assertEqual(violation["additions"], [])
        self.assertEqual(
            self.assert_secret_delta_status(review, "violations")["location_status"],
            "inconclusive",
        )

    def test_frozen_diff_keeps_initialized_submodule_metadata_only(self) -> None:
        subrepo = pathlib.Path(self.temporary.name) / "external-repo"
        subprocess.run(
            ("git", "init", "-b", "master", str(subrepo)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(subrepo, "config", "user.name", "Review Test")
        git(subrepo, "config", "user.email", "review@example.com")
        git(subrepo, "config", "commit.gpgsign", "false")
        marker = b"EXTERNAL_SUBMODULE_CONTENT_MARKER_987654\n"
        (subrepo / "foreign.txt").write_bytes(b"safe submodule content\n")
        git(subrepo, "add", "foreign.txt")
        git(subrepo, "commit", "-m", "External base")
        submodule_base = git(subrepo, "rev-parse", "HEAD")
        (subrepo / "foreign.txt").write_bytes(marker)
        git(subrepo, "add", "foreign.txt")
        git(subrepo, "commit", "-m", "External head")
        submodule_head = git(subrepo, "rev-parse", "HEAD")

        gitlink_path = "vendor/external"
        git(
            self.repo,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            str(subrepo),
            gitlink_path,
        )
        checkout = self.repo / gitlink_path
        git(checkout, "checkout", "--detach", submodule_base)
        git(self.repo, "add", ".gitmodules", gitlink_path)
        git(self.repo, "commit", "-m", "Add external gitlink")
        gitlink_base = git(self.repo, "rev-parse", "HEAD")
        git(checkout, "checkout", "--detach", submodule_head)
        git(self.repo, "add", gitlink_path)
        git(self.repo, "commit", "-m", "Update external gitlink")
        gitlink_head = git(self.repo, "rev-parse", "HEAD")
        self.assertEqual(git(checkout, "rev-parse", "HEAD"), submodule_head)

        previous_cwd = pathlib.Path.cwd()
        try:
            os.chdir(self.repo)
            review = self.prepare_range(gitlink_base, gitlink_head)
        finally:
            os.chdir(previous_cwd)
        diff = review.diff_file.read_bytes()

        self.assertIn(f"Subproject commit {submodule_base}".encode(), diff)
        self.assertIn(f"Subproject commit {submodule_head}".encode(), diff)
        self.assertNotIn(marker.rstrip(), diff)
        self.assertNotIn(b"diff --git a/vendor/external/foreign.txt", diff)
        validate_external_workspace(review)

    def test_new_secret_shaped_gitlink_path_is_an_admission_violation(self) -> None:
        secret = "sk-" + "G" * 40
        gitlink_path = f"vendor/{secret}"
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},{gitlink_path}",
        )
        git(self.repo, "commit", "-m", "Add secret-shaped gitlink path")
        gitlink_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(self.head, gitlink_head)
        violation = self.assert_secret_violation(
            review,
            secret.encode("ascii"),
            base_count=0,
            head_count=1,
        )

        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": None,
                    "occurrence_count": 1,
                    "path": gitlink_path,
                    "surface": "path",
                }
            ],
        )
        materialized = review.workspace_root / gitlink_path
        self.assertTrue(materialized.is_dir())
        self.assertEqual(list(materialized.iterdir()), [])
        self.assertIn(secret.encode("ascii"), review.diff_file.read_bytes())

    def test_unchanged_secret_shaped_gitlink_path_has_clean_global_delta(
        self,
    ) -> None:
        secret = "sk-" + "H" * 40
        gitlink_path = f"vendor/{secret}"
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},{gitlink_path}",
        )
        git(self.repo, "commit", "-m", "Add retained secret-shaped gitlink")
        gitlink_base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("unrelated\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Change unrelated tracked file")
        unrelated_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(gitlink_base, unrelated_head)
        secret_delta = self.assert_secret_delta_status(review, "clean")

        self.assertEqual(secret_delta["violations"], [])
        materialized = review.workspace_root / gitlink_path
        self.assertTrue(materialized.is_dir())
        self.assertEqual(list(materialized.iterdir()), [])
        self.assertNotIn(secret.encode("ascii"), review.diff_file.read_bytes())

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
                "wrapped-generic",
                unregistered_generic_credential(),
                lambda value: b'password = ("""' + value + b'""")\n',
            ),
            (
                "multiline-wrapped-generic",
                b"CriticalCredential\nAlpha9!",
                lambda value: b'password = ("""' + value + b'""")\n',
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

    def test_inconclusive_secret_delta_does_not_block_workspace_validation(
        self,
    ) -> None:
        with mock.patch.object(
            workspace_runtime,
            "_secret_count_manifests",
            side_effect=ReviewError("injected incomplete exact-value scan"),
        ):
            review = self.prepare_range(self.base, self.head)

        secret_delta = self.assert_secret_delta_status(review, "inconclusive")
        self.assertEqual(
            secret_delta["failure_class"],
            "exact-value-scan-incomplete",
        )
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(b"+two", review.diff_file.read_bytes())
        self.assertEqual(
            (review.workspace_root / "example.txt").read_text(encoding="utf-8"),
            "one\ntwo\n",
        )
        evidence = validate_external_workspace(review)
        self.assertEqual(
            evidence["secret_delta"]["failure_class"],
            "exact-value-scan-incomplete",
        )

    def test_secret_delta_os_error_does_not_block_workspace_validation(
        self,
    ) -> None:
        with mock.patch.object(
            workspace_runtime,
            "_secret_count_manifests",
            side_effect=OSError("injected secret-count subprocess failure"),
        ):
            review = self.prepare_range(self.base, self.head)

        secret_delta = self.assert_secret_delta_status(review, "inconclusive")
        self.assertEqual(
            secret_delta["failure_class"],
            "exact-value-scan-incomplete",
        )
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(b"+two", review.diff_file.read_bytes())
        evidence = validate_external_workspace(review)
        self.assertEqual(evidence["secret_delta"], secret_delta)

    def test_unextractable_secret_shape_marks_admission_inconclusive(self) -> None:
        payload = b'password = "' + b"D" * 513 + b'"\n'
        oversized_head = self.commit_bytes(
            "oversized-secret.txt",
            payload,
            "Add an unextractable credential shape",
        )

        review = self.prepare_range(self.head, oversized_head)
        secret_delta = self.assert_secret_delta_status(review, "inconclusive")
        self.assertEqual(
            secret_delta["failure_class"],
            "exact-value-scan-incomplete",
        )
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(payload.rstrip(b"\n"), review.diff_file.read_bytes())
        evidence = validate_external_workspace(review)
        self.assertEqual(evidence["secret_delta"], secret_delta)

    def test_unclosed_secret_assignment_at_eof_marks_admission_inconclusive(
        self,
    ) -> None:
        payload = b'password = "' + b"E" * 32
        unclosed_head = self.commit_bytes(
            "unclosed-secret.txt",
            payload,
            "Add an unclosed credential assignment",
        )

        review = self.prepare_range(self.head, unclosed_head)
        secret_delta = self.assert_secret_delta_status(review, "inconclusive")
        self.assertEqual(
            secret_delta["failure_class"],
            "exact-value-scan-incomplete",
        )
        self.assertEqual(secret_delta["location_status"], "inconclusive")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(payload, review.diff_file.read_bytes())
        evidence = validate_external_workspace(review)
        self.assertEqual(evidence["secret_delta"], secret_delta)

    def test_unregistered_secret_addition_is_raw_with_violation_evidence(
        self,
    ) -> None:
        raw_value = unregistered_generic_credential()
        payload = b'password = "' + raw_value + b'"\n'
        added_head = self.commit_bytes(
            "added-secret.txt",
            payload,
            "Add unregistered credential",
        )

        review = self.prepare_range(self.head, added_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=0,
            head_count=1,
        )
        self.assertEqual(violation["additions"][0]["path"], "added-secret.txt")
        self.assertEqual(violation["additions"][0]["surface"], "blob")
        self.assertEqual(
            (review.workspace_root / "added-secret.txt").read_bytes(),
            payload,
        )
        self.assertIn(raw_value, review.diff_file.read_bytes())

    def test_large_file_backed_legacy_catalog_stays_clean_and_launchable(
        self,
    ) -> None:
        values, catalog = self.maximal_file_backed_legacy_catalog(
            rule="generic-secret-assignment",
            compact_values=True,
        )
        payload = b"".join(b'password = "' + value + b'"\n' for value in values)
        existing_base = self.commit_bytes(
            "existing-legacy-values.txt",
            payload,
            "Add existing cataloged legacy values",
        )
        clean_head = self.commit_bytes(
            "unrelated-large-catalog-change.txt",
            b"unrelated\n",
            "Change unrelated content with a large catalog",
        )

        with mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog):
            review = self.prepare_range(existing_base, clean_head)
            public_manifest_path = (
                review.workspace_root
                / ".codex-review"
                / workspace_runtime.SYNTHETIC_MANIFEST_NAME
            )
            private_manifest_path = (
                review.container_dir / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
            )
            public_manifest = json.loads(public_manifest_path.read_text("utf-8"))
            private_manifest = json.loads(private_manifest_path.read_text("utf-8"))
            evidence = validate_external_workspace(review)

        self.assertLessEqual(
            public_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        self.assertLessEqual(
            private_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        self.assertNotEqual(public_manifest["entries"], private_manifest["entries"])
        self.assertEqual(
            len(public_manifest["entries"]) + len(private_manifest["entries"]),
            len(values),
        )
        self.assertEqual(public_manifest["secret_delta"]["status"], "clean")
        self.assertEqual(private_manifest["secret_delta"]["status"], "clean")
        self.assertEqual(public_manifest["secret_delta"]["violations"], [])
        self.assertEqual(private_manifest["secret_delta"]["violations"], [])
        public_commitments = [
            item
            for item in public_manifest["secret_delta"]["limitations"]
            if item.startswith(
                workspace_runtime.PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX
            )
        ]
        private_commitments = [
            item
            for item in private_manifest["secret_delta"]["limitations"]
            if item.startswith(
                workspace_runtime.PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX
            )
        ]
        self.assertEqual(len(public_commitments), 1)
        self.assertEqual(private_commitments, public_commitments)
        self.assertEqual(evidence["secret_delta"]["status"], "clean")
        self.assertEqual(evidence["secret_delta"]["violations"], [])
        self.assertEqual(evidence["synthetic_tokens"]["accepted"], [])
        self.assertEqual(evidence["synthetic_tokens"]["legacy_counts"], [])
        self.assertEqual(evidence["synthetic_tokens"]["secret_reductions"], [])
        encoded_preflight = workspace_runtime.encode_preflight_json(
            workspace_runtime.build_preflight_evidence(review, evidence)
        ).encode("utf-8")
        self.assertLessEqual(
            len(encoded_preflight),
            workspace_runtime.MAX_PREFLIGHT_JSON_BYTES,
        )

    def test_one_growth_in_large_legacy_catalog_stays_blocked_and_launchable(
        self,
    ) -> None:
        values, catalog = self.maximal_file_backed_legacy_catalog(
            rule="generic-secret-assignment",
            compact_values=True,
        )
        payload = b"".join(b'password = "' + value + b'"\n' for value in values)
        existing_base = self.commit_bytes(
            "existing-legacy-values.txt",
            payload,
            "Add existing cataloged legacy values",
        )
        growth_head = self.commit_bytes(
            "one-legacy-growth.txt",
            b'password = "' + values[0] + b'"\n',
            "Grow one cataloged legacy value",
        )

        with mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog):
            review = self.prepare_range(existing_base, growth_head)
            public_manifest_path = (
                review.workspace_root
                / ".codex-review"
                / workspace_runtime.SYNTHETIC_MANIFEST_NAME
            )
            private_manifest_path = (
                review.container_dir / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
            )
            public_manifest = json.loads(public_manifest_path.read_text("utf-8"))
            private_manifest = json.loads(private_manifest_path.read_text("utf-8"))
            evidence = validate_external_workspace(review)

        self.assertLessEqual(
            public_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        self.assertLessEqual(
            private_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        shard_violations = [
            *public_manifest["secret_delta"]["violations"],
            *private_manifest["secret_delta"]["violations"],
        ]
        self.assertEqual(len(shard_violations), 1)
        self.assertEqual(
            sorted(
                (
                    len(public_manifest["secret_delta"]["violations"]),
                    len(private_manifest["secret_delta"]["violations"]),
                )
            ),
            [0, 1],
        )
        self.assertEqual(
            len(public_manifest["entries"]) + len(private_manifest["entries"]),
            len(values) - 1,
        )
        secret_delta = evidence["secret_delta"]
        self.assertEqual(secret_delta["status"], "violations")
        self.assertEqual(secret_delta["location_status"], "complete")
        self.assertEqual(len(secret_delta["violations"]), 1)
        violation = secret_delta["violations"][0]
        self.assertEqual(
            violation["value_sha256"],
            hashlib.sha256(values[0]).hexdigest(),
        )
        self.assertEqual(
            (violation["base_count"], violation["head_count"], violation["delta"]),
            (1, 2, 1),
        )
        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": 1,
                    "occurrence_count": 1,
                    "path": "one-legacy-growth.txt",
                    "surface": "blob",
                }
            ],
        )
        self.assertEqual(evidence["synthetic_tokens"]["accepted"], [])
        self.assertEqual(evidence["synthetic_tokens"]["legacy_counts"], [])
        self.assertEqual(evidence["synthetic_tokens"]["secret_reductions"], [])
        encoded_preflight = workspace_runtime.encode_preflight_json(
            workspace_runtime.build_preflight_evidence(review, evidence)
        ).encode("utf-8")
        self.assertLessEqual(
            len(encoded_preflight),
            workspace_runtime.MAX_PREFLIGHT_JSON_BYTES,
        )

    def test_mixed_catalog_shards_round_trip_and_bind_exact_rows(self) -> None:
        values = tuple(
            b"S" * 11 + f"{index:05d}".encode("ascii") for index in range(256)
        )
        encoded_catalog = self.encoded_file_catalog_with_legacy_values(
            values,
            rule="generic-secret-assignment",
        )
        self.assertLessEqual(
            len(encoded_catalog),
            synthetic_tokens_runtime.MAX_CATALOG_BYTES,
        )
        catalog = synthetic_tokens_runtime.parse_catalog_bytes(encoded_catalog)
        split = len(values) // 2
        existing_base = self.commit_bytes(
            "mixed-existing-legacy-values.txt",
            b"".join(b'password = "' + value + b'"\n' for value in values[:split]),
            "Add existing mixed catalog values",
        )
        growth_head = self.commit_bytes(
            "mixed-added-legacy-values.txt",
            b"".join(b'password = "' + value + b'"\n' for value in values[split:]),
            "Grow mixed catalog values",
        )

        with mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog):
            review = self.prepare_range(existing_base, growth_head)
            public_manifest_path = (
                review.workspace_root
                / ".codex-review"
                / workspace_runtime.SYNTHETIC_MANIFEST_NAME
            )
            private_manifest_path = (
                review.container_dir / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
            )
            public_manifest = json.loads(public_manifest_path.read_text("utf-8"))
            private_manifest = json.loads(private_manifest_path.read_text("utf-8"))
            evidence = validate_external_workspace(review)

        for manifest in (public_manifest, private_manifest):
            self.assertTrue(manifest["entries"])
            self.assertTrue(manifest["secret_delta"]["violations"])
        self.assertEqual(
            len(public_manifest["entries"]) + len(private_manifest["entries"]),
            split,
        )
        self.assertEqual(
            len(public_manifest["secret_delta"]["violations"])
            + len(private_manifest["secret_delta"]["violations"]),
            len(values) - split,
        )
        self.assertEqual(evidence["secret_delta"]["status"], "violations")
        self.assertEqual(
            len(evidence["secret_delta"]["violations"]),
            len(values) - split,
        )
        self.assertEqual(
            {
                violation["value_sha256"]
                for violation in evidence["secret_delta"]["violations"]
            },
            {hashlib.sha256(value).hexdigest() for value in values[split:]},
        )

        for mutation in ("delete", "duplicate", "reorder"):
            with self.subTest(private_entries=mutation):
                mutated_private = json.loads(json.dumps(private_manifest))
                if mutation == "delete":
                    mutated_private["entries"].pop()
                elif mutation == "duplicate":
                    mutated_private["entries"].append(
                        dict(mutated_private["entries"][0])
                    )
                else:
                    self.assertGreater(len(mutated_private["entries"]), 1)
                    mutated_private["entries"].reverse()
                with self.assertRaisesRegex(
                    ReviewError,
                    "helper-private manifest shard commitment does not match",
                ):
                    workspace_runtime._merge_secret_count_manifest_shards(
                        public_manifest,
                        mutated_private,
                    )

        tampered_public = json.loads(json.dumps(public_manifest))
        tampered_public["entries"][0]["head_count"] += 1
        public_manifest_path.write_text(
            json.dumps(tampered_public, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog),
            self.assertRaisesRegex(
                ReviewError,
                "does not match helper-private control state",
            ),
        ):
            validate_external_workspace(review)

    def test_file_backed_legacy_growth_at_capacity_stays_blocked_and_launchable(
        self,
    ) -> None:
        values, catalog = self.maximal_file_backed_legacy_catalog(
            rule="generic-secret-assignment",
        )
        accepted = workspace_runtime.accepted_legacy_values(
            catalog,
            catalog.legacy_exemptions,
        )
        probe = b'password = "' + values[0] + b'"\n'
        unfiltered = workspace_runtime._scan_secret_value(
            probe,
            accepted_values=accepted,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )
        filtered = workspace_runtime._scan_secret_value(
            probe,
            accepted_values=accepted,
            capture_blocking_candidates=True,
            reduced_secret_values=frozenset(values),
            _continue_after_blocking=True,
        )
        self.assertEqual(unfiltered.accepted_counts, {})
        self.assertIn("openai-key", unfiltered.blocking_candidates[values[0]])
        self.assertEqual(filtered.accepted_counts, {})
        self.assertEqual(filtered.blocking_candidates, {})
        payload = b"".join(b'password = "' + value + b'"\n' for value in values)
        added_head = self.commit_bytes(
            "many-legacy-growths.txt",
            payload,
            "Add many cataloged legacy values",
        )

        with mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog):
            review = self.prepare_range(self.head, added_head)
            public_manifest_path = (
                review.workspace_root
                / ".codex-review"
                / workspace_runtime.SYNTHETIC_MANIFEST_NAME
            )
            private_manifest_path = (
                review.container_dir / workspace_runtime.SYNTHETIC_PRIVATE_MANIFEST_NAME
            )
            public_manifest = json.loads(public_manifest_path.read_text("utf-8"))
            private_manifest = json.loads(private_manifest_path.read_text("utf-8"))
            evidence = validate_external_workspace(review)

        self.assertLessEqual(
            public_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        self.assertLessEqual(
            private_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        public_digests = {
            item["value_sha256"]
            for item in public_manifest["secret_delta"]["violations"]
        }
        private_digests = {
            item["value_sha256"]
            for item in private_manifest["secret_delta"]["violations"]
        }
        self.assertTrue(public_digests)
        self.assertTrue(private_digests)
        self.assertTrue(public_digests.isdisjoint(private_digests))
        self.assertEqual(
            public_digests | private_digests,
            {hashlib.sha256(value).hexdigest() for value in values},
        )
        public_commitments = [
            item
            for item in public_manifest["secret_delta"]["limitations"]
            if item.startswith(
                workspace_runtime.PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX
            )
        ]
        private_commitments = [
            item
            for item in private_manifest["secret_delta"]["limitations"]
            if item.startswith(
                workspace_runtime.PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX
            )
        ]
        self.assertEqual(len(public_commitments), 1)
        self.assertEqual(private_commitments, public_commitments)

        for mutation in ("missing", "duplicate"):
            with self.subTest(commitment=mutation):
                mutated_public = json.loads(json.dumps(public_manifest))
                mutated_private = json.loads(json.dumps(private_manifest))
                for manifest in (mutated_public, mutated_private):
                    limitations = manifest["secret_delta"]["limitations"]
                    if mutation == "missing":
                        limitations.remove(public_commitments[0])
                    else:
                        limitations.append(public_commitments[0])
                with self.assertRaisesRegex(ReviewError, "shard commitment"):
                    workspace_runtime._merge_secret_count_manifest_shards(
                        mutated_public,
                        mutated_private,
                    )
        duplicated_public = json.loads(json.dumps(public_manifest))
        duplicated_private = json.loads(json.dumps(private_manifest))
        duplicated_private["secret_delta"]["violations"].append(
            dict(duplicated_public["secret_delta"]["violations"][0])
        )
        duplicate_digest = workspace_runtime._private_manifest_shard_rows_sha256(
            duplicated_private,
            [],
        )
        duplicate_commitment = workspace_runtime._private_manifest_shard_commitment(
            duplicate_digest
        )
        for manifest in (duplicated_public, duplicated_private):
            manifest["secret_delta"]["limitations"] = [
                duplicate_commitment
                if item.startswith(
                    workspace_runtime.PRIVATE_MANIFEST_SHARD_COMMITMENT_PREFIX
                )
                else item
                for item in manifest["secret_delta"]["limitations"]
            ]
        with self.assertRaisesRegex(ReviewError, "does not match helper-private state"):
            workspace_runtime._merge_secret_count_manifest_shards(
                duplicated_public,
                duplicated_private,
            )
        secret_delta = evidence["secret_delta"]
        self.assertEqual(secret_delta["status"], "violations")
        self.assertEqual(
            len(secret_delta["violations"]),
            len(values),
        )
        self.assertEqual(
            {item["value_sha256"] for item in secret_delta["violations"]},
            {hashlib.sha256(value).hexdigest() for value in values},
        )
        self.assertTrue(
            all(
                (item["base_count"], item["head_count"], item["delta"]) == (0, 1, 1)
                for item in secret_delta["violations"]
            )
        )
        self.assertEqual(evidence["synthetic_tokens"]["accepted"], [])
        self.assertEqual(evidence["synthetic_tokens"]["legacy_counts"], [])
        self.assertEqual(evidence["synthetic_tokens"]["secret_reductions"], [])
        complete_preflight = workspace_runtime.build_preflight_evidence(
            review,
            evidence,
        )
        encoded_preflight = workspace_runtime.encode_preflight_json(
            complete_preflight
        ).encode("utf-8")
        self.assertLessEqual(
            len(encoded_preflight),
            workspace_runtime.MAX_PREFLIGHT_JSON_BYTES,
        )
        self.assertEqual(
            len(json.loads(encoded_preflight)["secret_delta"]["violations"]),
            len(values),
        )
        self.assertIn(values[0], review.diff_file.read_bytes())
        self.assertIn(
            values[-1],
            (review.workspace_root / "many-legacy-growths.txt").read_bytes(),
        )

        tampered_private = json.loads(private_manifest_path.read_text("utf-8"))
        tampered_violation = tampered_private["secret_delta"]["violations"][0]
        tampered_violation["base_count"] = 1
        tampered_violation["head_count"] = 2
        tampered_violation["delta"] = 1
        private_manifest_path.write_text(
            json.dumps(tampered_private, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertLessEqual(
            private_manifest_path.stat().st_size,
            workspace_runtime.MAX_SYNTHETIC_EVIDENCE_BYTES,
        )
        with (
            mock.patch.object(
                workspace_runtime,
                "load_catalog",
                return_value=catalog,
            ),
            self.assertRaisesRegex(ReviewError, "commitment does not match"),
        ):
            validate_external_workspace(review)

    def test_cataloged_exact_bytes_merge_across_scanner_rules(self) -> None:
        raw_value = unregistered_provider_credential()
        catalog = self.catalog_with_legacy_values(
            (raw_value,),
            rule="github-token",
        )
        rendered = b'password = "' + raw_value + b'"\n'
        secret_base = self.commit_bytes(
            "cataloged-secret.txt",
            rendered,
            "Add cataloged secret",
        )
        unchanged_head = self.commit_bytes(
            "unrelated.txt",
            b"unrelated change\n",
            "Change unrelated content",
        )
        growth_head = self.commit_bytes(
            "copied-cataloged-secret.txt",
            rendered,
            "Copy cataloged secret",
        )
        deletion_head = self.remove_and_commit(
            "copied-cataloged-secret.txt",
            "Delete copied cataloged secret",
        )

        with mock.patch.object(workspace_runtime, "load_catalog", return_value=catalog):
            unchanged_review = self.prepare_range(secret_base, unchanged_head)
            deletion_review = self.prepare_range(growth_head, deletion_head)
            growth_review = self.prepare_range(secret_base, growth_head)

            unchanged = self.assert_secret_delta_status(unchanged_review, "clean")
            deletion = self.assert_secret_delta_status(deletion_review, "clean")
            growth = self.assert_secret_violation(
                growth_review,
                raw_value,
                base_count=1,
                head_count=2,
            )
            growth_evidence = validate_external_workspace(growth_review)

        self.assertEqual(unchanged["violations"], [])
        self.assertEqual(deletion["violations"], [])
        self.assertEqual(growth["rules"], ["github-token"])
        self.assertEqual(
            growth["additions"],
            [
                {
                    "line": 1,
                    "occurrence_count": 1,
                    "path": "copied-cataloged-secret.txt",
                    "surface": "blob",
                }
            ],
        )
        self.assertEqual(
            growth_evidence["synthetic_tokens"]["secret_reductions"],
            [],
        )

    def test_wrapped_unregistered_secret_addition_is_raw_with_violation_evidence(
        self,
    ) -> None:
        raw_value = unregistered_generic_credential()
        payload = b'password = ("""' + raw_value + b'""")\n'
        added_head = self.commit_bytes(
            "added-wrapped-secret.txt",
            payload,
            "Add wrapped unregistered credential",
        )

        review = self.prepare_range(self.head, added_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=0,
            head_count=1,
        )
        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": 1,
                    "occurrence_count": 1,
                    "path": "added-wrapped-secret.txt",
                    "surface": "blob",
                }
            ],
        )
        self.assertEqual(
            self.assert_secret_delta_status(review, "violations")["location_status"],
            "complete",
        )
        self.assertEqual(
            (review.workspace_root / "added-wrapped-secret.txt").read_bytes(),
            payload,
        )
        self.assertIn(raw_value, review.diff_file.read_bytes())

    def test_multiline_generic_secret_addition_is_raw_with_violation_evidence(
        self,
    ) -> None:
        raw_value = b"CriticalCredential\nAlpha9!"
        payload = b'password = """' + raw_value + b'"""\n'
        added_head = self.commit_bytes(
            "added-multiline-secret.txt",
            payload,
            "Add multiline unregistered credential",
        )

        review = self.prepare_range(self.head, added_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=0,
            head_count=1,
        )
        self.assertEqual(
            violation["additions"],
            [
                {
                    "line": 1,
                    "occurrence_count": 1,
                    "path": "added-multiline-secret.txt",
                    "surface": "blob",
                }
            ],
        )
        self.assertEqual(
            self.assert_secret_delta_status(review, "violations")["location_status"],
            "complete",
        )
        self.assertEqual(
            (review.workspace_root / "added-multiline-secret.txt").read_bytes(),
            payload,
        )
        added_lines = [
            line
            for line in review.diff_file.read_bytes().splitlines()
            if line.startswith(b"+")
        ]
        for line in raw_value.splitlines():
            self.assertTrue(any(line in added_line for added_line in added_lines))

    def test_unchanged_unregistered_secret_is_raw_with_clean_delta(
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

        review = self.prepare_range(secret_base, unrelated_head)
        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(
            raw_value,
            (review.workspace_root / "retained-secret.txt").read_bytes(),
        )

    def test_moved_unregistered_secret_is_raw_with_clean_delta(self) -> None:
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

        review = self.prepare_range(secret_base, moved_head)
        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(
            raw_value,
            (review.workspace_root / new_path).read_bytes(),
        )

    def test_moved_secret_plus_copy_does_not_invent_addition_location(self) -> None:
        raw_value = unregistered_generic_credential()
        rendered = b'password = "' + raw_value + b'"\n'
        secret_base = self.commit_bytes(
            "old-secret.txt",
            rendered,
            "Add credential before move and copy",
        )
        git(self.repo, "mv", "old-secret.txt", "new-secret.txt")
        (self.repo / "copied-secret.txt").write_bytes(rendered)
        git(self.repo, "add", "copied-secret.txt")
        git(self.repo, "commit", "-m", "Move and copy credential")
        copied_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(secret_base, copied_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=1,
            head_count=2,
        )
        self.assertEqual(violation["delta"], 1)
        self.assertEqual(violation["additions"], [])
        self.assertEqual(violation["omitted_addition_location_count"], 0)
        self.assertEqual(
            self.assert_secret_delta_status(review, "violations")["location_status"],
            "inconclusive",
        )

    def test_cross_surface_move_plus_copy_does_not_invent_location(self) -> None:
        raw_value = unregistered_generic_credential()
        rendered = b'password = "' + raw_value + b'"\n'
        secret_base = self.commit_bytes(
            "old-secret.txt",
            rendered,
            "Add credential before cross-surface move",
        )
        git(self.repo, "rm", "old-secret.txt")
        (self.repo / "copied-secret.txt").write_bytes(rendered)
        (self.repo / "moved-secret-link").symlink_to(os.fsdecode(raw_value))
        git(self.repo, "add", "copied-secret.txt", "moved-secret-link")
        git(self.repo, "commit", "-m", "Move and copy credential across surfaces")
        copied_head = git(self.repo, "rev-parse", "HEAD")

        review = self.prepare_range(secret_base, copied_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=1,
            head_count=2,
        )
        self.assertEqual(violation["delta"], 1)
        self.assertEqual(violation["additions"], [])
        self.assertEqual(
            self.assert_secret_delta_status(review, "violations")["location_status"],
            "inconclusive",
        )

    def test_copied_unregistered_secret_count_increase_is_raw_violation(self) -> None:
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

        review = self.prepare_range(secret_base, copied_head)
        violation = self.assert_secret_violation(
            review,
            raw_value,
            base_count=1,
            head_count=2,
        )
        self.assertEqual(violation["additions"][0]["path"], "copied-secret.txt")
        self.assertIn(
            raw_value,
            (review.workspace_root / "copied-secret.txt").read_bytes(),
        )

    def test_replacing_secret_occurrences_reports_only_the_new_value(
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

        review = self.prepare_range(secret_base, replaced_head)
        violation = self.assert_secret_violation(
            review,
            second,
            base_count=0,
            head_count=1,
        )
        self.assertEqual(
            len(self.assert_secret_delta_status(review, "violations")["violations"]), 1
        )
        self.assertEqual(
            violation["value_sha256"],
            hashlib.sha256(second).hexdigest(),
        )
        self.assertNotEqual(
            violation["value_sha256"],
            hashlib.sha256(first).hexdigest(),
        )
        self.assertIn(
            second,
            (review.workspace_root / "replaced-secret.txt").read_bytes(),
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

    def test_base_only_secret_path_pure_deletion_is_allowed(self) -> None:
        secret = "sk-" + "A" * 40
        source = f"fixtures/{secret}"
        secret_base = self.commit_bytes(
            source,
            b"ordinary content\n",
            "Add secret-shaped path",
        )
        clean_head = self.remove_and_commit(source, "Delete secret-shaped path")

        review = self.prepare_range(secret_base, clean_head)
        validate_external_workspace(review)
        self.assertIn(os.fsencode(source), review.diff_file.read_bytes())
        self.assertIn(
            workspace_runtime.CHANGED_PATH_BASE_ONLY_TAG + os.fsencode(source),
            (
                review.container_dir / workspace_runtime.PRIVATE_CHANGED_PATHS_NAME
            ).read_bytes(),
        )

    def test_renamed_secret_path_is_raw_with_clean_global_delta(self) -> None:
        cases = (
            ("head-before-base", "B", lambda secret: "a" + secret),
            ("base-before-head", "C", lambda secret: "x" + secret),
            (
                "encoded-retention",
                "D",
                lambda secret: "x"
                + base64.b64encode(secret.encode("ascii")).decode("ascii"),
            ),
        )
        for label, fill, destination_name in cases:
            with self.subTest(case=label):
                secret = "sk-" + fill * 40
                source = f"fixtures/{secret}"
                destination = f"fixtures/{destination_name(secret)}"
                secret_base = self.commit_bytes(
                    source,
                    b"ordinary content\n",
                    f"Add {label} secret-shaped path",
                )
                git(self.repo, "mv", source, destination)
                git(self.repo, "commit", "-m", f"Rename {label} secret-shaped path")
                retained_head = git(self.repo, "rev-parse", "HEAD")
                review = self.prepare_range(secret_base, retained_head)

                secret_delta = self.assert_secret_delta_status(review, "clean")
                self.assertEqual(secret_delta["violations"], [])
                self.assertEqual(
                    (review.workspace_root / destination).read_bytes(),
                    b"ordinary content\n",
                )
                diff = review.diff_file.read_bytes()
                self.assertIn(os.fsencode(source), diff)
                self.assertIn(os.fsencode(destination), diff)

    def test_path_secret_moved_into_blob_is_raw_with_clean_global_delta(self) -> None:
        secret = "sk-" + "E" * 40
        source = f"fixtures/{secret}"
        secret_base = self.commit_bytes(
            source,
            b"ordinary content\n",
            "Add path-only secret for blob move",
        )
        git(self.repo, "rm", source)
        prefix = b"x" * (
            workspace_runtime.MAX_SECRET_PREFIX_PROOF_BYTES
            + workspace_runtime.STREAM_SCAN_OVERLAP
            - 10
        )
        (self.repo / "retained.txt").write_bytes(
            prefix + secret.encode("ascii") + b"\n"
        )
        git(self.repo, "add", "retained.txt")
        git(self.repo, "commit", "-m", "Move path secret into blob")
        retained_head = git(self.repo, "rev-parse", "HEAD")
        review = self.prepare_range(secret_base, retained_head)

        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["violations"], [])
        self.assertIn(
            secret.encode("ascii"),
            (review.workspace_root / "retained.txt").read_bytes(),
        )
        self.assertIn(secret.encode("ascii"), review.diff_file.read_bytes())

    def test_path_secret_moved_into_symlink_is_raw_with_clean_global_delta(
        self,
    ) -> None:
        secret = "sk-" + "F" * 40
        source = f"fixtures/{secret}"
        secret_base = self.commit_bytes(
            source,
            b"ordinary content\n",
            "Add path-only secret for symlink move",
        )
        git(self.repo, "rm", source)
        target = "x" + secret
        (self.repo / "retained-link").symlink_to(target)
        git(self.repo, "add", "retained-link")
        git(self.repo, "commit", "-m", "Move path secret into symlink target")
        retained_head = git(self.repo, "rev-parse", "HEAD")
        review = self.prepare_range(secret_base, retained_head)

        secret_delta = self.assert_secret_delta_status(review, "clean")
        self.assertEqual(secret_delta["violations"], [])
        self.assertEqual(os.readlink(review.workspace_root / "retained-link"), target)
        self.assertIn(secret.encode("ascii"), review.diff_file.read_bytes())

    def test_base_only_cleanup_quarantine_path_is_allowed(self) -> None:
        deleted_path = "nested/.codex-review-cleanup-deleted-marker/tracked.txt"
        reserved_base = self.commit_bytes(
            deleted_path,
            b"tracked\n",
            "Add cleanup quarantine path for deletion",
        )
        clean_head = self.remove_and_commit(
            deleted_path,
            "Delete cleanup quarantine path",
        )

        review = self.prepare_range(reserved_base, clean_head)
        validate_external_workspace(review)
        self.assertFalse(
            (review.workspace_root / deleted_path).exists(),
        )
        self.assertIn(os.fsencode(deleted_path), review.diff_file.read_bytes())

    def test_new_and_retained_credential_paths_are_available_to_reviewer(self) -> None:
        added_head = self.commit_bytes(
            "fixtures/.netrc",
            b"machine example.invalid login reviewer\n",
            "Add credential-shaped path",
        )
        with self.subTest(transition="new-sensitive-path"):
            review = self.prepare_range(self.head, added_head)
            secret_delta = self.assert_secret_delta_status(review, "clean")
            self.assertEqual(secret_delta["violations"], [])
            self.assertEqual(
                (review.workspace_root / "fixtures/.netrc").read_bytes(),
                b"machine example.invalid login reviewer\n",
            )

        retained_head = self.commit_bytes(
            "unrelated-path-change.txt",
            b"unrelated change\n",
            "Make unrelated change with retained credential path",
        )
        with self.subTest(transition="retained-sensitive-path"):
            review = self.prepare_range(added_head, retained_head)
            secret_delta = self.assert_secret_delta_status(review, "clean")
            self.assertEqual(secret_delta["violations"], [])
            self.assertEqual(
                (review.workspace_root / "fixtures/.netrc").read_bytes(),
                b"machine example.invalid login reviewer\n",
            )

    def test_non_extractable_secret_deletions_remain_raw_and_launchable(self) -> None:
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

        for name, raw_value, _rule in fixtures:
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
                review = self.prepare_range(secret_base, clean_head)
                secret_delta = self.assert_secret_delta_status(review, "clean")
                self.assertEqual(secret_delta["violations"], [])
                self.assert_diff_retains_raw_deletion(review, raw_value)

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
