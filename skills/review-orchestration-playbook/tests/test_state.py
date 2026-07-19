from __future__ import annotations

import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cleanup_worker, state  # noqa: E402
from review_runtime.common import (  # noqa: E402
    ReviewError,
    read_json,
    write_json,
    write_text_atomic,
)
from review_runtime.workspace import (  # noqa: E402
    _load_control_artifact_state,
    cleanup_workspace,
    prepare_workspace as _prepare_workspace,
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


def prepare_workspace(**kwargs):
    captured = []
    review = _prepare_workspace(ownership_handoff=captured.append, **kwargs)
    if captured != [review]:
        raise AssertionError("workspace ownership was not handed off exactly once")
    return review


def prepared_workspace(review):
    def prepare(**kwargs):
        kwargs["ownership_handoff"](review)
        return review

    return prepare


class StatefulLifecycleTest(unittest.TestCase):
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
        (self.repo / "example.txt").write_text("one\n", encoding="utf-8")
        git(self.repo, "add", ".gitignore", "example.txt")
        git(self.repo, "commit", "-m", "Initial")
        self.base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "example.txt").write_text("two\n", encoding="utf-8")
        git(self.repo, "add", "example.txt")
        git(self.repo, "commit", "-m", "Update")
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.review = prepare_workspace(
            repo=self.repo,
            base_ref=self.base,
            head_ref=self.head,
        )

    def tearDown(self) -> None:
        if self.review.workspace_root.exists():
            cleanup_workspace(self.review, keep_container=False)
        self.temporary.cleanup()

    def write_completed_state(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "claude",
                "egress_consent": "double-review",
                "workspace": self.review.to_json(),
                "keep_workspace": False,
                "pid": 99999999,
            },
        )
        write_json(
            state_dir / "attempts.json",
            [{"runtime": "claude", "requested_model": "claude-opus-4-8"}],
        )
        (state_dir / state.EXIT_FILE).write_text("0\n", encoding="utf-8")
        (state_dir / "final.txt").write_text("No findings.\n", encoding="utf-8")

    def write_codex_unavailable_state(self) -> None:
        self.write_completed_state()
        current = state.load_state(self.review.container_dir)
        current["reviewer"] = "codex"
        current["egress_consent"] = None
        write_json(self.review.container_dir / state.STATE_FILE, current)
        (self.review.container_dir / state.EXIT_FILE).write_text(
            "127\n",
            encoding="utf-8",
        )
        (self.review.container_dir / "final.txt").unlink()
        (self.review.container_dir / "runner-error.txt").write_text(
            "codex is not available in a validated executable path\n",
            encoding="utf-8",
        )

    def primary_diff_attestation(self) -> dict[str, object]:
        control_state = _load_control_artifact_state(
            container_dir=self.review.container_dir
        )
        primary_diff = control_state.artifacts["review.diff"]
        return {
            "path": state.PRIMARY_DIFF_RELATIVE_PATH,
            "sha256": primary_diff.sha256,
            "size": primary_diff.size,
        }

    def write_passed_preflight(
        self,
        *,
        primary_diff: dict[str, object] | None = None,
    ) -> None:
        evidence: dict[str, object] = {
            "review_range": f"{self.base}..{self.head}",
            "status": "sensitive-content and escaping-symlink checks passed",
        }
        if primary_diff is not None:
            evidence["primary_diff"] = primary_diff
        write_json(self.review.container_dir / "preflight.json", evidence)

    def test_final_returns_artifact_and_cleans_detached_workspace(self) -> None:
        self.write_completed_state()
        summary = state.status(self.review.container_dir)
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["egress_consent"], "double-review")
        self.assertEqual(len(summary["attempts"]), 1)

        exit_code, text = state.final(self.review.container_dir)
        self.assertEqual(exit_code, 0)
        self.assertEqual(text, "No findings.")
        self.assertFalse(self.review.workspace_root.exists())
        self.assertTrue(self.review.container_dir.exists())

    def test_codex_unavailable_retains_preflight_workspace_until_cleanup(self) -> None:
        self.write_codex_unavailable_state()
        self.write_passed_preflight(
            primary_diff=self.primary_diff_attestation(),
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertIn("retained for clean-context fallback", text)
        self.assertTrue(self.review.workspace_root.exists())
        summary = state.status(self.review.container_dir)
        self.assertTrue(summary["fallback_workspace_retained"])
        self.assertEqual(
            summary["fallback_workspace"],
            str(self.review.workspace_root),
        )

        self.assertEqual(
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
            0,
        )
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_fallback_accepts_bounded_preflight_larger_than_compact_evidence(self) -> None:
        self.write_codex_unavailable_state()
        evidence: dict[str, object] = {
            "review_range": f"{self.base}..{self.head}",
            "status": "sensitive-content and escaping-symlink checks passed",
            "primary_diff": self.primary_diff_attestation(),
            "padding": "",
        }
        preflight_path = self.review.container_dir / "preflight.json"

        def write_exact_size(target_size: int) -> None:
            evidence["padding"] = ""
            empty_size = len(
                (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
            )
            evidence["padding"] = "x" * (target_size - empty_size)
            encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
            self.assertEqual(len(encoded.encode("utf-8")), target_size)
            write_text_atomic(preflight_path, encoded)

        write_exact_size(state.MAX_PREFLIGHT_JSON_BYTES)

        self.assertTrue(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

        write_exact_size(state.MAX_PREFLIGHT_JSON_BYTES + 1)
        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_deep_valid_fallback_preflight_is_rejected_and_cleanup_succeeds(
        self,
    ) -> None:
        self.write_codex_unavailable_state()
        evidence: dict[str, object] = {
            "review_range": f"{self.base}..{self.head}",
            "status": "sensitive-content and escaping-symlink checks passed",
            "primary_diff": self.primary_diff_attestation(),
        }
        encoded_prefix = json.dumps(evidence, sort_keys=True)[:-1]
        depth = 50_000
        encoded = (
            encoded_prefix
            + ', "padding": '
            + "[" * depth
            + "null"
            + "]" * depth
            + "}\n"
        )
        self.assertLessEqual(
            len(encoded.encode("utf-8")),
            state.MAX_PREFLIGHT_JSON_BYTES,
        )
        preflight_path = self.review.container_dir / "preflight.json"
        write_text_atomic(preflight_path, encoded)

        with self.assertRaisesRegex(
            ReviewError,
            "retained fallback preflight evidence exceeds the JSON nesting depth limit",
        ):
            state._read_bounded_json(
                preflight_path,
                label="retained fallback preflight evidence",
                max_bytes=state.MAX_PREFLIGHT_JSON_BYTES,
            )
        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

        self.assertEqual(
            state.cleanup(self.review.container_dir, timeout_seconds=1),
            0,
        )
        self.assertFalse(self.review.workspace_root.exists())

    def test_codex_unavailable_rejects_missing_or_tampered_diff_attestation(
        self,
    ) -> None:
        self.write_codex_unavailable_state()
        valid = self.primary_diff_attestation()
        invalid_attestations = {
            "missing": None,
            "wrong path": {**valid, "path": "review.diff"},
            "negative size": {**valid, "size": -1},
            "oversized size": {**valid, "size": (128 * 1024 * 1024) + 1},
            "boolean size": {**valid, "size": True},
            "uppercase digest": {**valid, "sha256": "A" * 64},
            "wrong digest": {**valid, "sha256": "0" * 64},
            "extra field": {**valid, "unexpected": "value"},
        }

        for label, primary_diff in invalid_attestations.items():
            with self.subTest(label=label):
                self.write_passed_preflight(primary_diff=primary_diff)
                self.assertFalse(
                    state.status(self.review.container_dir)[
                        "fallback_workspace_retained"
                    ]
                )

    def test_status_does_not_digest_same_size_tampered_primary_diff(self) -> None:
        self.write_codex_unavailable_state()
        self.write_passed_preflight(
            primary_diff=self.primary_diff_attestation(),
        )
        original = self.review.diff_file.read_bytes()
        self.assertTrue(original)
        self.review.diff_file.write_bytes(bytes([original[0] ^ 1]) + original[1:])

        self.assertTrue(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_status_rejects_current_primary_diff_size_mismatch(self) -> None:
        self.write_codex_unavailable_state()
        self.write_passed_preflight(
            primary_diff=self.primary_diff_attestation(),
        )
        with self.review.diff_file.open("ab") as diff_handle:
            diff_handle.write(b"x")

        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_status_rejects_control_state_primary_diff_mismatch(self) -> None:
        self.write_codex_unavailable_state()
        self.write_passed_preflight(
            primary_diff=self.primary_diff_attestation(),
        )
        control_state_path = self.review.container_dir / "control-artifact-state.json"
        control_state = read_json(control_state_path)
        for artifact in control_state["artifacts"]:
            if artifact["name"] == "review.diff":
                artifact["sha256"] = "0" * 64
                break
        else:
            self.fail("review.diff control artifact is missing")
        write_json(control_state_path, control_state)

        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_codex_unavailable_without_preflight_does_not_retain_workspace(
        self,
    ) -> None:
        self.write_completed_state()
        current = state.load_state(self.review.container_dir)
        current["reviewer"] = "codex"
        current["egress_consent"] = None
        write_json(self.review.container_dir / state.STATE_FILE, current)
        (self.review.container_dir / state.EXIT_FILE).write_text(
            "127\n",
            encoding="utf-8",
        )
        (self.review.container_dir / "final.txt").unlink()

        exit_code, _text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertFalse(self.review.workspace_root.exists())

    def test_status_redacts_legacy_attempt_final_text(self) -> None:
        self.write_completed_state()
        artifact = "legacy terminal artifact"
        write_json(
            self.review.container_dir / "attempts.json",
            [{"runtime": "codex", "final_text": artifact}],
        )

        summary = state.status(self.review.container_dir)

        self.assertNotIn("final_text", summary["attempts"][0])
        self.assertTrue(summary["attempts"][0]["final_available"])
        self.assertNotIn(artifact, str(summary))

    def test_concurrent_wait_serializes_workspace_cleanup(self) -> None:
        self.write_completed_state()
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(state.wait, self.review.container_dir, timeout_seconds=2)
            second = executor.submit(state.wait, self.review.container_dir, timeout_seconds=2)
            self.assertEqual(first.result(timeout=2), 0)
            self.assertEqual(second.result(timeout=2), 0)

        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse((self.review.container_dir / "cleanup-error.txt").exists())

    def test_wait_clears_stale_cleanup_error_after_successful_retry(self) -> None:
        self.write_completed_state()
        cleanup_error_path = self.review.container_dir / "cleanup-error.txt"
        with mock.patch.object(
            state,
            "cleanup_workspace",
            return_value="cannot remove workspace",
        ):
            self.assertEqual(
                state.wait(self.review.container_dir, timeout_seconds=None),
                1,
            )

        self.assertTrue(cleanup_error_path.is_file())
        self.assertEqual(
            state.wait(self.review.container_dir, timeout_seconds=None),
            0,
        )
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(cleanup_error_path.exists())

    def test_cleanup_worker_clears_stale_error_after_success(self) -> None:
        self.write_completed_state()
        cleanup_error_path = self.review.container_dir / "cleanup-error.txt"
        cleanup_error_path.write_text("previous cleanup failed\n", encoding="utf-8")
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        with lock_path.open("a+b") as cleanup_lock:
            exit_code = cleanup_worker.main(
                [str(self.review.container_dir), str(cleanup_lock.fileno())]
            )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(cleanup_error_path.exists())

    def test_private_lock_creation_has_fixed_mode_with_permissive_umask(self) -> None:
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        previous_umask = os.umask(0)
        try:
            with state.open_private_lock_file(
                lock_path,
                label="test cleanup lock",
            ) as cleanup_lock:
                self.assertEqual(
                    stat.S_IMODE(os.fstat(cleanup_lock.fileno()).st_mode),
                    0o600,
                )
        finally:
            os.umask(previous_umask)

    def test_private_lock_existing_open_does_not_recreate_deleted_file(self) -> None:
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        original_open = os.open
        open_count = 0

        def delete_before_existing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal open_count
            open_count += 1
            if open_count == 2:
                lock_path.unlink()
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(
                state.os,
                "open",
                side_effect=delete_before_existing_open,
            ),
            self.assertRaisesRegex(ReviewError, "cannot open test cleanup lock safely"),
        ):
            state.open_private_lock_file(lock_path, label="test cleanup lock")

        self.assertEqual(open_count, 2)
        self.assertFalse(lock_path.exists())

    def test_private_lock_existing_open_rejects_replacement(self) -> None:
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"original")
        lock_path.chmod(0o644)
        original_metadata = lock_path.stat()
        original_identity = (original_metadata.st_dev, original_metadata.st_ino)
        replacement_path = self.review.container_dir / "replacement.lock"
        replacement_path.write_bytes(b"replacement")
        replacement_path.chmod(0o644)
        original_open = os.open
        open_count = 0

        def replace_before_existing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal open_count
            open_count += 1
            if open_count == 2:
                os.replace(replacement_path, lock_path)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(
                state.os,
                "open",
                side_effect=replace_before_existing_open,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "test cleanup lock changed before it could be opened safely",
            ),
        ):
            state.open_private_lock_file(
                lock_path,
                label="test cleanup lock",
                allow_legacy_read_mode=True,
            )

        replacement_metadata = lock_path.stat()
        self.assertEqual(open_count, 2)
        self.assertNotEqual(
            (replacement_metadata.st_dev, replacement_metadata.st_ino),
            original_identity,
        )
        self.assertEqual(lock_path.read_bytes(), b"replacement")
        self.assertEqual(stat.S_IMODE(replacement_metadata.st_mode), 0o644)

    def test_private_lock_accepts_exact_safe_legacy_modes(self) -> None:
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE

        for mode in sorted(state.SAFE_LEGACY_LOCK_MODES):
            with self.subTest(mode=oct(mode)):
                lock_path.write_bytes(b"")
                lock_path.chmod(mode)
                with state.open_private_lock_file(
                    lock_path,
                    label="test cleanup lock",
                    allow_legacy_read_mode=True,
                ):
                    pass
                self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), mode)

    def test_general_legacy_lock_open_rejects_cleanup_only_0664_mode(self) -> None:
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o664)

        with self.assertRaisesRegex(ReviewError, "unsafe legacy mode"):
            state.open_private_lock_file(
                lock_path,
                label="test cleanup lock",
                allow_legacy_read_mode=True,
            )

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o664)

    def test_cleanup_migrates_safe_legacy_lock_mode_after_flock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)

        self.assertEqual(
            state.cleanup(self.review.container_dir, timeout_seconds=1),
            0,
        )

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)
        self.assertFalse(self.review.workspace_root.exists())

    def test_cleanup_migrates_private_empty_legacy_0664_lock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        previous_umask = os.umask(0o002)
        try:
            with lock_path.open("a+b"):
                pass
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o664)

        self.assertEqual(
            state.cleanup(self.review.container_dir, timeout_seconds=1),
            0,
        )

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)
        self.assertFalse(self.review.workspace_root.exists())

    def test_cleanup_rejects_0664_lock_outside_exact_private_state_mode(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o664)
        self.review.container_dir.chmod(0o750)
        try:
            with self.assertRaisesRegex(ReviewError, "mode must be exactly 0700"):
                state.cleanup(self.review.container_dir, timeout_seconds=1)
        finally:
            self.review.container_dir.chmod(0o700)

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o664)
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_rejects_0664_lock_under_writable_review_root(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o664)
        review_root = self.review.container_dir.parent
        original_mode = stat.S_IMODE(review_root.stat().st_mode)
        review_root.chmod(0o770)
        try:
            with self.assertRaisesRegex(
                ReviewError,
                "review state root must not be group or other writable",
            ):
                state.cleanup(self.review.container_dir, timeout_seconds=1)
        finally:
            review_root.chmod(original_mode)

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o664)
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_revalidates_private_state_mode_after_flock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o664)

        def acquire_then_change_state_mode(handle, *, deadline):
            del deadline
            state.fcntl.flock(
                handle.fileno(),
                state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
            )
            self.review.container_dir.chmod(0o750)
            return True

        try:
            with (
                mock.patch.object(
                    state,
                    "_acquire_cleanup_lock",
                    side_effect=acquire_then_change_state_mode,
                ),
                self.assertRaisesRegex(ReviewError, "mode must be exactly 0700"),
            ):
                state.cleanup(self.review.container_dir, timeout_seconds=1)
        finally:
            self.review.container_dir.chmod(0o700)

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o664)
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_rejects_unsafe_legacy_lock_modes(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")

        for mode in (0o1644, 0o700, 0o611, 0o660):
            with self.subTest(mode=oct(mode)):
                lock_path.chmod(mode)
                with self.assertRaisesRegex(
                    ReviewError,
                    "unsafe legacy mode|group or other writable",
                ):
                    state.cleanup(self.review.container_dir, timeout_seconds=1)

        self.assertTrue(self.review.workspace_root.exists())

    def test_legacy_lock_mode_whitelist_rejects_special_bits(self) -> None:
        metadata = mock.Mock(st_mode=stat.S_IFREG | 0o4644)
        handle = mock.Mock()
        handle.fileno.return_value = 9

        with mock.patch.object(
            state,
            "_validate_regular_file_path_identity",
            return_value=metadata,
        ):
            with self.assertRaisesRegex(ReviewError, "unsafe legacy mode"):
                state.validate_safe_legacy_lock_file(
                    pathlib.Path("cleanup.lock"),
                    handle,
                    label="review cleanup lock",
                )

    def test_cleanup_revalidates_legacy_lock_mode_after_flock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)

        def mutate_mode_after_flock(*_args, **_kwargs) -> bool:
            lock_path.chmod(0o700)
            return True

        with mock.patch.object(
            state,
            "_acquire_cleanup_lock",
            side_effect=mutate_mode_after_flock,
        ):
            with self.assertRaisesRegex(ReviewError, "unsafe legacy mode"):
                state.cleanup(self.review.container_dir, timeout_seconds=1)

        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o700)
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_rejects_symlink_lock(self) -> None:
        self.write_completed_state()
        lock_target = self.review.container_dir / "cleanup-lock-target"
        lock_target.write_bytes(b"unchanged")
        lock_target.chmod(0o600)
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        lock_path.symlink_to(lock_target.name)

        with self.assertRaisesRegex(ReviewError, "cannot open review cleanup lock"):
            state.cleanup(self.review.container_dir, timeout_seconds=1)

        self.assertEqual(lock_target.read_bytes(), b"unchanged")
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_rejects_lock_path_replacement_after_flock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE

        def acquire_then_replace(handle, *, deadline):
            del deadline
            state.fcntl.flock(
                handle.fileno(),
                state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
            )
            lock_path.unlink()
            with state.open_private_lock_file(
                lock_path,
                label="replacement cleanup lock",
            ):
                pass
            return True

        with (
            mock.patch.object(
                state,
                "_acquire_cleanup_lock",
                side_effect=acquire_then_replace,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "path does not match its open file descriptor",
            ),
        ):
            state.cleanup(self.review.container_dir, timeout_seconds=1)

        self.assertTrue(self.review.workspace_root.exists())

    def test_wait_timeout_includes_shared_cleanup_lock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        with state.open_private_lock_file(
            lock_path,
            label="test cleanup lock",
        ) as cleanup_lock:
            state.fcntl.flock(cleanup_lock.fileno(), state.fcntl.LOCK_SH)
            started = time.monotonic()
            exit_code = state.wait(self.review.container_dir, timeout_seconds=0.05)
            elapsed = time.monotonic() - started

        self.assertEqual(exit_code, 124)
        self.assertLess(elapsed, 0.5)

    def test_wait_rejects_negative_and_non_finite_timeouts(self) -> None:
        for timeout in (-0.1, float("nan"), float("inf"), float("-inf")):
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(
                    ReviewError,
                    "non-negative finite number",
                ),
            ):
                state.wait(self.review.container_dir, timeout_seconds=timeout)

    def test_cleanup_rejects_negative_and_non_finite_timeouts(self) -> None:
        for timeout in (-0.1, float("nan"), float("inf"), float("-inf")):
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(
                    ReviewError,
                    "non-negative finite number",
                ),
            ):
                state.cleanup(self.review.container_dir, timeout_seconds=timeout)

    def test_wait_timeout_includes_workspace_cleanup(self) -> None:
        self.write_completed_state()
        worker = mock.Mock()
        worker.poll.return_value = None
        worker.wait.return_value = 0

        with mock.patch.object(state.subprocess, "Popen", return_value=worker):
            started = time.monotonic()
            exit_code = state.wait(self.review.container_dir, timeout_seconds=0.05)
            elapsed = time.monotonic() - started

        self.assertEqual(exit_code, 124)
        self.assertLess(elapsed, 0.5)
        worker.wait.assert_called_once_with()

    def test_wait_interruption_keeps_cleanup_worker_lock_owned(self) -> None:
        self.write_completed_state()
        worker = mock.Mock()
        worker.poll.side_effect = KeyboardInterrupt

        with (
            mock.patch.object(state.subprocess, "Popen", return_value=worker),
            mock.patch.object(state, "_acquire_cleanup_lock", return_value=True),
            mock.patch.object(state.fcntl, "flock") as flock,
            self.assertRaises(KeyboardInterrupt),
        ):
            state.wait(self.review.container_dir, timeout_seconds=1)

        flock.assert_not_called()

    def test_final_reports_bounded_cleanup_timeout(self) -> None:
        self.write_completed_state()
        with mock.patch.object(state, "wait", return_value=124):
            exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 3)
        self.assertIn("cleanup did not finish before timeout", text)

    def test_final_rereads_exit_code_after_wait(self) -> None:
        self.write_completed_state()

        def finish_with_signal(*_args, **_kwargs):
            (self.review.container_dir / state.EXIT_FILE).write_text(
                str(128 + signal.SIGINT) + "\n",
                encoding="utf-8",
            )
            return 128 + signal.SIGINT

        with mock.patch.object(state, "wait", side_effect=finish_with_signal):
            exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 128 + signal.SIGINT)
        self.assertNotEqual(text, "No findings.")

    def test_forged_workspace_escape_is_rejected_before_cleanup(self) -> None:
        self.write_completed_state()
        value = self.review.to_json()
        value["workspace_root"] = str(self.repo)
        current = state.load_state(self.review.container_dir)
        current["workspace"] = value
        write_json(self.review.container_dir / state.STATE_FILE, current)

        with self.assertRaises(ReviewError):
            state.load_review_state(self.review.container_dir)
        self.assertTrue(self.repo.exists())
        self.assertTrue(self.review.workspace_root.exists())

    def test_start_wait_final_runs_in_a_pollable_background_process(self) -> None:
        fake_runner = pathlib.Path(self.temporary.name) / "fake_runner.py"
        fake_runner.write_text(
            """from pathlib import Path
import sys
import time

state_dir = Path(sys.argv[sys.argv.index("--state-dir") + 1])
time.sleep(0.2)
(state_dir / "final.txt").write_text("No findings.\\n", encoding="utf-8")
(state_dir / "attempts.json").write_text("[]\\n", encoding="utf-8")
(state_dir / "exit-code").write_text("0\\n", encoding="utf-8")
""",
            encoding="utf-8",
        )
        state_dir = state.start(
            script_path=fake_runner,
            repo=self.repo,
            reviewer="codex",
            base_ref=self.base,
            head_ref=self.head,
            prompt_file=None,
            keep_workspace=False,
            egress_consent=None,
        )
        self.assertEqual(state.wait(state_dir, timeout_seconds=5), 0)
        exit_code, text = state.final(state_dir)
        self.assertEqual(exit_code, 0)
        self.assertEqual(text, "No findings.")
        self.assertFalse((state_dir / "workspace").exists())

    def test_runner_unblocks_signals_inherited_from_stateful_start(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        with (
            mock.patch.object(state, "unblock_forwarded_signals") as unblock,
            mock.patch.object(
                state,
                "run_review",
                return_value=mock.Mock(returncode=0),
            ),
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
            )

        self.assertEqual(exit_code, 0)
        unblock.assert_called_once_with()
        self.assertEqual((state_dir / state.EXIT_FILE).read_text().strip(), "0")

    def test_runner_records_forwarded_signal_detail_for_stateful_final(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "claude",
                "egress_consent": "double-review",
                "workspace": self.review.to_json(),
            },
        )
        carrier = state_dir / "claude-runtime" / "linux" / "claude-carrier-signal"
        detail = f"private recovery carrier retained at {carrier}"

        with mock.patch.object(
            state,
            "run_review",
            side_effect=state.ForwardedSignal(signal.SIGTERM, detail=detail),
        ):
            exit_code = state.run_state(state_dir=state_dir)

        self.assertEqual(exit_code, 128 + signal.SIGTERM)
        runner_error = (state_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"signal {int(signal.SIGTERM)}", runner_error)
        self.assertIn(str(carrier), runner_error)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )

    def test_runner_preserves_signal_exit_when_diagnostic_write_fails(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "claude",
                "egress_consent": "double-review",
                "workspace": self.review.to_json(),
            },
        )
        runner_error_path = state_dir / "runner-error.txt"
        original_write_text_atomic = state.write_text_atomic

        def fail_runner_error_write(path: pathlib.Path, text: str) -> None:
            if path == runner_error_path:
                raise RuntimeError("runner error diagnostic unavailable")
            original_write_text_atomic(path, text)

        with (
            mock.patch.object(
                state,
                "run_review",
                side_effect=state.ForwardedSignal(
                    signal.SIGTERM,
                    detail="recovery carrier retained",
                ),
            ),
            mock.patch.object(
                state,
                "write_text_atomic",
                side_effect=fail_runner_error_write,
            ),
        ):
            exit_code = state.run_state(state_dir=state_dir)

        self.assertEqual(exit_code, 128 + signal.SIGTERM)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )
        self.assertFalse(runner_error_path.exists())

    def test_runner_installs_signal_handler_before_unblocking_inherited_mask(
        self,
    ) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        installed: dict[signal.Signals, object] = {}

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def deliver_pending_signal():
            handler = installed[signal.SIGINT]
            assert callable(handler)
            handler(signal.SIGINT, None)

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "unblock_forwarded_signals",
                side_effect=deliver_pending_signal,
            ),
            mock.patch.object(state, "run_review") as run_review,
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
            )

        self.assertEqual(exit_code, 128 + signal.SIGINT)
        run_review.assert_not_called()
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGINT),
        )

    def test_start_cancellation_during_prepare_does_not_spawn_runner(self) -> None:
        installed: dict[signal.Signals, object] = {}

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def cancel_prepare(**_kwargs):
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=cancel_prepare,
            ),
            mock.patch.object(state.subprocess, "Popen") as popen,
        ):
            with self.assertRaises(state.ForwardedSignal):
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer="codex",
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=None,
                )

        popen.assert_not_called()

    def test_start_cleans_workspace_when_signal_follows_handoff(self) -> None:
        def handoff_then_signal(**kwargs):
            kwargs["ownership_handoff"](self.review)
            raise state.ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=handoff_then_signal,
            ),
            mock.patch.object(state.subprocess, "Popen") as popen,
            mock.patch.object(
                state,
                "cleanup_workspace",
                return_value=None,
            ) as cleanup,
            self.assertRaises(state.ForwardedSignal) as raised,
        ):
            state.start(
                script_path=pathlib.Path("runner.py"),
                repo=self.repo,
                reviewer="codex",
                base_ref=self.base,
                head_ref=self.head,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        popen.assert_not_called()
        cleanup.assert_called_once_with(self.review, keep_container=False)

    def test_start_preserves_prepare_cleanup_failure_detail(self) -> None:
        installed: dict[signal.Signals, object] = {}
        retained_detail = (
            "snapshot preparation failed and cleanup failed; evidence retained at "
            "/tmp/isolated-review-retained: permission denied"
        )

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def cancel_prepare(**_kwargs):
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            try:
                handler(signal.SIGTERM, None)
            except state.ForwardedSignal as error:
                raise state.ForwardedSignal(
                    error.signum,
                    detail=retained_detail,
                ) from error

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=cancel_prepare,
            ),
            mock.patch.object(state.subprocess, "Popen") as popen,
            self.assertRaises(state.ForwardedSignal) as raised,
        ):
            state.start(
                script_path=pathlib.Path("runner.py"),
                repo=self.repo,
                reviewer="codex",
                base_ref=self.base,
                head_ref=self.head,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(raised.exception.detail, retained_detail)
        popen.assert_not_called()

    def test_start_defers_spawn_signal_and_never_publishes_runner(self) -> None:
        installed: dict[signal.Signals, object] = {}
        process = mock.Mock(pid=12345)
        publisher = mock.Mock()

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def spawn(*_args, **_kwargs):
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)
            return process

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(state, "signal_process_group") as forward,
            mock.patch.object(state, "terminate_process_group") as terminate,
            mock.patch.object(state, "cleanup_workspace", return_value=None),
        ):
            with self.assertRaises(state.ForwardedSignal):
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer="codex",
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=None,
                    publisher=publisher,
                )

        publisher.assert_not_called()
        forward.assert_called_once_with(process, signal.SIGTERM)
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=True,
            grace_seconds=state.RUNNER_SHUTDOWN_GRACE_SECONDS,
        )

    def test_start_blocks_signals_until_child_inherits_the_mask(self) -> None:
        process = mock.Mock(pid=12345)
        events: list[str] = []

        def block_signals():
            events.append("block")
            return {signal.SIGTERM}

        def spawn(*_args, **_kwargs):
            events.append("spawn")
            return process

        def restore_mask(_mask):
            events.append("restore")

        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(
                state,
                "block_forwarded_signals",
                side_effect=block_signals,
            ),
            mock.patch.object(state, "restore_signal_mask", side_effect=restore_mask),
            mock.patch.object(
                state,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(state, "terminate_process_group"),
            mock.patch.object(state, "cleanup_workspace", return_value=None),
        ):
            state_dir = state.start(
                script_path=pathlib.Path("runner.py"),
                repo=self.repo,
                reviewer="codex",
                base_ref=self.base,
                head_ref=self.head,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )

        self.assertEqual(state_dir, self.review.container_dir)
        self.assertEqual(events[:3], ["block", "spawn", "restore"])
        self.assertEqual(events[3:], ["block", "restore"])
        state._STARTED_PROCESSES.pop(process.pid, None)

    def test_start_publisher_failure_cleans_unpublished_runner(self) -> None:
        process = mock.Mock(pid=12345)
        publisher = mock.Mock(side_effect=BrokenPipeError("closed output"))
        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", return_value=process),
            mock.patch.object(state, "terminate_process_group") as terminate,
            mock.patch.object(
                state, "cleanup_workspace", return_value=None
            ) as cleanup,
        ):
            with self.assertRaises(BrokenPipeError):
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer="codex",
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=None,
                    publisher=publisher,
                )

        publisher.assert_called_once_with(self.review.container_dir)
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
            grace_seconds=state.RUNNER_SHUTDOWN_GRACE_SECONDS,
        )
        cleanup.assert_called_once_with(self.review, keep_container=False)

    def test_start_cleanup_failure_reports_retained_container(self) -> None:
        process = mock.Mock(pid=12345)
        publisher = mock.Mock(side_effect=BrokenPipeError("closed output"))
        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", return_value=process),
            mock.patch.object(state, "terminate_process_group"),
            mock.patch.object(
                state,
                "cleanup_workspace",
                return_value="permission denied",
            ) as cleanup,
            self.assertRaisesRegex(
                ReviewError,
                r"evidence retained at .*isolated-review.*permission denied",
            ),
        ):
            state.start(
                script_path=pathlib.Path("runner.py"),
                repo=self.repo,
                reviewer="codex",
                base_ref=self.base,
                head_ref=self.head,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
                publisher=publisher,
            )

        cleanup.assert_called_once_with(self.review, keep_container=False)

    def test_start_failure_cleanup_defers_a_second_signal(self) -> None:
        installed: dict[signal.Signals, object] = {}
        process = mock.Mock(pid=12345)
        publisher = mock.Mock(side_effect=BrokenPipeError("closed output"))

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def signal_during_cleanup(*_args, **_kwargs):
            handler = installed[signal.SIGQUIT]
            assert callable(handler)
            handler(signal.SIGQUIT, None)

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", return_value=process),
            mock.patch.object(
                state,
                "terminate_process_group",
                side_effect=signal_during_cleanup,
            ) as terminate,
            mock.patch.object(
                state, "cleanup_workspace", return_value=None
            ) as cleanup,
        ):
            with self.assertRaises(state.ForwardedSignal) as raised:
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer="codex",
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=None,
                    publisher=publisher,
                )

        self.assertEqual(raised.exception.signum, signal.SIGQUIT)
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
            grace_seconds=state.RUNNER_SHUTDOWN_GRACE_SECONDS,
        )
        cleanup.assert_called_once_with(self.review, keep_container=False)

    def test_start_keeps_published_state_when_signal_arrives_during_publication(
        self,
    ) -> None:
        process = mock.Mock(pid=12345)
        publisher = mock.Mock()
        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepared_workspace(self.review),
            ),
            mock.patch.object(state.subprocess, "Popen", return_value=process),
            mock.patch.object(
                state,
                "block_forwarded_signals",
                return_value={signal.SIGTERM},
            ) as block,
            mock.patch.object(
                state,
                "consume_pending_forwarded_signal",
                return_value=signal.SIGINT,
            ) as consume,
            mock.patch.object(state, "restore_signal_mask") as restore,
            mock.patch.object(state, "signal_process_group") as forward,
            mock.patch.object(state, "terminate_process_group") as terminate,
            mock.patch.object(state, "cleanup_workspace") as cleanup,
        ):
            with self.assertRaises(state.ForwardedSignal) as raised:
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer="codex",
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=None,
                    publisher=publisher,
                )

        self.assertEqual(raised.exception.signum, signal.SIGINT)
        publisher.assert_called_once_with(self.review.container_dir)
        self.assertEqual(block.call_count, 3)
        self.assertEqual(consume.call_count, 2)
        self.assertEqual(
            restore.call_args_list,
            [
                mock.call({signal.SIGTERM}),
                mock.call({signal.SIGTERM}),
                mock.call({signal.SIGTERM}),
            ],
        )
        forward.assert_called_once_with(process, signal.SIGINT)
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGINT,
            signal_already_sent=True,
            grace_seconds=state.RUNNER_SHUTDOWN_GRACE_SECONDS,
        )
        cleanup.assert_not_called()

    def test_runner_records_signal_between_reviewer_attempts(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        installed: dict[signal.Signals, object] = {}

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def interrupt_review(**_kwargs):
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(state, "run_review", side_effect=interrupt_review),
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
            )

        self.assertEqual(exit_code, 128 + signal.SIGTERM)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )

    def test_runner_defers_signal_while_blocking_for_terminal_publish(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        installed: dict[signal.Signals, object] = {}

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def interrupt_mask_handoff():
            handler = installed[signal.SIGQUIT]
            assert callable(handler)
            handler(signal.SIGQUIT, None)
            return set()

        with (
            mock.patch.object(state.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                state,
                "run_review",
                return_value=mock.Mock(returncode=0),
            ),
            mock.patch.object(
                state,
                "block_forwarded_signals",
                side_effect=interrupt_mask_handoff,
            ),
            mock.patch.object(
                state,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(state, "restore_signal_mask"),
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
            )

        self.assertEqual(exit_code, 128 + signal.SIGQUIT)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGQUIT),
        )

    def test_terminal_runner_keeps_signals_blocked_through_process_exit(self) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_text(
            "isolated-review-state-v1\n",
            encoding="utf-8",
        )
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": 1,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        with (
            mock.patch.object(
                state,
                "run_review",
                return_value=mock.Mock(returncode=0),
            ),
            mock.patch.object(
                state,
                "block_forwarded_signals",
                return_value={signal.SIGTERM},
            ) as block,
            mock.patch.object(
                state,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(state, "restore_signal_mask") as restore,
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
                terminal_process=True,
            )

        self.assertEqual(exit_code, 0)
        block.assert_called_once_with()
        restore.assert_not_called()
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            "0",
        )

    def test_final_reports_cleanup_failure_instead_of_clean_result(self) -> None:
        self.write_completed_state()
        worker = mock.Mock()
        worker.poll.return_value = 1
        (self.review.container_dir / "cleanup-error.txt").write_text(
            "cannot remove worktree\n",
            encoding="utf-8",
        )
        with mock.patch.object(state.subprocess, "Popen", return_value=worker):
            exit_code, text = state.final(self.review.container_dir)
        self.assertEqual(exit_code, 1)
        self.assertIn("cleanup failed", text)

    def test_status_rejects_live_pid_without_runner_lock(self) -> None:
        self.write_completed_state()
        (self.review.container_dir / state.EXIT_FILE).unlink()
        (self.review.container_dir / "final.txt").unlink()
        value = state.load_state(self.review.container_dir)
        value["pid"] = os.getpid()
        write_json(self.review.container_dir / state.STATE_FILE, value)

        summary = state.status(self.review.container_dir)
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 1)
        self.assertIn("without recording", summary["runner_error"])

    def test_status_treats_exit_code_as_provisional_while_runner_lock_is_held(
        self,
    ) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.LOCK_FILE
        with lock_path.open("a+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            summary = state.status(self.review.container_dir)

        self.assertTrue(summary["running"])
        self.assertTrue(summary["runner_lock_held"])
        self.assertIsNone(summary["exit_code"])

    def test_status_reads_terminal_exit_after_observing_released_lock(self) -> None:
        self.write_completed_state()
        calls: list[str] = []

        def read_lock(_path):
            calls.append("lock")
            return False

        def read_exit(_state_dir):
            calls.append("exit")
            return 0

        with (
            mock.patch.object(state, "_runner_lock_held", side_effect=read_lock),
            mock.patch.object(state, "_read_exit_code", side_effect=read_exit),
        ):
            summary = state.status(self.review.container_dir)

        self.assertEqual(calls, ["lock", "exit"])
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 0)

    def test_runner_lock_probe_fails_closed_on_io_error(self) -> None:
        lock_path = self.review.container_dir / state.LOCK_FILE
        lock_path.write_bytes(b"")

        with (
            mock.patch.object(
                state.fcntl,
                "flock",
                side_effect=OSError("lock service unavailable"),
            ),
            self.assertRaisesRegex(ReviewError, "cannot probe review runner lock"),
        ):
            state._runner_lock_held(lock_path)

    def test_status_does_not_terminalize_runner_lock_probe_error(self) -> None:
        self.write_completed_state()
        (self.review.container_dir / state.EXIT_FILE).unlink()

        with (
            mock.patch.object(
                state,
                "_runner_lock_held",
                side_effect=ReviewError("lock probe failed"),
            ),
            self.assertRaisesRegex(ReviewError, "lock probe failed"),
        ):
            state.status(self.review.container_dir)

        self.assertFalse((self.review.container_dir / state.EXIT_FILE).exists())
        self.assertFalse((self.review.container_dir / "runner-error.txt").exists())

    def test_exit_code_read_fails_closed_on_io_error(self) -> None:
        with (
            mock.patch.object(
                pathlib.Path,
                "read_text",
                side_effect=PermissionError("permission denied"),
            ),
            self.assertRaisesRegex(ReviewError, "cannot read review exit code"),
        ):
            state._read_exit_code(self.review.container_dir)


if __name__ == "__main__":
    unittest.main()
