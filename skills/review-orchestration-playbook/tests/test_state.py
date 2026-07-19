from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cleanup_worker, providers, state  # noqa: E402
from review_runtime.common import ReviewError, write_json  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    PRIVATE_CHANGED_PATHS_NAME,
    REVIEW_CLEANUP_QUARANTINE_PREFIX,
    SYNTHETIC_PRIVATE_MANIFEST_NAME,
    CleanupIdentity,
    PrivateCleanupEvidence,
    cleanup_workspace,
    prepare_workspace as _prepare_workspace,
    remove_private_review_artifacts,
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
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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

    def legacy_workspace_json(self) -> dict[str, str]:
        workspace = self.review.to_json()
        workspace.pop("private_cleanup")
        return workspace

    def write_legacy_state(
        self,
        *,
        keep_workspace: bool = False,
        terminal: bool = True,
    ) -> None:
        state_dir = self.review.container_dir
        (state_dir / state.STATE_MARKER).write_bytes(state.LEGACY_STATE_MARKER)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.LEGACY_STATE_SCHEMA_VERSION,
                "reviewer": "claude",
                "egress_consent": "double-review",
                "workspace": self.legacy_workspace_json(),
                "keep_workspace": keep_workspace,
                "stdout_path": str(state_dir / "runner.stdout.log"),
                "stderr_path": str(state_dir / "runner.stderr.log"),
                "final_path": str(state_dir / "final.txt"),
                "attempts_path": str(state_dir / "attempts.json"),
                "started_at": time.time(),
                "pid": 99999999,
            },
        )
        if terminal:
            (state_dir / state.EXIT_FILE).write_text("0\n", encoding="utf-8")
            (state_dir / "final.txt").write_text(
                "Legacy result.\n",
                encoding="utf-8",
            )

    def test_state_marker_round_trips_private_cleanup_identity(self) -> None:
        state._write_state_marker(self.review)

        self.assertEqual(
            state._load_state_marker_cleanup(self.review.container_dir),
            self.review.private_cleanup,
        )

    def test_ready_marker_bound_write_survives_container_swap_back(self) -> None:
        container = self.review.container_dir
        moved_container = container.with_name(f"{container.name}-marker-bound")
        replacement = container.with_name(f"{container.name}-marker-replacement")
        guard = state.ReviewPreparationGuard()
        guard.accept_preparation_cleanup(container, self.review.private_cleanup)
        real_replace = os.replace
        swapped = False

        def swap_around_bound_replace(source, destination, *args, **kwargs):
            nonlocal swapped
            if destination != state.STATE_MARKER or kwargs.get("dst_dir_fd") is None:
                return real_replace(source, destination, *args, **kwargs)
            swapped = True
            container.rename(moved_container)
            container.mkdir(mode=0o700)
            (container / "sentinel").write_text("keep me\n", encoding="utf-8")
            result = real_replace(source, destination, *args, **kwargs)
            container.rename(replacement)
            moved_container.rename(container)
            return result

        try:
            with mock.patch.object(
                os, "replace", side_effect=swap_around_bound_replace
            ):
                guard.accept_workspace(self.review)

            self.assertTrue(swapped)
            self.assertIs(guard.review, self.review)
            self.assertEqual(state._load_state_marker(container).phase, "ready")
            self.assertFalse((replacement / state.STATE_MARKER).exists())
            self.assertEqual(
                (replacement / "sentinel").read_text(encoding="utf-8"),
                "keep me\n",
            )
        finally:
            guard.close()
            if replacement.is_dir():
                (replacement / "sentinel").unlink(missing_ok=True)
                replacement.rmdir()

    def test_ready_marker_rejects_container_left_replaced_after_bound_write(
        self,
    ) -> None:
        container = self.review.container_dir
        moved_container = container.with_name(f"{container.name}-marker-bound")
        guard = state.ReviewPreparationGuard()
        guard.accept_preparation_cleanup(container, self.review.private_cleanup)
        real_replace = os.replace
        swapped = False

        def leave_replacement_after_bound_replace(
            source,
            destination,
            *args,
            **kwargs,
        ):
            nonlocal swapped
            if destination != state.STATE_MARKER or kwargs.get("dst_dir_fd") is None:
                return real_replace(source, destination, *args, **kwargs)
            swapped = True
            container.rename(moved_container)
            container.mkdir(mode=0o700)
            (container / "sentinel").write_text("keep me\n", encoding="utf-8")
            return real_replace(source, destination, *args, **kwargs)

        try:
            with (
                mock.patch.object(
                    os,
                    "replace",
                    side_effect=leave_replacement_after_bound_replace,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "container changed after runtime artifact persistence",
                ),
            ):
                guard.accept_workspace(self.review)

            self.assertTrue(swapped)
            self.assertIsNone(guard.review)
            self.assertFalse((container / state.STATE_MARKER).exists())
            self.assertEqual(
                (container / "sentinel").read_text(encoding="utf-8"),
                "keep me\n",
            )
            self.assertEqual(
                json.loads(
                    (moved_container / state.STATE_MARKER).read_text(encoding="utf-8")
                )["phase"],
                "ready",
            )
        finally:
            guard.close()
            if container.is_dir():
                (container / "sentinel").unlink(missing_ok=True)
                container.rmdir()
            if moved_container.is_dir():
                moved_container.rename(container)

    def test_ready_marker_rejects_parent_left_replaced_after_bound_write(
        self,
    ) -> None:
        container = self.review.container_dir
        parent = container.parent
        moved_parent = parent.with_name(f"{parent.name}-marker-bound")
        moved_container = moved_parent / container.name
        guard = state.ReviewPreparationGuard()
        guard.accept_preparation_cleanup(container, self.review.private_cleanup)
        real_replace = os.replace
        swapped = False

        def leave_parent_replacement_after_bound_replace(
            source,
            destination,
            *args,
            **kwargs,
        ):
            nonlocal swapped
            if destination != state.STATE_MARKER or kwargs.get("dst_dir_fd") is None:
                return real_replace(source, destination, *args, **kwargs)
            swapped = True
            parent.rename(moved_parent)
            parent.mkdir(mode=0o700)
            container.mkdir(mode=0o700)
            (container / "sentinel").write_text("keep me\n", encoding="utf-8")
            return real_replace(source, destination, *args, **kwargs)

        try:
            with (
                mock.patch.object(
                    os,
                    "replace",
                    side_effect=leave_parent_replacement_after_bound_replace,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "parent changed after runtime artifact persistence",
                ),
            ):
                guard.accept_workspace(self.review)

            self.assertTrue(swapped)
            self.assertIsNone(guard.review)
            self.assertFalse((container / state.STATE_MARKER).exists())
            self.assertEqual(
                (container / "sentinel").read_text(encoding="utf-8"),
                "keep me\n",
            )
            self.assertEqual(
                json.loads(
                    (moved_container / state.STATE_MARKER).read_text(encoding="utf-8")
                )["phase"],
                "ready",
            )
        finally:
            guard.close()
            if container.is_dir():
                (container / "sentinel").unlink(missing_ok=True)
                container.rmdir()
            if parent.is_dir():
                parent.rmdir()
            if moved_parent.is_dir():
                moved_parent.rename(parent)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_state_marker_fifo_is_rejected_without_blocking(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        os.mkfifo(marker_path, mode=0o600)
        probe = (
            "import pathlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from review_runtime import state\n"
            "from review_runtime.common import ReviewError\n"
            "try:\n"
            "    state._load_state_marker(pathlib.Path(sys.argv[2]))\n"
            "except ReviewError as error:\n"
            "    print(error)\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(2)\n"
        )

        completed = subprocess.run(
            (sys.executable, "-c", probe, str(SCRIPTS), str(self.review.container_dir)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("must be a regular file", completed.stdout)

    def test_state_marker_open_uses_nofollow_and_nonblock(self) -> None:
        state._write_state_marker(self.review)
        real_open = os.open
        marker_flags = []

        def guarded_open(path, flags, *args, **kwargs):
            if path == state.STATE_MARKER:
                marker_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(state.os, "open", side_effect=guarded_open):
            state._load_state_marker(self.review.container_dir)

        self.assertEqual(len(marker_flags), 1)
        self.assertTrue(marker_flags[0] & os.O_NOFOLLOW)
        self.assertTrue(marker_flags[0] & os.O_NONBLOCK)

    def test_state_marker_rejects_symlink_owner_and_writable_mode(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        state._write_state_marker(self.review)
        marker_path.chmod(0o620)
        with self.assertRaisesRegex(ReviewError, "group or other writable"):
            state._load_state_marker(self.review.container_dir)

        marker_path.chmod(0o644)
        with (
            mock.patch.object(state.os, "geteuid", return_value=os.geteuid() + 1),
            self.assertRaisesRegex(ReviewError, "owned by the current user"),
        ):
            state._load_state_marker(self.review.container_dir)

        marker_path.unlink()
        target = self.review.container_dir / "marker-target"
        target.write_bytes(state.LEGACY_STATE_MARKER)
        marker_path.symlink_to(target.name)
        with self.assertRaisesRegex(ReviewError, "must be a regular file"):
            state._load_state_marker(self.review.container_dir)

    def test_legacy_state_marker_allows_read_only_shared_mode(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        marker_path.write_bytes(state.LEGACY_STATE_MARKER)
        marker_path.chmod(0o644)

        loaded = state._load_state_marker(self.review.container_dir)

        self.assertEqual(loaded.version, state.LEGACY_STATE_SCHEMA_VERSION)

    def test_state_marker_rejects_hardlink_and_oversized_file(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        state._write_state_marker(self.review)
        hardlink = self.review.container_dir / "marker-hardlink"
        os.link(marker_path, hardlink)

        with self.assertRaisesRegex(ReviewError, "exactly one hard link"):
            state._load_state_marker(self.review.container_dir)

        hardlink.unlink()
        marker_path.write_bytes(b"x" * (state.MAX_STATE_MARKER_BYTES + 1))
        with self.assertRaisesRegex(ReviewError, "exceeds the size limit"):
            state._load_state_marker(self.review.container_dir)

    def test_state_marker_rejects_content_change_while_reading(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        state._write_state_marker(self.review)
        real_read = os.read
        mutated = False

        def mutate_before_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            if not mutated:
                mutated = True
                marker_path.write_text("{}\n", encoding="utf-8")
            return real_read(descriptor, size)

        with (
            mock.patch.object(state.os, "read", side_effect=mutate_before_read),
            self.assertRaisesRegex(ReviewError, "changed while reading"),
        ):
            state._load_state_marker(self.review.container_dir)

    def test_v2_marker_and_state_remain_compatible(self) -> None:
        self.write_completed_state()
        write_json(
            self.review.container_dir / state.STATE_MARKER,
            {
                "container_dir": str(self.review.container_dir),
                "private_cleanup": self.review.private_cleanup.to_json(),
                "version": state.COMPATIBLE_STATE_MARKER_SCHEMA_VERSION,
            },
        )

        loaded, review = state.load_review_state(self.review.container_dir)

        self.assertEqual(loaded["version"], state.STATE_SCHEMA_VERSION)
        self.assertEqual(review, self.review)

    def test_preparing_marker_recovers_partial_container_without_state(self) -> None:
        retained_name = PRIVATE_CHANGED_PATHS_NAME
        removed_name = SYNTHETIC_PRIVATE_MANIFEST_NAME
        (self.review.container_dir / removed_name).unlink()
        partial = PrivateCleanupEvidence(
            container=self.review.private_cleanup.container,
            artifacts={
                retained_name: self.review.private_cleanup.artifacts[retained_name]
            },
        )
        state._write_preparing_state_marker(self.review.container_dir, partial)

        exit_code = state.cleanup(
            self.review.container_dir,
            timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.container_dir.exists())

    def test_ready_marker_recovers_complete_container_without_state(self) -> None:
        state._write_state_marker(self.review)

        exit_code = state.cleanup(
            self.review.container_dir,
            timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.container_dir.exists())

    def test_preparation_guard_ready_marker_recovers_without_state(self) -> None:
        guard = state.ReviewPreparationGuard()
        guard.accept_preparation_cleanup(
            self.review.container_dir,
            self.review.private_cleanup,
        )
        self.assertEqual(
            state._load_state_marker(self.review.container_dir).phase,
            "preparing",
        )
        guard.accept_workspace(self.review)
        self.assertEqual(
            state._load_state_marker(self.review.container_dir).phase,
            "ready",
        )
        self.assertEqual(
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
            3,
        )
        guard.close()

        self.assertFalse((self.review.container_dir / state.STATE_FILE).exists())
        self.assertEqual(
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
            0,
        )
        self.assertFalse(self.review.container_dir.exists())

    def test_preparation_guard_does_not_expose_workspace_before_ready_marker(
        self,
    ) -> None:
        guard = state.ReviewPreparationGuard()
        guard.accept_preparation_cleanup(
            self.review.container_dir,
            self.review.private_cleanup,
        )
        with (
            mock.patch.object(
                state,
                "_write_state_marker",
                side_effect=ReviewError("ready marker failed"),
            ),
            self.assertRaisesRegex(ReviewError, "ready marker failed"),
        ):
            guard.accept_workspace(self.review)

        self.assertIsNone(guard.review)
        self.assertEqual(
            state._load_state_marker(self.review.container_dir).phase,
            "preparing",
        )
        guard.close()

    def test_ready_marker_recovers_after_private_artifact_receipts(self) -> None:
        state._write_state_marker(self.review)
        cleanup_error = remove_private_review_artifacts(
            self.review.container_dir,
            expected=self.review.private_cleanup,
        )
        self.assertIsNone(cleanup_error)
        self.assertTrue(
            all(
                not (self.review.container_dir / name).exists()
                for name in (
                    PRIVATE_CHANGED_PATHS_NAME,
                    SYNTHETIC_PRIVATE_MANIFEST_NAME,
                )
            )
        )

        exit_code = state.cleanup(
            self.review.container_dir,
            timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.container_dir.exists())

    def test_v3_marker_layout_is_bound_to_canonical_source_root(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        victim = self.review.workspace_root / "layout-victim.txt"
        victim.write_text("retain\n", encoding="utf-8")
        payload = state._state_marker_payload(self.review)
        invalid_source_roots = (
            str(self.review.source_root.parent),
            str(self.review.source_root / "missing" / ".."),
            "relative-source-root",
        )

        for source_root in invalid_source_roots:
            with self.subTest(source_root=source_root):
                payload["source_root"] = source_root
                write_json(marker_path, payload)
                with self.assertRaises(ReviewError):
                    state.cleanup(
                        self.review.container_dir,
                        timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                    )
                self.assertEqual(victim.read_text(encoding="utf-8"), "retain\n")

    def test_preparing_marker_forged_container_identity_fails_closed(self) -> None:
        identity = self.review.private_cleanup.container
        forged = PrivateCleanupEvidence(
            container=CleanupIdentity(identity.device, identity.inode + 1),
            artifacts={},
        )
        write_json(
            self.review.container_dir / state.STATE_MARKER,
            state._preparing_state_marker_payload(
                self.review.container_dir,
                forged,
            ),
        )
        victim = self.review.workspace_root / "victim.txt"
        victim.write_text("retain\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "preparation-bound cleanup lock"):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertEqual(victim.read_text(encoding="utf-8"), "retain\n")

    def test_marker_phase_and_partial_evidence_are_strict(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        partial = PrivateCleanupEvidence(
            container=self.review.private_cleanup.container,
            artifacts={},
        )
        invalid_payloads = (
            {
                "container_dir": str(self.review.container_dir),
                "phase": "ready",
                "private_cleanup": partial.to_json(),
                "source_root": str(self.review.source_root),
                "version": state.STATE_MARKER_SCHEMA_VERSION,
            },
            {
                "container_dir": str(self.review.container_dir),
                "phase": False,
                "private_cleanup": partial.to_json(),
                "source_root": str(self.review.source_root),
                "version": state.STATE_MARKER_SCHEMA_VERSION,
            },
            {
                "container_dir": str(self.review.container_dir),
                "phase": "preparing",
                "private_cleanup": {
                    **partial.to_json(),
                    "schema_version": True,
                },
                "source_root": str(self.review.source_root),
                "version": state.STATE_MARKER_SCHEMA_VERSION,
            },
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                write_json(marker_path, payload)
                with self.assertRaises(ReviewError):
                    state._load_state_marker(self.review.container_dir)

    def test_terminal_v1_status_final_and_cleanup(self) -> None:
        self.write_legacy_state()
        private_artifacts = tuple(
            self.review.container_dir / name
            for name in (PRIVATE_CHANGED_PATHS_NAME, SYNTHETIC_PRIVATE_MANIFEST_NAME)
        )

        summary = state.status(self.review.container_dir)
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 0)

        exit_code, text = state.final(self.review.container_dir)
        self.assertEqual((exit_code, text), (0, "Legacy result."))
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))
        self.assertEqual(
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
            0,
        )

    def test_active_v1_status_uses_runner_lock(self) -> None:
        self.write_legacy_state(terminal=False)
        lock_path = self.review.container_dir / state.LOCK_FILE

        with lock_path.open("a+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            summary = state.status(self.review.container_dir)

        self.assertTrue(summary["running"])
        self.assertTrue(summary["runner_lock_held"])
        self.assertIsNone(summary["exit_code"])

    def test_v1_keep_scrubs_private_artifacts_and_retains_workspace(self) -> None:
        self.write_legacy_state(keep_workspace=True)

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual((exit_code, text), (0, "Legacy result."))
        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(
            any(
                (self.review.container_dir / name).exists()
                for name in (
                    PRIVATE_CHANGED_PATHS_NAME,
                    SYNTHETIC_PRIVATE_MANIFEST_NAME,
                )
            )
        )

    def test_v1_codex_unavailable_retains_validated_fallback_workspace(self) -> None:
        self.write_legacy_state()
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
            "codex is unavailable\n",
            encoding="utf-8",
        )
        write_json(
            self.review.container_dir / "preflight.json",
            {
                "review_range": f"{self.base}..{self.head}",
                "scope": "frozen tracked workspace, diff, and review prompt",
                "status": "sensitive-content and escaping-symlink checks passed",
            },
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertIn("retained for clean-context fallback", text)
        self.assertTrue(self.review.workspace_root.exists())
        self.assertTrue(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

        preflight_path = self.review.container_dir / "preflight.json"
        preflight = state.read_json(preflight_path)
        preflight["status"] = "secret-delta and escaping-symlink checks passed"
        write_json(preflight_path, preflight)
        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

    def test_v1_marker_is_exact_and_versions_cannot_be_mixed(self) -> None:
        self.write_legacy_state()
        marker_path = self.review.container_dir / state.STATE_MARKER
        state_path = self.review.container_dir / state.STATE_FILE
        state.load_review_state(self.review.container_dir)

        for invalid_marker in (
            b"isolated-review-state-v1",
            b"isolated-review-state-v1\n\n",
        ):
            with self.subTest(invalid_marker=invalid_marker):
                marker_path.write_bytes(invalid_marker)
                with self.assertRaises(ReviewError):
                    state.load_review_state(self.review.container_dir)

        marker_path.write_bytes(state.LEGACY_STATE_MARKER)
        current = state.load_state(self.review.container_dir)
        current["version"] = state.STATE_SCHEMA_VERSION
        write_json(state_path, current)
        with self.assertRaisesRegex(ReviewError, "versions are inconsistent"):
            state.load_review_state(self.review.container_dir)

        current["version"] = True
        write_json(state_path, current)
        with self.assertRaisesRegex(ReviewError, "version is invalid"):
            state.load_review_state(self.review.container_dir)

    def test_v1_top_level_schema_and_artifact_paths_are_strict(self) -> None:
        self.write_legacy_state()
        state_path = self.review.container_dir / state.STATE_FILE
        original = state.load_state(self.review.container_dir)
        mutations = (
            ("extra", "unexpected"),
            ("keep_workspace", 1),
            ("started_at", float("nan")),
            ("stdout_path", str(self.repo / "outside.log")),
            ("synthetic_secret_exemptions", [1]),
            ("pid", True),
            ("reviewer", None),
            ("egress_consent", 1),
        )

        for field, value in mutations:
            with self.subTest(field=field):
                current = dict(original)
                current[field] = value
                write_json(state_path, current)
                with self.assertRaisesRegex(ReviewError, "legacy v1 review state"):
                    state.load_review_state(self.review.container_dir)

        compatible = dict(original)
        compatible["synthetic_secret_exemptions"] = ["known-fixture"]
        write_json(state_path, compatible)
        loaded, _review = state.load_review_state(self.review.container_dir)
        self.assertEqual(
            loaded["synthetic_secret_exemptions"],
            ["known-fixture"],
        )

    def test_invalid_v1_layout_is_retained_for_manual_recovery(self) -> None:
        self.write_legacy_state()
        current = state.load_state(self.review.container_dir)
        current["workspace"]["workspace_root"] = str(self.repo)
        write_json(self.review.container_dir / state.STATE_FILE, current)
        private_artifacts = tuple(
            self.review.container_dir / name
            for name in (PRIVATE_CHANGED_PATHS_NAME, SYNTHETIC_PRIVATE_MANIFEST_NAME)
        )

        with self.assertRaisesRegex(ReviewError, "manual recovery"):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertTrue(self.review.workspace_root.exists())
        self.assertTrue(all(path.exists() for path in private_artifacts))

    def test_run_state_refuses_v1_before_reviewer_launch(self) -> None:
        self.write_legacy_state(terminal=False)

        with mock.patch.object(state, "run_review") as launch:
            exit_code = state.run_state(state_dir=self.review.container_dir)

        self.assertEqual(exit_code, 1)
        launch.assert_not_called()
        self.assertEqual(
            (self.review.container_dir / state.EXIT_FILE).read_text().strip(),
            "1",
        )
        self.assertIn(
            "legacy v1 review state cannot be resumed",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_marker_control_identity_mismatch_fails_closed(self) -> None:
        self.write_completed_state()
        forged_cleanup = self.review.private_cleanup.to_json()
        forged_cleanup["container"]["inode"] += 1

        marker = state._state_marker_payload(self.review)
        marker["private_cleanup"] = forged_cleanup
        write_json(self.review.container_dir / state.STATE_MARKER, marker)

        current = state.load_state(self.review.container_dir)
        forged_workspace = self.review.to_json()
        forged_workspace["private_cleanup"] = forged_cleanup
        current["workspace"] = forged_workspace
        write_json(self.review.container_dir / state.STATE_FILE, current)

        with self.assertRaisesRegex(
            ReviewError,
            "private artifact container does not match preparation identity",
        ):
            state.load_review_state(self.review.container_dir)

    def test_final_returns_artifact_and_cleans_detached_workspace(self) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        self.assertTrue(all(path.exists() for path in private_artifacts))
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
        self.assertFalse(any(path.exists() for path in private_artifacts))

    def test_final_keep_workspace_scrubs_private_artifacts(self) -> None:
        self.write_completed_state()
        current = state.load_state(self.review.container_dir)
        current["keep_workspace"] = True
        write_json(self.review.container_dir / state.STATE_FILE, current)
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 0)
        self.assertEqual(text, "No findings.")
        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))
        self.assertEqual(
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
            0,
        )
        self.assertFalse(self.review.workspace_root.exists())

    def test_codex_unavailable_retains_preflight_workspace_until_cleanup(self) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
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
        write_json(
            self.review.container_dir / "preflight.json",
            {
                "private_artifacts": "removed",
                "review_range": f"{self.base}..{self.head}",
                "status": "secret-delta and escaping-symlink checks passed",
            },
        )
        self.assertIsNone(
            state.remove_private_review_artifacts(
                self.review.container_dir,
                expected=self.review.private_cleanup,
            )
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertIn("retained for clean-context fallback", text)
        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))
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
        self.assertFalse(any(path.exists() for path in private_artifacts))
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

    def test_codex_unavailable_without_private_cleanup_proof_does_not_retain_workspace(
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
        write_json(
            self.review.container_dir / "preflight.json",
            {
                "review_range": f"{self.base}..{self.head}",
                "status": "secret-delta and escaping-symlink checks passed",
            },
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertNotIn("retained for clean-context fallback", text)
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(
            state.status(self.review.container_dir)["fallback_workspace_retained"]
        )

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
            first = executor.submit(
                state.wait, self.review.container_dir, timeout_seconds=2
            )
            second = executor.submit(
                state.wait, self.review.container_dir, timeout_seconds=2
            )
            self.assertEqual(first.result(timeout=2), 0)
            self.assertEqual(second.result(timeout=2), 0)

        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse((self.review.container_dir / "cleanup-error.txt").exists())

    def test_wait_clears_stale_cleanup_error_after_successful_retry(self) -> None:
        self.write_completed_state()
        cleanup_error_path = self.review.container_dir / "cleanup-error.txt"
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )

        def fail_after_workspace_removal(review, *, keep_container: bool) -> str:
            self.assertTrue(keep_container)
            shutil.rmtree(review.workspace_root)
            return "cannot remove private artifacts"

        with mock.patch.object(
            state,
            "cleanup_workspace",
            side_effect=fail_after_workspace_removal,
        ):
            self.assertEqual(
                state.wait(self.review.container_dir, timeout_seconds=None),
                1,
            )

        self.assertTrue(cleanup_error_path.is_file())
        self.assertFalse(self.review.workspace_root.exists())
        self.assertTrue(all(path.exists() for path in private_artifacts))
        with mock.patch.object(
            state,
            "cleanup_workspace",
            return_value="cannot remove private artifacts",
        ) as retry_cleanup:
            self.assertEqual(
                state.wait(self.review.container_dir, timeout_seconds=None),
                1,
            )
        retry_cleanup.assert_called_once_with(self.review, keep_container=True)
        self.assertTrue(cleanup_error_path.is_file())
        self.assertTrue(all(path.exists() for path in private_artifacts))
        self.assertEqual(
            state.wait(self.review.container_dir, timeout_seconds=None),
            0,
        )
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))
        self.assertFalse(cleanup_error_path.exists())

    def test_wait_preserves_cleanup_error_for_workspace_quarantine(self) -> None:
        self.write_completed_state()
        cleanup_error_path = self.review.container_dir / "cleanup-error.txt"

        with mock.patch(
            "review_runtime.workspace._remove_open_directory_contents",
            return_value=["permission denied"],
        ):
            self.assertEqual(
                state.wait(self.review.container_dir, timeout_seconds=None),
                1,
            )

        quarantines = list(
            self.review.container_dir.glob(f"{REVIEW_CLEANUP_QUARANTINE_PREFIX}*")
        )
        self.assertEqual(len(quarantines), 1)
        self.assertTrue(cleanup_error_path.is_file())
        self.assertFalse(self.review.workspace_root.exists())

        self.assertEqual(
            state.wait(self.review.container_dir, timeout_seconds=None),
            1,
        )
        self.assertTrue(cleanup_error_path.is_file())
        self.assertIn(
            "pre-existing review cleanup quarantine requires manual recovery",
            cleanup_error_path.read_text(encoding="utf-8"),
        )
        self.assertTrue(quarantines[0].exists())

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

    def test_wait_timeout_includes_cleanup_lock(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        with lock_path.open("a+b") as cleanup_lock:
            state.fcntl.flock(cleanup_lock.fileno(), state.fcntl.LOCK_EX)
            started = time.monotonic()
            with mock.patch.object(state, "_cleanup_before_deadline") as cleanup:
                exit_code = state.wait(
                    self.review.container_dir,
                    timeout_seconds=0.05,
                )
            elapsed = time.monotonic() - started

        self.assertEqual(exit_code, 124)
        self.assertLess(elapsed, 0.5)
        cleanup.assert_not_called()

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
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        value = self.review.to_json()
        value["workspace_root"] = str(self.repo)
        current = state.load_state(self.review.container_dir)
        current["workspace"] = value
        write_json(self.review.container_dir / state.STATE_FILE, current)

        with self.assertRaises(ReviewError):
            state.load_review_state(self.review.container_dir)
        with self.assertRaises(ReviewError):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )
        self.assertTrue(self.repo.exists())
        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))

    def test_explicit_cleanup_scrubs_private_artifacts_after_corrupt_state(
        self,
    ) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        (self.review.container_dir / state.STATE_FILE).write_text(
            "{\n",
            encoding="utf-8",
        )

        with self.assertRaises(ReviewError):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))

    def test_explicit_cleanup_scrubs_noncanonical_resolving_state(self) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        current = state.load_state(self.review.container_dir)
        workspace = self.review.to_json()
        container = (
            self.review.container_dir.parent
            / "nonexistent"
            / ".."
            / self.review.container_dir.name
        )
        workspace_root = container / "workspace"
        control = workspace_root / ".codex-review"
        workspace.update(
            {
                "container_dir": str(container),
                "workspace_root": str(workspace_root),
                "diff_file": str(control / "review.diff"),
                "prompt_file": str(control / "review.prompt"),
            }
        )
        current["workspace"] = workspace
        write_json(self.review.container_dir / state.STATE_FILE, current)

        with self.assertRaisesRegex(ReviewError, "not canonical"):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))

    def test_explicit_cleanup_scrubs_private_artifacts_after_symlink_loop_state(
        self,
    ) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        first_loop = self.repo / "cleanup-loop-first"
        second_loop = self.repo / "cleanup-loop-second"
        first_loop.symlink_to(second_loop.name)
        second_loop.symlink_to(first_loop.name)
        current = state.load_state(self.review.container_dir)
        workspace = self.review.to_json()
        workspace["workspace_root"] = str(first_loop)
        current["workspace"] = workspace
        write_json(self.review.container_dir / state.STATE_FILE, current)
        real_resolve = pathlib.Path.resolve

        def fail_loop_resolution(path, *args, **kwargs):
            if path == first_loop:
                raise RuntimeError("symlink loop")
            return real_resolve(path, *args, **kwargs)

        try:
            with (
                mock.patch.object(
                    pathlib.Path,
                    "resolve",
                    autospec=True,
                    side_effect=fail_loop_resolution,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "review workspace path cannot be resolved",
                ),
            ):
                state.cleanup(
                    self.review.container_dir,
                    timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                )

            self.assertTrue(first_loop.is_symlink())
            self.assertTrue(second_loop.is_symlink())
            self.assertTrue(self.review.workspace_root.exists())
            self.assertFalse(any(path.exists() for path in private_artifacts))
        finally:
            first_loop.unlink(missing_ok=True)
            second_loop.unlink(missing_ok=True)

    def test_explicit_cleanup_scrubs_private_artifacts_after_invalid_state_path(
        self,
    ) -> None:
        self.write_completed_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        current = state.load_state(self.review.container_dir)
        workspace = self.review.to_json()
        workspace["workspace_root"] = str(self.repo / "invalid-path") + "\0suffix"
        current["workspace"] = workspace
        write_json(self.review.container_dir / state.STATE_FILE, current)

        with self.assertRaisesRegex(
            ReviewError,
            "review workspace path cannot be resolved",
        ):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertTrue(self.review.workspace_root.exists())
        self.assertFalse(any(path.exists() for path in private_artifacts))

    def test_invalid_state_cleanup_aggregates_private_scrub_failure(self) -> None:
        self.write_completed_state()
        (self.review.container_dir / state.STATE_FILE).write_text(
            "{\n",
            encoding="utf-8",
        )

        with (
            mock.patch.object(
                state,
                "remove_private_review_artifacts",
                return_value="unlink denied",
            ) as remove_private,
            self.assertRaisesRegex(
                ReviewError,
                "private artifact cleanup failed: unlink denied",
            ),
        ):
            state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        remove_private.assert_called_once_with(
            self.review.container_dir,
            expected=self.review.private_cleanup,
        )

    def test_explicit_cleanup_does_not_scrub_while_runner_lock_is_held(self) -> None:
        self.write_completed_state()

        with (
            mock.patch.object(state, "_runner_lock_held", return_value=True),
            mock.patch.object(
                state,
                "remove_private_review_artifacts",
            ) as remove_private,
        ):
            exit_code = state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            )

        self.assertEqual(exit_code, 3)
        remove_private.assert_not_called()

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
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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

    def test_runner_does_not_publish_exit_to_replaced_container(self) -> None:
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-moved")
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        stderr = io.StringIO()

        def replace_container(**_kwargs):
            state_dir.rename(moved_state_dir)
            state_dir.mkdir(mode=0o700)
            (state_dir / "sentinel").write_text("keep me\n", encoding="utf-8")
            return mock.Mock(returncode=2)

        try:
            with (
                mock.patch.object(state, "run_review", side_effect=replace_container),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = state.run_state(state_dir=state_dir)

            self.assertEqual(exit_code, 2)
            self.assertEqual(
                (state_dir / "sentinel").read_text(encoding="utf-8"),
                "keep me\n",
            )
            self.assertFalse((state_dir / state.EXIT_FILE).exists())
            self.assertFalse((state_dir / "runner-error.txt").exists())
            self.assertFalse((moved_state_dir / state.EXIT_FILE).exists())
            self.assertFalse((moved_state_dir / "runner-error.txt").exists())
            self.assertIn("exit code was not persisted", stderr.getvalue())
        finally:
            if state_dir.is_dir():
                (state_dir / "sentinel").unlink(missing_ok=True)
                state_dir.rmdir()
            if moved_state_dir.is_dir():
                moved_state_dir.rename(state_dir)

    def test_runner_rejects_tampered_state_range_before_provider_launch(
        self,
    ) -> None:
        for field, forged_ref in (
            ("base_ref", "c" * 40),
            ("head_ref", "d" * 40),
        ):
            with self.subTest(field=field):
                review = prepare_workspace(
                    repo=self.repo,
                    base_ref=self.base,
                    head_ref=self.head,
                )
                state_dir = review.container_dir
                try:
                    state._write_state_marker(review)
                    forged_workspace = review.to_json()
                    forged_workspace[field] = forged_ref
                    write_json(
                        state_dir / state.STATE_FILE,
                        {
                            "version": state.STATE_SCHEMA_VERSION,
                            "reviewer": "codex",
                            "workspace": forged_workspace,
                        },
                    )
                    with (
                        mock.patch.object(providers, "_run_model_chain") as launch,
                        mock.patch.object(
                            providers,
                            "resolve_reviewer_executable",
                        ) as resolve,
                    ):
                        exit_code = state.run_state(state_dir=state_dir)

                    self.assertEqual(exit_code, 2)
                    launch.assert_not_called()
                    resolve.assert_not_called()
                    self.assertFalse((state_dir / "preflight.json").exists())
                    error = (state_dir / "runner-error.txt").read_text(encoding="utf-8")
                    self.assertIn(
                        "synthetic secret manifest version or review range is invalid",
                        error,
                    )
                finally:
                    if review.workspace_root.exists():
                        cleanup_workspace(review, keep_container=False)

    def test_runner_records_forwarded_signal_detail_for_stateful_final(self) -> None:
        state_dir = self.review.container_dir
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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
        runner_error = (state_dir / "runner-error.txt").read_text(encoding="utf-8")
        self.assertIn(f"signal {int(signal.SIGTERM)}", runner_error)
        self.assertIn(str(carrier), runner_error)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )

    def test_runner_preserves_signal_exit_when_diagnostic_write_fails(self) -> None:
        state_dir = self.review.container_dir
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "claude",
                "egress_consent": "double-review",
                "workspace": self.review.to_json(),
            },
        )
        runner_error_path = state_dir / "runner-error.txt"
        original_write_bound_review_text = state.write_bound_review_text

        def fail_runner_error_write(
            container: pathlib.Path,
            *,
            expected: PrivateCleanupEvidence,
            name: str,
            text: str,
        ) -> str | None:
            if name == "runner-error.txt":
                return "runner error diagnostic unavailable"
            return original_write_bound_review_text(
                container,
                expected=expected,
                name=name,
                text=text,
            )

        stderr = io.StringIO()
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
                "write_bound_review_text",
                side_effect=fail_runner_error_write,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = state.run_state(state_dir=state_dir)

        self.assertEqual(exit_code, 128 + signal.SIGTERM)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )
        self.assertFalse(runner_error_path.exists())
        self.assertIn("runner diagnostic was not persisted", stderr.getvalue())

    def test_cleanup_worker_identity_failure_does_not_write_replacement(self) -> None:
        self.write_completed_state()
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-moved")
        state_dir.rename(moved_state_dir)
        state_dir.mkdir(mode=0o700)
        sentinel = state_dir / "sentinel"
        sentinel.write_text("keep me\n", encoding="utf-8")
        shutil.copy2(
            moved_state_dir / state.STATE_MARKER, state_dir / state.STATE_MARKER
        )
        shutil.copy2(moved_state_dir / state.STATE_FILE, state_dir / state.STATE_FILE)
        stderr = io.StringIO()
        lock_path = moved_state_dir / "handoff.lock"
        try:
            with (
                lock_path.open("a+b") as cleanup_lock,
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = cleanup_worker.main(
                    [str(state_dir), str(cleanup_lock.fileno())]
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep me\n")
            self.assertFalse((state_dir / "cleanup-error.txt").exists())
            self.assertFalse((moved_state_dir / "cleanup-error.txt").exists())
            self.assertIn("cleanup worker failed", stderr.getvalue())
            self.assertIn(
                "container does not match preparation identity", stderr.getvalue()
            )
        finally:
            sentinel.unlink(missing_ok=True)
            (state_dir / state.STATE_MARKER).unlink(missing_ok=True)
            (state_dir / state.STATE_FILE).unlink(missing_ok=True)
            state_dir.rmdir()
            moved_state_dir.rename(state_dir)

    def test_cleanup_identity_failure_does_not_create_replacement_lock(self) -> None:
        self.write_completed_state()
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-moved")
        state_dir.rename(moved_state_dir)
        state_dir.mkdir(mode=0o700)
        shutil.copy2(
            moved_state_dir / state.STATE_MARKER, state_dir / state.STATE_MARKER
        )
        shutil.copy2(moved_state_dir / state.STATE_FILE, state_dir / state.STATE_FILE)
        try:
            with self.assertRaisesRegex(
                ReviewError,
                "preparation-bound cleanup lock",
            ):
                state.cleanup(
                    state_dir,
                    timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                )

            self.assertFalse((state_dir / state.CLEANUP_LOCK_FILE).exists())
            self.assertFalse((state_dir / "cleanup-error.txt").exists())
            self.assertFalse((moved_state_dir / state.CLEANUP_LOCK_FILE).exists())
            self.assertFalse((moved_state_dir / "cleanup-error.txt").exists())
        finally:
            (state_dir / state.STATE_MARKER).unlink(missing_ok=True)
            (state_dir / state.STATE_FILE).unlink(missing_ok=True)
            state_dir.rmdir()
            moved_state_dir.rename(state_dir)

    def test_runner_installs_signal_handler_before_unblocking_inherited_mask(
        self,
    ) -> None:
        state_dir = self.review.container_dir
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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

    def test_start_holds_preparation_lock_through_child_fd_handoff(self) -> None:
        process = mock.Mock(pid=12345)
        lock_identity: tuple[int, int] | None = None

        def prepare_with_live_cleanup_probe(**kwargs):
            nonlocal lock_identity
            self.assertFalse((self.review.container_dir / state.LOCK_FILE).exists())
            self.assertFalse((self.review.container_dir / state.STATE_MARKER).exists())
            kwargs["preparation_cleanup_handoff"](
                self.review.container_dir,
                self.review.private_cleanup,
            )
            lock_metadata = os.lstat(self.review.container_dir / state.LOCK_FILE)
            lock_identity = (lock_metadata.st_dev, lock_metadata.st_ino)
            self.assertEqual(
                state.cleanup(
                    self.review.container_dir,
                    timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                ),
                3,
            )
            kwargs["ownership_handoff"](self.review)
            return self.review

        def spawn_with_inherited_lock(*_args, **kwargs):
            self.assertIsNotNone(lock_identity)
            self.assertEqual(len(kwargs["pass_fds"]), 1)
            inherited = os.fstat(kwargs["pass_fds"][0])
            self.assertEqual(
                (inherited.st_dev, inherited.st_ino),
                lock_identity,
            )
            self.assertTrue(
                state._runner_lock_held(self.review.container_dir / state.LOCK_FILE)
            )
            return process

        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                side_effect=prepare_with_live_cleanup_probe,
            ),
            mock.patch.object(
                state.subprocess,
                "Popen",
                side_effect=spawn_with_inherited_lock,
            ),
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
        state._STARTED_PROCESSES.pop(process.pid, None)

    def test_sigkill_releases_preparation_lock_for_recovery(self) -> None:
        state._write_preparing_state_marker(
            self.review.container_dir,
            self.review.private_cleanup,
        )
        lock_script = pathlib.Path(self.temporary.name) / "hold_runner_lock.py"
        lock_script.write_text(
            """import fcntl
import pathlib
import sys
import time

with pathlib.Path(sys.argv[1]).open("a+b") as handle:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    print("locked", flush=True)
    time.sleep(60)
""",
            encoding="utf-8",
        )
        holder = subprocess.Popen(
            (
                sys.executable,
                str(lock_script),
                str(self.review.container_dir / state.LOCK_FILE),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout is not None
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            self.assertEqual(
                state.cleanup(
                    self.review.container_dir,
                    timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                ),
                3,
            )
            holder.kill()
            holder.wait(timeout=5)

            self.assertEqual(
                state.cleanup(
                    self.review.container_dir,
                    timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
                ),
                0,
            )
            self.assertFalse(self.review.container_dir.exists())
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)
            if holder.stdout is not None:
                holder.stdout.close()
            if holder.stderr is not None:
                holder.stderr.close()

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
            mock.patch.object(state, "cleanup_workspace", return_value=None) as cleanup,
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
                r"evidence may remain near .*isolated-review.*permission denied",
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
            mock.patch.object(state, "cleanup_workspace", return_value=None) as cleanup,
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
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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
        state._write_state_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
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
