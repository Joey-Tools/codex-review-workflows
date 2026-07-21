from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cleanup_worker, cli, providers, state  # noqa: E402
from review_runtime.common import (  # noqa: E402
    ReviewError,
    read_json,
    write_json,
    write_text_atomic,
)
from review_runtime.workspace import (  # noqa: E402
    MAX_SYNTHETIC_EVIDENCE_ENTRIES,
    PRIVATE_CHANGED_PATHS_NAME,
    REVIEW_CLEANUP_QUARANTINE_PREFIX,
    SYNTHETIC_PRIVATE_MANIFEST_NAME,
    CleanupIdentity,
    PrivateCleanupEvidence,
    _load_control_artifact_state,
    cleanup_workspace,
    encode_preflight_json,
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


def runner_lock_identity(review) -> CleanupIdentity:
    lock_path = review.container_dir / state.LOCK_FILE
    with state.open_private_lock_file(
        lock_path,
        label="test review runner lock",
    ) as handle:
        metadata = os.fstat(handle.fileno())
        return CleanupIdentity(metadata.st_dev, metadata.st_ino)


def write_ready_marker(review) -> None:
    state._write_state_marker(review, runner_lock_identity(review))


def write_preparing_marker(
    review,
    private_cleanup: PrivateCleanupEvidence,
) -> None:
    state._write_preparing_state_marker(
        review.container_dir,
        private_cleanup,
        runner_lock_identity(review),
    )


def write_marker_with_raw_top_level_value(
    path: pathlib.Path,
    marker: dict[str, object],
    *,
    field: str,
    raw_value: str,
    raw_field_name: str | None = None,
) -> None:
    entries = []
    for key, value in marker.items():
        encoded_key = (
            raw_field_name
            if key == field and raw_field_name is not None
            else json.dumps(key)
        )
        encoded_value = raw_value if key == field else json.dumps(value, sort_keys=True)
        entries.append(f"{encoded_key}: {encoded_value}")
    write_text_atomic(path, "{" + ", ".join(entries) + "}\n")


@contextlib.contextmanager
def held_runner_lock(review):
    lock_path = review.container_dir / state.LOCK_FILE
    with state.open_private_lock_file(
        lock_path,
        label="test review runner lock",
    ) as handle:
        state.fcntl.flock(handle.fileno(), state.fcntl.LOCK_EX | state.fcntl.LOCK_NB)
        metadata = os.fstat(handle.fileno())
        state._write_state_marker(
            review,
            CleanupIdentity(metadata.st_dev, metadata.st_ino),
        )
        try:
            yield handle
        finally:
            state.fcntl.flock(handle.fileno(), state.fcntl.LOCK_UN)


@contextlib.contextmanager
def held_cleanup_worker_locks(review):
    container_fd = os.open(
        review.container_dir,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    compatibility = None
    try:
        compatibility = state.open_private_lock_file(
            review.container_dir / state.CLEANUP_LOCK_FILE,
            label="test cleanup compatibility lock",
        )
        descriptors = (container_fd, compatibility.fileno())
        for descriptor in descriptors:
            state.fcntl.flock(
                descriptor,
                state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
            )
        try:
            yield descriptors
        finally:
            for descriptor in reversed(descriptors):
                state.fcntl.flock(descriptor, state.fcntl.LOCK_UN)
    finally:
        if compatibility is not None:
            compatibility.close()
        os.close(container_fd)


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
        write_ready_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "claude",
                "egress_consent": "explicit-claude-with-copilot-fallback",
                "workspace": self.review.to_json(),
                "keep_workspace": False,
                "pid": 99999999,
            },
        )
        write_json(
            state_dir / "attempts.json",
            [{"runtime": "claude", "requested_model": "claude-opus-4-8"}],
        )
        write_text_atomic(state_dir / state.EXIT_FILE, "0\n")
        write_text_atomic(state_dir / "final.txt", "No findings.\n")

    def write_preflight(
        self,
        secret_delta: dict[str, object],
        *,
        review_range: str | None = None,
    ) -> None:
        write_json(
            self.review.container_dir / state.PREFLIGHT_FILE,
            {
                "private_artifacts": state.PREFLIGHT_PRIVATE_ARTIFACTS,
                "review_range": review_range or f"{self.base}..{self.head}",
                "scope": state.PREFLIGHT_SCOPE,
                "secret_delta": secret_delta,
                "status": state.PREFLIGHT_STATUS,
            },
        )
        with held_runner_lock(self.review) as runner_lock:
            state._seal_preflight_receipt(
                self.review.container_dir,
                review=self.review,
                lock_fd=runner_lock.fileno(),
            )

    def clean_secret_delta(self) -> dict[str, object]:
        return {
            "limitations": [],
            "location_status": "complete",
            "status": "clean",
            "violations": [],
        }

    def violating_secret_delta(
        self,
        *,
        location_status: str = "complete",
    ) -> dict[str, object]:
        return {
            "limitations": [],
            "location_status": location_status,
            "status": "violations",
            "violations": [
                {
                    "additions": [
                        {
                            "line": 1,
                            "occurrence_count": 1,
                            "path": "example.txt",
                            "surface": "blob",
                        }
                    ],
                    "base_count": 0,
                    "delta": 1,
                    "head_count": 1,
                    "omitted_addition_location_count": 0,
                    "rules": ["generic-secret-assignment"],
                    "value_length": 16,
                    "value_sha256": "a" * 64,
                }
            ],
        }

    def inconclusive_secret_delta(self) -> dict[str, object]:
        return {
            "failure_class": "secret-count-incomplete",
            "limitations": [],
            "location_status": "inconclusive",
            "status": "inconclusive",
            "violations": [],
        }

    def read_final_without_cleanup(self) -> tuple[int, str]:
        summary = {
            "running": False,
            "exit_code": 0,
            "runner_error": "",
            "stderr_tail": "",
            "fallback_workspace_retained": False,
        }
        with (
            mock.patch.object(state, "status", return_value=summary),
            mock.patch.object(state, "wait", return_value=0),
        ):
            return state.final(self.review.container_dir)

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
        expected_runner_lock = runner_lock_identity(self.review)
        state._write_state_marker(self.review, expected_runner_lock)

        marker = state._load_state_marker(self.review.container_dir)

        self.assertEqual(marker.private_cleanup, self.review.private_cleanup)
        self.assertEqual(marker.runner_lock, expected_runner_lock)

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
        write_ready_marker(self.review)
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
        write_ready_marker(self.review)
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
        write_ready_marker(self.review)
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
        write_ready_marker(self.review)
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

    def test_v3_marker_is_readable_but_not_automatically_terminalized(self) -> None:
        self.write_completed_state()
        payload = state._state_marker_payload(
            self.review,
            runner_lock_identity(self.review),
        )
        payload.pop("preflight_receipt")
        payload.pop("runner_lock")
        payload["version"] = state.PREVIOUS_STATE_MARKER_SCHEMA_VERSION
        write_json(self.review.container_dir / state.STATE_MARKER, payload)

        loaded, review = state.load_review_state(self.review.container_dir)

        self.assertEqual(loaded["version"], state.STATE_SCHEMA_VERSION)
        self.assertEqual(review, self.review)
        for action in (
            lambda: state.status(self.review.container_dir),
            lambda: state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
        ):
            with self.assertRaisesRegex(ReviewError, "manual recovery"):
                action()

    def test_v4_terminal_state_remains_compatible_with_status_and_final(self) -> None:
        self.write_completed_state()
        marker_path = self.review.container_dir / state.STATE_MARKER
        marker = read_json(marker_path)
        marker.pop("preflight_receipt")
        marker["version"] = state.BOUND_STATE_MARKER_SCHEMA_VERSION
        write_json(marker_path, marker)

        summary = state.status(self.review.container_dir)
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["admission"]["status"], "inconclusive")

        with mock.patch.object(state, "wait", return_value=0):
            exit_code, text = state.final(self.review.container_dir)
        self.assertEqual((exit_code, text), (0, "No findings."))

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
        write_preparing_marker(self.review, partial)

        exit_code = state.cleanup(
            self.review.container_dir,
            timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.container_dir.exists())

    def test_preparing_marker_recovers_partial_private_payloads(self) -> None:
        for index, name in enumerate(
            (PRIVATE_CHANGED_PATHS_NAME, SYNTHETIC_PRIVATE_MANIFEST_NAME),
            start=1,
        ):
            (self.review.container_dir / name).write_bytes(b"partial" * index)
        write_preparing_marker(self.review, self.review.private_cleanup)

        exit_code = state.cleanup(
            self.review.container_dir,
            timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.container_dir.exists())

    def test_ready_marker_recovers_complete_container_without_state(self) -> None:
        write_ready_marker(self.review)

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
        write_ready_marker(self.review)
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
        payload = state._state_marker_payload(
            self.review,
            runner_lock_identity(self.review),
        )
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
                runner_lock_identity(self.review),
            ),
        )
        victim = self.review.workspace_root / "victim.txt"
        victim.write_text("retain\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "preparation identity"):
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
        runner_lock = runner_lock_identity(self.review).to_json()
        invalid_payloads = (
            {
                "container_dir": str(self.review.container_dir),
                "phase": "ready",
                "private_cleanup": partial.to_json(),
                "runner_lock": runner_lock,
                "source_root": str(self.review.source_root),
                "version": state.STATE_MARKER_SCHEMA_VERSION,
            },
            {
                "container_dir": str(self.review.container_dir),
                "phase": False,
                "private_cleanup": partial.to_json(),
                "runner_lock": runner_lock,
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
                "runner_lock": runner_lock,
                "source_root": str(self.review.source_root),
                "version": state.STATE_MARKER_SCHEMA_VERSION,
            },
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                write_json(marker_path, payload)
                with self.assertRaises(ReviewError):
                    state._load_state_marker(self.review.container_dir)

    def test_v5_preflight_receipt_parser_is_strict_and_marker_retains_error(
        self,
    ) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        base = state._state_marker_payload(
            self.review,
            runner_lock_identity(self.review),
        )
        valid = {
            "algorithm": state.PREFLIGHT_RECEIPT_ALGORITHM,
            "schema_version": state.PREFLIGHT_RECEIPT_SCHEMA_VERSION,
            "sha256": "a" * 64,
            "size": 17,
        }
        invalid_receipts = (
            {**valid, "schema_version": True},
            {**valid, "algorithm": "sha512"},
            {**valid, "size": -1},
            {**valid, "sha256": "A" * 64},
            {**valid, "extra": "field"},
        )
        for receipt in invalid_receipts:
            with self.subTest(receipt=receipt):
                with self.assertRaises(ReviewError):
                    state._parse_preflight_receipt(receipt)
                write_json(marker_path, {**base, "preflight_receipt": receipt})
                marker = state._load_state_marker(self.review.container_dir)
                self.assertIsNone(marker.preflight_receipt)
                self.assertIsNotNone(marker.preflight_receipt_error)

    def test_v5_marker_keeps_nonreceipt_duplicate_fields_strict(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        base = state._state_marker_payload(
            self.review,
            runner_lock_identity(self.review),
        )
        encoded = json.dumps(base, sort_keys=True)
        duplicated = encoded.replace(
            '"phase": "ready"',
            '"phase": "ready", "phase": "ready"',
            1,
        )
        write_text_atomic(marker_path, duplicated + "\n")

        with self.assertRaisesRegex(ReviewError, "duplicate field: phase"):
            state._load_state_marker(self.review.container_dir)

    def test_v2_marker_keeps_nested_cleanup_duplicates_strict(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        payload = {
            "container_dir": str(self.review.container_dir),
            "private_cleanup": self.review.private_cleanup.to_json(),
            "version": state.COMPATIBLE_STATE_MARKER_SCHEMA_VERSION,
        }
        encoded = json.dumps(payload, sort_keys=True)
        duplicated = encoded.replace(
            '"schema_version": 1',
            '"schema_version": 1, "schema_version": 1',
            1,
        )
        write_text_atomic(marker_path, duplicated + "\n")

        with self.assertRaisesRegex(ReviewError, "duplicate field: schema_version"):
            state._load_state_marker(self.review.container_dir)

    def test_terminal_v1_is_readable_but_requires_manual_recovery(self) -> None:
        self.write_legacy_state()
        private_artifacts = tuple(
            self.review.container_dir / name
            for name in (PRIVATE_CHANGED_PATHS_NAME, SYNTHETIC_PRIVATE_MANIFEST_NAME)
        )

        loaded, _review = state.load_review_state(self.review.container_dir)
        self.assertEqual(loaded["version"], state.LEGACY_STATE_SCHEMA_VERSION)
        for action in (
            lambda: state.status(self.review.container_dir),
            lambda: state.final(self.review.container_dir),
            lambda: state.cleanup(
                self.review.container_dir,
                timeout_seconds=state.FINAL_CLEANUP_TIMEOUT_SECONDS,
            ),
        ):
            with self.assertRaisesRegex(ReviewError, "manual recovery"):
                action()

        self.assertTrue(self.review.workspace_root.exists())
        self.assertTrue(all(path.exists() for path in private_artifacts))

    def test_active_v1_status_does_not_trust_unbound_runner_lock(self) -> None:
        self.write_legacy_state(terminal=False)
        lock_path = self.review.container_dir / state.LOCK_FILE

        with lock_path.open("a+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            with self.assertRaisesRegex(ReviewError, "manual recovery"):
                state.status(self.review.container_dir)

    def test_v1_keep_does_not_trigger_automatic_scrub(self) -> None:
        self.write_legacy_state(keep_workspace=True)

        with self.assertRaisesRegex(ReviewError, "manual recovery"):
            state.final(self.review.container_dir)
        self.assertTrue(self.review.workspace_root.exists())
        self.assertTrue(
            all(
                (self.review.container_dir / name).exists()
                for name in (
                    PRIVATE_CHANGED_PATHS_NAME,
                    SYNTHETIC_PRIVATE_MANIFEST_NAME,
                )
            )
        )

    def test_v1_codex_unavailable_requires_manual_recovery(self) -> None:
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

        with self.assertRaisesRegex(ReviewError, "manual recovery"):
            state.final(self.review.container_dir)
        self.assertTrue(self.review.workspace_root.exists())

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

        marker = state._state_marker_payload(
            self.review,
            runner_lock_identity(self.review),
        )
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
        cleanup_error = state.remove_private_review_artifacts(
            self.review.container_dir,
            expected=self.review.private_cleanup,
        )
        if cleanup_error is not None:
            raise AssertionError(cleanup_error)
        evidence: dict[str, object] = {
            "private_artifacts": "removed",
            "review_range": f"{self.base}..{self.head}",
            "status": "review workspace containment and integrity checks passed",
        }
        if primary_diff is not None:
            evidence["primary_diff"] = primary_diff
        write_json(self.review.container_dir / "preflight.json", evidence)

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
        self.assertEqual(summary["review_contract"], "supplied-diff-no-git")
        self.assertFalse(summary["named_lane_eligible"])
        self.assertEqual(
            summary["egress_consent"], "explicit-claude-with-copilot-fallback"
        )
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

    def test_final_rejects_non_private_artifact_mode(self) -> None:
        self.write_completed_state()
        (self.review.container_dir / "final.txt").chmod(0o640)

        with self.assertRaisesRegex(ReviewError, "mode must be exactly 0600"):
            self.read_final_without_cleanup()

    def test_final_rejects_hard_linked_artifact(self) -> None:
        self.write_completed_state()
        final_path = self.review.container_dir / "final.txt"
        os.link(final_path, self.review.container_dir / "final-copy.txt")

        with self.assertRaisesRegex(ReviewError, "exactly one hard link"):
            self.read_final_without_cleanup()

    def test_final_rejects_symlink_artifact(self) -> None:
        self.write_completed_state()
        final_path = self.review.container_dir / "final.txt"
        target = pathlib.Path(self.temporary.name) / "outside-final.txt"
        write_text_atomic(target, "forged\n")
        final_path.unlink()
        final_path.symlink_to(target)

        with self.assertRaisesRegex(ReviewError, "regular file"):
            self.read_final_without_cleanup()

    def test_final_rejects_fifo_without_blocking(self) -> None:
        self.write_completed_state()
        final_path = self.review.container_dir / "final.txt"
        final_path.unlink()
        os.mkfifo(final_path, 0o600)

        started = time.monotonic()
        with self.assertRaisesRegex(ReviewError, "regular file"):
            self.read_final_without_cleanup()
        self.assertLess(time.monotonic() - started, 1.0)

    def test_final_rejects_oversized_artifact(self) -> None:
        self.write_completed_state()

        with (
            mock.patch.object(state, "MAX_FINAL_ARTIFACT_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "size limit"),
        ):
            self.read_final_without_cleanup()

    def test_final_rejects_path_swap_while_opening(self) -> None:
        self.write_completed_state()
        final_path = self.review.container_dir / "final.txt"
        replacement = self.review.container_dir / "replacement-final.txt"
        write_text_atomic(replacement, "forged\n")
        original_open = state.os.open
        swapped = False

        def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == pathlib.Path("final.txt") and dir_fd is not None:
                swapped = True
                os.replace(replacement, final_path)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(state.os, "open", side_effect=swap_before_open),
            self.assertRaisesRegex(ReviewError, "changed while opening"),
        ):
            self.read_final_without_cleanup()
        self.assertTrue(swapped)

    def test_final_rejects_length_change_while_reading(self) -> None:
        self.write_completed_state()
        final_path = self.review.container_dir / "final.txt"
        expected = os.stat(final_path, follow_symlinks=False)
        original_read = state.os.read
        mutated = False

        def append_after_read(descriptor, count):
            nonlocal mutated
            payload = original_read(descriptor, count)
            metadata = os.fstat(descriptor)
            if not mutated and (metadata.st_dev, metadata.st_ino) == (
                expected.st_dev,
                expected.st_ino,
            ):
                mutated = True
                with final_path.open("ab") as handle:
                    handle.write(b"late mutation\n")
            return payload

        with (
            mock.patch.object(state.os, "read", side_effect=append_after_read),
            self.assertRaisesRegex(ReviewError, "changed while reading"),
        ):
            self.read_final_without_cleanup()
        self.assertTrue(mutated)

    def test_final_rejects_container_swap_while_opening(self) -> None:
        self.write_completed_state()
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-final-bound")
        original_open = state.os.open
        swapped = False

        def swap_container_after_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == pathlib.Path("final.txt") and dir_fd is not None:
                swapped = True
                state_dir.rename(moved_state_dir)
                state_dir.mkdir(mode=0o700)
            return descriptor

        try:
            with (
                mock.patch.object(
                    state.os,
                    "open",
                    side_effect=swap_container_after_open,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "state directory path does not match its open descriptor",
                ),
            ):
                self.read_final_without_cleanup()
            self.assertTrue(swapped)
        finally:
            if state_dir.is_dir():
                state_dir.rmdir()
            if moved_state_dir.is_dir():
                moved_state_dir.rename(state_dir)

    def test_codex_unavailable_retains_helper_workspace_until_cleanup(self) -> None:
        self.write_codex_unavailable_state()
        private_artifacts = (
            self.review.container_dir / PRIVATE_CHANGED_PATHS_NAME,
            self.review.container_dir / SYNTHETIC_PRIVATE_MANIFEST_NAME,
        )
        self.write_passed_preflight(
            primary_diff=self.primary_diff_attestation(),
        )

        exit_code, text = state.final(self.review.container_dir)

        self.assertEqual(exit_code, 127)
        self.assertIn("legacy helper workspace retained for diagnosis only", text)
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

    def test_fallback_accepts_bounded_preflight_larger_than_compact_evidence(
        self,
    ) -> None:
        self.write_codex_unavailable_state()
        self.assertIsNone(
            state.remove_private_review_artifacts(
                self.review.container_dir,
                expected=self.review.private_cleanup,
            )
        )
        evidence: dict[str, object] = {
            "private_artifacts": "removed",
            "review_range": f"{self.base}..{self.head}",
            "status": "review workspace containment and integrity checks passed",
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
        self.assertIsNone(
            state.remove_private_review_artifacts(
                self.review.container_dir,
                expected=self.review.private_cleanup,
            )
        )
        evidence: dict[str, object] = {
            "private_artifacts": "removed",
            "review_range": f"{self.base}..{self.head}",
            "status": "review workspace containment and integrity checks passed",
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
                "status": "review workspace containment and integrity checks passed",
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

    def test_admission_maps_clean_blocked_and_inconclusive_evidence(self) -> None:
        self.write_completed_state()
        cases = (
            (self.clean_secret_delta(), "clean", 0, None),
            (self.violating_secret_delta(), "blocked", 1, None),
            (
                self.violating_secret_delta(location_status="inconclusive"),
                "blocked",
                1,
                None,
            ),
            (
                self.inconclusive_secret_delta(),
                "inconclusive",
                75,
                "secret-count-incomplete",
            ),
        )
        for secret_delta, expected_status, expected_exit, failure_class in cases:
            with self.subTest(expected_status=expected_status, delta=secret_delta):
                self.write_preflight(secret_delta)
                exit_code, summary = state.admission(self.review.container_dir)
                self.assertEqual(exit_code, expected_exit)
                self.assertEqual(summary["status"], expected_status)
                self.assertEqual(summary["failure_class"], failure_class)
                self.assertEqual(summary["secret_delta"], secret_delta)
                self.assertEqual(summary["schema_version"], 1)
                self.assertEqual(summary["review_range"], f"{self.base}..{self.head}")
                self.assertEqual(
                    summary["evidence_path"],
                    str(self.review.container_dir / state.PREFLIGHT_FILE),
                )

    def test_admission_missing_evidence_is_pending_only_while_runner_is_held(
        self,
    ) -> None:
        self.write_completed_state()
        terminal = state.admission_status(self.review.container_dir)
        self.assertEqual(terminal["status"], "inconclusive")
        self.assertEqual(terminal["exit_code"], 75)
        self.assertEqual(terminal["failure_class"], "preflight-unsealed")

        lock_path = self.review.container_dir / state.LOCK_FILE
        with lock_path.open("r+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            pending = state.admission_status(self.review.container_dir)

        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["exit_code"], 3)
        self.assertEqual(pending["failure_class"], "preflight-not-ready")

    def test_admission_with_sealed_receipt_stays_pending_while_runner_is_held(
        self,
    ) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())

        lock_path = self.review.container_dir / state.LOCK_FILE
        with lock_path.open("r+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            pending = state.admission_status(self.review.container_dir)
            lifecycle = state.status(self.review.container_dir)

        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["exit_code"], 3)
        self.assertEqual(pending["failure_class"], "preflight-not-ready")
        self.assertIsNone(pending["secret_delta"])
        self.assertTrue(lifecycle["running"])
        self.assertTrue(lifecycle["runner_lock_held"])
        self.assertEqual(lifecycle["admission"], pending)

        terminal = state.admission_status(self.review.container_dir)
        self.assertEqual(terminal["status"], "clean")
        self.assertEqual(terminal["exit_code"], 0)

    def test_admission_rejects_malformed_range_and_symlink_evidence(self) -> None:
        self.write_completed_state()
        preflight_path = self.review.container_dir / state.PREFLIGHT_FILE

        self.write_preflight(self.clean_secret_delta())
        write_text_atomic(preflight_path, "not-json\n")
        malformed = state.admission_status(self.review.container_dir)
        self.assertEqual(malformed["failure_class"], "preflight-invalid")
        self.assertEqual(malformed["exit_code"], 75)

        self.write_preflight(
            self.clean_secret_delta(),
            review_range=f"{'b' * 40}..{'c' * 40}",
        )
        mismatch = state.admission_status(self.review.container_dir)
        self.assertEqual(mismatch["failure_class"], "preflight-range-mismatch")

        outside = pathlib.Path(self.temporary.name) / "outside-preflight.json"
        write_json(outside, {"secret_delta": self.clean_secret_delta()})
        preflight_path.unlink()
        preflight_path.symlink_to(outside)
        symlink = state.admission_status(self.review.container_dir)
        self.assertEqual(symlink["failure_class"], "preflight-invalid")
        self.assertIsNone(symlink["secret_delta"])

    def test_admission_rejects_container_swap_during_bound_read(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-admission-bound")
        original_reader = state._read_modern_bound_state_artifact
        swapped = False

        def swap_then_read(bound_state_dir, **kwargs):
            nonlocal swapped
            swapped = True
            state_dir.rename(moved_state_dir)
            state_dir.mkdir(mode=0o700)
            return original_reader(bound_state_dir, **kwargs)

        try:
            with mock.patch.object(
                state,
                "_read_modern_bound_state_artifact",
                side_effect=swap_then_read,
            ):
                summary = state.admission_status(state_dir)
            self.assertTrue(swapped)
            self.assertEqual(summary["failure_class"], "preflight-invalid")
            self.assertEqual(summary["exit_code"], 75)
        finally:
            if state_dir.is_dir():
                state_dir.rmdir()
            if moved_state_dir.is_dir():
                moved_state_dir.rename(state_dir)

    def test_admission_rejects_valid_preflight_replacement_after_runner_seal(
        self,
    ) -> None:
        self.write_completed_state()
        self.write_preflight(self.violating_secret_delta())

        write_json(
            self.review.container_dir / state.PREFLIGHT_FILE,
            {
                "private_artifacts": state.PREFLIGHT_PRIVATE_ARTIFACTS,
                "review_range": f"{self.base}..{self.head}",
                "scope": state.PREFLIGHT_SCOPE,
                "secret_delta": self.clean_secret_delta(),
                "status": state.PREFLIGHT_STATUS,
            },
        )

        summary = state.admission_status(self.review.container_dir)

        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["exit_code"], 75)
        self.assertEqual(summary["failure_class"], "preflight-invalid")
        self.assertIsNone(summary["secret_delta"])

    def test_v4_admission_is_pending_while_held_and_inconclusive_when_terminal(
        self,
    ) -> None:
        self.write_completed_state()
        marker_path = self.review.container_dir / state.STATE_MARKER
        marker = read_json(marker_path)
        marker.pop("preflight_receipt")
        marker["version"] = state.BOUND_STATE_MARKER_SCHEMA_VERSION
        write_json(marker_path, marker)

        terminal = state.admission_status(self.review.container_dir)
        self.assertEqual(terminal["status"], "inconclusive")
        self.assertEqual(
            terminal["failure_class"],
            "legacy-state-no-preflight-receipt",
        )

        lock_path = self.review.container_dir / state.LOCK_FILE
        with lock_path.open("r+b") as runner_lock:
            state.fcntl.flock(runner_lock.fileno(), state.fcntl.LOCK_EX)
            pending = state.admission_status(self.review.container_dir)

        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["exit_code"], 3)
        self.assertEqual(pending["failure_class"], "preflight-not-ready")

    def test_status_admission_matches_standalone_result(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.violating_secret_delta())

        standalone = state.admission_status(self.review.container_dir)
        status_summary = state.status(self.review.container_dir)

        self.assertEqual(status_summary["admission"], standalone)
        self.assertEqual(status_summary["admission"]["status"], "blocked")

    def test_admission_keeps_full_legacy_violation_capacity_blocked(self) -> None:
        self.write_completed_state()
        violation_count = MAX_SYNTHETIC_EVIDENCE_ENTRIES
        secret_delta = {
            "limitations": [
                "added secret locations were omitted to keep evidence bounded"
            ],
            "location_status": "inconclusive",
            "status": "violations",
            "violations": [
                {
                    "additions": [],
                    "base_count": 0,
                    "delta": 1,
                    "head_count": 1,
                    "omitted_addition_location_count": 1,
                    "rules": ["generic-secret-assignment"],
                    "value_length": 16,
                    "value_sha256": f"{index:064x}",
                }
                for index in range(violation_count)
            ],
        }
        preflight = {
            "private_artifacts": state.PREFLIGHT_PRIVATE_ARTIFACTS,
            "review_range": f"{self.base}..{self.head}",
            "scope": state.PREFLIGHT_SCOPE,
            "secret_delta": secret_delta,
            "status": state.PREFLIGHT_STATUS,
        }
        encoded_preflight = encode_preflight_json(preflight)
        self.assertLess(
            len(encoded_preflight),
            len(json.dumps(preflight, indent=2, sort_keys=True) + "\n"),
        )
        write_text_atomic(
            self.review.container_dir / state.PREFLIGHT_FILE,
            encoded_preflight,
        )
        with held_runner_lock(self.review) as runner_lock:
            state._seal_preflight_receipt(
                self.review.container_dir,
                review=self.review,
                lock_fd=runner_lock.fileno(),
            )

        exit_code, summary = state.admission(self.review.container_dir)

        self.assertEqual(exit_code, 1)
        self.assertEqual(summary["status"], "blocked")
        self.assertEqual(summary["secret_delta"], secret_delta)
        self.assertEqual(
            len(summary["secret_delta"]["violations"]),
            violation_count,
        )

    def test_final_success_is_independent_of_nonclean_admission(self) -> None:
        self.write_completed_state()
        with mock.patch.object(state, "wait", return_value=0):
            for secret_delta in (
                self.violating_secret_delta(),
                self.inconclusive_secret_delta(),
            ):
                with self.subTest(secret_delta=secret_delta):
                    self.write_preflight(secret_delta)
                    exit_code, text = state.final(self.review.container_dir)
                    self.assertEqual((exit_code, text), (0, "No findings."))

    def test_malformed_unhashable_admission_does_not_block_final(self) -> None:
        self.write_completed_state()
        malformed = self.violating_secret_delta()
        malformed["violations"][0]["rules"] = [
            {},
            "generic-secret-assignment",
        ]
        self.write_preflight(malformed)

        summary = state.admission_status(self.review.container_dir)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["exit_code"], 75)
        self.assertEqual(summary["failure_class"], "preflight-invalid")
        with mock.patch.object(state, "wait", return_value=0):
            exit_code, text = state.final(self.review.container_dir)
        self.assertEqual((exit_code, text), (0, "No findings."))

    def test_malformed_receipt_is_inconclusive_without_blocking_final(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())
        marker_path = self.review.container_dir / state.STATE_MARKER
        marker = read_json(marker_path)
        marker["preflight_receipt"]["algorithm"] = "sha512"
        write_json(marker_path, marker)

        exit_code, summary = state.admission(self.review.container_dir)
        self.assertEqual(exit_code, 75)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["failure_class"], "preflight-invalid")
        self.assertIsNone(summary["secret_delta"])
        self.assertEqual(state.status(self.review.container_dir)["admission"], summary)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            cli_exit = cli.main(
                [
                    "stateful",
                    "admission",
                    "--state-dir",
                    str(self.review.container_dir),
                ]
            )
        self.assertEqual(cli_exit, 75)
        self.assertEqual(json.loads(stdout.getvalue()), summary)
        self.assertEqual(stderr.getvalue(), "")

        lock_path = self.review.container_dir / state.LOCK_FILE
        with state.open_private_lock_file(
            lock_path,
            label="test review runner lock",
        ) as runner_lock:
            state.fcntl.flock(
                runner_lock.fileno(),
                state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
            )
            with self.assertRaisesRegex(ReviewError, "receipt algorithm is invalid"):
                state._seal_preflight_receipt(
                    self.review.container_dir,
                    review=self.review,
                    lock_fd=runner_lock.fileno(),
                )

        final_exit, text = state.final(self.review.container_dir)
        self.assertEqual((final_exit, text), (0, "No findings."))
        self.assertFalse(self.review.workspace_root.exists())

    def test_deep_receipt_is_inconclusive_without_blocking_final(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())
        marker_path = self.review.container_dir / state.STATE_MARKER
        marker = read_json(marker_path)
        deep_receipt = "[" * 20_000 + '"bracket: }] and quote: \\""' + "]" * 20_000
        write_marker_with_raw_top_level_value(
            marker_path,
            marker,
            field="preflight_receipt",
            raw_field_name='"preflight_\\u0072eceipt"',
            raw_value=deep_receipt,
        )
        self.assertLess(marker_path.stat().st_size, state.MAX_STATE_MARKER_BYTES)

        loaded = state._load_state_marker(self.review.container_dir)
        self.assertIsNone(loaded.preflight_receipt)
        self.assertRegex(
            loaded.preflight_receipt_error or "",
            "receipt exceeds the JSON nesting depth limit",
        )
        exit_code, summary = state.admission(self.review.container_dir)
        self.assertEqual(exit_code, 75)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["failure_class"], "preflight-invalid")
        self.assertEqual(state.status(self.review.container_dir)["admission"], summary)

        lock_path = self.review.container_dir / state.LOCK_FILE
        with state.open_private_lock_file(
            lock_path,
            label="test review runner lock",
        ) as runner_lock:
            state.fcntl.flock(
                runner_lock.fileno(),
                state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
            )
            with self.assertRaisesRegex(
                ReviewError,
                "receipt exceeds the JSON nesting depth limit",
            ):
                state._seal_preflight_receipt(
                    self.review.container_dir,
                    review=self.review,
                    lock_fd=runner_lock.fileno(),
                )

        final_exit, text = state.final(self.review.container_dir)
        self.assertEqual((final_exit, text), (0, "No findings."))
        self.assertFalse(self.review.workspace_root.exists())

    def test_receipt_local_numeric_decode_error_does_not_block_final(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())
        marker_path = self.review.container_dir / state.STATE_MARKER
        write_marker_with_raw_top_level_value(
            marker_path,
            read_json(marker_path),
            field="preflight_receipt",
            raw_value="9" * 5_000,
        )

        loaded = state._load_state_marker(self.review.container_dir)
        self.assertIsNone(loaded.preflight_receipt)
        self.assertRegex(
            loaded.preflight_receipt_error or "",
            "receipt is not valid JSON",
        )
        exit_code, summary = state.admission(self.review.container_dir)
        self.assertEqual(exit_code, 75)
        self.assertEqual(summary["failure_class"], "preflight-invalid")
        self.assertEqual(state.status(self.review.container_dir)["admission"], summary)

        final_exit, text = state.final(self.review.container_dir)
        self.assertEqual((final_exit, text), (0, "No findings."))
        self.assertFalse(self.review.workspace_root.exists())

    def test_deep_core_marker_fields_remain_hard_state_errors(self) -> None:
        self.write_completed_state()
        marker_path = self.review.container_dir / state.STATE_MARKER
        valid_marker = read_json(marker_path)

        for depth in (65, 20_000):
            with self.subTest(depth=depth):
                write_marker_with_raw_top_level_value(
                    marker_path,
                    valid_marker,
                    field="runner_lock",
                    raw_value="[" * depth + "0" + "]" * depth,
                )
                self.assertLess(
                    marker_path.stat().st_size,
                    state.MAX_STATE_MARKER_BYTES,
                )
                for operation in (
                    lambda: state._load_state_marker(self.review.container_dir),
                    lambda: state.status(self.review.container_dir),
                    lambda: state.admission_status(self.review.container_dir),
                    lambda: state.cleanup(
                        self.review.container_dir,
                        timeout_seconds=1,
                    ),
                ):
                    with self.assertRaisesRegex(
                        ReviewError,
                        "state marker exceeds the JSON nesting depth limit",
                    ):
                        operation()
                self.assertTrue(self.review.workspace_root.exists())

    def test_deep_receipt_does_not_mask_core_phase_or_version_errors(self) -> None:
        marker_path = self.review.container_dir / state.STATE_MARKER
        deep_receipt = "[" * 20_000 + "0" + "]" * 20_000

        write_ready_marker(self.review)
        invalid_version = read_json(marker_path)
        invalid_version["version"] = 999
        write_marker_with_raw_top_level_value(
            marker_path,
            invalid_version,
            field="preflight_receipt",
            raw_value=deep_receipt,
        )
        with self.assertRaisesRegex(ReviewError, "version is invalid"):
            state._load_state_marker(self.review.container_dir)

        write_ready_marker(self.review)
        preparing = read_json(marker_path)
        preparing["phase"] = "preparing"
        write_marker_with_raw_top_level_value(
            marker_path,
            preparing,
            field="preflight_receipt",
            raw_value=deep_receipt,
        )
        with self.assertRaisesRegex(
            ReviewError,
            "preparing marker cannot contain a preflight receipt",
        ):
            state._load_state_marker(self.review.container_dir)

    def test_preparing_marker_rejects_any_non_null_duplicate_receipt(self) -> None:
        write_ready_marker(self.review)
        marker_path = self.review.container_dir / state.STATE_MARKER
        preparing = read_json(marker_path)
        preparing["phase"] = "preparing"
        preparing.pop("preflight_receipt")
        marker_prefix = json.dumps(preparing, sort_keys=True)[:-1]

        receipt_fields = (
            ', "preflight_receipt": [], "preflight_\\u0072eceipt": null',
            ', "preflight_\\u0072eceipt": null, "preflight_receipt": []',
            ', "preflight_receipt": \u00a0null\u00a0',
            ', "preflight_receipt": \vnull\v',
        )
        for fields in receipt_fields:
            with self.subTest(fields=fields):
                write_text_atomic(marker_path, marker_prefix + fields + "}\n")
                with self.assertRaisesRegex(
                    ReviewError,
                    "preparing marker cannot contain a preflight receipt",
                ):
                    state._load_state_marker(self.review.container_dir)

    def test_missing_or_duplicate_receipt_is_admission_inconclusive(self) -> None:
        self.write_completed_state()
        self.write_preflight(self.clean_secret_delta())
        marker_path = self.review.container_dir / state.STATE_MARKER
        valid_marker = read_json(marker_path)

        missing_marker = dict(valid_marker)
        missing_marker.pop("preflight_receipt")
        write_json(marker_path, missing_marker)
        missing_exit, missing = state.admission(self.review.container_dir)
        self.assertEqual(missing_exit, 75)
        self.assertEqual(missing["failure_class"], "preflight-invalid")

        receipt = valid_marker["preflight_receipt"]
        marker_without_receipt = {
            key: value
            for key, value in valid_marker.items()
            if key != "preflight_receipt"
        }
        marker_prefix = json.dumps(marker_without_receipt, sort_keys=True)[:-1]
        duplicate_receipt = (
            marker_prefix
            + ', "preflight_receipt": {'
            + f'"algorithm": "{receipt["algorithm"]}", '
            + '"algorithm": "sha512", '
            + f'"schema_version": {receipt["schema_version"]}, '
            + f'"sha256": "{receipt["sha256"]}", '
            + f'"size": {receipt["size"]}'
            + "}}\n"
        )
        write_text_atomic(marker_path, duplicate_receipt)

        duplicate_exit, duplicate = state.admission(self.review.container_dir)
        self.assertEqual(duplicate_exit, 75)
        self.assertEqual(duplicate["failure_class"], "preflight-invalid")

        receipt_json = json.dumps(receipt, sort_keys=True)
        duplicate_top_level_receipt = (
            marker_prefix
            + f', "preflight_receipt": {receipt_json}'
            + f', "preflight_receipt": {receipt_json}'
            + "}\n"
        )
        write_text_atomic(marker_path, duplicate_top_level_receipt)

        top_level_exit, top_level = state.admission(self.review.container_dir)
        self.assertEqual(top_level_exit, 75)
        self.assertEqual(top_level["failure_class"], "preflight-invalid")

    def test_legacy_admission_is_inconclusive(self) -> None:
        self.write_legacy_state()

        summary = state.admission_status(self.review.container_dir)

        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["exit_code"], 75)
        self.assertEqual(summary["failure_class"], "legacy-state-no-admission")

    def test_concurrent_wait_serializes_workspace_cleanup(self) -> None:
        self.write_completed_state()
        status_barrier = threading.Barrier(3)
        status_threads: set[int] = set()
        status_threads_lock = threading.Lock()
        first_compatibility_open = threading.Event()
        second_container_attempt = threading.Event()
        allow_compatibility_open = threading.Event()
        cleanup_owner: int | None = None
        cleanup_owner_lock = threading.Lock()
        real_status = state.status
        real_open_private_lock_file = state.open_private_lock_file
        real_acquire_descriptor = state._acquire_cleanup_lock_descriptor

        def synchronized_status(*args, **kwargs):
            summary = real_status(*args, **kwargs)
            if summary["running"]:
                thread_id = threading.get_ident()
                with status_threads_lock:
                    first_observation = thread_id not in status_threads
                    status_threads.add(thread_id)
                if first_observation:
                    status_barrier.wait(timeout=2)
            return summary

        def acquire_descriptor(descriptor, *, deadline):
            nonlocal cleanup_owner
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                thread_id = threading.get_ident()
                with cleanup_owner_lock:
                    if cleanup_owner is None:
                        cleanup_owner = thread_id
                    elif cleanup_owner != thread_id:
                        second_container_attempt.set()
            return real_acquire_descriptor(descriptor, deadline=deadline)

        def open_private_lock_file(path, **kwargs):
            if pathlib.Path(path).name == state.CLEANUP_LOCK_FILE:
                with cleanup_owner_lock:
                    is_owner = cleanup_owner == threading.get_ident()
                if is_owner:
                    first_compatibility_open.set()
                    if not allow_compatibility_open.wait(timeout=2):
                        raise AssertionError("timed out serializing cleanup lock open")
            return real_open_private_lock_file(path, **kwargs)

        with (
            mock.patch.object(state, "status", side_effect=synchronized_status),
            mock.patch.object(
                state,
                "_acquire_cleanup_lock_descriptor",
                side_effect=acquire_descriptor,
            ),
            mock.patch.object(
                state,
                "open_private_lock_file",
                side_effect=open_private_lock_file,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            with held_runner_lock(self.review):
                first = executor.submit(
                    state.wait, self.review.container_dir, timeout_seconds=5
                )
                second = executor.submit(
                    state.wait, self.review.container_dir, timeout_seconds=5
                )
                status_barrier.wait(timeout=2)

            self.assertTrue(first_compatibility_open.wait(timeout=2))
            self.assertTrue(second_container_attempt.wait(timeout=2))
            self.assertFalse(
                (self.review.container_dir / state.CLEANUP_LOCK_FILE).exists()
            )
            allow_compatibility_open.set()
            self.assertEqual(first.result(timeout=5), 0)
            self.assertEqual(second.result(timeout=5), 0)

        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse((self.review.container_dir / "cleanup-error.txt").exists())

    def test_cleanup_opens_compatibility_lock_after_container_lock(self) -> None:
        self.write_completed_state()
        probe_fd = os.open(
            self.review.container_dir,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        real_open_private_lock_file = state.open_private_lock_file

        def open_with_container_probe(path, **kwargs):
            if pathlib.Path(path).name == state.CLEANUP_LOCK_FILE:
                with self.assertRaises(BlockingIOError):
                    state.fcntl.flock(
                        probe_fd,
                        state.fcntl.LOCK_EX | state.fcntl.LOCK_NB,
                    )
            return real_open_private_lock_file(path, **kwargs)

        try:
            with mock.patch.object(
                state,
                "open_private_lock_file",
                side_effect=open_with_container_probe,
            ):
                self.assertEqual(
                    state.cleanup(self.review.container_dir, timeout_seconds=5),
                    0,
                )
        finally:
            os.close(probe_fd)

    def test_shared_runner_probe_does_not_block_terminal_cleanup(self) -> None:
        self.write_completed_state()
        with state.open_private_lock_file(
            self.review.container_dir / state.LOCK_FILE,
            label="test shared runner probe",
        ) as observer:
            state.fcntl.flock(observer.fileno(), state.fcntl.LOCK_SH)
            self.assertFalse(state._runner_lock_held(self.review.container_dir))
            self.assertEqual(
                state.cleanup(self.review.container_dir, timeout_seconds=5),
                0,
            )

        self.assertFalse(self.review.workspace_root.exists())

    def test_exclusive_runner_lease_still_blocks_terminal_cleanup(self) -> None:
        self.write_completed_state()
        with held_runner_lock(self.review):
            self.assertTrue(state._runner_lock_held(self.review.container_dir))
            self.assertEqual(
                state.cleanup(self.review.container_dir, timeout_seconds=1),
                3,
            )

        self.assertTrue(self.review.workspace_root.exists())

    def test_directory_identity_allows_child_entry_changes(self) -> None:
        state_dir = self.review.container_dir
        descriptor = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
        original_stat = os.stat
        path_stat_calls = 0

        def stat_then_create_child(*args, **kwargs):
            nonlocal path_stat_calls
            metadata = original_stat(*args, **kwargs)
            path_stat_calls += 1
            if path_stat_calls == 1:
                (state_dir / "concurrent-child").mkdir()
            return metadata

        try:
            with mock.patch.object(
                state.os, "stat", side_effect=stat_then_create_child
            ):
                state._validate_private_directory_path_identity(
                    state_dir,
                    descriptor,
                    label="review state directory",
                    expected_mode=0o700,
                )
        finally:
            os.close(descriptor)
            (state_dir / "concurrent-child").rmdir()

    def test_directory_identity_rejects_path_replacement(self) -> None:
        state_dir = self.review.container_dir
        moved_state_dir = state_dir.with_name(f"{state_dir.name}-moved")
        descriptor = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
        state_dir.rename(moved_state_dir)
        state_dir.mkdir(mode=0o700)
        state_dir.chmod(0o700)

        try:
            with self.assertRaisesRegex(
                state.ReviewError,
                "review state directory path does not match its open descriptor",
            ):
                state._validate_private_directory_path_identity(
                    state_dir,
                    descriptor,
                    label="review state directory",
                    expected_mode=0o700,
                )
        finally:
            os.close(descriptor)
            state_dir.rmdir()
            moved_state_dir.rename(state_dir)

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
        with held_cleanup_worker_locks(self.review) as lock_fds:
            exit_code = cleanup_worker.main(
                [
                    str(self.review.container_dir),
                    *(str(descriptor) for descriptor in lock_fds),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertFalse(self.review.workspace_root.exists())
        self.assertFalse(cleanup_error_path.exists())

    def test_cleanup_worker_lock_validator_accepts_exact_inherited_leases(
        self,
    ) -> None:
        self.write_completed_state()
        with held_cleanup_worker_locks(self.review) as lock_fds:
            for descriptor in lock_fds:
                os.set_inheritable(descriptor, True)

            state.validate_cleanup_worker_lock_leases(
                self.review.container_dir,
                lock_fds,
            )

            self.assertTrue(
                all(not os.get_inheritable(descriptor) for descriptor in lock_fds)
            )

    def test_cleanup_worker_lock_validator_rejects_role_swap(self) -> None:
        self.write_completed_state()
        with held_cleanup_worker_locks(self.review) as lock_fds:
            with self.assertRaisesRegex(ReviewError, "container lock"):
                state.validate_cleanup_worker_lock_leases(
                    self.review.container_dir,
                    tuple(reversed(lock_fds)),
                )

    def test_cleanup_worker_lock_validator_rejects_unlocked_exact_fds(self) -> None:
        self.write_completed_state()
        container_fd = os.open(
            self.review.container_dir,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            with state.open_private_lock_file(
                self.review.container_dir / state.CLEANUP_LOCK_FILE,
                label="test unlocked cleanup compatibility lock",
            ) as compatibility:
                with self.assertRaisesRegex(ReviewError, "not an inherited-held lease"):
                    state.validate_cleanup_worker_lock_leases(
                        self.review.container_dir,
                        (container_fd, compatibility.fileno()),
                    )
        finally:
            os.close(container_fd)

    def test_cleanup_worker_lock_validator_rejects_independent_descriptions(
        self,
    ) -> None:
        self.write_completed_state()
        with held_cleanup_worker_locks(self.review):
            container_fd = os.open(
                self.review.container_dir,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                with state.open_private_lock_file(
                    self.review.container_dir / state.CLEANUP_LOCK_FILE,
                    label="test independent cleanup compatibility lock",
                ) as compatibility:
                    with self.assertRaisesRegex(
                        ReviewError,
                        "does not share the inherited-held lock description",
                    ):
                        state.validate_cleanup_worker_lock_leases(
                            self.review.container_dir,
                            (container_fd, compatibility.fileno()),
                        )
            finally:
                os.close(container_fd)

    def test_cleanup_worker_lock_validator_rejects_replaced_lock_path(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.CLEANUP_LOCK_FILE
        stale_path = self.review.container_dir / "stale-cleanup.lock"
        with held_cleanup_worker_locks(self.review) as lock_fds:
            lock_path.rename(stale_path)
            os.mkfifo(lock_path, 0o600)

            started = time.monotonic()
            with self.assertRaisesRegex(
                ReviewError,
                "path does not match its open file descriptor",
            ):
                state.validate_cleanup_worker_lock_leases(
                    self.review.container_dir,
                    lock_fds,
                )
            self.assertLess(time.monotonic() - started, 1.0)

    def test_cleanup_worker_lock_validator_rejects_closed_fds(self) -> None:
        self.write_completed_state()
        with held_cleanup_worker_locks(self.review) as lock_fds:
            closed_fds = lock_fds

        with self.assertRaisesRegex(ReviewError, "lock descriptor"):
            state.validate_cleanup_worker_lock_leases(
                self.review.container_dir,
                closed_fds,
            )

    def test_cleanup_worker_rejects_missing_extra_and_duplicate_fds(self) -> None:
        self.write_completed_state()
        state_dir = str(self.review.container_dir)
        for arguments in (
            [state_dir],
            [state_dir, "3", "4", "5"],
            [state_dir, "3", "3"],
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(cleanup_worker.main(arguments), 2)
        self.assertTrue(self.review.workspace_root.exists())

    def test_cleanup_worker_rejects_legacy_automatic_execution(self) -> None:
        self.write_legacy_state()
        stderr = io.StringIO()
        with (
            held_cleanup_worker_locks(self.review) as lock_fds,
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = cleanup_worker.main(
                [
                    str(self.review.container_dir),
                    *(str(descriptor) for descriptor in lock_fds),
                ]
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(self.review.workspace_root.exists())
        self.assertIn("modern v4/v5 ready state marker", stderr.getvalue())

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
        real_acquire_cleanup_lock = state._acquire_cleanup_lock

        def acquire_then_change_state_mode(handle, *, deadline):
            acquired = real_acquire_cleanup_lock(handle, deadline=deadline)
            if not acquired:
                return False
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
        real_acquire_cleanup_lock = state._acquire_cleanup_lock

        def mutate_mode_after_flock(handle, *, deadline) -> bool:
            acquired = real_acquire_cleanup_lock(handle, deadline=deadline)
            if not acquired:
                return False
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
        real_acquire_cleanup_lock = state._acquire_cleanup_lock

        def acquire_then_replace(handle, *, deadline):
            acquired = real_acquire_cleanup_lock(handle, deadline=deadline)
            if not acquired:
                return False
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
        real_flock = state.fcntl.flock

        with (
            mock.patch.object(state.subprocess, "Popen", return_value=worker),
            mock.patch.object(state, "_runner_lock_held", return_value=False),
            mock.patch.object(state.fcntl, "flock", wraps=real_flock) as flock,
            self.assertRaises(KeyboardInterrupt),
        ):
            state.wait(self.review.container_dir, timeout_seconds=1)

        self.assertFalse(
            any(
                len(call.args) >= 2 and call.args[1] == state.fcntl.LOCK_UN
                for call in flock.call_args_list
            )
        )

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
final_path = state_dir / "final.txt"
final_path.write_text("No findings.\\n", encoding="utf-8")
final_path.chmod(0o600)
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

    def test_permissive_umask_workspace_completes_final_cleanup(self) -> None:
        fake_runner = pathlib.Path(self.temporary.name) / "umask_runner.py"
        fake_runner.write_text(
            """from pathlib import Path
import sys

state_dir = Path(sys.argv[sys.argv.index("--state-dir") + 1])
final_path = state_dir / "final.txt"
final_path.write_text("No findings.\\n", encoding="utf-8")
final_path.chmod(0o600)
(state_dir / "attempts.json").write_text("[]\\n", encoding="utf-8")
(state_dir / "exit-code").write_text("0\\n", encoding="utf-8")
""",
            encoding="utf-8",
        )
        previous_umask = os.umask(0)
        try:
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
        finally:
            os.umask(previous_umask)

        _loaded, review = state.load_review_state(state_dir)
        self.assertFalse(
            review.workspace_root.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
        self.assertEqual(state.wait(state_dir, timeout_seconds=5), 0)
        exit_code, text = state.final(state_dir)
        self.assertEqual((exit_code, text), (0, "No findings."))
        self.assertFalse(review.workspace_root.exists())

    def test_start_fixes_runner_log_modes_with_owner_masking_umask(self) -> None:
        process = mock.Mock(pid=12345)

        def spawn_with_private_logs(
            *_args: object,
            **kwargs: object,
        ) -> mock.Mock:
            for stream in (kwargs["stdout"], kwargs["stderr"]):
                self.assertEqual(
                    stat.S_IMODE(os.fstat(stream.fileno()).st_mode),
                    0o600,
                )
            return process

        previous_umask = os.umask(0o777)
        try:
            with (
                mock.patch.object(
                    state,
                    "prepare_workspace",
                    side_effect=prepared_workspace(self.review),
                ),
                mock.patch.object(
                    state.subprocess,
                    "Popen",
                    side_effect=spawn_with_private_logs,
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
        finally:
            os.umask(previous_umask)

        try:
            for name in ("runner.stdout.log", "runner.stderr.log"):
                self.assertEqual(
                    stat.S_IMODE((state_dir / name).stat().st_mode),
                    0o600,
                )
        finally:
            state._STARTED_PROCESSES.pop(process.pid, None)

    def test_runner_unblocks_signals_inherited_from_stateful_start(self) -> None:
        state_dir = self.review.container_dir
        write_ready_marker(self.review)
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
        write_ready_marker(self.review)
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
                    write_ready_marker(review)
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
        write_ready_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "claude",
                "egress_consent": "explicit-claude-with-copilot-fallback",
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
        write_ready_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "claude",
                "egress_consent": "explicit-claude-with-copilot-fallback",
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
        sentinel = state_dir / "sentinel"
        stderr = io.StringIO()
        try:
            with held_cleanup_worker_locks(self.review) as lock_fds:
                state_dir.rename(moved_state_dir)
                state_dir.mkdir(mode=0o700)
                sentinel = state_dir / "sentinel"
                sentinel.write_text("keep me\n", encoding="utf-8")
                shutil.copy2(
                    moved_state_dir / state.STATE_MARKER,
                    state_dir / state.STATE_MARKER,
                )
                shutil.copy2(
                    moved_state_dir / state.STATE_FILE,
                    state_dir / state.STATE_FILE,
                )
                with contextlib.redirect_stderr(stderr):
                    exit_code = cleanup_worker.main(
                        [
                            str(state_dir),
                            *(str(descriptor) for descriptor in lock_fds),
                        ]
                    )

            self.assertEqual(exit_code, 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep me\n")
            self.assertFalse((state_dir / "cleanup-error.txt").exists())
            self.assertFalse((moved_state_dir / "cleanup-error.txt").exists())
            self.assertIn("cleanup worker failed", stderr.getvalue())
            self.assertIn(
                "container lock path does not match its open descriptor",
                stderr.getvalue(),
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
                "preparation identity",
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
        write_ready_marker(self.review)
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

    def test_direct_start_rejects_invalid_reviewer_policy_before_preparation(
        self,
    ) -> None:
        cases = (
            ("unknown", None),
            ("claude", None),
            ("claude", "untrusted-consent"),
            ("codex", "double-review"),
        )
        for reviewer, egress_consent in cases:
            with (
                self.subTest(reviewer=reviewer, egress_consent=egress_consent),
                mock.patch.object(state, "prepare_workspace") as prepare,
                self.assertRaises(ReviewError),
            ):
                state.start(
                    script_path=pathlib.Path("runner.py"),
                    repo=self.repo,
                    reviewer=reviewer,
                    base_ref=self.base,
                    head_ref=self.head,
                    prompt_file=None,
                    keep_workspace=False,
                    egress_consent=egress_consent,
                )
            prepare.assert_not_called()

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

        def spawn_with_inherited_lock(arguments, **kwargs):
            self.assertIsNotNone(lock_identity)
            self.assertEqual(
                arguments[arguments.index("--reviewer") + 1],
                "codex",
            )
            self.assertNotIn("--egress-consent", arguments)
            self.assertEqual(len(kwargs["pass_fds"]), 1)
            inherited = os.fstat(kwargs["pass_fds"][0])
            self.assertEqual(
                (inherited.st_dev, inherited.st_ino),
                lock_identity,
            )
            self.assertTrue(state._runner_lock_held(self.review.container_dir))
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
        write_preparing_marker(self.review, self.review.private_cleanup)
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
        write_ready_marker(self.review)
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
        write_ready_marker(self.review)
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
        with held_runner_lock(self.review) as runner_lock:
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
                    lock_fd=runner_lock.fileno(),
                    terminal_process=True,
                    expected_reviewer="codex",
                    expected_egress_consent=None,
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(block.call_args_list, [mock.call(), mock.call()])
        restore.assert_not_called()
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            "0",
        )

    def test_terminal_runner_seals_preflight_receipt_before_releasing_lock(
        self,
    ) -> None:
        state_dir = self.review.container_dir
        with held_runner_lock(self.review) as runner_lock:
            write_json(
                state_dir / state.STATE_FILE,
                {
                    "version": state.STATE_SCHEMA_VERSION,
                    "reviewer": "codex",
                    "egress_consent": None,
                    "workspace": self.review.to_json(),
                },
            )
            write_json(
                state_dir / state.PREFLIGHT_FILE,
                {
                    "private_artifacts": state.PREFLIGHT_PRIVATE_ARTIFACTS,
                    "review_range": f"{self.base}..{self.head}",
                    "scope": state.PREFLIGHT_SCOPE,
                    "secret_delta": self.clean_secret_delta(),
                    "status": state.PREFLIGHT_STATUS,
                },
            )
            with mock.patch.object(
                state,
                "run_review",
                return_value=mock.Mock(returncode=0),
            ) as run_review:
                exit_code = state.run_state(
                    state_dir=state_dir,
                    lock_fd=runner_lock.fileno(),
                    terminal_process=True,
                    expected_reviewer="codex",
                    expected_egress_consent=None,
                )
            self.assertIsNotNone(state._load_state_marker(state_dir).preflight_receipt)

        self.assertEqual(exit_code, 0)
        run_review.assert_called_once_with(
            review=self.review,
            reviewer="codex",
            egress_consent=None,
        )
        admission_exit, summary = state.admission(state_dir)
        self.assertEqual(admission_exit, 0)
        self.assertEqual(summary["status"], "clean")

    def test_terminal_preflight_seal_failure_does_not_change_reviewer_outcome(
        self,
    ) -> None:
        state_dir = self.review.container_dir
        stderr = io.StringIO()
        with held_runner_lock(self.review) as runner_lock:
            write_json(
                state_dir / state.STATE_FILE,
                {
                    "version": state.STATE_SCHEMA_VERSION,
                    "reviewer": "codex",
                    "egress_consent": None,
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
                    "_seal_preflight_receipt",
                    side_effect=OSError("receipt storage unavailable"),
                ),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = state.run_state(
                    state_dir=state_dir,
                    lock_fd=runner_lock.fileno(),
                    terminal_process=True,
                    expected_reviewer="codex",
                    expected_egress_consent=None,
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            "0",
        )
        self.assertFalse((state_dir / "runner-error.txt").exists())
        self.assertIn("receipt storage unavailable", stderr.getvalue())
        summary = state.admission_status(state_dir)
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["failure_class"], "preflight-unsealed")

    def test_terminal_runner_rejects_state_policy_replacement_before_launch(
        self,
    ) -> None:
        state_dir = self.review.container_dir
        with held_runner_lock(self.review) as runner_lock:
            write_json(
                state_dir / state.STATE_FILE,
                {
                    "version": state.STATE_SCHEMA_VERSION,
                    "reviewer": "claude",
                    "egress_consent": "explicit-claude-review",
                    "workspace": self.review.to_json(),
                },
            )
            with mock.patch.object(state, "run_review") as run_review:
                exit_code = state.run_state(
                    state_dir=state_dir,
                    lock_fd=runner_lock.fileno(),
                    terminal_process=True,
                    expected_reviewer="codex",
                    expected_egress_consent=None,
                )

        self.assertEqual(exit_code, 1)
        run_review.assert_not_called()
        self.assertIn(
            "does not match its trusted launch binding",
            (state_dir / "runner-error.txt").read_text(encoding="utf-8"),
        )

    def test_runner_lock_validator_accepts_exact_inherited_lease(self) -> None:
        with held_runner_lock(self.review) as runner_lock:
            os.set_inheritable(runner_lock.fileno(), True)

            state.validate_inherited_runner_lock_lease(
                self.review.container_dir,
                runner_lock.fileno(),
            )

            self.assertFalse(os.get_inheritable(runner_lock.fileno()))

    def test_runner_lock_validator_rejects_unlocked_exact_fd(self) -> None:
        write_ready_marker(self.review)
        with state.open_private_lock_file(
            self.review.container_dir / state.LOCK_FILE,
            label="test unlocked runner lock",
        ) as runner_lock:
            with self.assertRaisesRegex(ReviewError, "not an inherited-held lease"):
                state.validate_inherited_runner_lock_lease(
                    self.review.container_dir,
                    runner_lock.fileno(),
                )

    def test_runner_lock_validator_rejects_independent_description(self) -> None:
        with held_runner_lock(self.review):
            with state.open_private_lock_file(
                self.review.container_dir / state.LOCK_FILE,
                label="test independent runner lock",
            ) as runner_lock:
                with self.assertRaisesRegex(
                    ReviewError,
                    "does not share the inherited-held lock description",
                ):
                    state.validate_inherited_runner_lock_lease(
                        self.review.container_dir,
                        runner_lock.fileno(),
                    )

    def test_runner_lock_validator_rejects_replaced_path(self) -> None:
        lock_path = self.review.container_dir / state.LOCK_FILE
        stale_path = self.review.container_dir / "stale-runner.lock"
        with held_runner_lock(self.review) as runner_lock:
            lock_path.rename(stale_path)
            write_text_atomic(lock_path, "")

            with self.assertRaisesRegex(
                ReviewError,
                "path does not match its open file descriptor",
            ):
                state.validate_inherited_runner_lock_lease(
                    self.review.container_dir,
                    runner_lock.fileno(),
                )

    def test_runner_lock_validator_rejects_arbitrary_and_closed_fds(self) -> None:
        with held_runner_lock(self.review):
            arbitrary_path = self.review.container_dir / "arbitrary.lock"
            write_text_atomic(arbitrary_path, "")
            with arbitrary_path.open("r+b") as arbitrary:
                with self.assertRaisesRegex(
                    ReviewError,
                    "path does not match its open file descriptor",
                ):
                    state.validate_inherited_runner_lock_lease(
                        self.review.container_dir,
                        arbitrary.fileno(),
                    )

            closed_fd = os.open(arbitrary_path, os.O_RDWR | os.O_CLOEXEC)
            os.close(closed_fd)
            with self.assertRaisesRegex(ReviewError, "cannot validate"):
                state.validate_inherited_runner_lock_lease(
                    self.review.container_dir,
                    closed_fd,
                )

    def test_terminal_runner_rejects_missing_lock_before_provider_launch(self) -> None:
        state_dir = self.review.container_dir
        write_ready_marker(self.review)
        write_json(
            state_dir / state.STATE_FILE,
            {
                "version": state.STATE_SCHEMA_VERSION,
                "reviewer": "codex",
                "workspace": self.review.to_json(),
            },
        )
        with (
            mock.patch.object(state, "run_review") as run_review,
            mock.patch.object(
                state.signal,
                "signal",
                return_value=signal.SIG_DFL,
            ),
            mock.patch.object(state, "block_forwarded_signals", return_value=None),
        ):
            exit_code = state.run_state(
                state_dir=state_dir,
                terminal_process=True,
            )

        self.assertEqual(exit_code, 1)
        run_review.assert_not_called()

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

        def read_lock(_path, **_kwargs):
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
        self.write_completed_state()

        with (
            mock.patch.object(
                state.fcntl,
                "flock",
                side_effect=OSError("lock service unavailable"),
            ),
            self.assertRaisesRegex(ReviewError, "cannot probe review runner lock"),
        ):
            state._runner_lock_held(self.review.container_dir)

    def test_status_rejects_replaced_runner_lock_without_terminalizing(self) -> None:
        self.write_completed_state()
        state_dir = self.review.container_dir
        lock_path = state_dir / state.LOCK_FILE
        lock_path.rename(state_dir / "stale-runner.lock")
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        (state_dir / state.EXIT_FILE).unlink()

        with self.assertRaisesRegex(ReviewError, "preparation identity"):
            state.status(state_dir)

        self.assertFalse((state_dir / state.EXIT_FILE).exists())
        self.assertFalse((state_dir / "runner-error.txt").exists())

    def test_runner_lock_probe_rejects_missing_lock(self) -> None:
        self.write_completed_state()
        (self.review.container_dir / state.LOCK_FILE).unlink()

        with self.assertRaisesRegex(ReviewError, "cannot open review runner lock"):
            state._runner_lock_held(self.review.container_dir)

    def test_runner_lock_probe_rejects_symlink(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.LOCK_FILE
        target = self.review.container_dir / "runner-lock-target"
        lock_path.unlink()
        target.write_bytes(b"")
        target.chmod(0o600)
        lock_path.symlink_to(target.name)

        with self.assertRaisesRegex(ReviewError, "cannot open review runner lock"):
            state._runner_lock_held(self.review.container_dir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_runner_lock_probe_rejects_fifo_without_blocking(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.LOCK_FILE
        lock_path.unlink()
        os.mkfifo(lock_path, mode=0o600)

        started = time.monotonic()
        with self.assertRaisesRegex(ReviewError, "not a regular file"):
            state._runner_lock_held(self.review.container_dir)

        self.assertLess(time.monotonic() - started, 1.0)

    def test_runner_lock_probe_rejects_path_swap_after_open(self) -> None:
        self.write_completed_state()
        state_dir = self.review.container_dir
        lock_path = state_dir / state.LOCK_FILE
        moved_lock = state_dir / "runner.lock.original"
        real_open = os.open
        swapped = False

        def swap_after_open(path, flags, *args, **kwargs):
            nonlocal swapped
            descriptor = real_open(path, flags, *args, **kwargs)
            if (
                not swapped
                and path == pathlib.Path(state.LOCK_FILE)
                and kwargs.get("dir_fd") is not None
            ):
                swapped = True
                lock_path.rename(moved_lock)
                lock_path.write_bytes(b"")
                lock_path.chmod(0o600)
            return descriptor

        try:
            with (
                mock.patch.object(state.os, "open", side_effect=swap_after_open),
                self.assertRaisesRegex(ReviewError, "open file descriptor"),
            ):
                state._runner_lock_held(state_dir)
        finally:
            if swapped:
                lock_path.unlink(missing_ok=True)
                moved_lock.rename(lock_path)

    def test_runner_lock_probe_validates_mode_link_count_and_owner(self) -> None:
        self.write_completed_state()
        lock_path = self.review.container_dir / state.LOCK_FILE

        lock_path.chmod(0o620)
        with self.assertRaisesRegex(ReviewError, "mode must be exactly 0600"):
            state._runner_lock_held(self.review.container_dir)

        lock_path.chmod(0o600)
        hardlink = self.review.container_dir / "runner-lock-hardlink"
        os.link(lock_path, hardlink)
        with self.assertRaisesRegex(ReviewError, "exactly one hard link"):
            state._runner_lock_held(self.review.container_dir)
        hardlink.unlink()

        with (
            mock.patch.object(state.os, "getuid", return_value=os.getuid() + 1),
            self.assertRaisesRegex(ReviewError, "owned by the current user"),
        ):
            state._runner_lock_held(self.review.container_dir)

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
