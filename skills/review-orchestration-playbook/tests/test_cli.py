from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cli, providers, state  # noqa: E402
from review_runtime.workspace import (  # noqa: E402
    PRIVATE_HELPER_ARTIFACT_NAMES,
    CleanupIdentity,
    PrivateCleanupEvidence,
    ReviewWorkspace,
    cleanup_workspace as cleanup_workspace_impl,
    prepare_workspace as prepare_workspace_impl,
)


def prepared_workspace(review):
    def prepare(**kwargs):
        kwargs["preparation_cleanup_handoff"](
            review.container_dir,
            review.private_cleanup,
        )
        kwargs["ownership_handoff"](review)
        return review

    return prepare


def private_cleanup_evidence(container: pathlib.Path) -> PrivateCleanupEvidence:
    metadata = os.lstat(container)
    return PrivateCleanupEvidence(
        container=CleanupIdentity(device=metadata.st_dev, inode=metadata.st_ino),
        artifacts={
            name: CleanupIdentity(device=1, inode=index + 2)
            for index, name in enumerate(PRIVATE_HELPER_ARTIFACT_NAMES)
        },
    )


class ForegroundCleanupTest(unittest.TestCase):
    def test_stateful_admission_always_prints_json_and_returns_embedded_code(
        self,
    ) -> None:
        state_dir = pathlib.Path("/tmp/isolated-review-state")
        summary = {
            "schema_version": 1,
            "status": "inconclusive",
            "exit_code": 75,
            "review_range": f"{'a' * 40}..{'b' * 40}",
            "evidence_path": str(state_dir / "preflight.json"),
            "failure_class": "secret-count-incomplete",
            "secret_delta": None,
        }
        stdout = io.StringIO()
        with (
            mock.patch.object(cli, "admission", return_value=(75, summary)),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = cli.main(
                ["stateful", "admission", "--state-dir", str(state_dir)]
            )

        self.assertEqual(returncode, 75)
        self.assertEqual(json.loads(stdout.getvalue()), summary)

    def test_stateful_status_stays_success_when_admission_is_blocked(self) -> None:
        state_dir = pathlib.Path("/tmp/isolated-review-state")
        summary = {"admission": {"status": "blocked", "exit_code": 1}}
        stdout = io.StringIO()
        with (
            mock.patch.object(cli, "status", return_value=summary),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = cli.main(["stateful", "status", "--state-dir", str(state_dir)])

        self.assertEqual(returncode, 0)
        self.assertEqual(json.loads(stdout.getvalue()), summary)

    def test_internal_runner_forwards_inherited_lock_fd(self) -> None:
        state_dir = pathlib.Path("/tmp/isolated-review-state")
        with (
            mock.patch.object(cli, "run_state", return_value=17) as run_state,
            mock.patch.object(cli.os, "_exit", side_effect=SystemExit(17)),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main(
                [
                    "_run-state",
                    "--state-dir",
                    str(state_dir),
                    "--lock-fd",
                    "41",
                    "--reviewer",
                    "claude",
                    "--egress-consent",
                    "explicit-claude-with-copilot-fallback",
                ]
            )

        self.assertEqual(raised.exception.code, 17)
        run_state.assert_called_once_with(
            state_dir=state_dir,
            lock_fd=41,
            terminal_process=True,
            expected_reviewer="claude",
            expected_egress_consent="explicit-claude-with-copilot-fallback",
        )

    def test_stateful_cleanup_dispatches_bounded_cleanup(self) -> None:
        state_dir = pathlib.Path("/tmp/isolated-review-state")
        with mock.patch.object(cli, "cleanup_state", return_value=0) as cleanup:
            returncode = cli.main(
                ["stateful", "cleanup", "--state-dir", str(state_dir)]
            )

        self.assertEqual(returncode, 0)
        cleanup.assert_called_once_with(
            state_dir,
            timeout_seconds=cli.FINAL_CLEANUP_TIMEOUT_SECONDS,
        )

    def test_stateful_wait_rejects_nan_timeout(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            returncode = cli.main(
                [
                    "stateful",
                    "wait",
                    "--state-dir",
                    "/does-not-need-to-exist",
                    "--timeout-seconds",
                    "nan",
                ]
            )

        self.assertEqual(returncode, 2)
        self.assertIn("non-negative finite number", stderr.getvalue())

    def test_main_reports_signal_cleanup_detail(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                cli,
                "_run_foreground",
                side_effect=cli.ForwardedSignal(
                    signal.SIGTERM,
                    detail="evidence retained at /tmp/review: permission denied",
                ),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = cli.main(["--base-ref", "a" * 40, "--head-ref", "b" * 40])

        self.assertEqual(returncode, 128 + signal.SIGTERM)
        self.assertIn("evidence retained at /tmp/review", stderr.getvalue())

    def test_signal_handler_covers_workspace_preparation(self) -> None:
        args = argparse.Namespace(
            repo=".",
            reviewer="codex",
            base_ref="a" * 40,
            head_ref="b" * 40,
            prompt_file=None,
            keep_workspace=False,
            egress_consent=None,
        )
        handlers = {}

        def install_handler(signum, handler):
            previous = handlers.get(signum, signal.SIG_DFL)
            handlers[signum] = handler
            return previous

        def cancelled_prepare(**_kwargs):
            handler = handlers[signal.SIGTERM]
            handler(signal.SIGTERM, None)
            self.fail("signal handler should interrupt workspace preparation")

        with (
            mock.patch.object(cli.signal, "signal", side_effect=install_handler),
            mock.patch.object(
                cli,
                "prepare_workspace",
                side_effect=cancelled_prepare,
            ),
            mock.patch.object(cli, "run_review") as run_review,
            mock.patch.object(cli, "block_forwarded_signals", return_value=set()),
            mock.patch.object(
                cli,
                "consume_pending_forwarded_signal",
                return_value=None,
            ),
            mock.patch.object(cli, "restore_signal_mask"),
            self.assertRaises(cli.ForwardedSignal) as raised,
        ):
            cli._run_foreground(args)

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        run_review.assert_not_called()

    def test_foreground_guard_holds_runner_and_cleanup_locks_until_zero_residue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary) / "repo"
            repo.mkdir()
            subprocess.run(
                ("git", "init", "-b", "master", str(repo)),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for key, value in (
                ("user.name", "Review Test"),
                ("user.email", "review@example.com"),
                ("commit.gpgsign", "false"),
            ):
                subprocess.run(
                    ("git", "-C", str(repo), "config", key, value),
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            (repo / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
            (repo / "example.txt").write_text("one\n", encoding="utf-8")
            subprocess.run(
                ("git", "-C", str(repo), "add", ".gitignore", "example.txt"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ("git", "-C", str(repo), "commit", "-m", "Initial"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            base = subprocess.run(
                ("git", "-C", str(repo), "rev-parse", "HEAD"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            (repo / "example.txt").write_text("two\n", encoding="utf-8")
            subprocess.run(
                ("git", "-C", str(repo), "add", "example.txt"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ("git", "-C", str(repo), "commit", "-m", "Update"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            head = subprocess.run(
                ("git", "-C", str(repo), "rev-parse", "HEAD"),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            captured: list[ReviewWorkspace] = []
            review = prepare_workspace_impl(
                repo=repo,
                base_ref=base,
                head_ref=head,
                ownership_handoff=captured.append,
            )
            self.assertEqual(captured, [review])

            args = argparse.Namespace(
                repo=str(repo),
                reviewer="codex",
                base_ref=base,
                head_ref=head,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )

            def prepare_with_guard(**kwargs):
                kwargs["preparation_cleanup_handoff"](
                    review.container_dir,
                    review.private_cleanup,
                )
                self.assertEqual(
                    state._load_state_marker(review.container_dir).phase,
                    "preparing",
                )
                kwargs["ownership_handoff"](review)
                self.assertEqual(
                    state._load_state_marker(review.container_dir).phase,
                    "ready",
                )
                return review

            def review_with_live_cleanup_probe(**_kwargs):
                self.assertFalse((review.container_dir / state.STATE_FILE).exists())
                self.assertEqual(
                    state.cleanup(review.container_dir, timeout_seconds=0),
                    3,
                )
                (review.container_dir / "final.txt").write_text(
                    "No findings.\n",
                    encoding="utf-8",
                )
                return providers.Outcome(0, "No findings.", tuple())

            def cleanup_with_lock_probe(prepared, *, keep_container):
                self.assertIs(prepared, review)
                self.assertFalse(keep_container)
                self.assertTrue(state._runner_lock_held(review.container_dir))
                probe, lock_error = state.open_bound_review_lock(
                    review.container_dir,
                    expected=review.private_cleanup,
                    name=state.CLEANUP_LOCK_FILE,
                )
                self.assertIsNone(lock_error)
                assert probe is not None
                try:
                    self.assertFalse(
                        state._acquire_cleanup_lock(
                            probe,
                            deadline=time.monotonic(),
                        )
                    )
                finally:
                    probe.close()
                return cleanup_workspace_impl(prepared, keep_container=False)

            with (
                mock.patch.object(
                    cli,
                    "prepare_workspace",
                    side_effect=prepare_with_guard,
                ),
                mock.patch.object(
                    cli,
                    "run_review",
                    side_effect=review_with_live_cleanup_probe,
                ) as run_review,
                mock.patch.object(
                    cli,
                    "cleanup_workspace",
                    side_effect=cleanup_with_lock_probe,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                returncode = cli._run_foreground(args)

            self.assertEqual(returncode, 0)
            run_review.assert_called_once_with(
                review=review,
                reviewer="codex",
                egress_consent=None,
            )
            self.assertFalse(review.container_dir.exists())

    def test_handoff_signal_cleans_workspace_owned_by_caller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            container = root / ".codex-tmp/isolated-review-test"
            container.mkdir(mode=0o700, parents=True)
            review = ReviewWorkspace(
                source_root=root,
                container_dir=container,
                workspace_root=container / "workspace",
                base_ref="a" * 40,
                head_ref="b" * 40,
                diff_file=container / "workspace/.codex-review/review.diff",
                prompt_file=container / "workspace/.codex-review/review.prompt",
                private_cleanup=private_cleanup_evidence(container),
            )
            args = argparse.Namespace(
                repo=str(root),
                reviewer="codex",
                base_ref=review.base_ref,
                head_ref=review.head_ref,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )

            def handoff_then_signal(**kwargs):
                kwargs["preparation_cleanup_handoff"](
                    review.container_dir,
                    review.private_cleanup,
                )
                kwargs["ownership_handoff"](review)
                raise cli.ForwardedSignal(signal.SIGTERM)

            with (
                mock.patch.object(
                    cli,
                    "prepare_workspace",
                    side_effect=handoff_then_signal,
                ),
                mock.patch.object(cli, "run_review") as run_review,
                mock.patch.object(
                    cli,
                    "cleanup_workspace",
                    return_value=None,
                ) as cleanup,
                self.assertRaises(cli.ForwardedSignal) as raised,
            ):
                cli._run_foreground(args)

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        run_review.assert_not_called()
        cleanup.assert_called_once_with(review, keep_container=True)

    def test_success_becomes_failure_when_workspace_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            container = root / ".codex-tmp/isolated-review-test"
            container.mkdir(mode=0o700, parents=True)
            review = ReviewWorkspace(
                source_root=root,
                container_dir=container,
                workspace_root=container / "workspace",
                base_ref="a" * 40,
                head_ref="b" * 40,
                diff_file=root
                / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.diff",
                prompt_file=root
                / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.prompt",
                private_cleanup=private_cleanup_evidence(container),
            )
            args = argparse.Namespace(
                repo=str(root),
                reviewer="codex",
                base_ref=review.base_ref,
                head_ref=review.head_ref,
                prompt_file=None,
                keep_workspace=False,
                egress_consent=None,
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    cli,
                    "prepare_workspace",
                    side_effect=prepared_workspace(review),
                ),
                mock.patch.object(
                    cli,
                    "run_review",
                    return_value=providers.Outcome(0, "No findings.", tuple()),
                ),
                mock.patch.object(
                    cli, "cleanup_workspace", return_value="cannot remove worktree"
                ),
                contextlib.redirect_stderr(stderr),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                returncode = cli._run_foreground(args)
        self.assertEqual(returncode, 1)
        self.assertIn("cleanup failed", stderr.getvalue())
        self.assertIn("isolated-review-test", stderr.getvalue())

    def test_keep_workspace_retries_private_artifact_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            container = root / ".codex-tmp/isolated-review-test"
            container.mkdir(mode=0o700, parents=True)
            review = ReviewWorkspace(
                source_root=root,
                container_dir=container,
                workspace_root=container / "workspace",
                base_ref="a" * 40,
                head_ref="b" * 40,
                diff_file=container / "workspace/.codex-review/review.diff",
                prompt_file=container / "workspace/.codex-review/review.prompt",
                private_cleanup=private_cleanup_evidence(container),
            )
            args = argparse.Namespace(
                repo=str(root),
                reviewer="codex",
                base_ref=review.base_ref,
                head_ref=review.head_ref,
                prompt_file=None,
                keep_workspace=True,
                egress_consent=None,
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    cli,
                    "prepare_workspace",
                    side_effect=prepared_workspace(review),
                ),
                mock.patch.object(
                    cli,
                    "run_review",
                    return_value=providers.Outcome(0, "No findings.", tuple()),
                ),
                mock.patch.object(
                    cli,
                    "remove_private_review_artifacts",
                    return_value="unlink denied",
                ) as remove_private,
                contextlib.redirect_stderr(stderr),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                returncode = cli._run_foreground(args)

        self.assertEqual(returncode, 1)
        remove_private.assert_called_once_with(
            review.container_dir,
            expected=review.private_cleanup,
        )
        self.assertIn("cleanup failed", stderr.getvalue())
        self.assertIn("kept review workspace", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
