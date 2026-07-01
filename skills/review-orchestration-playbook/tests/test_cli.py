from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import signal
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cli, providers  # noqa: E402
from review_runtime.workspace import ReviewWorkspace  # noqa: E402


def prepared_workspace(review):
    def prepare(**kwargs):
        kwargs["ownership_handoff"](review)
        return review

    return prepare


class ForegroundCleanupTest(unittest.TestCase):
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
            returncode = cli.main(
                ["--base-ref", "a" * 40, "--head-ref", "b" * 40]
            )

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

    def test_handoff_signal_cleans_workspace_owned_by_caller(self) -> None:
        root = pathlib.Path("/tmp/review-handoff")
        review = ReviewWorkspace(
            source_root=root,
            container_dir=root / ".codex-tmp/isolated-review-test",
            workspace_root=root / ".codex-tmp/isolated-review-test/workspace",
            base_ref="a" * 40,
            head_ref="b" * 40,
            diff_file=root
            / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.diff",
            prompt_file=root
            / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.prompt",
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
            review = ReviewWorkspace(
                source_root=root,
                container_dir=root / ".codex-tmp/isolated-review-test",
                workspace_root=root / ".codex-tmp/isolated-review-test/workspace",
                base_ref="a" * 40,
                head_ref="b" * 40,
                diff_file=root
                / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.diff",
                prompt_file=root
                / ".codex-tmp/isolated-review-test/workspace/.codex-review/review.prompt",
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


if __name__ == "__main__":
    unittest.main()
