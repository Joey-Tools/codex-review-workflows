from __future__ import annotations

import os
import pathlib
import signal
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

from review_runtime import state  # noqa: E402
from review_runtime.common import ReviewError, write_json  # noqa: E402
from review_runtime.workspace import cleanup_workspace, prepare_workspace  # noqa: E402


def git(repo: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


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
        cleanup_started = threading.Event()
        allow_cleanup = threading.Event()
        cleanup_calls = 0

        def delayed_cleanup(*args, **kwargs):
            nonlocal cleanup_calls
            cleanup_calls += 1
            cleanup_started.set()
            self.assertTrue(allow_cleanup.wait(timeout=2))
            return cleanup_workspace(*args, **kwargs)

        with (
            mock.patch.object(state, "cleanup_workspace", side_effect=delayed_cleanup),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(state.wait, self.review.container_dir, timeout_seconds=0)
            self.assertTrue(cleanup_started.wait(timeout=2))
            second = executor.submit(state.wait, self.review.container_dir, timeout_seconds=0)
            time.sleep(0.05)
            self.assertEqual(cleanup_calls, 1)
            allow_cleanup.set()
            self.assertEqual(first.result(timeout=2), 0)
            self.assertEqual(second.result(timeout=2), 0)

        self.assertEqual(cleanup_calls, 1)
        self.assertFalse((self.review.container_dir / "cleanup-error.txt").exists())

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
                shim_source=SCRIPTS / "git_readonly_shim",
            )

        self.assertEqual(exit_code, 0)
        unblock.assert_called_once_with()
        self.assertEqual((state_dir / state.EXIT_FILE).read_text().strip(), "0")

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
                return_value=self.review,
            ),
            mock.patch.object(state.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(state, "signal_process_group") as forward,
            mock.patch.object(state, "terminate_process_group") as terminate,
            mock.patch.object(state, "cleanup_workspace"),
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
        )

    def test_start_publisher_failure_cleans_unpublished_runner(self) -> None:
        process = mock.Mock(pid=12345)
        publisher = mock.Mock(side_effect=BrokenPipeError("closed output"))
        with (
            mock.patch.object(
                state,
                "prepare_workspace",
                return_value=self.review,
            ),
            mock.patch.object(state.subprocess, "Popen", return_value=process),
            mock.patch.object(state, "terminate_process_group") as terminate,
            mock.patch.object(state, "cleanup_workspace") as cleanup,
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
        )
        cleanup.assert_called_once_with(self.review, keep_container=False)

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
                shim_source=SCRIPTS / "git_readonly_shim",
            )

        self.assertEqual(exit_code, 128 + signal.SIGTERM)
        self.assertEqual(
            (state_dir / state.EXIT_FILE).read_text(encoding="utf-8").strip(),
            str(128 + signal.SIGTERM),
        )

    def test_final_reports_cleanup_failure_instead_of_clean_result(self) -> None:
        self.write_completed_state()
        with mock.patch.object(
            state,
            "cleanup_workspace",
            return_value="cannot remove worktree",
        ):
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


if __name__ == "__main__":
    unittest.main()
