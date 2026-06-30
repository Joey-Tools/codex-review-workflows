from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
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

state_dir = Path(sys.argv[sys.argv.index("--state-dir") + 1])
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


if __name__ == "__main__":
    unittest.main()
