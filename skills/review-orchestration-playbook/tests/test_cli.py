from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cli, providers  # noqa: E402
from review_runtime.workspace import ReviewWorkspace  # noqa: E402


class ForegroundCleanupTest(unittest.TestCase):
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
                mock.patch.object(cli, "prepare_workspace", return_value=review),
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
                returncode = cli._run_foreground(
                    args,
                    script_path=SCRIPTS / "isolated_review",
                )
        self.assertEqual(returncode, 1)
        self.assertIn("cleanup failed", stderr.getvalue())
        self.assertIn("isolated-review-test", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
