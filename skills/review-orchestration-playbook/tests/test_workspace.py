from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import ReviewError  # noqa: E402
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
        (self.repo / "example.txt").write_text("one\n", encoding="utf-8")
        git(self.repo, "add", ".gitignore", "example.txt")
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
        self.assertNotIn("Source repository:", prompt)
        self.assertEqual(
            git(review.workspace_root, "rev-parse", "HEAD"),
            self.head,
        )

        cleanup_workspace(review, keep_container=False)
        self.assertFalse(review.container_dir.exists())

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

    def test_invalid_ref_fails_before_creating_a_review_container(self) -> None:
        with self.assertRaises(ReviewError):
            prepare_workspace(
                repo=self.repo,
                base_ref="missing-ref",
                head_ref=self.head,
            )
        review_root = self.repo / ".codex-tmp"
        self.assertFalse(review_root.exists())


if __name__ == "__main__":
    unittest.main()
