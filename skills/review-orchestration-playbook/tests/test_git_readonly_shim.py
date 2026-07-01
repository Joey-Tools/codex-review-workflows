from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
SHIM = SCRIPTS / "git_readonly_shim"


class ReadonlyGitShimTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self.real_git = pathlib.Path(shutil.which("git") or "/usr/bin/git").resolve()
        subprocess.run(
            (str(self.real_git), "init", "-b", "master", str(self.repo)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            (
                str(self.real_git),
                "-C",
                str(self.repo),
                "config",
                "user.name",
                "Review Test",
            ),
            check=True,
        )
        subprocess.run(
            (
                str(self.real_git),
                "-C",
                str(self.repo),
                "config",
                "user.email",
                "review@example.com",
            ),
            check=True,
        )
        subprocess.run(
            (
                str(self.real_git),
                "-C",
                str(self.repo),
                "config",
                "commit.gpgsign",
                "false",
            ),
            check=True,
        )
        (self.repo / "example.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(
            (str(self.real_git), "-C", str(self.repo), "add", "example.txt"),
            check=True,
        )
        subprocess.run(
            (str(self.real_git), "-C", str(self.repo), "commit", "-m", "Initial"),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.env = os.environ.copy()
        self.env["CODEX_REAL_GIT"] = str(self.real_git)
        self.env["CODEX_ISOLATED_REVIEW_ROOT"] = str(self.repo)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_shim(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(SHIM), *args),
            cwd=self.repo,
            env=self.env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_allows_readonly_status(self) -> None:
        completed = self.run_shim("status", "--short")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_blocks_mutating_subcommands(self) -> None:
        for subcommand in (
            "add",
            "commit",
            "checkout",
            "switch",
            "reset",
            "clean",
            "stash",
        ):
            with self.subTest(subcommand=subcommand):
                completed = self.run_shim(subcommand)
                self.assertEqual(completed.returncode, 126)
                self.assertIn("blocked subcommand", completed.stderr)

    def test_blocks_config_and_external_diff_injection(self) -> None:
        configured = self.run_shim("-c", "alias.status=!echo unsafe", "status")
        self.assertEqual(configured.returncode, 126)
        external = self.run_shim("diff", "--ext-diff")
        self.assertEqual(external.returncode, 126)

    def test_blocks_diff_output_redirection(self) -> None:
        for args in (
            ("diff", "--output", str(self.repo / "leak.diff")),
            ("diff", f"--output={self.repo / 'leak.diff'}"),
        ):
            with self.subTest(args=args):
                completed = self.run_shim(*args)
                self.assertEqual(completed.returncode, 126)
                self.assertIn("blocked subcommand option: --output", completed.stderr)
                self.assertFalse((self.repo / "leak.diff").exists())

    def test_blocks_repository_routing_options(self) -> None:
        for args in (
            ("-C", str(self.repo), "status"),
            (f"--git-dir={self.repo / '.git'}", "status"),
            ("--work-tree", str(self.repo), "status"),
        ):
            with self.subTest(args=args):
                completed = self.run_shim(*args)
                self.assertEqual(completed.returncode, 126)
                self.assertIn("blocked global option", completed.stderr)

    def test_does_not_discover_parent_repository(self) -> None:
        snapshot = self.repo / "snapshot"
        snapshot.mkdir()
        env = dict(self.env)
        env["CODEX_ISOLATED_REVIEW_ROOT"] = str(snapshot)
        completed = subprocess.run(
            (sys.executable, str(SHIM), "status", "--short"),
            cwd=snapshot,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not a git repository", completed.stderr)

    def test_apply_is_allowed_only_in_readonly_summary_mode(self) -> None:
        blocked = self.run_shim("apply", "-")
        self.assertEqual(blocked.returncode, 126)
        readonly = self.run_shim("apply", "--stat", "-")
        self.assertNotEqual(readonly.returncode, 126)


if __name__ == "__main__":
    unittest.main()
