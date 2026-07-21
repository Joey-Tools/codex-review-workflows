from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime.common import (  # noqa: E402
    ForwardedSignal,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
)
from review_runtime.named_lane import (  # noqa: E402
    NamedLaneGuardError,
    _validate_materialized_gitlink,
    _validate_materialized_symlink,
    main as named_lane_main,
    run_claude,
    validate_worktree,
)


def git(repo: pathlib.Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )
    completed = subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


class NamedLaneGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
        self.temporary = tempfile.TemporaryDirectory(
            prefix="named-lane-test-",
            dir=temp_root,
        )
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "master")
        git(self.repo, "config", "user.name", "Named Lane Test")
        git(self.repo, "config", "user.email", "named-lane@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def commit(self, message: str = "fixture") -> str:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def make_executable(self, source: str) -> pathlib.Path:
        executable = self.root / f"command-{time.monotonic_ns()}.py"
        executable.write_text(
            f"#!{sys.executable}\n{source}",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable.resolve()

    def test_entrypoint_does_not_write_import_bytecode(self) -> None:
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copy2(SCRIPTS / "named_lane_guard", scripts / "named_lane_guard")
        shutil.copytree(
            SCRIPTS / "review_runtime",
            scripts / "review_runtime",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

        subprocess.run(
            (sys.executable, str(scripts / "named_lane_guard"), "--help"),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(list(scripts.rglob("__pycache__")), [])

    def add_gitlink(self, path: str = "vendor") -> str:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        target = self.commit("gitlink target")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            target,
            path,
        )
        git(self.repo, "commit", "-m", "add gitlink")
        return git(self.repo, "rev-parse", "HEAD")

    def add_deinitialized_gitlink(self, path: str = "vendor") -> str:
        source = self.root / "submodule-source"
        source.mkdir()
        git(source, "init", "-b", "master")
        git(source, "config", "user.name", "Named Lane Test")
        git(source, "config", "user.email", "named-lane@example.invalid")
        git(source, "config", "commit.gpgsign", "false")
        (source / "tracked.txt").write_text("submodule\n", encoding="utf-8")
        git(source, "add", "tracked.txt")
        git(source, "commit", "-m", "submodule fixture")
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit("superproject fixture")
        git(
            self.repo,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            str(source),
            path,
        )
        git(self.repo, "commit", "-m", "add registered gitlink")
        git(self.repo, "submodule", "deinit", "-f", "--", path)
        return git(self.repo, "rev-parse", "HEAD")

    def test_safe_internal_source_symlink_is_allowed(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / "target.txt").write_text("tracked\n", encoding="utf-8")
        (self.repo / "source-link").symlink_to("target.txt")
        head = self.commit()

        result = validate_worktree(self.repo.resolve(), head)

        self.assertEqual(result.symlink_count, 1)
        self.assertEqual(result.guidance_count, 1)

    def test_worktree_path_through_symlink_ancestor_is_allowed(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        ancestor = self.root / "ancestor"
        ancestor.symlink_to(self.root, target_is_directory=True)

        result = validate_worktree((ancestor / self.repo.name).absolute(), head)

        self.assertEqual(result.root, self.repo.resolve())

    def test_worktree_path_with_symlink_leaf_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        worktree_link = self.root / "worktree-link"
        worktree_link.symlink_to(self.repo, target_is_directory=True)

        with self.assertRaisesRegex(NamedLaneGuardError, "real directory"):
            validate_worktree(worktree_link.absolute(), head)

    def test_absolute_and_relative_escaping_symlinks_are_rejected(self) -> None:
        for target in (str(self.root / "outside"), "../outside"):
            with self.subTest(target=target):
                link = self.repo / "escape"
                link.unlink(missing_ok=True)
                link.symlink_to(target)
                head = self.commit(f"escape {target}")
                with self.assertRaisesRegex(NamedLaneGuardError, "escapes"):
                    validate_worktree(self.repo.resolve(), head)

    def test_ignored_transitive_link_is_rejected_at_pristine_gate(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("bridge\n", encoding="utf-8")
        (self.repo / "review-link").symlink_to("bridge")
        head = self.commit()
        (self.repo / "bridge").symlink_to(self.root / "outside")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), head)

    def test_guidance_symlink_is_rejected_even_when_it_stays_inside(self) -> None:
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "rules.md").write_text("rules\n", encoding="utf-8")
        (self.repo / "AGENTS.md").symlink_to("docs/rules.md")
        head = self.commit()

        with self.assertRaisesRegex(NamedLaneGuardError, "guidance must"):
            validate_worktree(self.repo.resolve(), head)

    def test_materialized_symlink_mismatch_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / "target.txt").write_text("target\n", encoding="utf-8")
        link = self.repo / "source-link"
        link.symlink_to("target.txt")
        head = self.commit()
        git(self.repo, "update-index", "--assume-unchanged", "source-link")
        link.unlink()
        link.symlink_to("AGENTS.md")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(
            NamedLaneGuardError, "differs from the frozen tree"
        ):
            _validate_materialized_symlink(
                self.repo.resolve(),
                pathlib.PurePosixPath("source-link"),
                "target.txt",
            )
        with self.assertRaisesRegex(NamedLaneGuardError, "assume-unchanged"):
            validate_worktree(self.repo.resolve(), head)

    def test_skip_worktree_index_bit_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        git(self.repo, "update-index", "--skip-worktree", "AGENTS.md")

        with self.assertRaisesRegex(NamedLaneGuardError, "skip-worktree"):
            validate_worktree(self.repo.resolve(), head)

    def test_ignored_artifact_is_rejected_even_when_default_status_is_clean(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        head = self.commit()
        (self.repo / "ignored.txt").write_text("artifact\n", encoding="utf-8")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), head)

    def test_gitlink_may_be_absent_or_an_empty_real_directory(self) -> None:
        head = self.add_deinitialized_gitlink()
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        (self.repo / "vendor").chmod(0o700)
        os.utime(self.repo / "vendor", None)
        empty = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(empty.head_sha, head)

        (self.repo / "vendor").rmdir()
        missing = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(missing.head_sha, head)

    def test_gitlink_rejects_materialized_content_symlink_and_regular_file(
        self,
    ) -> None:
        self.add_gitlink()
        gitlink = self.repo / "vendor"
        gitlink.mkdir()
        (gitlink / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "uninitialized"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

        (gitlink / ".git").unlink()
        gitlink.rmdir()
        gitlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

        gitlink.unlink()
        ancestor = self.repo / "nested"
        ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("nested/vendor")
            )

        gitlink.write_text("not a submodule\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

    def test_initialized_clean_submodule_is_rejected_end_to_end(self) -> None:
        head = self.add_deinitialized_gitlink()
        git(
            self.repo,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "--",
            "vendor",
        )
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

    def test_initialized_unpopulated_submodule_is_rejected_end_to_end(self) -> None:
        head = self.add_deinitialized_gitlink()
        git(
            self.repo,
            "config",
            "submodule.unrelated.url",
            str(self.root / "unrelated"),
        )
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "submodule", "init", "--", "vendor")
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

    def test_guard_does_not_scan_ordinary_file_contents(self) -> None:
        (self.repo / "AGENTS.md").write_text(
            "synthetic-looking text sk-" + "A" * 48 + "\n",
            encoding="utf-8",
        )
        head = self.commit()

        result = validate_worktree(self.repo.resolve(), head)

        self.assertEqual(result.symlink_count, 0)

    def test_exact_head_and_clean_status_are_required(self) -> None:
        tracked = self.repo / "AGENTS.md"
        tracked.write_text("one\n", encoding="utf-8")
        first = self.commit("first")
        tracked.write_text("two\n", encoding="utf-8")
        second = self.commit("second")

        with self.assertRaisesRegex(NamedLaneGuardError, "does not match"):
            validate_worktree(self.repo.resolve(), first)

        tracked.write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), second)

        tracked.write_text("two\n", encoding="utf-8")
        untracked = self.repo / "untracked.txt"
        untracked.write_text("artifact\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), second)

        with self.assertRaisesRegex(NamedLaneGuardError, "full Git object ID"):
            validate_worktree(self.repo.resolve(), "--not-a-revision")

    def test_successful_process_writes_private_bounded_outputs(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(payload)\n"
            "sys.stderr.buffer.write(b'err')\n"
        )
        stdout = self.root / "stdout.bin"
        stderr = self.root / "stderr.bin"

        result = run_claude(
            worktree=self.repo.resolve(),
            stdout_path=stdout,
            stderr_path=stderr,
            command=(str(executable),),
            prompt=b"review",
            timeout_seconds=2.0,
            stream_limit_bytes=64,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(stdout.read_bytes(), b"review")
        self.assertEqual(stderr.read_bytes(), b"err")
        self.assertEqual(stat.S_IMODE(stdout.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(stderr.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "account environment requires POSIX")
    def test_process_receives_only_the_named_lane_environment_allowlist(
        self,
    ) -> None:
        import pwd

        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import json, os, sys\n"
            "json.dump(dict(os.environ), sys.stdout, sort_keys=True)\n"
        )
        stdout = self.root / "environment.json"
        stderr = self.root / "environment.err"
        allowed = {
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "https_proxy": "http://proxy.example.invalid:8080",
            "REQUESTS_CA_BUNDLE": "/etc/example-ca.pem",
        }
        denied = {
            "ANTHROPIC_API_KEY": "secret",
            "CLAUDE_CONFIG_DIR": "/private/claude",
            "GITHUB_TOKEN": "secret",
            "GH_TOKEN": "secret",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "NODE_OPTIONS": "--require=/private/hook.js",
            "NODE_EXTRA_CA_CERTS": "/private/node-ca.pem",
            "LD_PRELOAD": "/private/preload.so",
            "DYLD_INSERT_LIBRARIES": "/private/inject.dylib",
            "TMPDIR": "/private/tmpdir",
            "XDG_CONFIG_HOME": "/private/config",
        }
        with mock.patch.dict(os.environ, {**allowed, **denied}, clear=True):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        child = json.loads(stdout.read_text(encoding="utf-8"))
        account = pwd.getpwuid(os.getuid())
        for key, value in allowed.items():
            self.assertEqual(child[key], value)
        self.assertEqual(child["HOME"], account.pw_dir)
        self.assertEqual(child["USER"], account.pw_name)
        self.assertEqual(child["LOGNAME"], account.pw_name)
        self.assertEqual(child["SHELL"], account.pw_shell)
        self.assertEqual(child["PATH"], TRUSTED_PATH)
        for key in denied:
            self.assertNotIn(key, child)
        self.assertEqual(child["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(child["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(child["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(child["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(child["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(child["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(child["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(child["GIT_ASKPASS"], "/usr/bin/false")
        self.assertEqual(child["GIT_ATTR_NOSYSTEM"], "1")
        self.assertEqual(child["GIT_PAGER"], "cat")
        self.assertEqual(child["PAGER"], "cat")
        self.assertNotIn("GIT_ALLOW_PROTOCOL", child)

    def test_stream_limit_accepts_exact_limit_and_rejects_one_more_byte(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        for size, should_pass in ((4, True), (5, False)):
            with self.subTest(size=size):
                executable = self.make_executable(
                    f"import sys\nsys.stdout.buffer.write(b'x' * {size})\n"
                )
                stdout = self.root / f"stdout-{size}.bin"
                stderr = self.root / f"stderr-{size}.bin"
                if should_pass:
                    result = run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=stdout,
                        stderr_path=stderr,
                        command=(str(executable),),
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=4,
                    )
                    self.assertEqual(result["stdout_bytes"], 4)
                else:
                    with self.assertRaises(ReviewOutputLimitError):
                        run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=stdout,
                            stderr_path=stderr,
                            command=(str(executable),),
                            prompt=b"",
                            timeout_seconds=2.0,
                            stream_limit_bytes=4,
                        )
                    self.assertFalse(stdout.exists())
                    self.assertFalse(stderr.exists())

    @unittest.skipUnless(os.name == "posix", "process-group test requires POSIX")
    def test_timeout_cleans_a_term_resistant_process_group(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.05)\n"
        )
        started = time.monotonic()

        with self.assertRaises(ReviewTimeoutError):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "timeout.out",
                stderr_path=self.root / "timeout.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=0.1,
                stream_limit_bytes=64,
            )

        self.assertLess(time.monotonic() - started, 3.0)

    @unittest.skipUnless(os.name == "posix", "detached-process test requires POSIX")
    def test_process_supervisor_does_not_claim_detached_tree_containment(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        pid_path = self.root / "detached.pid"
        executable = self.make_executable(
            "import os, pathlib, sys, time\n"
            "ready_read, ready_write = os.pipe()\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.close(ready_write)\n"
            "    if os.read(ready_read, 1) != b'1':\n"
            "        os._exit(1)\n"
            "    os.close(ready_read)\n"
            "    os.setsid()\n"
            "    for descriptor in (0, 1, 2):\n"
            "        try:\n"
            "            os.close(descriptor)\n"
            "        except OSError:\n"
            "            pass\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "os.close(ready_read)\n"
            "pid_path = pathlib.Path(sys.argv[1])\n"
            "temporary_path = pid_path.with_suffix('.tmp')\n"
            "temporary_path.write_text(str(pid), encoding='ascii')\n"
            "os.replace(temporary_path, pid_path)\n"
            "os.write(ready_write, b'1')\n"
            "os.close(ready_write)\n"
            "os._exit(0)\n"
        )
        detached_pid: int | None = None
        try:
            result = run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "detached.out",
                stderr_path=self.root / "detached.err",
                command=(str(executable), str(pid_path)),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )
            self.assertTrue(pid_path.exists())
            detached_pid = int(pid_path.read_text(encoding="ascii"))
            os.kill(detached_pid, 0)
            self.assertEqual(result["status"], "complete")
        finally:
            if detached_pid is None:
                try:
                    detached_pid = int(pid_path.read_text(encoding="ascii"))
                except FileNotFoundError:
                    pass
            if detached_pid is not None:
                try:
                    os.kill(detached_pid, 9)
                except ProcessLookupError:
                    pass

    def test_process_rejects_output_inside_worktree_and_nonexact_executable(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")

        with self.assertRaisesRegex(NamedLaneGuardError, "outside the worktree"):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.repo / "stdout",
                stderr_path=self.root / "stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )
        with self.assertRaisesRegex(NamedLaneGuardError, "must be absolute"):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "stdout",
                stderr_path=self.root / "stderr",
                command=(executable.name,),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

    def test_process_rejects_dangling_output_leaf_and_symlink_parent(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        dangling = self.root / "dangling-output"
        dangling.symlink_to(self.root / "missing-target")

        with self.assertRaisesRegex(NamedLaneGuardError, "already exist"):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=dangling,
                stderr_path=self.root / "dangling.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

        real_parent = self.root / "real-output"
        real_parent.mkdir()
        linked_parent = self.root / "linked-output"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(
            NamedLaneGuardError, "real directory|traverse a symlink"
        ):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=linked_parent / "stdout",
                stderr_path=self.root / "linked.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

        real_ancestor = self.root / "real-ancestor"
        nested_parent = real_ancestor / "nested"
        nested_parent.mkdir(parents=True)
        linked_ancestor = self.root / "linked-ancestor"
        linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "traverse a symlink"):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=linked_ancestor / "nested" / "stdout",
                stderr_path=self.root / "ancestor.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

    def test_cli_classifies_bounded_failures_by_subcommand(self) -> None:
        cases = (
            ("deadline", lambda: ReviewTimeoutError("deadline"), 2),
            ("output-limit", lambda: ReviewOutputLimitError("limit"), 2),
            ("output-drain", lambda: ReviewOutputDrainError("drain"), 2),
            ("process-leak", lambda: ReviewProcessLeakError("leak"), 2),
            (
                "forwarded-signal",
                lambda: ForwardedSignal(signal.SIGTERM),
                128 + signal.SIGTERM,
            ),
        )
        commands = (
            (
                "validate-worktree",
                "review_runtime.named_lane.validate_worktree",
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--head",
                    "0" * 40,
                ),
                "blocked-safety",
            ),
            (
                "run-claude",
                "review_runtime.named_lane.run_claude",
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--stdout-path",
                    str(self.root / "stdout"),
                    "--stderr-path",
                    str(self.root / "stderr"),
                    "--",
                    "/usr/bin/false",
                ),
                "inconclusive",
            ),
        )

        for command, target, argv, expected_status in commands:
            for reason, error_factory, expected_returncode in cases:
                with self.subTest(command=command, reason=reason):
                    stderr = io.StringIO()
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(
                            mock.patch(target, side_effect=error_factory())
                        )
                        if command == "run-claude":
                            stdin = mock.Mock()
                            stdin.buffer = io.BytesIO(b"")
                            stack.enter_context(mock.patch.object(sys, "stdin", stdin))
                        stack.enter_context(contextlib.redirect_stderr(stderr))
                        returncode = named_lane_main(argv)

                    self.assertEqual(returncode, expected_returncode)
                    self.assertEqual(
                        json.loads(stderr.getvalue()),
                        {"status": expected_status, "reason": reason},
                    )

    def test_cli_wraps_thread_start_failure_by_subcommand(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        executable = self.make_executable("pass\n")
        commands = (
            (
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--head",
                    head,
                ),
                "blocked-safety",
            ),
            (
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--stdout-path",
                    str(self.root / "thread-start.stdout"),
                    "--stderr-path",
                    str(self.root / "thread-start.stderr"),
                    "--",
                    str(executable),
                ),
                "inconclusive",
            ),
        )

        for argv, expected_status in commands:
            with self.subTest(command=argv[0]):
                stderr = io.StringIO()
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "review_runtime.common.threading.Thread.start",
                            side_effect=RuntimeError("cannot start new thread"),
                        )
                    )
                    if argv[0] == "run-claude":
                        stdin = mock.Mock()
                        stdin.buffer = io.BytesIO(b"")
                        stack.enter_context(mock.patch.object(sys, "stdin", stdin))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    returncode = named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": expected_status, "reason": "output-drain"},
                )


if __name__ == "__main__":
    unittest.main()
