from __future__ import annotations

import pathlib
import signal
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


class ChildEnvironmentTest(unittest.TestCase):
    def test_tail_text_reads_only_a_bounded_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "review.log"
            path.write_bytes(
                b"discarded-line\n" * 10_000
                + b"keep-one\nkeep-two\nkeep-three\n"
            )

            result = common.tail_text(path, line_count=2, byte_count=128)

        self.assertEqual(result, "keep-two\nkeep-three")
        self.assertNotIn("discarded-line", result)

    def test_streamed_command_logs_are_complete_and_memory_capture_is_bounded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"

            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    "import sys; "
                    "sys.stdout.buffer.write(b'H' * 100 + b'T' * 100); "
                    "sys.stderr.buffer.write(b'E' * 200)",
                ),
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                capture_limit_bytes=32,
            )

            self.assertEqual(stdout_path.read_bytes(), b"H" * 100 + b"T" * 100)
            self.assertEqual(stderr_path.read_bytes(), b"E" * 200)
            self.assertTrue(completed.stdout.startswith(b"H" * 16))
            self.assertTrue(completed.stdout.endswith(b"T" * 16))
            self.assertLess(len(completed.stdout), 128)

    def test_logged_command_forwards_termination_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            process = mock.Mock(pid=12345, returncode=None)

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def communicate(*, input=None):
                self.assertIsNone(input)
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)

            process.communicate.side_effect = communicate
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(common, "signal_process_group") as forward,
                mock.patch.object(common, "terminate_process_group") as terminate,
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ForwardedSignal):
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

            forward.assert_called_once_with(process, signal.SIGTERM)
            terminate.assert_called_once_with(
                process,
                initial_signal=signal.SIGTERM,
                signal_already_sent=True,
            )

    def test_outer_cleanup_waits_without_resending_forwarded_signal(self) -> None:
        process = mock.Mock(pid=12345)
        with (
            mock.patch.object(
                common,
                "_process_group_exists",
                side_effect=(True, False, False),
            ),
            mock.patch.object(common, "signal_process_group") as forward,
        ):
            common.terminate_process_group(
                process,
                initial_signal=signal.SIGINT,
                signal_already_sent=True,
                grace_seconds=2.0,
            )

        forward.assert_not_called()
        process.wait.assert_called_once_with(timeout=2.0)

    def test_logged_command_preserves_signal_arriving_during_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            process = mock.Mock(pid=12345, returncode=0)
            process.communicate.return_value = (None, None)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common.signal, "signal", return_value=signal.SIG_DFL),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    return_value=set(),
                ),
                mock.patch.object(
                    common,
                    "consume_pending_forwarded_signal",
                    return_value=signal.SIGQUIT,
                ),
                mock.patch.object(common, "restore_signal_mask") as restore,
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

            self.assertEqual(raised.exception.signum, signal.SIGQUIT)
            restore.assert_called_once_with(set())

    def test_logged_command_defers_signal_during_spawn_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            process = mock.Mock(pid=12345, returncode=None)

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def spawn(*args, **kwargs):
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)
                return process

            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(common, "signal_process_group") as forward,
                mock.patch.object(common, "terminate_process_group") as terminate,
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            forward.assert_called_once_with(process, signal.SIGTERM)
            terminate.assert_called_once_with(
                process,
                initial_signal=signal.SIGTERM,
                signal_already_sent=True,
            )

    def test_passes_only_review_runtime_and_auth_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = pathlib.Path(temporary)
            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": "/home/reviewer",
                        "GH_TOKEN": "github-auth",
                        "REQUESTS_CA_BUNDLE": "/etc/corporate-ca.pem",
                        "CURL_CA_BUNDLE": "/etc/curl-ca.pem",
                        "GIT_SSL_CAINFO": "/etc/git-ca.pem",
                        "UNRELATED_PRIVATE_VALUE": "must-not-pass",
                        "DATABASE_PASSWORD": "must-not-pass",
                    },
                    clear=True,
                ),
            ):
                env = common.child_environment(
                    container_dir=container,
                    passthrough_keys=("GH_TOKEN",),
                )
        self.assertEqual(env["HOME"], "/home/reviewer")
        self.assertEqual(env["GH_TOKEN"], "github-auth")
        self.assertEqual(env["REQUESTS_CA_BUNDLE"], "/etc/corporate-ca.pem")
        self.assertEqual(env["CURL_CA_BUNDLE"], "/etc/curl-ca.pem")
        self.assertEqual(env["GIT_SSL_CAINFO"], "/etc/git-ca.pem")
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", env)
        self.assertNotIn("DATABASE_PASSWORD", env)

    def test_review_environment_does_not_expose_git_runtime_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = pathlib.Path(temporary)
            env = common.child_environment(container_dir=container)

        self.assertEqual(env["PATH"], common.TRUSTED_PATH)
        self.assertNotIn("CODEX_REAL_GIT", env)
        self.assertNotIn("CODEX_ISOLATED_REVIEW_GIT_POLICY", env)
        self.assertNotIn("CODEX_ISOLATED_REVIEW_GIT_SHIM", env)

    def test_explicit_reviewer_path_requires_expected_cli_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            executable = root / "custom-codex"
            executable.write_text(
                "#!/bin/sh\necho 'codex-cli 0.142.4'\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with mock.patch.dict(
                common.os.environ,
                {
                    "HOME": str(root),
                    "CODEX_REVIEW_CODEX_PATH": str(executable),
                },
                clear=True,
            ):
                resolved = common.resolve_reviewer_executable("codex")
        self.assertEqual(resolved, executable.absolute())

    def test_env_shebang_identity_uses_validated_nvm_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            node = home / ".nvm/versions/node/v24.1.0/bin/node"
            node.parent.mkdir(parents=True)
            node.write_text(
                "#!/bin/sh\necho 'claude code 2.1.0'\n",
                encoding="utf-8",
            )
            node.chmod(0o755)
            executable = home / ".local/bin/claude"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            executable.chmod(0o755)

            with mock.patch.dict(
                common.os.environ,
                {
                    "HOME": str(home),
                    "CODEX_REVIEW_CLAUDE_PATH": str(executable),
                },
                clear=True,
            ):
                resolved = common.resolve_reviewer_executable("claude")
                reviewer_path = common.reviewer_executable_path(executable)

        self.assertEqual(resolved, executable.absolute())
        self.assertEqual(
            reviewer_path.split(common.os.pathsep)[:2],
            [str(executable.parent), str(node.parent)],
        )

    @mock.patch.object(common.subprocess, "run")
    def test_claude_identity_probe_enters_bare_mode_before_version(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = common.subprocess.CompletedProcess(
            args=("claude", "--bare", "--version"),
            returncode=0,
            stdout=b"2.1.187 (Claude Code)\n",
            stderr=b"",
        )

        matched = common._executable_identity_matches(
            pathlib.Path("/opt/homebrew/bin/claude"),
            ("claude code",),
        )

        self.assertTrue(matched)
        self.assertEqual(
            run_command.call_args.args[0],
            ("/opt/homebrew/bin/claude", "--bare", "--version"),
        )

    def test_reviewer_path_override_must_be_absolute(self) -> None:
        with mock.patch.dict(
            common.os.environ,
            {"HOME": "/tmp", "CODEX_REVIEW_CODEX_PATH": "relative/codex"},
            clear=True,
        ):
            with self.assertRaises(ReviewError):
                common.resolve_reviewer_executable("codex")

    def test_validated_user_local_install_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            executable = home / ".local/bin/claude"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)

            def matches(path: pathlib.Path, _markers) -> bool:
                return path == executable

            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(
                    common,
                    "_executable_identity_matches",
                    side_effect=matches,
                ),
            ):
                resolved = common.resolve_reviewer_executable("claude")
        self.assertEqual(resolved, executable.absolute())

    def test_present_but_invalid_cli_is_not_treated_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            executable = home / ".local/bin/claude"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            executable.chmod(0o755)
            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[executable],
                ),
                mock.patch.object(
                    common,
                    "_executable_identity_matches",
                    return_value=False,
                ),
                mock.patch.object(
                    common.os,
                    "access",
                    side_effect=lambda path, _mode: pathlib.Path(path) == executable,
                ),
            ):
                with self.assertRaisesRegex(ReviewError, "validation failed"):
                    common.resolve_reviewer_executable("claude")


if __name__ == "__main__":
    unittest.main()
