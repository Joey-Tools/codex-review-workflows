from __future__ import annotations

import os
import pathlib
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


class ChildEnvironmentTest(unittest.TestCase):
    def test_atomic_writers_force_owner_mode_under_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path_artifact = root / "path-artifact.txt"
            directory_descriptor = os.open(root, os.O_RDONLY)
            previous_umask = os.umask(0o777)
            try:
                common.write_text_atomic(path_artifact, "path artifact\n")
                common.write_bytes_atomic_at(
                    directory_descriptor,
                    "bound-artifact.txt",
                    b"bound artifact\n",
                )
            finally:
                os.umask(previous_umask)
                os.close(directory_descriptor)

            self.assertEqual(
                path_artifact.read_text(encoding="utf-8"), "path artifact\n"
            )
            self.assertEqual(
                (root / "bound-artifact.txt").read_bytes(),
                b"bound artifact\n",
            )
            self.assertEqual(path_artifact.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (root / "bound-artifact.txt").stat().st_mode & 0o777,
                0o600,
            )

    def test_path_atomic_writer_closes_descriptor_when_fchmod_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            descriptor = -1

            def fail_fchmod(fd: int, _mode: int) -> None:
                nonlocal descriptor
                descriptor = fd
                raise OSError("forced fchmod failure")

            with (
                mock.patch.object(common.os, "fchmod", side_effect=fail_fchmod),
                self.assertRaisesRegex(OSError, "forced fchmod failure"),
            ):
                common.write_text_atomic(root / "artifact.txt", "artifact\n")

            self.assertGreaterEqual(descriptor, 0)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual(list(root.iterdir()), [])

    def test_tail_text_reads_only_a_bounded_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "review.log"
            path.write_bytes(
                b"discarded-line\n" * 10_000 + b"keep-one\nkeep-two\nkeep-three\n"
            )

            result = common.tail_text(path, line_count=2, byte_count=128)

        self.assertEqual(result, "keep-two\nkeep-three")
        self.assertNotIn("discarded-line", result)

    def test_logged_command_timeout_terminates_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(ReviewError, "command timed out"):
                common.run(
                    (sys.executable, "-c", "import time; time.sleep(5)"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=0.05,
                )

    @mock.patch.object(common.subprocess, "run")
    def test_unlogged_timeout_is_rejected_before_launch(
        self, subprocess_run: mock.Mock
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "requires logged output paths"):
            common.run((sys.executable, "-c", "pass"), timeout_seconds=1)

        subprocess_run.assert_not_called()

    def test_logged_command_output_file_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        "import os; os.write(1, b'x' * 1048576)",
                    ),
                    stdout_path=stdout_path,
                    stderr_path=root / "stderr.log",
                    capture_limit_bytes=4096,
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                )
            output_size = stdout_path.stat().st_size

        self.assertLessEqual(output_size, 4096)

    def test_logged_command_reads_held_files_after_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            attempts = root / "attempts"
            attempts.mkdir()
            retained = root / "attempts-retained"
            stdout_path = attempts / "stdout.log"
            stderr_path = attempts / "stderr.log"
            with (
                stdout_path.open("w+b") as stdout_file,
                stderr_path.open("w+b") as stderr_file,
            ):

                def replace_paths() -> None:
                    attempts.rename(retained)
                    attempts.mkdir()
                    stdout_path.write_bytes(b"forged clean verdict")
                    stderr_path.write_bytes(b"")

                completed = common.run(
                    (
                        sys.executable,
                        "-c",
                        "import os; os.write(1, b'real finding')",
                    ),
                    stdout_file=stdout_file,
                    stderr_file=stderr_file,
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                    on_process_started=replace_paths,
                )

            self.assertEqual(completed.stdout, b"real finding")
            self.assertEqual(stdout_path.read_bytes(), b"forged clean verdict")
            self.assertEqual(
                (retained / "stdout.log").read_bytes(),
                b"real finding",
            )

    def test_bounded_capture_enforces_independent_stream_limits(self) -> None:
        with self.assertRaises(common.ReviewOutputLimitError):
            common.run_bounded_capture(
                (
                    sys.executable,
                    "-c",
                    "import os; os.write(2, b'x' * 2048)",
                ),
                timeout_seconds=5,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=1024,
            )

    def test_output_limit_is_detected_while_stream_remains_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        ("import os,time; os.write(1, b'x' * 4097); time.sleep(5)"),
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    capture_limit_bytes=4096,
                    timeout_seconds=1,
                    output_file_limit_bytes=4096,
                )

    @unittest.skipUnless(hasattr(signal, "SIGTERM"), "requires SIGTERM")
    def test_output_limit_kills_process_that_ignores_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,signal,time; "
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                            "os.write(1, b'x' * 4097); "
                            "time.sleep(5)"
                        ),
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    capture_limit_bytes=4096,
                    timeout_seconds=2,
                    output_file_limit_bytes=4096,
                )

    @mock.patch.object(common.subprocess, "Popen")
    def test_output_file_limit_requires_timeout_before_launch(
        self, popen: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(ReviewError, "requires timeout_seconds"):
                common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    output_file_limit_bytes=4096,
                )

        popen.assert_not_called()

    @mock.patch.object(common.subprocess, "Popen")
    def test_invalid_bounded_output_arguments_preserve_existing_logs(
        self, popen: mock.Mock
    ) -> None:
        cases = (({"output_file_limit_bytes": 0}, "must be positive"),)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, (arguments, message) in enumerate(cases):
                with self.subTest(message=message):
                    stdout_path = root / f"stdout-{index}.log"
                    stderr_path = root / f"stderr-{index}.log"
                    stdout_path.write_bytes(b"existing stdout")
                    stderr_path.write_bytes(b"existing stderr")

                    with self.assertRaisesRegex(ReviewError, message):
                        common.run(
                            (sys.executable, "-c", "pass"),
                            stdout_path=stdout_path,
                            stderr_path=stderr_path,
                            timeout_seconds=5,
                            **arguments,
                        )

                    self.assertEqual(stdout_path.read_bytes(), b"existing stdout")
                    self.assertEqual(stderr_path.read_bytes(), b"existing stderr")

        popen.assert_not_called()

    def test_bounded_logged_output_supports_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    "import os,sys; os.write(1, sys.stdin.buffer.read())",
                ),
                stdin=b"review prompt",
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
                timeout_seconds=5,
                output_file_limit_bytes=4096,
            )

        self.assertEqual(completed.stdout, b"review prompt")

    def test_bounded_capture_supports_mutable_stdin(self) -> None:
        payload = bytearray(b"mutable review prompt")
        completed = common.run_bounded_capture(
            (
                sys.executable,
                "-c",
                "import os,sys; os.write(1, sys.stdin.buffer.read())",
            ),
            stdin=payload,
            timeout_seconds=5,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
        )

        self.assertEqual(completed.stdout, payload)
        payload[:] = b"\x00" * len(payload)
        completed.stdout[:] = b"\x00" * len(completed.stdout)
        completed.stderr[:] = b"\x00" * len(completed.stderr)

    @mock.patch.object(common.threading, "Thread")
    def test_failed_drain_thread_start_is_not_joined(
        self, thread_factory: mock.Mock
    ) -> None:
        thread = thread_factory.return_value
        thread.start.side_effect = RuntimeError("thread start failed")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "thread start failed"):
                common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                )

        thread.join.assert_not_called()

    def test_drain_thread_io_failure_is_propagated(self) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_process_group_exists", return_value=False),
                mock.patch.object(common, "signal_process_group") as terminate,
                mock.patch.object(common.os, "set_blocking"),
                mock.patch.object(
                    common.select, "select", return_value=([123], [], [])
                ),
                mock.patch.object(
                    common.os, "read", side_effect=OSError("read failed")
                ),
            ):
                with self.assertRaises(common.ReviewOutputDrainError):
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=5,
                        output_file_limit_bytes=4096,
                    )

        self.assertGreaterEqual(terminate.call_count, 1)
        terminate.assert_any_call(process, signal.SIGTERM)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_timeout_does_not_wait_for_detached_descendant_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            child_pid_path = root / "child.pid"
            started = time.monotonic()
            try:
                with self.assertRaises(common.ReviewTimeoutError):
                    common.run(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import os,pathlib,sys,time\n"
                                "pid = os.fork()\n"
                                "if pid == 0:\n"
                                "    os.setsid()\n"
                                "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                                "    time.sleep(3)\n"
                                "    os._exit(0)\n"
                                "time.sleep(3)\n"
                            ),
                            str(child_pid_path),
                        ),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=0.2,
                        output_file_limit_bytes=4096,
                    )
            finally:
                if child_pid_path.exists():
                    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

            self.assertLess(time.monotonic() - started, 1.5)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_logged_command_allows_prompt_descendant_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "import os,time; pid=os.fork(); "
                        "os._exit(0) if pid else (time.sleep(0.1), os._exit(0))"
                    ),
                ),
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
                timeout_seconds=5,
                output_file_limit_bytes=4096,
            )

        self.assertEqual(completed.returncode, 0)

    @mock.patch.object(
        common,
        "_linux_process_group_has_live_members",
        return_value=False,
    )
    @mock.patch.object(common.os, "killpg")
    def test_process_group_ignores_zombie_only_linux_group(
        self,
        _killpg: mock.Mock,
        live_members: mock.Mock,
    ) -> None:
        with mock.patch.object(common.sys, "platform", "linux"):
            self.assertFalse(common._process_group_exists(12345))

        live_members.assert_called_once_with(12345)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_logged_command_rejects_descendant_holding_output_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(common.ReviewProcessLeakError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,time; pid=os.fork(); "
                            "os._exit(0) if pid else (time.sleep(5), os._exit(0))"
                        ),
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                )

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

    def test_logged_command_does_not_publish_failed_process_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            on_process_started = mock.Mock()
            with (
                mock.patch.object(
                    common.subprocess,
                    "Popen",
                    side_effect=OSError("spawn failed"),
                ),
                mock.patch.object(
                    common.signal,
                    "signal",
                    return_value=signal.SIG_DFL,
                ),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    return_value=None,
                ),
            ):
                with self.assertRaisesRegex(OSError, "spawn failed"):
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_started=on_process_started,
                    )

            on_process_started.assert_not_called()

    def test_logged_command_publishes_successful_process_start_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            events: list[str] = []
            process = mock.Mock(pid=12345, returncode=0)

            def communicate(*, input=None):
                self.assertIsNone(input)
                events.append("communicate")

            process.communicate.side_effect = communicate

            def spawn(*args, **kwargs):
                events.append("spawn")
                return process

            on_process_started = mock.Mock(side_effect=lambda: events.append("started"))
            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(
                    common.signal,
                    "signal",
                    return_value=signal.SIG_DFL,
                ),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    return_value=None,
                ),
            ):
                common.run(
                    ("reviewer",),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_started=on_process_started,
                )

            self.assertEqual(events, ["spawn", "started", "communicate"])
            on_process_started.assert_called_once_with()

    def test_logged_command_publishes_start_before_pending_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            events: list[str] = []
            installed: dict[signal.Signals, object] = {}
            process = mock.Mock(pid=12345, returncode=None)

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def spawn(*args, **kwargs):
                events.append("spawn")
                return process

            def publish_process_start():
                events.append("hook")
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)
                events.append("started")

            on_process_started = mock.Mock(side_effect=publish_process_start)
            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(
                    common,
                    "signal_process_group",
                    side_effect=lambda *_args: events.append("forward"),
                ),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    return_value=None,
                ),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_started=on_process_started,
                    )

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertEqual(
                events[:4],
                ["spawn", "hook", "started", "forward"],
            )
            on_process_started.assert_called_once_with()

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
                        "https_proxy": "http://corporate-proxy:8080",
                        "no_proxy": "localhost",
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
        self.assertEqual(env["https_proxy"], "http://corporate-proxy:8080")
        self.assertEqual(env["no_proxy"], "localhost")
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

            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": str(home),
                        "CODEX_REVIEW_CLAUDE_PATH": str(executable),
                    },
                    clear=True,
                ),
            ):
                resolved = common.resolve_reviewer_executable("claude")
        self.assertEqual(resolved, executable.absolute())

    def test_deferred_identity_continues_past_invalid_claude_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            invalid = home / "invalid/claude"
            valid = home / "valid/claude"
            for executable in (invalid, valid):
                executable.parent.mkdir(parents=True)
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o755)
            validated: list[pathlib.Path] = []

            def validate(candidate: pathlib.Path) -> None:
                validated.append(candidate)
                if candidate == invalid:
                    raise common.InvalidReviewerExecutable("not Claude Code")

            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[invalid, valid],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common.os,
                    "access",
                    side_effect=lambda path, _mode: pathlib.Path(path)
                    in {invalid, valid},
                ),
            ):
                resolved = common.resolve_reviewer_executable(
                    "claude", candidate_validator=validate
                )

        self.assertEqual(resolved, valid.absolute())
        self.assertEqual(validated, [invalid.absolute(), valid.absolute()])

    def test_invalid_explicit_claude_override_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = pathlib.Path(temporary) / "claude"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)

            with mock.patch.dict(
                common.os.environ,
                {
                    "HOME": temporary,
                    "CODEX_REVIEW_CLAUDE_PATH": str(executable),
                },
                clear=True,
            ):
                with self.assertRaisesRegex(ReviewError, "sandboxed claude validation"):
                    common.resolve_reviewer_executable(
                        "claude",
                        candidate_validator=mock.Mock(
                            side_effect=common.InvalidReviewerExecutable(
                                "not Claude Code"
                            )
                        ),
                    )

    def test_all_invalid_deferred_candidates_are_not_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            executable = home / ".local/bin/claude"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)

            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[executable],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common.os,
                    "access",
                    side_effect=lambda path, _mode: pathlib.Path(path) == executable,
                ),
            ):
                with self.assertRaisesRegex(ReviewError, "validation failed"):
                    common.resolve_reviewer_executable(
                        "claude",
                        candidate_validator=mock.Mock(
                            side_effect=common.InvalidReviewerExecutable(
                                "not Claude Code"
                            )
                        ),
                    )

    def test_non_utf8_shebang_dependency_fails_closed_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = pathlib.Path(temporary) / "claude"
            executable.write_bytes(b"#!/\xff\n")

            dependencies = common.reviewer_executable_dependencies(executable)

        self.assertIn(executable.absolute(), dependencies)
        self.assertTrue(
            all(
                dependency in {executable.absolute(), executable.resolve()}
                for dependency in dependencies
            )
        )

    def test_deferred_identity_does_not_swallow_probe_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            executable = home / "claude"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)

            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[executable],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common.os,
                    "access",
                    side_effect=lambda path, _mode: pathlib.Path(path) == executable,
                ),
            ):
                with self.assertRaises(common.ReviewTimeoutError):
                    common.resolve_reviewer_executable(
                        "claude",
                        candidate_validator=mock.Mock(
                            side_effect=common.ReviewTimeoutError("probe timed out")
                        ),
                    )

    def test_present_but_invalid_codex_cli_is_not_treated_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            executable = home / ".local/bin/codex"
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
                    common.resolve_reviewer_executable("codex")


if __name__ == "__main__":
    unittest.main()
