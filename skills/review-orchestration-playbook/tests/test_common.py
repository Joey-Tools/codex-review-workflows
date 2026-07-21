from __future__ import annotations

import errno
import math
import os
import pathlib
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on native Windows
    resource = None  # type: ignore[assignment]


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


class CandidateInspectionInconclusive(ReviewError):
    pass


class ChildEnvironmentTest(unittest.TestCase):
    def test_strict_json_rejects_recursive_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            common.strict_json_loads('{"outer":{"value":1,"value":2}}')

    def test_strict_json_rejects_nonstandard_constants(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with (
                self.subTest(constant=constant),
                self.assertRaisesRegex(
                    ValueError,
                    "non-standard JSON constant",
                ),
            ):
                common.strict_json_loads(f'{{"value":{constant}}}')

    def test_strict_json_rejects_overflowed_floats(self) -> None:
        for number in ("1e10000", "-1e10000"):
            with (
                self.subTest(number=number),
                self.assertRaisesRegex(ValueError, "non-finite JSON number"),
            ):
                common.strict_json_loads(f'{{"outer":[{{"value":{number}}}]}}')

    def test_strict_json_accepts_finite_float_boundaries(self) -> None:
        parsed = common.strict_json_loads(
            '{"positive":1.7976931348623157e308,'
            '"negative":-1.7976931348623157e308,"subnormal":5e-324}'
        )

        self.assertTrue(all(math.isfinite(value) for value in parsed.values()))
        self.assertEqual(parsed["positive"], sys.float_info.max)
        self.assertEqual(parsed["negative"], -sys.float_info.max)
        self.assertGreater(parsed["subnormal"], 0.0)

    def test_strict_json_bounds_integer_literal_digits(self) -> None:
        boundary = "9" * common.STRICT_JSON_MAX_INTEGER_DIGITS
        parsed = common.strict_json_loads(
            f'{{"positive":{boundary},"negative":-{boundary}}}'
        )

        self.assertEqual(len(str(parsed["positive"])), len(boundary))
        self.assertEqual(len(str(abs(parsed["negative"]))), len(boundary))

        oversized = "9" * (common.STRICT_JSON_MAX_INTEGER_DIGITS + 1)
        for number in (oversized, f"-{oversized}"):
            with (
                self.subTest(number=number[:2]),
                self.assertRaisesRegex(ValueError, "integer exceeds"),
            ):
                common.strict_json_loads(f'{{"value":{number}}}')

    def test_strict_json_recursively_rejects_decoder_nonfinite_values(self) -> None:
        with (
            mock.patch.object(
                common.json,
                "loads",
                return_value={"outer": [float("inf")]},
            ),
            self.assertRaisesRegex(ValueError, "non-finite JSON number"),
        ):
            common.strict_json_loads("{}")

    def test_strict_json_rejects_over_nested_payload(self) -> None:
        payload = (
            "[" * (common.STRICT_JSON_MAX_NESTING_DEPTH + 1)
            + "0"
            + "]" * (common.STRICT_JSON_MAX_NESTING_DEPTH + 1)
        )

        with self.assertRaisesRegex(ValueError, "nesting exceeds"):
            common.strict_json_loads(payload)

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

    def test_bounded_capture_enforces_independent_stream_limits(self) -> None:
        with self.assertRaises(common.ReviewOutputLimitError) as raised:
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
        self.assertEqual(raised.exception.limit_kind, "stream")

    def test_process_spawn_callback_validation_happens_before_launch(self) -> None:
        prepare = mock.Mock(return_value=mock.sentinel.binding)
        callback = mock.Mock()
        command = (sys.executable, "-c", "raise SystemExit('must not execute')")
        with (
            mock.patch.object(common.subprocess, "run") as subprocess_run,
            mock.patch.object(common.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                ReviewError,
                "process spawn preparation requires logged output paths",
            ),
        ):
            common.run(
                command,
                timeout_seconds=5,
                prepare_process_spawned=prepare,
                on_process_spawned=callback,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            for index, timeout_seconds in enumerate((None, math.inf, math.nan)):
                stdout_path.write_bytes(b"existing stdout")
                stderr_path.write_bytes(b"existing stderr")
                with (
                    self.subTest(index=index),
                    mock.patch.object(common.subprocess, "Popen") as popen,
                    self.assertRaisesRegex(
                        ReviewError,
                        "requires a finite timeout or deadline",
                    ),
                ):
                    common.run(
                        command,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                        timeout_seconds=timeout_seconds,
                        prepare_process_spawned=prepare,
                        on_process_spawned=callback,
                    )

                popen.assert_not_called()
                self.assertEqual(stdout_path.read_bytes(), b"existing stdout")
                self.assertEqual(stderr_path.read_bytes(), b"existing stderr")

            for callbacks in (
                {"prepare_process_spawned": prepare},
                {"on_process_spawned": callback},
            ):
                with (
                    self.subTest(callbacks=tuple(callbacks)),
                    mock.patch.object(common.subprocess, "Popen") as popen,
                    self.assertRaisesRegex(
                        ReviewError,
                        "must be provided together",
                    ),
                ):
                    common.run(
                        command,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                        timeout_seconds=5,
                        **callbacks,
                    )
                popen.assert_not_called()

            with (
                mock.patch.object(common.os, "name", "nt"),
                mock.patch.object(common.subprocess, "Popen") as popen,
                self.assertRaisesRegex(ReviewError, "requires POSIX"),
            ):
                common.run(
                    command,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=5,
                    prepare_process_spawned=prepare,
                    on_process_spawned=callback,
                )

            popen.assert_not_called()

        subprocess_run.assert_not_called()
        prepare.assert_not_called()
        callback.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires the POSIX launch gate")
    def test_internal_process_spawn_callback_requires_finite_timeout_form(
        self,
    ) -> None:
        prepare = mock.Mock(return_value=mock.sentinel.binding)
        callback = mock.Mock()
        command = (sys.executable, "-c", "raise SystemExit('must not execute')")
        cases = ({}, {"timeout_seconds": math.inf}, {"deadline": math.nan})
        with (
            tempfile.TemporaryFile() as stdout_handle,
            tempfile.TemporaryFile() as stderr_handle,
        ):
            for arguments in cases:
                with (
                    self.subTest(arguments=arguments),
                    mock.patch.object(common.subprocess, "Popen") as popen,
                    self.assertRaisesRegex(
                        ReviewError,
                        "requires a finite timeout or deadline",
                    ),
                ):
                    common._run_logged_process(
                        command,
                        cwd=None,
                        env=None,
                        stdin=None,
                        stdout_handle=stdout_handle,
                        stderr_handle=stderr_handle,
                        prepare_process_spawned=prepare,
                        on_process_spawned=callback,
                        **arguments,
                    )

                popen.assert_not_called()

        prepare.assert_not_called()
        callback.assert_not_called()

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "getsid")
        and hasattr(os, "getpgid")
        and hasattr(os, "getpgrp"),
        "requires POSIX session inspection",
    )
    def test_process_spawn_callback_precedes_launch_and_started_callback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            events: list[str] = []
            callback_state: dict[str, int] = {}
            real_read = common.os.read
            real_write = common.os.write

            def track_ready(descriptor: int, size: int) -> bytes:
                payload = real_read(descriptor, size)
                if payload == b"R":
                    events.append("ready")
                return payload

            def track_launch(descriptor: int, payload: bytes) -> int:
                if payload == b"L":
                    events.append("launch")
                return real_write(descriptor, payload)

            def prepare_process(process_pid: int) -> tuple[int, int, int]:
                events.append("prepared")
                callback_state.update(
                    pid=process_pid,
                    sid=os.getsid(process_pid),
                    pgid=os.getpgid(process_pid),
                )
                return (
                    callback_state["pid"],
                    callback_state["sid"],
                    callback_state["pgid"],
                )

            def commit_process(binding: object) -> None:
                events.append("committed")
                self.assertEqual(
                    binding,
                    (
                        callback_state["pid"],
                        callback_state["sid"],
                        callback_state["pgid"],
                    ),
                )

            def process_started() -> None:
                events.append("started")

            prepare_process_spawned = mock.Mock(side_effect=prepare_process)
            on_process_spawned = mock.Mock(side_effect=commit_process)
            on_process_started = mock.Mock(side_effect=process_started)
            wrapper_command = common._absolute_deadline_wrapper_command
            with (
                mock.patch.object(common.os, "read", side_effect=track_ready),
                mock.patch.object(common.os, "write", side_effect=track_launch),
                mock.patch.object(
                    common,
                    "_absolute_deadline_wrapper_command",
                    wraps=wrapper_command,
                ) as launch_gate,
            ):
                completed = common.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os; "
                            "print(os.getpid(), os.getsid(0), os.getpgrp(), flush=True)"
                        ),
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    prepare_process_spawned=prepare_process_spawned,
                    on_process_spawned=on_process_spawned,
                    on_process_started=on_process_started,
                )

        target_pid, target_sid, target_pgid = (
            int(value) for value in completed.stdout.split()
        )
        self.assertEqual(
            events,
            ["ready", "prepared", "committed", "launch", "started"],
        )
        self.assertEqual(
            callback_state,
            {"pid": target_pid, "sid": target_sid, "pgid": target_pgid},
        )
        self.assertEqual(target_pid, target_sid)
        self.assertEqual(target_pid, target_pgid)
        launch_gate.assert_called_once()
        self.assertTrue(math.isfinite(launch_gate.call_args.kwargs["deadline"]))
        prepare_process_spawned.assert_called_once_with(target_pid)
        on_process_spawned.assert_called_once_with(
            (target_pid, target_sid, target_pgid)
        )
        on_process_started.assert_called_once_with()

    @unittest.skipUnless(os.name == "posix", "requires the POSIX launch gate")
    def test_process_spawn_callback_failure_prevents_target_exec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "target-ran"
            launch_authorizations: list[bytes] = []
            real_write = common.os.write

            def track_launch(descriptor: int, payload: bytes) -> int:
                if payload == b"L":
                    launch_authorizations.append(payload)
                return real_write(descriptor, payload)

            prepare_process_spawned = mock.Mock(return_value=mock.sentinel.binding)
            on_process_spawned = mock.Mock(
                side_effect=RuntimeError("session binding failed")
            )
            on_process_started = mock.Mock()
            with (
                mock.patch.object(common.os, "write", side_effect=track_launch),
                self.assertRaisesRegex(RuntimeError, "session binding failed"),
            ):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import pathlib,sys; "
                            "pathlib.Path(sys.argv[1]).write_text('launched')"
                        ),
                        str(marker),
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    prepare_process_spawned=prepare_process_spawned,
                    on_process_spawned=on_process_spawned,
                    on_process_started=on_process_started,
                )

            self.assertFalse(marker.exists())
            self.assertEqual(launch_authorizations, [])
            prepare_process_spawned.assert_called_once()
            self.assertIsInstance(prepare_process_spawned.call_args.args[0], int)
            on_process_spawned.assert_called_once_with(mock.sentinel.binding)
            on_process_started.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires the POSIX launch gate")
    def test_process_spawn_callback_cannot_outlive_launch_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "target-ran"
            callback_entered = threading.Event()
            release_callback = threading.Event()
            callback_finished = threading.Event()
            launch_authorizations: list[bytes] = []
            real_write = common.os.write

            def blocking_preparation(_process_pid: int) -> object:
                callback_entered.set()
                release_callback.wait(timeout=5)
                callback_finished.set()
                return mock.sentinel.late_binding

            def track_launch(descriptor: int, payload: bytes) -> int:
                if payload == b"L":
                    launch_authorizations.append(payload)
                return real_write(descriptor, payload)

            started_at = time.monotonic()
            on_process_spawned = mock.Mock()
            try:
                with (
                    mock.patch.object(common.os, "write", side_effect=track_launch),
                    self.assertRaises(common.ReviewTimeoutError),
                ):
                    common.run(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys; "
                                "pathlib.Path(sys.argv[1]).write_text('launched')"
                            ),
                            str(marker),
                        ),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=2.0,
                        prepare_process_spawned=blocking_preparation,
                        on_process_spawned=on_process_spawned,
                    )
            finally:
                release_callback.set()

            self.assertTrue(callback_entered.is_set())
            self.assertTrue(callback_finished.wait(timeout=2))
            self.assertLess(time.monotonic() - started_at, 4)
            self.assertFalse(marker.exists())
            self.assertEqual(launch_authorizations, [])
            on_process_spawned.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires POSIX descriptor passing")
    def test_absolute_deadline_rejects_parent_scheduling_gap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            real_popen = common.subprocess.Popen

            def delayed_spawn(*args: object, **kwargs: object):
                process = real_popen(*args, **kwargs)
                time.sleep(0.15)
                return process

            with (
                mock.patch.object(
                    common.subprocess,
                    "Popen",
                    side_effect=delayed_spawn,
                ),
                self.assertRaisesRegex(
                    common.ReviewTimeoutError,
                    "exceeded its absolute deadline",
                ),
            ):
                common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import pathlib,sys; "
                            "pathlib.Path(sys.argv[1]).write_text('launched')"
                        ),
                        str(marker),
                    ),
                    deadline=time.monotonic() + 0.05,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )

            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "requires POSIX descriptor passing")
    def test_absolute_deadline_classifies_coalesced_ready_timeout_status(self) -> None:
        wrapper = common.ABSOLUTE_DEADLINE_WRAPPER.replace(
            'os.write(status_fd, b"R")\n    launch = os.read(launch_fd, 1)',
            'os.write(status_fd, b"RT")\n    os._exit(124)',
        )
        self.assertNotEqual(wrapper, common.ABSOLUTE_DEADLINE_WRAPPER)

        with (
            mock.patch.object(common, "ABSOLUTE_DEADLINE_WRAPPER", wrapper),
            self.assertRaisesRegex(
                common.ReviewTimeoutError,
                "exceeded its absolute deadline",
            ),
        ):
            common.run_bounded_capture(
                (sys.executable, "-c", "raise SystemExit('must not execute')"),
                deadline=time.monotonic() + 2,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )

    @unittest.skipUnless(os.name == "posix", "requires POSIX descriptor passing")
    def test_absolute_deadline_classifies_launch_pipe_epipe(self) -> None:
        real_write = common.os.write

        def delay_before_launch(descriptor: int, value: bytes) -> int:
            if value == b"L":
                time.sleep(0.1)
            return real_write(descriptor, value)

        with (
            mock.patch.object(
                common.os,
                "write",
                side_effect=delay_before_launch,
            ),
            self.assertRaisesRegex(
                common.ReviewTimeoutError,
                "exceeded its absolute deadline",
            ),
        ):
            common.run_bounded_capture(
                (sys.executable, "-c", "raise SystemExit('must not execute')"),
                deadline=time.monotonic() + 0.05,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )

    @unittest.skipUnless(os.name == "posix", "requires POSIX descriptor passing")
    def test_absolute_deadline_rejects_expiry_after_child_final_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            wrapper = common.ABSOLUTE_DEADLINE_WRAPPER.replace(
                "try:\n    os.execve(sys.argv[5], sys.argv[5:], os.environ)",
                (
                    "time.sleep(0.15)\n"
                    "try:\n    os.execve(sys.argv[5], sys.argv[5:], os.environ)"
                ),
            )
            self.assertNotEqual(wrapper, common.ABSOLUTE_DEADLINE_WRAPPER)
            real_write = common.os.write

            def delay_parent_after_launch(descriptor: int, value: bytes) -> int:
                written = real_write(descriptor, value)
                if value == b"L":
                    time.sleep(0.2)
                return written

            with (
                mock.patch.object(common, "ABSOLUTE_DEADLINE_WRAPPER", wrapper),
                mock.patch.object(
                    common.os,
                    "write",
                    side_effect=delay_parent_after_launch,
                ),
                self.assertRaisesRegex(
                    common.ReviewTimeoutError,
                    "exceeded its absolute deadline",
                ),
            ):
                common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import pathlib,sys; "
                            "pathlib.Path(sys.argv[1]).write_text('launched')"
                        ),
                        str(marker),
                    ),
                    deadline=time.monotonic() + 0.05,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )

            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "requires POSIX descriptor passing")
    def test_absolute_deadline_rechecks_after_signal_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            wrapper = common.ABSOLUTE_DEADLINE_WRAPPER.replace(
                "remaining = deadline - time.monotonic()",
                "time.sleep(0.15)\nremaining = deadline - time.monotonic()",
                1,
            )
            self.assertNotEqual(wrapper, common.ABSOLUTE_DEADLINE_WRAPPER)

            with (
                mock.patch.object(common, "ABSOLUTE_DEADLINE_WRAPPER", wrapper),
                self.assertRaisesRegex(
                    common.ReviewTimeoutError,
                    "exceeded its absolute deadline",
                ),
            ):
                common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import pathlib,sys; "
                            "pathlib.Path(sys.argv[1]).write_text('launched')"
                        ),
                        str(marker),
                    ),
                    deadline=time.monotonic() + 0.05,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )

            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "requires POSIX signal masks",
    )
    def test_absolute_deadline_unblocks_inherited_child_alarm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            wrapper = common.ABSOLUTE_DEADLINE_WRAPPER.replace(
                "try:\n    os.execve(sys.argv[5], sys.argv[5:], os.environ)",
                (
                    "time.sleep(0.15)\n"
                    "try:\n    os.execve(sys.argv[5], sys.argv[5:], os.environ)"
                ),
            )
            real_write = common.os.write

            def delay_parent_after_launch(descriptor: int, value: bytes) -> int:
                written = real_write(descriptor, value)
                if value == b"L":
                    time.sleep(0.2)
                return written

            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGALRM},
            )
            try:
                with (
                    mock.patch.object(common, "ABSOLUTE_DEADLINE_WRAPPER", wrapper),
                    mock.patch.object(
                        common.os,
                        "write",
                        side_effect=delay_parent_after_launch,
                    ),
                    self.assertRaisesRegex(
                        common.ReviewTimeoutError,
                        "exceeded its absolute deadline",
                    ),
                ):
                    common.run_bounded_capture(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys; "
                                "pathlib.Path(sys.argv[1]).write_text('launched')"
                            ),
                            str(marker),
                        ),
                        deadline=time.monotonic() + 0.05,
                        stdout_limit_bytes=4096,
                        stderr_limit_bytes=4096,
                    )
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "waitid")
        and hasattr(os, "WNOWAIT"),
        "requires Linux waitid zombie observation",
    )
    def test_terminate_process_group_reaps_zombie_leader(self) -> None:
        process = common.subprocess.Popen(
            (sys.executable, "-c", "pass"),
            start_new_session=True,
        )
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
            self.assertFalse(common._process_group_exists(process.pid))

            common.terminate_process_group(process)

            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        finally:
            if process.returncode is None:
                process.kill()
                process.wait()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "SIGTERM"),
        "requires POSIX signal forwarding",
    )
    def test_forwarded_signal_prevents_launch_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            real_write = common.os.write

            def signal_before_launch(descriptor: int, value: bytes) -> int:
                if value == b"L":
                    os.kill(os.getpid(), signal.SIGTERM)
                    time.sleep(0.1)
                return real_write(descriptor, value)

            with (
                mock.patch.object(
                    common.os,
                    "write",
                    side_effect=signal_before_launch,
                ),
                self.assertRaises(common.ForwardedSignal) as raised,
            ):
                common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import pathlib,sys; "
                            "pathlib.Path(sys.argv[1]).write_text('launched')"
                        ),
                        str(marker),
                    ),
                    deadline=time.monotonic() + 2,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "requires POSIX signal masks",
    )
    def test_forwarded_signal_unblocks_inherited_parent_mask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            real_write = common.os.write
            timer: threading.Timer | None = None

            def delay_launch_authorization(descriptor: int, value: bytes) -> int:
                nonlocal timer
                if value == b"L":
                    timer = threading.Timer(
                        0.02,
                        os.kill,
                        args=(os.getpid(), signal.SIGTERM),
                    )
                    timer.start()
                    time.sleep(0.1)
                return real_write(descriptor, value)

            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGTERM},
            )
            try:
                with (
                    mock.patch.object(
                        common.os,
                        "write",
                        side_effect=delay_launch_authorization,
                    ),
                    self.assertRaises(common.ForwardedSignal) as raised,
                ):
                    common.run_bounded_capture(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys; "
                                "pathlib.Path(sys.argv[1]).write_text('launched')"
                            ),
                            str(marker),
                        ),
                        deadline=time.monotonic() + 2,
                        stdout_limit_bytes=4096,
                        stderr_limit_bytes=4096,
                    )
            finally:
                if timer is not None:
                    timer.join()
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "SIGTERM"),
        "requires POSIX signal forwarding",
    )
    def test_forwarded_signal_wins_when_spawn_returns_after_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "launched"
            real_popen = common.subprocess.Popen
            timer: threading.Timer | None = None

            def delayed_spawn(*args: object, **kwargs: object):
                nonlocal timer
                process = real_popen(*args, **kwargs)
                timer = threading.Timer(
                    0.06,
                    os.kill,
                    args=(os.getpid(), signal.SIGTERM),
                )
                timer.start()
                time.sleep(0.15)
                return process

            try:
                with (
                    mock.patch.object(
                        common.subprocess,
                        "Popen",
                        side_effect=delayed_spawn,
                    ),
                    self.assertRaises(common.ForwardedSignal) as raised,
                ):
                    common.run_bounded_capture(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import pathlib,sys; "
                                "pathlib.Path(sys.argv[1]).write_text('launched')"
                            ),
                            str(marker),
                        ),
                        deadline=time.monotonic() + 0.03,
                        stdout_limit_bytes=4096,
                        stderr_limit_bytes=4096,
                    )
            finally:
                if timer is not None:
                    timer.join()

            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertFalse(marker.exists())

    def test_relative_bounded_capture_keeps_existing_launch_path(self) -> None:
        with mock.patch.object(
            common,
            "_absolute_deadline_wrapper_command",
        ) as deadline_wrapper:
            completed = common.run_bounded_capture(
                (sys.executable, "-c", "import os; os.write(1, b'relative')"),
                timeout_seconds=2,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )

        deadline_wrapper.assert_not_called()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, bytearray(b"relative"))

    def test_control_flow_cancellation_is_not_replaced_and_zeroizes_output(
        self,
    ) -> None:
        for cancellation in (
            common.ForwardedSignal(signal.SIGTERM),
            KeyboardInterrupt("cancelled"),
        ):
            now = [100.0]
            writers: dict[str, object] = {}

            def cancel_after_output(*_args: object, **kwargs: object) -> int:
                stdout = kwargs["stdout_handle"]
                stderr = kwargs["stderr_handle"]
                writers["stdout"] = stdout
                writers["stderr"] = stderr
                stdout.write(b"sensitive stdout")
                stderr.write(b"sensitive stderr")
                now[0] = 101.0
                raise cancellation

            with (
                self.subTest(cancellation=type(cancellation).__name__),
                mock.patch.object(
                    common.time,
                    "monotonic",
                    side_effect=lambda: now[0],
                ),
                mock.patch.object(
                    common,
                    "_run_logged_process",
                    side_effect=cancel_after_output,
                ),
                self.assertRaises(type(cancellation)) as raised,
            ):
                common.run_bounded_capture(
                    ("reviewer",),
                    deadline=101.0,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )

            if isinstance(cancellation, common.ForwardedSignal):
                self.assertIs(raised.exception, cancellation)
            self.assertEqual(writers["stdout"].data, bytearray(16))
            self.assertEqual(writers["stderr"].data, bytearray(16))

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ") and hasattr(os, "fork"),
        "requires POSIX file-size limits",
    )
    def test_bounded_capture_enforces_regular_file_limit_during_process(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "export.bin"
            with self.assertRaises(common.ReviewOutputLimitError) as raised:
                common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,sys; "
                            "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT, 0o600); "
                            "data=b'x' * 1048576; offset=0; "
                            "exec('while offset < len(data):\\n "
                            " offset += os.write(fd, data[offset:])')"
                        ),
                        str(output_path),
                    ),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=output_path,
                )
            output_size = output_path.stat().st_size

        self.assertEqual(raised.exception.limit_kind, "regular-file")

        self.assertLessEqual(output_size, 1025)

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ") and hasattr(os, "fork"),
        "requires POSIX file-size limits",
    )
    def test_bounded_capture_accepts_exact_regular_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "export.bin"
            completed = common.run_bounded_capture(
                (
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; "
                        "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT, 0o600); "
                        "os.write(fd, b'x' * 1024); os.close(fd)"
                    ),
                    str(output_path),
                ),
                timeout_seconds=5,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
                regular_file_limit_bytes=1024,
                regular_file_limit_path=output_path,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(output_path.stat().st_size, 1024)

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ") and hasattr(os, "fork"),
        "requires POSIX file-size limits",
    )
    def test_inherited_soft_file_limit_does_not_shrink_logical_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "export.bin"
            with mock.patch("resource.getrlimit", return_value=(1024, 1025)):
                completed = common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,sys; "
                            "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT, 0o600); "
                            "os.write(fd, b'x' * 1024); os.close(fd)"
                        ),
                        str(output_path),
                    ),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=output_path,
                )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(output_path.stat().st_size, 1024)

    @unittest.skipUnless(
        resource is not None and hasattr(signal, "SIGXFSZ"),
        "requires POSIX file-size limits",
    )
    def test_actual_low_soft_file_limit_does_not_shrink_logical_limit(self) -> None:
        assert resource is not None
        original_soft, original_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        logical_limit = 1024
        sentinel_limit = logical_limit + 1
        if original_hard != resource.RLIM_INFINITY and original_hard < sentinel_limit:
            self.skipTest("inherited hard file-size limit is below the test sentinel")
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (512, original_hard))
        except OSError as error:
            self.skipTest(f"cannot lower the soft file-size limit: {error}")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                output_path = pathlib.Path(temporary) / "export.bin"
                completed = common.run_bounded_capture(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,sys; "
                            "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT, 0o600); "
                            "os.write(fd, b'x' * 1024); os.close(fd)"
                        ),
                        str(output_path),
                    ),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=logical_limit,
                    regular_file_limit_path=output_path,
                )

                self.assertEqual(completed.returncode, 0)
                self.assertEqual(output_path.stat().st_size, logical_limit)
        finally:
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (original_soft, original_hard),
            )

    @unittest.skipUnless(os.name == "posix", "requires POSIX file-size limits")
    @mock.patch.object(common.subprocess, "Popen")
    def test_inherited_hard_file_limit_without_sentinel_blocks_before_launch(
        self,
        popen: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "export.bin"
            with (
                mock.patch("resource.getrlimit", return_value=(1024, 1024)),
                self.assertRaisesRegex(
                    ReviewError,
                    "hard limit cannot preserve an overflow sentinel",
                ),
            ):
                common.run_bounded_capture(
                    (sys.executable, "-c", "pass"),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=output_path,
                )

        popen.assert_not_called()

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ") and hasattr(os, "fork"),
        "requires POSIX file-size limits",
    )
    def test_regular_file_limit_normalizes_efbig_to_output_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "export.bin"
            code = (
                "import errno,os,signal,sys,time; "
                "signal.signal(signal.SIGXFSZ, signal.SIG_IGN); "
                "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT, 0o600); "
                "data=b'x' * 1048576; offset=0; "
                "exec('while offset < len(data):\\n"
                "  try:\\n"
                "    offset += os.write(fd, data[offset:])\\n"
                "  except OSError as error:\\n"
                "    if error.errno != errno.EFBIG: sys.exit(24)\\n"
                "    time.sleep(5)')"
            )
            started = time.monotonic()
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run_bounded_capture(
                    (sys.executable, "-c", code, str(output_path)),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=output_path,
                )

            self.assertGreater(output_path.stat().st_size, 1024)
            self.assertLessEqual(output_path.stat().st_size, 1025)
            self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ") and pathlib.Path("/bin/sh").is_file(),
        "requires POSIX signal handling",
    )
    def test_regular_file_wrapper_restores_default_file_size_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "unused.bin"
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run_bounded_capture(
                    (
                        "/bin/sh",
                        "-c",
                        f"kill -{int(signal.SIGXFSZ)} $$; exit 0",
                    ),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=output_path,
                )

    @unittest.skipUnless(
        hasattr(signal, "SIGXFSZ"),
        "requires POSIX file-size signals",
    )
    def test_regular_file_limit_does_not_treat_shell_exit_code_as_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = pathlib.Path(temporary) / "unused.bin"
            completed = common.run_bounded_capture(
                (
                    sys.executable,
                    "-c",
                    f"raise SystemExit({128 + int(signal.SIGXFSZ)})",
                ),
                timeout_seconds=5,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
                regular_file_limit_bytes=1024,
                regular_file_limit_path=output_path,
            )

            self.assertEqual(completed.returncode, 128 + int(signal.SIGXFSZ))
            self.assertFalse(output_path.exists())

    @unittest.skipUnless(os.name == "posix", "requires the POSIX wrapper")
    def test_regular_file_limit_preserves_exec_oserror(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            missing = root / "missing-command"
            with self.assertRaises(FileNotFoundError):
                common.run_bounded_capture(
                    (str(missing),),
                    timeout_seconds=5,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                    regular_file_limit_bytes=1024,
                    regular_file_limit_path=root / "unused.bin",
                )

    def test_regular_file_wrapper_disables_bytecode_before_isolation(self) -> None:
        command = common._regular_file_limit_wrapper_command(
            ("/usr/bin/example", "--version"),
            kernel_limit=1025,
            exec_status_write_fd=7,
        )

        self.assertEqual(command[1:4], ("-B", "-I", "-S"))
        self.assertEqual(command[-4:], ("1025", "7", "/usr/bin/example", "--version"))

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

    def test_automatic_reviewer_candidate_stat_io_is_inconclusive(self) -> None:
        candidate = pathlib.Path("/home/reviewer/.local/bin/claude")

        def stat_candidate(path: pathlib.Path, *_args, **_kwargs):
            if path == candidate:
                raise OSError(errno.EIO, "stat failed")
            raise FileNotFoundError(errno.ENOENT, "missing")

        with (
            mock.patch.dict(common.os.environ, {"HOME": "/home/reviewer"}, clear=True),
            mock.patch.object(
                common,
                "_user_executable_candidates",
                return_value=[candidate],
            ),
            mock.patch.object(common.shutil, "which", return_value=None),
            mock.patch.object(
                common.pathlib.Path,
                "stat",
                autospec=True,
                side_effect=stat_candidate,
            ),
            self.assertRaisesRegex(CandidateInspectionInconclusive, "stat failed"),
        ):
            common.resolve_reviewer_executable(
                "claude",
                inspection_error=CandidateInspectionInconclusive,
            )

    def test_explicit_reviewer_candidate_access_io_is_inconclusive(self) -> None:
        candidate = pathlib.Path("/explicit/claude")

        with (
            mock.patch.dict(
                common.os.environ,
                {
                    "HOME": "/home/reviewer",
                    "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                },
                clear=True,
            ),
            mock.patch.object(
                common.pathlib.Path,
                "stat",
                autospec=True,
                side_effect=PermissionError(errno.EACCES, "access denied"),
            ),
            self.assertRaisesRegex(CandidateInspectionInconclusive, "access denied"),
        ):
            common.resolve_reviewer_executable(
                "claude",
                inspection_error=CandidateInspectionInconclusive,
            )

    def test_reviewer_candidate_disappearance_after_metadata_check_is_inconclusive(
        self,
    ) -> None:
        candidate = pathlib.Path("/home/reviewer/.local/bin/claude")
        metadata = os.stat_result(
            (stat.S_IFREG | 0o700, 1, 2, 1, 1000, 1000, 1, 0, 0, 0)
        )
        candidate_stat_calls = 0

        def stat_candidate(path: pathlib.Path, *_args, **_kwargs):
            nonlocal candidate_stat_calls
            if path != candidate:
                raise FileNotFoundError(errno.ENOENT, "missing")
            candidate_stat_calls += 1
            if candidate_stat_calls == 1:
                return metadata
            raise FileNotFoundError(errno.ENOENT, "disappeared")

        with (
            mock.patch.dict(common.os.environ, {"HOME": "/home/reviewer"}, clear=True),
            mock.patch.object(
                common,
                "_user_executable_candidates",
                return_value=[candidate],
            ),
            mock.patch.object(common.shutil, "which", return_value=None),
            mock.patch.object(
                common.pathlib.Path,
                "stat",
                autospec=True,
                side_effect=stat_candidate,
            ),
            self.assertRaisesRegex(
                CandidateInspectionInconclusive,
                "changed during inspection",
            ),
        ):
            common.resolve_reviewer_executable(
                "claude",
                inspection_error=CandidateInspectionInconclusive,
            )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_automatic_dangling_final_symlink_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "claude"
            candidate.symlink_to("missing-target")
            valid = root / "valid" / "claude"
            valid.parent.mkdir()
            valid.write_bytes(b"#!/bin/sh\n")
            valid.chmod(0o700)
            inspect_candidate = common._reviewer_candidate_is_executable

            def inspect_only_candidate(path: pathlib.Path, **kwargs):
                if path not in {candidate, valid}:
                    return False
                return inspect_candidate(path, **kwargs)

            candidate_validator = mock.Mock()

            with (
                mock.patch.dict(
                    common.os.environ,
                    {"HOME": str(root)},
                    clear=True,
                ),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[candidate, valid],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common,
                    "_reviewer_candidate_is_executable",
                    side_effect=inspect_only_candidate,
                ),
            ):
                resolved = common.resolve_reviewer_executable(
                    "claude",
                    candidate_validator=candidate_validator,
                    inspection_error=CandidateInspectionInconclusive,
                )

        self.assertEqual(resolved, valid.absolute())
        candidate_validator.assert_called_once_with(valid.absolute())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_explicit_dangling_final_symlink_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "claude"
            candidate.symlink_to("missing-target")

            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": str(root),
                        "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                    },
                    clear=True,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "ENOENT involves a symlink",
                ),
            ):
                common.resolve_reviewer_executable(
                    "claude",
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_automatic_dangling_leaf_symlink_race_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "claude"
            candidate.symlink_to("missing-first")
            original_readlink = common.os.readlink
            changed = False

            def readlink_with_race(path, *, dir_fd=None):
                nonlocal changed
                target = original_readlink(path, dir_fd=dir_fd)
                if path == candidate.name and not changed:
                    candidate.unlink()
                    candidate.symlink_to("missing-second")
                    changed = True
                return target

            with (
                mock.patch.object(
                    common.os,
                    "readlink",
                    side_effect=readlink_with_race,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "changed during inspection",
                ),
            ):
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                    allow_dangling_leaf_symlink=True,
                )

    def test_existing_nonexecutable_candidate_races_are_inconclusive(self) -> None:
        candidate = pathlib.Path("/home/reviewer/.local/bin/claude")
        executable_mode = stat.S_IFREG | 0o700
        cases = (
            ("directory-replaced", stat.S_IFDIR | 0o700, executable_mode, 2, 2),
            ("fifo-replaced", stat.S_IFIFO | 0o600, executable_mode, 2, 2),
            ("regular-replaced", stat.S_IFREG | 0o600, stat.S_IFREG | 0o600, 2, 3),
            ("chmod", stat.S_IFREG | 0o600, executable_mode, 2, 2),
        )

        for name, before_mode, after_mode, before_inode, after_inode in cases:
            before = os.stat_result(
                (before_mode, 1, before_inode, 1, 1000, 1000, 1, 0, 0, 0)
            )
            after = os.stat_result(
                (after_mode, 1, after_inode, 1, 1000, 1000, 1, 0, 0, 0)
            )
            with (
                self.subTest(name=name),
                mock.patch.object(
                    common.pathlib.Path,
                    "stat",
                    autospec=True,
                    side_effect=(before, after),
                ) as candidate_stat,
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "changed during inspection",
                ),
            ):
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )
            self.assertEqual(candidate_stat.call_count, 2)

    def test_stable_existing_nonexecutable_candidates_are_absent(self) -> None:
        candidate = pathlib.Path("/home/reviewer/.local/bin/claude")
        for name, mode in (
            ("directory", stat.S_IFDIR | 0o700),
            ("fifo", stat.S_IFIFO | 0o600),
            ("no-exec", stat.S_IFREG | 0o600),
        ):
            metadata = os.stat_result((mode, 1, 2, 1, 1000, 1000, 1, 0, 0, 0))
            with (
                self.subTest(name=name),
                mock.patch.object(
                    common.pathlib.Path,
                    "stat",
                    autospec=True,
                    return_value=metadata,
                ) as candidate_stat,
            ):
                self.assertFalse(
                    common._reviewer_candidate_is_executable(
                        candidate,
                        inspection_error=CandidateInspectionInconclusive,
                    )
                )
            self.assertEqual(candidate_stat.call_count, 2)

    def test_mode_executable_candidate_without_effective_access_is_absent(self) -> None:
        candidate = pathlib.Path("/home/reviewer/.local/bin/claude")
        metadata = os.stat_result(
            (stat.S_IFREG | 0o711, 1, 2, 1, 1000, 1000, 1, 0, 0, 0)
        )
        with (
            mock.patch.object(
                common.pathlib.Path,
                "stat",
                autospec=True,
                return_value=metadata,
            ) as candidate_stat,
            mock.patch.object(common.os, "access", return_value=False) as access,
        ):
            self.assertFalse(
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )
            )

        self.assertEqual(candidate_stat.call_count, 2)
        access.assert_called_once_with(candidate, os.X_OK)

    def test_automatic_discovery_skips_inaccessible_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            inaccessible = home / "inaccessible" / "claude"
            valid = home / "valid" / "claude"
            for executable in (inaccessible, valid):
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b"#!/bin/sh\n")
                executable.chmod(0o700)
            candidate_validator = mock.Mock()

            with (
                mock.patch.dict(common.os.environ, {"HOME": str(home)}, clear=True),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[inaccessible, valid],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common.os,
                    "access",
                    side_effect=lambda path, mode: (
                        mode == os.X_OK and pathlib.Path(path) == valid
                    ),
                ),
            ):
                resolved = common.resolve_reviewer_executable(
                    "claude",
                    candidate_validator=candidate_validator,
                    inspection_error=CandidateInspectionInconclusive,
                )

        self.assertEqual(resolved, valid.absolute())
        candidate_validator.assert_called_once_with(valid.absolute())

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_existing_symlink_candidate_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            target = root / "claude-target"
            target.write_bytes(b"#!/bin/sh\n")
            target.chmod(0o700)
            candidate = root / "claude"
            candidate.symlink_to(target.name)
            candidate_validator = mock.Mock()

            with mock.patch.dict(
                common.os.environ,
                {
                    "HOME": str(root),
                    "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                },
                clear=True,
            ):
                resolved = common.resolve_reviewer_executable(
                    "claude",
                    candidate_validator=candidate_validator,
                    inspection_error=CandidateInspectionInconclusive,
                )

        self.assertEqual(resolved, candidate.absolute())
        candidate_validator.assert_called_once_with(candidate.absolute())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_dangling_parent_symlink_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            parent = root / "claude-parent"
            parent.symlink_to("missing-parent", target_is_directory=True)
            candidate = parent / "claude"

            with self.assertRaisesRegex(
                CandidateInspectionInconclusive,
                "involves a symlink",
            ):
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_resolved_parent_symlink_can_prove_candidate_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            target = root / "real-bin"
            target.mkdir()
            parent = root / "bin"
            parent.symlink_to(target.name, target_is_directory=True)
            candidate = parent / "missing-reviewer"

            self.assertFalse(
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )
            )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_parent_symlink_target_race_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            first_target = root / "first-bin"
            second_target = root / "second-bin"
            first_target.mkdir()
            second_target.mkdir()
            parent = root / "bin"
            parent.symlink_to(first_target.name, target_is_directory=True)
            candidate = parent / "missing-reviewer"
            original_readlink = common.os.readlink
            readlink_calls = 0

            def readlink_with_race(path, *, dir_fd=None):
                nonlocal readlink_calls
                result = original_readlink(path, dir_fd=dir_fd)
                if path == parent.name:
                    readlink_calls += 1
                    if readlink_calls == 1:
                        parent.unlink()
                        parent.symlink_to(second_target.name, target_is_directory=True)
                return result

            with (
                mock.patch.object(
                    common.os,
                    "readlink",
                    side_effect=readlink_with_race,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "parent changed during inspection",
                ),
            ):
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_candidate_component_lstat_io_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            parent = root / "claude-lstat-io-parent"
            parent.mkdir()
            candidate = parent / "claude"
            original_lstat = common.os.lstat

            def lstat_with_io(path, *, dir_fd=None):
                if path == parent.name:
                    raise OSError(errno.EIO, "lstat failed")
                return original_lstat(path, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    common.os,
                    "lstat",
                    side_effect=lstat_with_io,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "lstat failed",
                ),
            ):
                common._reviewer_candidate_is_executable(
                    candidate,
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_truly_missing_lexical_component_is_automatic_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "missing-install" / "bin" / "claude"
            inspect_candidate = common._reviewer_candidate_is_executable

            def inspect_only_candidate(path: pathlib.Path, **kwargs):
                if path != candidate:
                    return False
                return inspect_candidate(path, **kwargs)

            with (
                mock.patch.dict(
                    common.os.environ,
                    {"HOME": str(root)},
                    clear=True,
                ),
                mock.patch.object(
                    common,
                    "_user_executable_candidates",
                    return_value=[candidate],
                ),
                mock.patch.object(common.shutil, "which", return_value=None),
                mock.patch.object(
                    common,
                    "_reviewer_candidate_is_executable",
                    side_effect=inspect_only_candidate,
                ),
            ):
                resolved = common.resolve_reviewer_executable(
                    "claude",
                    inspection_error=CandidateInspectionInconclusive,
                )

        self.assertIsNone(resolved)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_explicit_dangling_candidate_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "claude"
            candidate.symlink_to("missing-target")

            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": str(root),
                        "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                    },
                    clear=True,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "involves a symlink",
                ),
            ):
                common.resolve_reviewer_executable(
                    "claude",
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_explicit_parent_disappearance_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            parent = root / "claude-race-parent"
            parent.mkdir()
            candidate = parent / "claude"
            original_open = common.os.open
            removed = False

            def open_with_parent_race(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal removed
                if path == parent.name and dir_fd is not None and not removed:
                    parent.rmdir()
                    removed = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": str(root),
                        "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                    },
                    clear=True,
                ),
                mock.patch.object(
                    common.os,
                    "open",
                    side_effect=open_with_parent_race,
                ),
                self.assertRaisesRegex(
                    CandidateInspectionInconclusive,
                    "parent changed during inspection",
                ),
            ):
                common.resolve_reviewer_executable(
                    "claude",
                    inspection_error=CandidateInspectionInconclusive,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "requires POSIX no-follow path inspection",
    )
    def test_explicit_truly_missing_candidate_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            candidate = root / "missing-install" / "claude"

            with (
                mock.patch.dict(
                    common.os.environ,
                    {
                        "HOME": str(root),
                        "CODEX_REVIEW_CLAUDE_PATH": str(candidate),
                    },
                    clear=True,
                ),
                self.assertRaisesRegex(ReviewError, "is not executable") as raised,
            ):
                common.resolve_reviewer_executable(
                    "claude",
                    inspection_error=CandidateInspectionInconclusive,
                )

        self.assertNotIsInstance(
            raised.exception,
            CandidateInspectionInconclusive,
        )

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
                    side_effect=lambda path, _mode: (
                        pathlib.Path(path) in {invalid, valid}
                    ),
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
