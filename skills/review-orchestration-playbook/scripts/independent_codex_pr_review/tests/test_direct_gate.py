from __future__ import annotations

import errno
import dis
import hashlib
import os
import pathlib
import select
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest import mock

import review_supervisor.direct_gate as direct_gate
from review_supervisor.appserver_protocol import (
    AppServerProtocol,
    AppServerProtocolError,
    AppServerSessionConfig,
    ExternalChatGPTAuth,
    encode_json_line,
)
from review_supervisor.direct_gate import (
    AppServerProcessResult,
    DirectGateError,
    ProcessCustodyState,
)
from review_supervisor.codex_executable import build_snapshot_seatbelt_policy

from tests.test_appserver_protocol import (
    CODEX_HOME,
    NEUTRAL_CWD,
    final_item,
    in_progress_turn,
    initialize_result,
    reasoning_item,
    safe_config_result,
    synthetic_external_access_token,
    thread_start_result,
)


def _call_result_store_offset(
    function: object,
    *,
    called_name: str,
    stored_name: str,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        if not any(candidate.argval == called_name for candidate in prior):
            continue
        store = instructions[index + 1]
        if store.opname == "STORE_FAST" and store.argval == stored_name:
            return store.offset
    raise AssertionError(
        f"cannot find {called_name} CALL-to-{stored_name} STORE_FAST boundary"
    )


def _running_transcript(config: AppServerSessionConfig) -> list[dict[str, object]]:
    thread_result = thread_start_result(config)
    turn = in_progress_turn()
    return [
        {"id": 1, "result": initialize_result()},
        {"id": 2, "result": safe_config_result()},
        {
            "id": 3,
            "result": {
                "data": [
                    {
                        "cwd": NEUTRAL_CWD,
                        "errors": [],
                        "hooks": [],
                        "warnings": [],
                    }
                ]
            },
        },
        {"method": "thread/started", "params": {"thread": thread_result["thread"]}},
        {"id": 4, "result": thread_result},
        {"id": 5, "result": {"turn": turn}},
        {
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": turn},
        },
    ]


def _successful_transcript(config: AppServerSessionConfig) -> bytes:
    started_reasoning = reasoning_item()
    completed_reasoning = reasoning_item(
        content=["ephemeral rationale"],
        summary=["inspection"],
    )
    started_final = final_item("")
    completed_final = final_item()
    messages = [
        *_running_transcript(config),
        {
            "method": "item/started",
            "params": {
                "item": started_reasoning,
                "startedAtMs": 100,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/reasoning/summaryPartAdded",
            "params": {
                "itemId": "reasoning-1",
                "summaryIndex": 0,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/reasoning/summaryTextDelta",
            "params": {
                "delta": "inspection",
                "itemId": "reasoning-1",
                "summaryIndex": 0,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/reasoning/textDelta",
            "params": {
                "contentIndex": 0,
                "delta": "ephemeral rationale",
                "itemId": "reasoning-1",
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/completed",
            "params": {
                "completedAtMs": 101,
                "item": completed_reasoning,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/started",
            "params": {
                "item": started_final,
                "startedAtMs": 102,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/agentMessage/delta",
            "params": {
                "delta": completed_final["text"],
                "itemId": completed_final["id"],
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "item/completed",
            "params": {
                "completedAtMs": 103,
                "item": completed_final,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [completed_reasoning, completed_final],
                    "status": "completed",
                },
            },
        },
    ]
    return b"".join(encode_json_line(message) for message in messages)


def _forbidden_item_transcript(config: AppServerSessionConfig) -> bytes:
    messages = [
        *_running_transcript(config),
        {
            "method": "item/started",
            "params": {
                "item": {"id": "tool-1", "type": "commandExecution"},
                "startedAtMs": 100,
                "threadId": "thread-1",
                "turnId": "turn-1",
            },
        },
    ]
    return b"".join(encode_json_line(message) for message in messages)


class ControlledAppServer:
    PID = 424_242

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        exit_code: int = 0,
        hold_open: bool = False,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.hold_open = hold_open
        self.stdin = bytearray()
        self.stop = threading.Event()
        self.done = threading.Event()
        self.thread: threading.Thread | None = None
        self.errors: list[BaseException] = []

    def launch(
        self,
        prepared: object,
        argv: tuple[str, ...],
        *,
        cwd: pathlib.Path,
        environment: dict[str, str],
        stdin_fd: int,
        stdout_fd: int,
        stderr_fd: int,
    ) -> SimpleNamespace:
        del argv, cwd, environment
        child_fds = (os.dup(stdin_fd), os.dup(stdout_fd), os.dup(stderr_fd))
        self.thread = threading.Thread(
            target=self._serve,
            args=child_fds,
            name="controlled-app-server",
            daemon=True,
        )
        self.thread.start()
        profile = getattr(prepared, "seatbelt_profile")
        return SimpleNamespace(
            pid=self.PID,
            pgid=self.PID,
            profile_sha256=hashlib.sha256(
                profile.encode("utf-8", "strict")
            ).hexdigest(),
        )

    def _serve(self, stdin_fd: int, stdout_fd: int, stderr_fd: int) -> None:
        try:
            self._write_all(stdout_fd, self.stdout)
            self._write_all(stderr_fd, self.stderr)
            if self.hold_open:
                self.stop.wait()
            else:
                self._drain_stdin(stdin_fd)
        except OSError as error:
            if error.errno not in {errno.EBADF, errno.EPIPE}:
                self.errors.append(error)
        except BaseException as error:
            self.errors.append(error)
        finally:
            for descriptor in (stdin_fd, stdout_fd, stderr_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            self.done.set()

    def _drain_stdin(self, descriptor: int) -> None:
        while not self.stop.is_set():
            readable, _, _ = select.select([descriptor], [], [], 0.02)
            if not readable:
                continue
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                return
            self.stdin.extend(chunk)

    @staticmethod
    def _write_all(descriptor: int, value: bytes) -> None:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "controlled pipe made no progress")
            view = view[written:]

    def terminal_status(self, pid: int) -> int | None:
        if pid != self.PID:
            raise AssertionError(f"unexpected process ID: {pid}")
        return self.exit_code if self.done.is_set() else None

    def reap(
        self,
        pid: int,
        *,
        signal_relay: direct_gate.HostSignalRelay,
    ) -> int:
        if pid != self.PID:
            raise AssertionError(f"unexpected process ID: {pid}")
        self._join()
        signal_relay.unbind(pid)
        return self.exit_code

    def terminate(
        self,
        launched: object,
        *,
        signal_relay: direct_gate.HostSignalRelay,
    ) -> int:
        if getattr(launched, "pid") != self.PID:
            raise AssertionError("unexpected process passed to cleanup")
        self.stop.set()
        self._join()
        signal_relay.unbind(self.PID)
        return self.exit_code

    def _join(self) -> None:
        if self.thread is None:
            raise AssertionError("controlled app-server was never launched")
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("controlled app-server thread did not stop")

    @contextmanager
    def patched_runtime(self) -> Iterator[None]:
        def launch_with_publisher(
            _launch_function: object,
            prepared: object,
            argv: tuple[str, ...],
            *,
            result_owner: object,
            cwd: pathlib.Path,
            environment: dict[str, str],
            stdin_fd: int,
            stdout_fd: int,
            stderr_fd: int,
        ) -> object:
            launched = self.launch(
                prepared,
                argv,
                cwd=cwd,
                environment=environment,
                stdin_fd=stdin_fd,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
            )
            result_owner.publish(launched)
            if not result_owner.owns(launched):
                raise AssertionError("controlled launch owner is incomplete")
            return launched

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    direct_gate,
                    "launch_no_child_process_with_result_publisher",
                    side_effect=launch_with_publisher,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    direct_gate,
                    "_terminal_status",
                    side_effect=self.terminal_status,
                )
            )
            stack.enter_context(
                mock.patch.object(direct_gate, "_reap_process", side_effect=self.reap)
            )
            stack.enter_context(
                mock.patch.object(
                    direct_gate,
                    "_terminate_process",
                    side_effect=self.terminate,
                )
            )
            try:
                yield
            finally:
                self.stop.set()
                if self.thread is not None:
                    self._join()
        if self.errors:
            raise AssertionError("controlled app-server failed") from self.errors[0]


class SnapshotMutationProbeTests(unittest.TestCase):
    def test_probe_uses_the_bound_python_target_and_authenticated_profile(
        self,
    ) -> None:
        policy = direct_gate.SnapshotSeatbeltPolicy(
            snapshot_directory="/synthetic/snapshot",
            protected_ancestors=("/synthetic",),
            rules='(deny file-write* (subpath "/synthetic/snapshot"))',
            sha256="a" * 64,
            required_denials=("write", "chmod", "rename", "unlink"),
        )
        prepared = SimpleNamespace(
            sandboxed_target=SimpleNamespace(path="/synthetic/python3.13")
        )
        result = SimpleNamespace(
            returncode=0,
            stdout=(b'{"chmod":true,"rename":true,"unlink":true,"write":true}\n'),
            stderr=b"",
        )
        with (
            mock.patch.object(
                direct_gate,
                "prepare_sandboxed_python_no_child_profile",
                return_value=prepared,
            ) as prepare,
            mock.patch.object(
                direct_gate,
                "run_bounded_command",
                return_value=result,
            ) as run,
        ):
            direct_gate._verify_snapshot_mutation_denials(
                policy=policy,
                snapshot_path=pathlib.Path("/synthetic/snapshot/codex"),
            )

        prepare.assert_called_once_with(additional_seatbelt_rules=policy.rules)
        self.assertEqual(run.call_args.args[0][0], "/synthetic/python3.13")
        self.assertIs(
            run.call_args.kwargs["_prepared_no_child_profile"],
            prepared,
        )

    @unittest.skipUnless(
        os.environ.get("CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE") == "1",
        "live snapshot mutation probe requires an explicit opt-in",
    )
    def test_live_probe_denies_every_snapshot_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root).resolve(strict=True)
            os.chmod(root, 0o700)
            snapshot_directory = root / "snapshot"
            snapshot_directory.mkdir(mode=0o700)
            snapshot_path = snapshot_directory / "codex"
            snapshot_path.write_bytes(b"synthetic snapshot\n")
            os.chmod(snapshot_path, 0o500)
            policy = build_snapshot_seatbelt_policy(snapshot_directory)

            direct_gate._verify_snapshot_mutation_denials(
                policy=policy,
                snapshot_path=snapshot_path,
            )

            self.assertEqual(snapshot_path.read_bytes(), b"synthetic snapshot\n")
            self.assertEqual(
                tuple(path.name for path in snapshot_directory.iterdir()),
                ("codex",),
            )


class BoundedAppServerProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
        )
        self.prepared = SimpleNamespace(seatbelt_profile="(version 1)")

    def run_server(
        self,
        server: ControlledAppServer,
    ) -> tuple[AppServerProcessResult, ProcessCustodyState, mock.Mock]:
        process_state = ProcessCustodyState()
        on_launch = mock.Mock()
        with server.patched_runtime():
            result = direct_gate.run_bounded_appserver_process(
                prepared=self.prepared,
                argv=("/authenticated/codex", "app-server"),
                cwd=pathlib.Path(NEUTRAL_CWD),
                environment={"HOME": CODEX_HOME},
                prompt=b"self-contained review evidence",
                config=self.config,
                process_state=process_state,
                on_launch=on_launch,
            )
        return result, process_state, on_launch

    def assert_runtime_error(
        self,
        server: ControlledAppServer,
        *,
        code: str,
    ) -> ProcessCustodyState:
        process_state = ProcessCustodyState()
        with server.patched_runtime(), self.assertRaises(DirectGateError) as raised:
            direct_gate.run_bounded_appserver_process(
                prepared=self.prepared,
                argv=("/authenticated/codex", "app-server"),
                cwd=pathlib.Path(NEUTRAL_CWD),
                environment={},
                prompt=b"evidence",
                config=self.config,
                process_state=process_state,
                on_launch=lambda _launched: None,
            )
        self.assertEqual(raised.exception.stage, "review-runtime")
        self.assertEqual(raised.exception.code, code)
        self.assertTrue(process_state.leader_reaped)
        self.assertTrue(process_state.process_group_empty)
        self.assertTrue(process_state.pipes_closed)
        return process_state

    def test_bounded_success_accepts_reasoning_and_streamed_final(self) -> None:
        transcript = _successful_transcript(self.config)
        server = ControlledAppServer(stdout=transcript)

        result, process_state, on_launch = self.run_server(server)

        self.assertEqual(result.session.review_status, "clean")
        self.assertEqual(result.session.final_text, "No findings.")
        self.assertEqual(
            result.session.streamed_message_bytes,
            len("No findings.".encode("utf-8")),
        )
        self.assertNotIn("ephemeral rationale", repr(result.session))
        self.assertEqual(result.stdout_bytes, len(transcript))
        self.assertEqual(result.stdout_sha256, hashlib.sha256(transcript).hexdigest())
        self.assertEqual(result.stderr_bytes, 0)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(process_state.leader_reaped)
        self.assertTrue(process_state.process_group_empty)
        self.assertTrue(process_state.pipes_closed)
        on_launch.assert_called_once()
        self.assertIn(b'"method":"initialize"', server.stdin)
        self.assertIn(b'"method":"turn/start"', server.stdin)

    def test_success_reap_unbinds_relay_before_waitpid(self) -> None:
        events: list[tuple[str, int]] = []
        relay = mock.Mock(spec=direct_gate.HostSignalRelay)
        relay.unbind.side_effect = lambda pid: events.append(("unbind", pid))

        def waitpid(pid: int, options: int) -> tuple[int, int]:
            self.assertEqual(options, 0)
            events.append(("waitpid", pid))
            return pid, 0

        with (
            mock.patch.object(direct_gate, "_terminal_status", return_value=0),
            mock.patch.object(direct_gate.os, "waitpid", side_effect=waitpid),
        ):
            exit_code = direct_gate._reap_process(
                ControlledAppServer.PID,
                signal_relay=relay,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            events,
            [
                ("unbind", ControlledAppServer.PID),
                ("waitpid", ControlledAppServer.PID),
            ],
        )

    def test_liveness_checkpoint_aborts_and_reaps_the_launched_process(self) -> None:
        server = ControlledAppServer(stdout=_successful_transcript(self.config))
        process_state = ProcessCustodyState()
        checkpoints = 0

        def require_liveness() -> None:
            nonlocal checkpoints
            checkpoints += 1
            if checkpoints >= 3:
                raise RuntimeError("outer closed")

        with (
            server.patched_runtime(),
            self.assertRaisesRegex(RuntimeError, "outer closed"),
        ):
            direct_gate.run_bounded_appserver_process(
                prepared=self.prepared,
                argv=("/authenticated/codex", "app-server"),
                cwd=pathlib.Path(NEUTRAL_CWD),
                environment={"HOME": CODEX_HOME},
                prompt=b"self-contained review evidence",
                config=self.config,
                process_state=process_state,
                on_launch=lambda _launched: None,
                liveness_checkpoint=require_liveness,
            )

        self.assertTrue(process_state.leader_reaped)
        self.assertTrue(process_state.process_group_empty)
        self.assertTrue(process_state.pipes_closed)

    def test_launch_call_to_store_interrupt_reaps_prepublished_reviewer(
        self,
    ) -> None:
        server = ControlledAppServer(hold_open=True)
        process_state = ProcessCustodyState()
        target_offset = _call_result_store_offset(
            direct_gate._run_bounded_appserver_process_inner,
            called_name="launch_no_child_process_with_result_publisher",
            stored_name="launched",
        )
        interruption = KeyboardInterrupt(
            "injected reviewer launch CALL-to-STORE interrupt"
        )
        injected = False

        def interrupt_result_store(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if (
                getattr(frame, "f_code", None)
                is direct_gate._run_bounded_appserver_process_inner.__code__
            ):
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_result_store

        previous_trace = sys.gettrace()
        try:
            with (
                server.patched_runtime(),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                sys.settrace(interrupt_result_store)
                direct_gate.run_bounded_appserver_process(
                    prepared=self.prepared,
                    argv=("/authenticated/codex", "app-server"),
                    cwd=pathlib.Path(NEUTRAL_CWD),
                    environment={"HOME": CODEX_HOME},
                    prompt=b"self-contained review evidence",
                    config=self.config,
                    process_state=process_state,
                    on_launch=lambda _launched: None,
                )
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertIs(caught.exception, interruption)
        self.assertTrue(process_state.leader_reaped)
        self.assertTrue(process_state.process_group_empty)
        self.assertTrue(process_state.pipes_closed)
        self.assertEqual(process_state.process_id, ControlledAppServer.PID)

    def test_cleanup_unbinds_relay_before_reaping_terminal_process(self) -> None:
        events: list[tuple[str, int]] = []
        relay = mock.Mock(spec=direct_gate.HostSignalRelay)
        relay.unbind.side_effect = lambda pid: events.append(("unbind", pid))
        launched = SimpleNamespace(
            pid=ControlledAppServer.PID,
            pgid=ControlledAppServer.PID,
        )

        def waitpid(pid: int, options: int) -> tuple[int, int]:
            self.assertEqual(options, 0)
            events.append(("waitpid", pid))
            return pid, 0

        with (
            mock.patch.object(direct_gate, "_terminal_status", return_value=0),
            mock.patch.object(direct_gate.os, "waitpid", side_effect=waitpid),
            mock.patch.object(direct_gate.os, "killpg") as killpg,
        ):
            exit_code = direct_gate._terminate_process(
                launched,
                signal_relay=relay,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            events,
            [
                ("unbind", ControlledAppServer.PID),
                ("waitpid", ControlledAppServer.PID),
            ],
        )
        killpg.assert_not_called()

    def test_auth_source_is_revalidated_at_the_serialization_transition(self) -> None:
        auth_config = AppServerSessionConfig(
            neutral_cwd=NEUTRAL_CWD,
            expected_codex_home=CODEX_HOME,
            external_auth=ExternalChatGPTAuth(
                access_token=synthetic_external_access_token(),
                chatgpt_account_id="account",
                chatgpt_plan_type="plus",
            ),
        )
        protocol = AppServerProtocol(prompt=b"evidence", config=auth_config)
        protocol.start()
        stdout_buffer = bytearray(
            encode_json_line({"id": 1, "result": initialize_result()})
        )
        outbound = bytearray()
        before_send = mock.Mock()

        direct_gate._consume_stdout_records(
            stdout_buffer=stdout_buffer,
            outbound=outbound,
            protocol=protocol,
            before_external_auth_send=before_send,
        )

        before_send.assert_called_once_with()
        self.assertIn(b'"method":"account/login/start"', outbound)
        self.assertEqual(stdout_buffer, b"")

    def test_partial_pipe_setup_closes_every_opened_descriptor(self) -> None:
        opened: list[int] = []
        real_pipe = os.pipe

        def fail_second_pipe() -> tuple[int, int]:
            if opened:
                raise OSError(errno.EMFILE, "injected pipe exhaustion")
            read_fd, write_fd = real_pipe()
            opened.extend((read_fd, write_fd))
            return read_fd, write_fd

        with (
            mock.patch.object(direct_gate.os, "pipe", side_effect=fail_second_pipe),
            self.assertRaises(OSError),
        ):
            direct_gate.run_bounded_appserver_process(
                prepared=self.prepared,
                argv=("/authenticated/codex", "app-server"),
                cwd=pathlib.Path(NEUTRAL_CWD),
                environment={},
                prompt=b"evidence",
                config=self.config,
                process_state=ProcessCustodyState(),
                on_launch=lambda _launched: None,
            )

        for descriptor in opened:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_stdout_stderr_record_and_timeout_fail_closed(self) -> None:
        cases = (
            (
                "stdout",
                ControlledAppServer(stdout=b"x" * 32),
                "STDOUT_LIMIT_BYTES",
                32,
                "stdout-limit",
            ),
            (
                "stderr",
                ControlledAppServer(stderr=b"x" * 32),
                "STDERR_LIMIT_BYTES",
                32,
                "stderr-limit",
            ),
            (
                "record",
                ControlledAppServer(stdout=b"x" * 33),
                "APP_SERVER_MAX_RECORD_BYTES",
                32,
                "record-limit",
            ),
            (
                "timeout",
                ControlledAppServer(hold_open=True),
                "REVIEWER_RUNTIME_SECONDS",
                0.02,
                "review-timeout",
            ),
        )
        for label, server, constant, value, code in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(direct_gate, constant, value),
            ):
                self.assert_runtime_error(server, code=code)

    def test_nonzero_process_classifies_bounded_stderr_and_fails_closed(self) -> None:
        server = ControlledAppServer(
            stdout=_successful_transcript(self.config),
            stderr=b"401 Unauthorized\n",
            exit_code=1,
        )

        self.assert_runtime_error(server, code="authentication-failed")

    def test_forbidden_item_fails_closed_inside_bounded_session(self) -> None:
        server = ControlledAppServer(stdout=_forbidden_item_transcript(self.config))
        process_state = ProcessCustodyState()
        with (
            server.patched_runtime(),
            self.assertRaises(AppServerProtocolError) as raised,
        ):
            direct_gate.run_bounded_appserver_process(
                prepared=self.prepared,
                argv=("/authenticated/codex", "app-server"),
                cwd=pathlib.Path(NEUTRAL_CWD),
                environment={},
                prompt=b"evidence",
                config=self.config,
                process_state=process_state,
                on_launch=lambda _launched: None,
            )

        self.assertEqual(raised.exception.code, "tool-or-item-forbidden")
        self.assertTrue(process_state.leader_reaped)
        self.assertTrue(process_state.process_group_empty)
        self.assertTrue(process_state.pipes_closed)


if __name__ == "__main__":
    unittest.main()
