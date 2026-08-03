from __future__ import annotations

import dis
import errno
import os
import pathlib
import signal
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tests import support


class RuntimeRootCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_state = support._RUNTIME_ROOT_STATE
        self._old_lock = support._RUNTIME_ROOT_LOCK
        self._old_lock_pid = support._RUNTIME_ROOT_LOCK_PID
        self._old_explicit_parent = os.environ.get(support._EXPLICIT_RUNTIME_PARENT_ENV)
        support._RUNTIME_ROOT_STATE = None
        support._RUNTIME_ROOT_LOCK = threading.RLock()
        support._RUNTIME_ROOT_LOCK_PID = os.getpid()
        self._temporary = tempfile.TemporaryDirectory(prefix="runtime-root-custody-")
        self.private_parent = pathlib.Path(self._temporary.name) / "private"
        self.private_parent.mkdir(mode=0o700)
        os.environ[support._EXPLICIT_RUNTIME_PARENT_ENV] = str(self.private_parent)

    def tearDown(self) -> None:
        state = support._RUNTIME_ROOT_STATE
        if state is not None and state.pid == os.getpid():
            support._cleanup_process_runtime_root(state)
        support._RUNTIME_ROOT_STATE = self._old_state
        support._RUNTIME_ROOT_LOCK = self._old_lock
        support._RUNTIME_ROOT_LOCK_PID = self._old_lock_pid
        if self._old_explicit_parent is None:
            os.environ.pop(support._EXPLICIT_RUNTIME_PARENT_ENV, None)
        else:
            os.environ[support._EXPLICIT_RUNTIME_PARENT_ENV] = self._old_explicit_parent
        self._temporary.cleanup()

    def test_owned_temporary_directory_never_deletes_replacement(self) -> None:
        displaced: pathlib.Path | None = None
        replacement: pathlib.Path | None = None
        caught: Exception | None = None
        try:
            with support.owned_temporary_directory("replacement-") as path:
                displaced = path.with_name(path.name + "-displaced")
                path.rename(displaced)
                path.mkdir(mode=0o700)
                replacement = path
                (replacement / "marker").write_text("replacement", encoding="utf-8")
        except Exception as error:
            caught = error

        self.assertIsNotNone(caught)
        assert caught is not None
        self.assertIsNotNone(
            getattr(caught, "owned_temporary_directory_result_owner", None)
        )
        assert displaced is not None
        assert replacement is not None
        self.assertTrue(displaced.is_dir())
        self.assertEqual(
            (replacement / "marker").read_text(encoding="utf-8"),
            "replacement",
        )

        (replacement / "marker").unlink()
        replacement.rmdir()
        displaced.rename(replacement)
        owner = caught.owned_temporary_directory_result_owner
        assert owner.binding is not None
        support._cleanup_owned_temporary_directory(
            state=support._process_runtime_root_state(),
            result_owner=owner,
            binding=owner.binding,
        )

    def test_cached_runtime_root_rejects_public_replacement(self) -> None:
        state = support._process_runtime_root_state()
        displaced = state.path.with_name(state.path.name + "-displaced")
        state.path.rename(displaced)
        state.path.mkdir(mode=0o700)
        replacement = state.path
        try:
            with self.assertRaisesRegex(OSError, "path changed"):
                support._process_runtime_root_state()
            self.assertTrue(replacement.is_dir())
            self.assertIs(support._RUNTIME_ROOT_STATE, state)
        finally:
            replacement.rmdir()
            displaced.rename(state.path)

    def test_exact_entry_cleanup_unlink_excludes_trace_replacement(self) -> None:
        parent_fd = os.open(
            self.private_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        original_name = b"fixture.fifo"
        displaced_name = b"fixture-original.fifo"
        os.mkfifo(original_name, 0o600, dir_fd=parent_fd)
        expected_object = support._test_entry_object_identity(
            os.stat(original_name, dir_fd=parent_fd, follow_symlinks=False)
        )
        cleanup_code = support._remove_exact_test_entry.__code__
        instructions = tuple(dis.get_instructions(cleanup_code))
        unlink_load_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.argval == "unlink"
        )
        unlink_call = next(
            instruction.offset
            for instruction in instructions[unlink_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        injected = False

        def replace_quarantine(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if getattr(frame, "f_code", None) is cleanup_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == unlink_call
                ):
                    injected = True
                    quarantine_name = getattr(frame, "f_locals")["quarantine_name"]
                    os.rename(
                        quarantine_name,
                        displaced_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    replacement_fd = os.open(
                        quarantine_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=parent_fd,
                    )
                    os.close(replacement_fd)
            return replace_quarantine

        previous_trace = sys.gettrace()
        try:
            sys.settrace(replace_quarantine)
            support._remove_exact_test_entry(
                parent_fd,
                original_name,
                expected_object,
            )
            self.assertFalse(injected)
            with self.assertRaises(FileNotFoundError):
                os.stat(
                    original_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            with self.assertRaises(FileNotFoundError):
                os.stat(
                    displaced_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
        finally:
            sys.settrace(previous_trace)
            for entry in os.listdir(parent_fd):
                raw_entry = os.fsencode(entry)
                if raw_entry in {original_name, displaced_name} or raw_entry.startswith(
                    b".codex-test-entry-quarantine-"
                ):
                    os.unlink(raw_entry, dir_fd=parent_fd)
            os.close(parent_fd)

    def test_exact_entry_cleanup_retains_precritical_replacement(self) -> None:
        parent_fd = os.open(
            self.private_parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        original_name = b"fixture.fifo"
        displaced_name = b"fixture-original.fifo"
        os.mkfifo(original_name, 0o600, dir_fd=parent_fd)
        expected_object = support._test_entry_object_identity(
            os.stat(original_name, dir_fd=parent_fd, follow_symlinks=False)
        )
        cleanup_code = support._remove_exact_test_entry.__code__
        instructions = tuple(dis.get_instructions(cleanup_code))
        guard_load_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.argval == "supported_async_publication"
        )
        guard_call = next(
            instruction.offset
            for instruction in instructions[guard_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        injected = False
        quarantine_name: bytes | None = None

        def replace_before_critical_section(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected, quarantine_name
            if getattr(frame, "f_code", None) is cleanup_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == guard_call
                ):
                    injected = True
                    quarantine_name = getattr(frame, "f_locals")["quarantine_name"]
                    os.rename(
                        quarantine_name,
                        displaced_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    replacement_fd = os.open(
                        quarantine_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=parent_fd,
                    )
                    os.close(replacement_fd)
            return replace_before_critical_section

        previous_trace = sys.gettrace()
        try:
            sys.settrace(replace_before_critical_section)
            with self.assertRaises(OSError) as caught:
                support._remove_exact_test_entry(
                    parent_fd,
                    original_name,
                    expected_object,
                )
            sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertEqual(caught.exception.errno, errno.ESTALE)
            self.assertIsNotNone(quarantine_name)
            assert quarantine_name is not None
            displaced_metadata = os.stat(
                displaced_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            replacement_metadata = os.stat(
                quarantine_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            self.assertEqual(
                support._test_entry_object_identity(displaced_metadata),
                expected_object,
            )
            self.assertTrue(stat.S_ISFIFO(displaced_metadata.st_mode))
            self.assertTrue(stat.S_ISREG(replacement_metadata.st_mode))
        finally:
            sys.settrace(previous_trace)
            for entry in os.listdir(parent_fd):
                raw_entry = os.fsencode(entry)
                if raw_entry in {original_name, displaced_name} or raw_entry.startswith(
                    b".codex-test-entry-quarantine-"
                ):
                    os.unlink(raw_entry, dir_fd=parent_fd)
            os.close(parent_fd)

    def test_initialization_control_flow_clears_reentry_marker(self) -> None:
        interruption = KeyboardInterrupt(
            "synthetic runtime-root initialization interrupt"
        )
        with (
            mock.patch.object(
                support,
                "_create_bound_owned_private_directory",
                side_effect=interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as caught,
        ):
            support._process_runtime_root_state()

        self.assertIs(caught.exception, interruption)
        self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
        state = support._process_runtime_root_state()
        self.assertEqual(state.pid, os.getpid())
        self.assertIs(support._RUNTIME_ROOT_STATE, state)

    def test_cleanup_guard_call_interrupt_clears_reentry_marker(self) -> None:
        cleanup_code = support._RuntimeRootReentryCleanup.clear.__code__
        instructions = tuple(dis.get_instructions(cleanup_code))
        guard_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and index > 0
            and instructions[index - 1].argval == "supported_async_publication"
        )
        cleanup_guard_call = instructions[guard_call_index].offset
        cleanup_preludes = tuple(
            instruction.offset
            for instruction in instructions[
                max(0, guard_call_index - 16) : guard_call_index
            ]
            if instruction.opname == "NOP"
        )
        self.assertGreaterEqual(len(cleanup_preludes), 1)
        scenarios = (
            ("try-header", cleanup_preludes[-1]),
            ("guard-call", cleanup_guard_call),
        )
        for label, injection_offset in scenarios:
            with self.subTest(boundary=label):
                initialization_interruption = KeyboardInterrupt(
                    f"synthetic runtime-root {label} initialization interrupt"
                )
                cleanup_intruder = RuntimeError(
                    f"synthetic marker cleanup {label} interruption"
                )
                fired = False

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    injection_offset: int = injection_offset,
                    cleanup_intruder: RuntimeError = cleanup_intruder,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is cleanup_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == injection_offset
                        ):
                            fired = True
                            raise cleanup_intruder
                    return trace

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(trace)
                    with (
                        mock.patch.object(
                            support,
                            "_create_bound_owned_private_directory",
                            side_effect=initialization_interruption,
                        ),
                        self.assertRaises(KeyboardInterrupt) as caught,
                    ):
                        support._process_runtime_root_state()
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(fired)
                self.assertIs(caught.exception, initialization_interruption)
                self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
                self.assertTrue(
                    any(
                        "marker cleanup also failed" in note
                        for note in initialization_interruption.__notes__
                    )
                )

        state = support._process_runtime_root_state()
        self.assertEqual(state.pid, os.getpid())
        self.assertIs(support._RUNTIME_ROOT_STATE, state)

    def test_same_inherited_object_reraised_locally_remains_primary(self) -> None:
        cleanup_code = support._RuntimeRootReentryCleanup.clear.__code__
        instructions = tuple(dis.get_instructions(cleanup_code))
        guard_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and index > 0
            and instructions[index - 1].argval == "supported_async_publication"
        )
        cleanup_guard_call = instructions[guard_call_index].offset
        shared_interruption = KeyboardInterrupt(
            "synthetic inherited and locally reraised interruption"
        )
        cleanup_intruder = RuntimeError(
            "synthetic same-object marker cleanup interruption"
        )
        fired = False
        caught: BaseException | None = None

        def trace(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal fired
            if getattr(frame, "f_code", None) is cleanup_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == cleanup_guard_call
                ):
                    fired = True
                    raise cleanup_intruder
            return trace

        previous_trace = sys.gettrace()
        try:
            try:
                raise shared_interruption
            except KeyboardInterrupt:
                sys.settrace(trace)
                try:
                    with mock.patch.object(
                        support,
                        "_create_bound_owned_private_directory",
                        side_effect=shared_interruption,
                    ):
                        support._process_runtime_root_state()
                except BaseException as error:
                    caught = error
                finally:
                    sys.settrace(previous_trace)

            self.assertTrue(fired)
            self.assertIs(caught, shared_interruption)
            self.assertIs(shared_interruption.__cause__, cleanup_intruder)
            self.assertTrue(
                any(
                    "marker cleanup also failed" in note
                    for note in shared_interruption.__notes__
                )
            )
            self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
        finally:
            sys.settrace(previous_trace)
            if getattr(support._RUNTIME_ROOT_REENTRY, "pid", None) == os.getpid():
                del support._RUNTIME_ROOT_REENTRY.pid

    def test_local_error_publication_boundaries_preserve_original(self) -> None:
        publish_code = (
            support._RuntimeRootReentryCleanup.publish_invocation_body_error.__code__
        )
        publish_instructions = tuple(dis.get_instructions(publish_code))
        publish_store = next(
            instruction.offset
            for instruction in publish_instructions
            if instruction.opname == "STORE_ATTR"
            and instruction.argval == "invocation_body_error"
        )
        scenarios = (
            (
                "store-trace-excluded",
                "trace",
                publish_code,
                "opcode",
                publish_store,
                False,
            ),
            (
                "method-return-profile",
                "profile",
                publish_code,
                "return",
                None,
                True,
            ),
        )
        for (
            label,
            hook_kind,
            target_code,
            target_event,
            target_offset,
            expected_fired,
        ) in scenarios:
            with self.subTest(boundary=label):
                shared_interruption = KeyboardInterrupt(
                    f"synthetic {label} inherited and local interruption"
                )
                publication_intruder = RuntimeError(
                    f"synthetic {label} publication interruption"
                )
                cleanup = support._RuntimeRootReentryCleanup(os.getpid())
                fired = False
                caught: BaseException | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    target_code: object = target_code,
                    target_event: str = target_event,
                    target_offset: int | None = target_offset,
                    publication_intruder: RuntimeError = publication_intruder,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is target_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == target_event
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            fired = True
                            raise publication_intruder
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    target_code: object = target_code,
                    target_event: str = target_event,
                    publication_intruder: RuntimeError = publication_intruder,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and getattr(frame, "f_code", None) is target_code
                        and event == target_event
                    ):
                        fired = True
                        raise publication_intruder

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    try:
                        raise shared_interruption
                    except KeyboardInterrupt:
                        if hook_kind == "trace":
                            sys.settrace(trace)
                        else:
                            sys.setprofile(profile)
                        try:
                            with (
                                mock.patch.object(
                                    support,
                                    "_RuntimeRootReentryCleanup",
                                    return_value=cleanup,
                                ),
                                mock.patch.object(
                                    support,
                                    "_create_bound_owned_private_directory",
                                    side_effect=shared_interruption,
                                ),
                            ):
                                support._process_runtime_root_state()
                        except BaseException as error:
                            caught = error
                        finally:
                            sys.setprofile(previous_profile)
                            sys.settrace(previous_trace)

                    self.assertEqual(fired, expected_fired)
                    self.assertIs(caught, shared_interruption)
                    self.assertIs(cleanup.invocation_body_error, shared_interruption)
                    self.assertIs(cleanup.local_active_error, shared_interruption)
                    self.assertEqual(cleanup.marker_state, "cleared")
                    self.assertEqual(cleanup.handoff_state, "ready-for-caller")
                    if expected_fired:
                        self.assertIs(
                            shared_interruption.__cause__,
                            publication_intruder,
                        )
                        self.assertTrue(
                            any(
                                "marker cleanup also failed" in note
                                for note in shared_interruption.__notes__
                            )
                        )
                    self.assertIsNone(
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                    )
                finally:
                    sys.setprofile(previous_profile)
                    sys.settrace(previous_trace)
                    if (
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                        == os.getpid()
                    ):
                        del support._RUNTIME_ROOT_REENTRY.pid

    def test_nested_context_publication_interruption_preserves_local_error(
        self,
    ) -> None:
        original_publish = (
            support._RuntimeRootReentryCleanup.publish_invocation_body_error
        )
        shared_interruption = KeyboardInterrupt(
            "synthetic nested-context inherited and local interruption"
        )
        nested_error = LookupError("synthetic callback-internal lookup failure")
        publication_intruder = RuntimeError(
            "synthetic nested-context publication interruption"
        )
        publish_calls = 0
        caught: BaseException | None = None
        observed_publication_context: BaseException | None = None
        observed_nested_context: BaseException | None = None

        def interrupt_first_publish(
            cleanup: support._RuntimeRootReentryCleanup,
            error: BaseException,
        ) -> None:
            nonlocal observed_nested_context
            nonlocal observed_publication_context
            nonlocal publish_calls
            publish_calls += 1
            original_publish(cleanup, error)
            if publish_calls == 1:
                try:
                    try:
                        raise nested_error
                    except LookupError:
                        raise publication_intruder
                except RuntimeError as delivered:
                    observed_publication_context = delivered.__context__
                    assert delivered.__context__ is not None
                    observed_nested_context = delivered.__context__.__context__
                    raise

        try:
            try:
                raise shared_interruption
            except KeyboardInterrupt:
                try:
                    with (
                        mock.patch.object(
                            support._RuntimeRootReentryCleanup,
                            "publish_invocation_body_error",
                            new=interrupt_first_publish,
                        ),
                        mock.patch.object(
                            support,
                            "_create_bound_owned_private_directory",
                            side_effect=shared_interruption,
                        ),
                    ):
                        support._process_runtime_root_state()
                except BaseException as error:
                    caught = error

            self.assertEqual(publish_calls, 1)
            self.assertIs(observed_publication_context, nested_error)
            self.assertIs(observed_nested_context, shared_interruption)
            self.assertIs(caught, shared_interruption)
            self.assertIs(shared_interruption.__cause__, publication_intruder)
            self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
        finally:
            if getattr(support._RUNTIME_ROOT_REENTRY, "pid", None) == os.getpid():
                del support._RUNTIME_ROOT_REENTRY.pid

    def test_prior_core_error_is_not_current_success_local_error(self) -> None:
        prior_error = ValueError("synthetic prior runtime-root core failure")
        cleanup_intruder = RuntimeError(
            "synthetic current-success cleanup interruption"
        )
        original_clear = support._RuntimeRootReentryCleanup.clear
        clear_calls = 0
        caught: BaseException | None = None
        current_cleanup: support._RuntimeRootReentryCleanup | None = None
        current_frame: object | None = None
        observed_retry_context: BaseException | None = None

        def interrupt_first_clear(
            cleanup: support._RuntimeRootReentryCleanup,
        ) -> None:
            nonlocal clear_calls
            nonlocal current_cleanup
            nonlocal current_frame
            nonlocal observed_retry_context
            clear_calls += 1
            if current_cleanup is None:
                current_cleanup = cleanup
                current_frame = cleanup.local_error_frame
            else:
                self.assertIs(current_cleanup, cleanup)
            if clear_calls == 1:
                raise cleanup_intruder
            active_error = sys.exception()
            if active_error is not None:
                observed_retry_context = active_error.__context__
            original_clear(cleanup)

        try:
            try:
                with mock.patch.object(
                    support,
                    "_create_bound_owned_private_directory",
                    side_effect=prior_error,
                ):
                    support._process_runtime_root_state()
            except ValueError as handled_prior_error:
                self.assertIs(handled_prior_error, prior_error)
                prior_frame = None
                traceback = handled_prior_error.__traceback__
                while traceback is not None:
                    if (
                        traceback.tb_frame.f_code
                        is support._initialize_process_runtime_root_core.__code__
                    ):
                        prior_frame = traceback.tb_frame
                        break
                    traceback = traceback.tb_next
                self.assertIsNotNone(prior_frame)

                try:
                    with mock.patch.object(
                        support._RuntimeRootReentryCleanup,
                        "clear",
                        new=interrupt_first_clear,
                    ):
                        support._process_runtime_root_state()
                except BaseException as error:
                    caught = error
            else:
                self.fail("prior runtime-root core failure did not propagate")

            self.assertEqual(clear_calls, 2)
            self.assertIsNotNone(current_cleanup)
            self.assertIsNotNone(current_frame)
            self.assertIsNot(current_frame, prior_frame)
            # A handled prior invocation may remain ambient in the caller, but
            # it is neither copied into this owner's provenance nor required
            # to become the retry exception's context.
            self.assertIsNone(observed_retry_context)
            self.assertIs(caught, cleanup_intruder)
            assert current_cleanup is not None
            self.assertIsNone(current_cleanup.local_error_frame)
            self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
        finally:
            state = support._RUNTIME_ROOT_STATE
            if state is not None and state.pid == os.getpid():
                support._cleanup_process_runtime_root(state)
            if getattr(support._RUNTIME_ROOT_REENTRY, "pid", None) == os.getpid():
                del support._RUNTIME_ROOT_REENTRY.pid

    def test_local_error_frame_binding_boundaries(self) -> None:
        core_code = support._initialize_process_runtime_root_core.__code__
        core_instructions = tuple(dis.get_instructions(core_code))
        getframe_load_index = next(
            index
            for index, instruction in enumerate(core_instructions)
            if instruction.argval == "_getframe"
        )
        getframe_call = next(
            instruction.offset
            for instruction in core_instructions[getframe_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        bind_load_index = next(
            index
            for index, instruction in enumerate(core_instructions)
            if instruction.argval == "bind_local_error_frame"
        )
        bind_caller_call = next(
            instruction.offset
            for instruction in core_instructions[bind_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )

        bind_code = support._RuntimeRootReentryCleanup.bind_local_error_frame.__code__
        bind_instructions = tuple(dis.get_instructions(bind_code))
        guard_load_index = next(
            index
            for index, instruction in enumerate(bind_instructions)
            if instruction.argval == "supported_async_publication"
        )
        guard_call = next(
            instruction.offset
            for instruction in bind_instructions[guard_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        protected_store = next(
            instruction.offset
            for instruction in bind_instructions
            if instruction.opname == "STORE_ATTR"
            and instruction.argval == "local_error_frame"
        )
        scenarios = (
            ("getframe-call-trace", "trace", core_code, "opcode", getframe_call, True),
            (
                "caller-bind-call-trace",
                "trace",
                core_code,
                "opcode",
                bind_caller_call,
                True,
            ),
            (
                "guard-call-trace",
                "trace",
                bind_code,
                "opcode",
                guard_call,
                True,
            ),
            (
                "store-trace-excluded",
                "trace",
                bind_code,
                "opcode",
                protected_store,
                False,
            ),
            ("method-call-profile", "profile", bind_code, "call", None, True),
            ("method-return-profile", "profile", bind_code, "return", None, True),
        )

        for (
            label,
            hook_kind,
            target_code,
            target_event,
            target_offset,
            expected_fired,
        ) in scenarios:
            with self.subTest(boundary=label):
                cleanup = support._RuntimeRootReentryCleanup(os.getpid())
                binding_intruder = RuntimeError(
                    f"synthetic local-error frame {label} interruption"
                )
                fired = False
                caught: BaseException | None = None
                state: support._RuntimeRootState | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    target_code: object = target_code,
                    target_event: str = target_event,
                    target_offset: int | None = target_offset,
                    binding_intruder: RuntimeError = binding_intruder,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is target_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == target_event
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            fired = True
                            raise binding_intruder
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    target_code: object = target_code,
                    target_event: str = target_event,
                    binding_intruder: RuntimeError = binding_intruder,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and getattr(frame, "f_code", None) is target_code
                        and event == target_event
                    ):
                        fired = True
                        raise binding_intruder

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    if hook_kind == "trace":
                        sys.settrace(trace)
                    else:
                        sys.setprofile(profile)
                    try:
                        state = support._initialize_process_runtime_root_locked(
                            os.getpid(),
                            cleanup,
                        )
                    except BaseException as error:
                        caught = error
                    finally:
                        sys.setprofile(previous_profile)
                        sys.settrace(previous_trace)

                    self.assertEqual(fired, expected_fired)
                    if expected_fired:
                        self.assertIs(caught, binding_intruder)
                        self.assertIsNone(support._RUNTIME_ROOT_STATE)
                        self.assertEqual(tuple(self.private_parent.iterdir()), ())
                    else:
                        self.assertIsNone(caught)
                        self.assertIsNotNone(state)
                        self.assertIs(support._RUNTIME_ROOT_STATE, state)
                    # Crossing the core frame is diagnostic only. A hook at
                    # frame-binding return is not an invocation-owned body
                    # exception and must never acquire local-error authority.
                    self.assertIsNone(cleanup.invocation_body_error)
                    self.assertIsNone(cleanup.local_active_error)
                    self.assertIsNone(cleanup.local_error_frame)
                    self.assertIsNone(
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                    )
                finally:
                    sys.setprofile(previous_profile)
                    sys.settrace(previous_trace)
                    if state is not None and state.pid == os.getpid():
                        support._cleanup_process_runtime_root(state)
                    if (
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                        == os.getpid()
                    ):
                        del support._RUNTIME_ROOT_REENTRY.pid

    def test_pre_core_call_error_does_not_outrank_cleanup_profile_error(
        self,
    ) -> None:
        caller_code = support._initialize_process_runtime_root_locked.__code__
        caller_instructions = tuple(dis.get_instructions(caller_code))
        core_load_index = next(
            index
            for index, instruction in enumerate(caller_instructions)
            if instruction.argval == "_initialize_process_runtime_root_core"
        )
        core_call = next(
            instruction.offset
            for instruction in caller_instructions[core_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        clear_code = support._RuntimeRootReentryCleanup.clear.__code__
        cleanup = support._RuntimeRootReentryCleanup(os.getpid())
        pre_core_error = RuntimeError("synthetic pre-core CALL interruption")
        cleanup_error = OSError("synthetic cleanup profile-call interruption")
        trace_fired = False
        profile_fired = False
        caught: BaseException | None = None

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal trace_fired
            if getattr(frame, "f_code", None) is caller_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not trace_fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == core_call
                ):
                    trace_fired = True
                    raise pre_core_error
            return trace

        def profile(frame: object, event: str, _argument: object) -> None:
            nonlocal profile_fired
            if (
                not profile_fired
                and getattr(frame, "f_code", None) is clear_code
                and event == "call"
            ):
                profile_fired = True
                raise cleanup_error

        previous_trace = sys.gettrace()
        previous_profile = sys.getprofile()
        try:
            sys.settrace(trace)
            sys.setprofile(profile)
            try:
                with mock.patch.object(
                    support,
                    "_RuntimeRootReentryCleanup",
                    return_value=cleanup,
                ):
                    support._process_runtime_root_state()
            except BaseException as error:
                caught = error
            finally:
                sys.setprofile(previous_profile)
                sys.settrace(previous_trace)

            self.assertTrue(trace_fired)
            self.assertTrue(profile_fired)
            self.assertIs(caught, cleanup_error)
            self.assertIsNone(cleanup.local_error_frame)
            self.assertIsNone(cleanup.local_active_error)
            self.assertIs(cleanup.clear_error, cleanup_error)
            self.assertIsNone(support._RUNTIME_ROOT_STATE)
            self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
            self.assertEqual(tuple(self.private_parent.iterdir()), ())
        finally:
            sys.setprofile(previous_profile)
            sys.settrace(previous_trace)
            if getattr(support._RUNTIME_ROOT_REENTRY, "pid", None) == os.getpid():
                del support._RUNTIME_ROOT_REENTRY.pid

    def test_publication_context_recovery_fails_closed_on_cycle_or_depth(
        self,
    ) -> None:
        original_publish = (
            support._RuntimeRootReentryCleanup.publish_invocation_body_error
        )
        for label in ("cycle", "overdeep"):
            with self.subTest(context_shape=label):
                local_interruption = KeyboardInterrupt(
                    f"synthetic {label} local initialization interruption"
                )
                publication_intruder = RuntimeError(
                    f"synthetic {label} publication interruption"
                )
                context_root = LookupError(f"synthetic {label} context root")
                publish_calls = 0
                caught: BaseException | None = None
                observed_context_tail: BaseException | None = None
                observed_cycle_return: BaseException | None = None

                def interrupt_publish(
                    cleanup: support._RuntimeRootReentryCleanup,
                    error: BaseException,
                    *,
                    label: str = label,
                    context_root: LookupError = context_root,
                    publication_intruder: RuntimeError = publication_intruder,
                ) -> None:
                    nonlocal observed_context_tail
                    nonlocal observed_cycle_return
                    nonlocal publish_calls
                    publish_calls += 1
                    self.assertTrue(
                        cleanup._traceback_contains_local_error_frame(error)
                    )
                    original_publish(cleanup, error)
                    try:
                        try:
                            raise context_root
                        except LookupError as internal_error:
                            if label == "cycle":
                                cycle_peer = OSError(
                                    "synthetic publication context cycle peer"
                                )
                                internal_error.__context__ = cycle_peer
                                cycle_peer.__context__ = internal_error
                            else:
                                cursor: BaseException = internal_error
                                for depth in range(
                                    support._RUNTIME_ROOT_CONTEXT_SCAN_LIMIT + 8
                                ):
                                    child = LookupError(
                                        f"synthetic publication context depth {depth}"
                                    )
                                    cursor.__context__ = child
                                    cursor = child
                                cursor.__context__ = error
                            raise publication_intruder
                    except RuntimeError:
                        if label == "cycle":
                            observed_context_tail = context_root.__context__
                            assert observed_context_tail is not None
                            observed_cycle_return = observed_context_tail.__context__
                        else:
                            cursor = context_root
                            for _depth in range(
                                support._RUNTIME_ROOT_CONTEXT_SCAN_LIMIT + 8
                            ):
                                assert cursor.__context__ is not None
                                cursor = cursor.__context__
                            observed_context_tail = cursor.__context__
                        raise

                try:
                    try:
                        with (
                            mock.patch.object(
                                support._RuntimeRootReentryCleanup,
                                "publish_invocation_body_error",
                                new=interrupt_publish,
                            ),
                            mock.patch.object(
                                support,
                                "_create_bound_owned_private_directory",
                                side_effect=local_interruption,
                            ),
                        ):
                            support._process_runtime_root_state()
                    except BaseException as error:
                        caught = error

                    self.assertEqual(publish_calls, 1)
                    if label == "cycle":
                        self.assertIs(observed_cycle_return, context_root)
                    else:
                        self.assertIs(observed_context_tail, local_interruption)
                    self.assertIs(caught, local_interruption)
                    self.assertIs(local_interruption.__cause__, publication_intruder)
                    self.assertIsNone(
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                    )
                finally:
                    if (
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                        == os.getpid()
                    ):
                        del support._RUNTIME_ROOT_REENTRY.pid

    def test_successful_cleanup_ignores_untrusted_context_shapes(self) -> None:
        original_clear = support._RuntimeRootReentryCleanup.clear

        for label in ("nested", "cycle", "overdeep"):
            with self.subTest(context_shape=label):
                ambient_error = ValueError(f"synthetic handled {label} caller error")
                cleanup_intruder = RuntimeError(
                    f"synthetic {label} cleanup interruption"
                )
                context_root = LookupError(f"synthetic {label} context root")
                clear_calls = 0
                caught: BaseException | None = None
                observed_boundary_context: BaseException | None = None
                observed_context_tail: BaseException | None = None
                observed_cycle_return: BaseException | None = None
                observed_retry_current: BaseException | None = None
                observed_retry_context: BaseException | None = None

                def interrupt_first_clear(
                    cleanup: support._RuntimeRootReentryCleanup,
                    *,
                    label: str = label,
                    ambient_error: ValueError = ambient_error,
                    context_root: LookupError = context_root,
                    cleanup_intruder: RuntimeError = cleanup_intruder,
                ) -> None:
                    nonlocal clear_calls
                    nonlocal observed_boundary_context
                    nonlocal observed_context_tail
                    nonlocal observed_cycle_return
                    nonlocal observed_retry_context
                    nonlocal observed_retry_current
                    clear_calls += 1
                    if clear_calls == 1:
                        try:
                            try:
                                raise context_root
                            except LookupError as internal_error:
                                if label == "cycle":
                                    cycle_peer = OSError("synthetic context cycle peer")
                                    internal_error.__context__ = cycle_peer
                                    cycle_peer.__context__ = internal_error
                                elif label == "overdeep":
                                    cursor: BaseException = internal_error
                                    for depth in range(80):
                                        child = LookupError(
                                            f"synthetic context depth {depth}"
                                        )
                                        cursor.__context__ = child
                                        cursor = child
                                    cursor.__context__ = ambient_error
                                raise cleanup_intruder
                        except RuntimeError as delivered:
                            observed_boundary_context = delivered.__context__
                            if label == "nested":
                                observed_context_tail = context_root.__context__
                            elif label == "cycle":
                                observed_context_tail = context_root.__context__
                                assert observed_context_tail is not None
                                observed_cycle_return = (
                                    observed_context_tail.__context__
                                )
                            else:
                                cursor = context_root
                                for _depth in range(80):
                                    assert cursor.__context__ is not None
                                    cursor = cursor.__context__
                                observed_context_tail = cursor.__context__
                            raise
                    observed_retry_current = sys.exception()
                    if observed_retry_current is not None:
                        observed_retry_context = observed_retry_current.__context__
                    original_clear(cleanup)

                try:
                    try:
                        raise ambient_error
                    except ValueError:
                        try:
                            with mock.patch.object(
                                support._RuntimeRootReentryCleanup,
                                "clear",
                                new=interrupt_first_clear,
                            ):
                                support._process_runtime_root_state()
                        except BaseException as error:
                            caught = error

                    self.assertEqual(clear_calls, 2)
                    self.assertIs(observed_boundary_context, context_root)
                    self.assertIs(observed_retry_current, ambient_error)
                    self.assertIsNone(observed_retry_context)
                    if label == "nested":
                        self.assertIs(observed_context_tail, ambient_error)
                    elif label == "cycle":
                        self.assertIs(observed_cycle_return, context_root)
                    else:
                        self.assertIs(observed_context_tail, ambient_error)
                    self.assertIs(caught, cleanup_intruder)
                    self.assertIsNot(caught, context_root)
                    self.assertIsNot(caught, ambient_error)
                    self.assertIsNone(
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                    )
                finally:
                    state = support._RUNTIME_ROOT_STATE
                    if state is not None and state.pid == os.getpid():
                        support._cleanup_process_runtime_root(state)
                    if (
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                        == os.getpid()
                    ):
                        del support._RUNTIME_ROOT_REENTRY.pid

    def test_successful_initialization_inside_outer_handler_propagates_cleanup_interrupt(
        self,
    ) -> None:
        cleanup_code = support._RuntimeRootReentryCleanup.clear.__code__
        cleanup_instructions = tuple(dis.get_instructions(cleanup_code))
        guard_call_index = next(
            index
            for index, instruction in enumerate(cleanup_instructions)
            if instruction.opname.startswith("CALL")
            and index > 0
            and cleanup_instructions[index - 1].argval == "supported_async_publication"
        )
        cleanup_preludes = tuple(
            instruction.offset
            for instruction in cleanup_instructions[
                max(0, guard_call_index - 16) : guard_call_index
            ]
            if instruction.opname == "NOP"
        )
        self.assertGreaterEqual(len(cleanup_preludes), 1)

        driver_code = support._drive_runtime_root_reentry_cleanup.__code__
        driver_instructions = tuple(dis.get_instructions(driver_code))
        clear_load_index = next(
            index
            for index, instruction in enumerate(driver_instructions)
            if instruction.argval == "clear"
        )
        driver_clear_call = next(
            instruction.offset
            for instruction in driver_instructions[clear_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        scenarios = (
            ("try-header", cleanup_code, cleanup_preludes[-1]),
            (
                "guard-call",
                cleanup_code,
                cleanup_instructions[guard_call_index].offset,
            ),
            ("driver-clear-call", driver_code, driver_clear_call),
        )
        for label, target_code, injection_offset in scenarios:
            with self.subTest(boundary=label):
                unrelated_error = ValueError(f"synthetic handled {label} caller error")
                cleanup_intruder = RuntimeError(
                    f"synthetic marker cleanup {label} interruption"
                )
                fired = False
                caught: BaseException | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    *,
                    target_code: object = target_code,
                    injection_offset: int = injection_offset,
                    cleanup_intruder: RuntimeError = cleanup_intruder,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is target_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == injection_offset
                        ):
                            fired = True
                            raise cleanup_intruder
                    return trace

                previous_trace = sys.gettrace()
                try:
                    try:
                        raise unrelated_error
                    except ValueError:
                        sys.settrace(trace)
                        try:
                            support._process_runtime_root_state()
                        except BaseException as error:
                            caught = error
                        finally:
                            sys.settrace(previous_trace)

                    self.assertTrue(fired)
                    self.assertIs(caught, cleanup_intruder)
                    self.assertIsNot(caught, unrelated_error)
                    self.assertIsNone(
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                    )
                finally:
                    state = support._RUNTIME_ROOT_STATE
                    if state is not None and state.pid == os.getpid():
                        support._cleanup_process_runtime_root(state)
                    if (
                        getattr(support._RUNTIME_ROOT_REENTRY, "pid", None)
                        == os.getpid()
                    ):
                        del support._RUNTIME_ROOT_REENTRY.pid

    def test_core_final_bare_raise_preserves_owned_body_for_trace_and_sigint(
        self,
    ) -> None:
        core_code = support._initialize_process_runtime_root_core.__code__
        final_bare_raise = tuple(
            instruction.offset
            for instruction in dis.get_instructions(core_code)
            if instruction.opname == "RAISE_VARARGS" and instruction.arg == 0
        )[-1]

        for delivery_kind in ("trace", "sigint"):
            with self.subTest(delivery=delivery_kind):
                cleanup = support._RuntimeRootReentryCleanup(os.getpid())
                body_error = KeyboardInterrupt(
                    f"synthetic {delivery_kind} owned initialization body"
                )
                boundary_error = RuntimeError(
                    f"synthetic {delivery_kind} final-bare boundary"
                )
                fired = False
                caught: BaseException | None = None

                def signal_handler(_signum: int, _frame: object) -> None:
                    raise boundary_error

                def trace(frame: object, event: str, _argument: object) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is core_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == final_bare_raise
                        ):
                            fired = True
                            if delivery_kind == "sigint":
                                os.kill(os.getpid(), signal.SIGINT)
                            else:
                                raise boundary_error
                    return trace

                previous_trace = sys.gettrace()
                previous_handler = signal.getsignal(signal.SIGINT)
                try:
                    if delivery_kind == "sigint":
                        signal.signal(signal.SIGINT, signal_handler)
                    sys.settrace(trace)
                    try:
                        with (
                            mock.patch.object(
                                support,
                                "_RuntimeRootReentryCleanup",
                                return_value=cleanup,
                            ),
                            mock.patch.object(
                                support,
                                "_create_bound_owned_private_directory",
                                side_effect=body_error,
                            ),
                        ):
                            support._process_runtime_root_state()
                    except BaseException as error:
                        caught = error
                finally:
                    sys.settrace(previous_trace)
                    signal.signal(signal.SIGINT, previous_handler)

                self.assertTrue(fired)
                self.assertIs(caught, body_error)
                self.assertIs(cleanup.invocation_body_error, body_error)
                self.assertIs(cleanup.local_active_error, body_error)
                self.assertIs(
                    getattr(body_error, "runtime_root_reentry_cleanup_owner", None),
                    cleanup,
                )
                self.assertTrue(
                    any(error is boundary_error for error in cleanup.boundary_errors)
                )
                self.assertTrue(
                    any(
                        traceback.tb_frame.f_code is core_code
                        for traceback in self._traceback_chain(boundary_error)
                    )
                )
                self.assertEqual(cleanup.marker_state, "cleared")
                self.assertTrue(cleanup.marker_cleared)
                self.assertEqual(cleanup.handoff_state, "ready-for-caller")
                self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))

    def test_finish_raise_is_settled_by_outer_owner_boundary(self) -> None:
        finish_code = support._RuntimeRootReentryCleanup.finish.__code__
        active_raise = next(
            instruction.offset
            for instruction in dis.get_instructions(finish_code)
            if instruction.opname == "RAISE_VARARGS" and instruction.arg == 1
        )
        cleanup = support._RuntimeRootReentryCleanup(os.getpid())
        body_error = KeyboardInterrupt("synthetic finish owned initialization body")
        boundary_error = RuntimeError("synthetic finish raise boundary")
        fired = False
        caught: BaseException | None = None

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal fired
            if getattr(frame, "f_code", None) is finish_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == active_raise
                ):
                    fired = True
                    raise boundary_error
            return trace

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            try:
                with (
                    mock.patch.object(
                        support,
                        "_RuntimeRootReentryCleanup",
                        return_value=cleanup,
                    ),
                    mock.patch.object(
                        support,
                        "_create_bound_owned_private_directory",
                        side_effect=body_error,
                    ),
                ):
                    support._process_runtime_root_state()
            except BaseException as error:
                caught = error
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(fired)
        self.assertIs(caught, body_error)
        self.assertIs(body_error.__cause__, boundary_error)
        self.assertIs(cleanup.invocation_body_error, body_error)
        self.assertTrue(
            any(error is boundary_error for error in cleanup.boundary_errors)
        )
        self.assertTrue(cleanup.marker_cleared)
        self.assertEqual(cleanup.handoff_state, "ready-for-caller")

    def test_owned_temporary_directory_uses_one_caller_owner_boundary(self) -> None:
        boundary_code = support._settle_runtime_root_owner_boundary.__code__
        boundary_instructions = tuple(dis.get_instructions(boundary_code))
        driver_load_index = next(
            index
            for index, instruction in enumerate(boundary_instructions)
            if instruction.argval == "_drive_runtime_root_reentry_cleanup"
        )
        driver_call = next(
            instruction.offset
            for instruction in boundary_instructions[driver_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        driver_code = support._drive_runtime_root_reentry_cleanup.__code__
        cleanup = support._RuntimeRootReentryCleanup(os.getpid())
        body_error = KeyboardInterrupt("synthetic production caller body")
        trace_error = RuntimeError("synthetic owner handoff trace boundary")
        profile_error = OSError("synthetic owner handoff profile boundary")
        trace_fired = False
        profile_fired = False
        caught: BaseException | None = None

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal trace_fired
            if getattr(frame, "f_code", None) is boundary_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not trace_fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == driver_call
                ):
                    trace_fired = True
                    raise trace_error
            return trace

        def profile(frame: object, event: str, _argument: object) -> None:
            nonlocal profile_fired
            if (
                not profile_fired
                and trace_fired
                and getattr(frame, "f_code", None) is driver_code
                and event == "call"
            ):
                profile_fired = True
                raise profile_error

        previous_trace = sys.gettrace()
        previous_profile = sys.getprofile()
        try:
            sys.settrace(trace)
            sys.setprofile(profile)
            try:
                with (
                    mock.patch.object(
                        support,
                        "_RuntimeRootReentryCleanup",
                        return_value=cleanup,
                    ),
                    mock.patch.object(
                        support,
                        "_create_bound_owned_private_directory",
                        side_effect=body_error,
                    ),
                ):
                    with support.owned_temporary_directory("owner-boundary-"):
                        self.fail("runtime-root initialization unexpectedly succeeded")
            except BaseException as error:
                caught = error
        finally:
            sys.setprofile(previous_profile)
            sys.settrace(previous_trace)

        self.assertTrue(trace_fired)
        self.assertTrue(profile_fired)
        self.assertIs(caught, body_error)
        self.assertIs(body_error.__cause__, trace_error)
        self.assertTrue(any(error is trace_error for error in cleanup.boundary_errors))
        self.assertTrue(
            any(error is profile_error for error in cleanup.boundary_errors)
        )
        self.assertTrue(cleanup.marker_cleared)
        self.assertEqual(cleanup.handoff_state, "ready-for-caller")
        self.assertIs(
            getattr(body_error, "runtime_root_reentry_cleanup_owner", None),
            cleanup,
        )

    def test_nested_reentry_never_clears_the_outer_marker_owner(self) -> None:
        current_pid = os.getpid()
        outer_cleanup = support._RuntimeRootReentryCleanup(current_pid)
        inner_cleanup = support._RuntimeRootReentryCleanup(current_pid)
        outer_cleanup.publish_marker()
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "same-thread process runtime-root initialization reentry",
            ):
                support._process_runtime_root_state_with_owner(
                    current_pid,
                    inner_cleanup,
                )

            self.assertIs(
                getattr(support._RUNTIME_ROOT_REENTRY, "cleanup_owner", None),
                outer_cleanup,
            )
            self.assertEqual(
                getattr(support._RUNTIME_ROOT_REENTRY, "pid", None),
                current_pid,
            )
            self.assertTrue(inner_cleanup.marker_cleared)
            self.assertEqual(inner_cleanup.handoff_state, "ready-for-caller")
        finally:
            support._drive_runtime_root_reentry_cleanup(
                outer_cleanup,
                resume_active=False,
            )

        self.assertTrue(outer_cleanup.marker_cleared)
        self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))
        self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "cleanup_owner", None))

    def test_trace_and_profile_each_interrupt_clear_before_marker_terminal(
        self,
    ) -> None:
        driver_code = support._drive_runtime_root_reentry_cleanup.__code__
        driver_instructions = tuple(dis.get_instructions(driver_code))
        clear_load_index = next(
            index
            for index, instruction in enumerate(driver_instructions)
            if instruction.argval == "clear"
        )
        clear_call = next(
            instruction.offset
            for instruction in driver_instructions[clear_load_index + 1 :]
            if instruction.opname.startswith("CALL")
        )
        clear_code = support._RuntimeRootReentryCleanup.clear.__code__
        cleanup = support._RuntimeRootReentryCleanup(os.getpid())
        body_error = KeyboardInterrupt(
            "synthetic trace-profile owned initialization body"
        )
        trace_error = RuntimeError("synthetic driver clear trace boundary")
        profile_error = OSError("synthetic clear call profile boundary")
        trace_fired = False
        profile_fired = False
        caught: BaseException | None = None

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal trace_fired
            if getattr(frame, "f_code", None) is driver_code:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not trace_fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == clear_call
                ):
                    trace_fired = True
                    raise trace_error
            return trace

        def profile(frame: object, event: str, _argument: object) -> None:
            nonlocal profile_fired
            if (
                not profile_fired
                and getattr(frame, "f_code", None) is clear_code
                and event == "call"
            ):
                profile_fired = True
                raise profile_error

        previous_trace = sys.gettrace()
        previous_profile = sys.getprofile()
        try:
            sys.settrace(trace)
            sys.setprofile(profile)
            try:
                with (
                    mock.patch.object(
                        support,
                        "_RuntimeRootReentryCleanup",
                        return_value=cleanup,
                    ),
                    mock.patch.object(
                        support,
                        "_create_bound_owned_private_directory",
                        side_effect=body_error,
                    ),
                ):
                    support._process_runtime_root_state()
            except BaseException as error:
                caught = error
        finally:
            sys.setprofile(previous_profile)
            sys.settrace(previous_trace)

        self.assertTrue(trace_fired)
        self.assertTrue(profile_fired)
        self.assertIs(caught, body_error)
        self.assertTrue(any(error is trace_error for error in cleanup.boundary_errors))
        self.assertTrue(
            any(error is profile_error for error in cleanup.boundary_errors)
        )
        self.assertTrue(cleanup.marker_cleared)
        self.assertEqual(cleanup.marker_state, "cleared")
        self.assertEqual(cleanup.handoff_state, "ready-for-caller")
        self.assertIsNone(getattr(support._RUNTIME_ROOT_REENTRY, "pid", None))

    def test_successful_core_return_attaches_exact_state_owner(self) -> None:
        core_code = support._initialize_process_runtime_root_core.__code__
        successful_return = tuple(
            instruction.offset
            for instruction in dis.get_instructions(core_code)
            if instruction.opname == "RETURN_VALUE"
        )[-1]

        for hook_kind in ("trace", "profile"):
            with self.subTest(hook=hook_kind):
                cleanup = support._RuntimeRootReentryCleanup(os.getpid())
                boundary_error = RuntimeError(
                    f"synthetic successful core {hook_kind} return boundary"
                )
                fired = False
                caught: BaseException | None = None

                def trace(frame: object, event: str, _argument: object) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is core_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == successful_return
                        ):
                            fired = True
                            raise boundary_error
                    return trace

                def profile(frame: object, event: str, _argument: object) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and getattr(frame, "f_code", None) is core_code
                        and event == "return"
                    ):
                        fired = True
                        raise boundary_error

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    if hook_kind == "trace":
                        sys.settrace(trace)
                    else:
                        sys.setprofile(profile)
                    try:
                        with mock.patch.object(
                            support,
                            "_RuntimeRootReentryCleanup",
                            return_value=cleanup,
                        ):
                            support._process_runtime_root_state()
                    except BaseException as error:
                        caught = error
                finally:
                    sys.setprofile(previous_profile)
                    sys.settrace(previous_trace)

                state = cleanup.published_state
                try:
                    self.assertTrue(fired)
                    self.assertIs(caught, boundary_error)
                    self.assertIsNotNone(state)
                    assert state is not None
                    self.assertIs(support._RUNTIME_ROOT_STATE, state)
                    self.assertIs(
                        getattr(boundary_error, "runtime_root_state_owner", None),
                        state,
                    )
                    self.assertIs(
                        getattr(
                            boundary_error,
                            "runtime_root_reentry_cleanup_owner",
                            None,
                        ),
                        cleanup,
                    )
                    self.assertEqual(
                        state.protected_property,
                        "object-identity-and-private-access-policy",
                    )
                    before = state.binding._metadata_object_key(
                        os.fstat(state.binding.fd)
                    )
                    state.binding.revalidate()
                    after = state.binding._metadata_object_key(
                        os.fstat(state.binding.fd)
                    )
                    self.assertEqual(before, state.binding._object_key())
                    self.assertEqual(after, before)
                    self.assertEqual(stat.S_IMODE(state.path.stat().st_mode), 0o700)
                    # Empty content is observed for leak detection only; it is
                    # not used as object-identity or access-policy evidence.
                    self.assertEqual(tuple(state.path.iterdir()), ())
                    self.assertTrue(cleanup.marker_cleared)
                    self.assertEqual(cleanup.handoff_state, "ready-for-caller")
                finally:
                    if state is not None and state.pid == os.getpid():
                        support._cleanup_process_runtime_root(state)

    @staticmethod
    def _traceback_chain(error: BaseException) -> tuple[object, ...]:
        tracebacks: list[object] = []
        traceback = error.__traceback__
        while traceback is not None:
            tracebacks.append(traceback)
            traceback = traceback.tb_next
        return tuple(tracebacks)

    def test_atexit_cleanup_quarantines_only_exact_empty_root(self) -> None:
        state = support._process_runtime_root_state()
        replacement = state.path
        displaced = replacement.with_name(replacement.name + "-displaced")
        replacement.rename(displaced)
        replacement.mkdir(mode=0o700)
        try:
            with self.assertRaises(Exception) as caught:
                support._cleanup_process_runtime_root(state)
            self.assertIs(
                getattr(caught.exception, "runtime_root_state_owner", None),
                state,
            )
            self.assertTrue(replacement.is_dir())
            self.assertTrue(displaced.is_dir())
        finally:
            replacement.rmdir()
            displaced.rename(replacement)
            state.cleanup_owner.state = "live"
            state.cleanup_owner.error = None


if __name__ == "__main__":
    unittest.main()
