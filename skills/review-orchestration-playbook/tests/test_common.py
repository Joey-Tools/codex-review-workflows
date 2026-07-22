from __future__ import annotations

import base64
import dis
import json
import os
import pathlib
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
FD_EXEC_SOURCE = SCRIPTS / "review_runtime/fd_exec.py"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import common  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


class StreamingBytesRedactorTest(unittest.TestCase):
    @staticmethod
    def redact_in_chunks(
        redact_values: tuple[str | bytes, ...],
        chunks: tuple[bytes, ...],
    ) -> bytes:
        redactor = common._StreamingBytesRedactor(redact_values)
        output = bytearray()
        for chunk in chunks:
            output.extend(redactor.feed(chunk))
        output.extend(redactor.finish())
        return bytes(output)

    def test_normalization_ignores_empty_values_and_sorts_unique_values_by_length(
        self,
    ) -> None:
        unicode_value = "凭据🔒"

        normalized = common._normalize_redact_values(
            (
                b"",
                "",
                b"prefix",
                b"prefix-long",
                b"prefix",
                unicode_value,
                os.fsencode(unicode_value),
            )
        )

        self.assertEqual(
            set(normalized),
            {b"prefix", b"prefix-long", os.fsencode(unicode_value)},
        )
        self.assertEqual(
            [len(value) for value in normalized],
            sorted((len(value) for value in normalized), reverse=True),
        )
        self.assertLess(normalized.index(b"prefix-long"), normalized.index(b"prefix"))

    def test_redacts_prefix_overlaps_across_every_split_position(self) -> None:
        values = (b"prefix", b"prefix-long", b"prefix")
        payload = b"<prefix-long>|<prefix>|prefix-longprefix"
        expected = (
            b"<"
            + b"*" * len(b"prefix-long")
            + b">|<"
            + b"*" * len(b"prefix")
            + b">|"
            + b"*" * len(b"prefix-long")
            + b"*" * len(b"prefix")
        )

        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                redacted = self.redact_in_chunks(
                    values,
                    (payload[:split], payload[split:]),
                )
                self.assertEqual(redacted, expected)
                self.assertEqual(len(redacted), len(payload))

        self.assertEqual(
            self.redact_in_chunks(values, tuple(bytes((byte,)) for byte in payload)),
            expected,
        )

    def test_redacts_unicode_value_across_utf8_byte_splits(self) -> None:
        value = "凭据🔒"
        encoded = os.fsencode(value)
        prefix = "前文:".encode()
        suffix = ":后文".encode()
        payload = prefix + encoded + suffix
        expected = prefix + b"*" * len(encoded) + suffix

        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(
                    self.redact_in_chunks((value,), (payload[:split], payload[split:])),
                    expected,
                )

    def test_redacts_union_of_offset_overlaps_across_every_split(self) -> None:
        values = (b"abc", b"bcde")
        payload = b"abcde"
        expected = b"*****"

        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(
                    self.redact_in_chunks(
                        values,
                        (payload[:split], payload[split:]),
                    ),
                    expected,
                )

        self.assertEqual(
            self.redact_in_chunks(values, tuple(bytes((byte,)) for byte in payload)),
            expected,
        )

    def test_redacts_union_of_three_offset_overlaps_across_chunks(self) -> None:
        self.assertEqual(
            self.redact_in_chunks(
                (b"abcde", b"bcdef", b"cdefg"),
                (b"a", b"bc", b"d", b"ef", b"g"),
            ),
            b"*******",
        )

    def test_fill_byte_cannot_reproduce_the_sensitive_value(self) -> None:
        self.assertEqual(
            self.redact_in_chunks((b"***",), (b"before *", b"** after")),
            b"before ### after",
        )

    def test_printable_byte_mask_survives_fixed_candidate_exhaustion(self) -> None:
        occupied = b"*#~^!"
        redacted = self.redact_in_chunks((occupied,), (occupied,))

        self.assertNotIn(occupied, redacted)
        self.assertNotIn(b"\x00", redacted)
        self.assertTrue(redacted.decode("utf-8").isprintable())

    def test_printable_byte_mask_fails_closed_when_all_candidates_exhausted(
        self,
    ) -> None:
        occupied = b"".join(common._PRINTABLE_MASK_BYTES)

        with self.assertRaisesRegex(ReviewError, "printable byte mask alphabet"):
            common._StreamingBytesRedactor((occupied,))

    def test_rejects_nul_containing_byte_redaction_values(self) -> None:
        with self.assertRaisesRegex(ReviewError, "must not contain NUL bytes"):
            common._normalize_redact_values((b"secret\x00value",))

    def test_normal_eof_flushes_nonsecret_tail_but_discard_does_not(self) -> None:
        redactor = common._StreamingBytesRedactor((b"secret",))
        emitted = redactor.feed(b"safe-secr")

        self.assertEqual(emitted + redactor.finish(), b"safe-secr")

        redactor = common._StreamingBytesRedactor((b"secret",))
        emitted = redactor.feed(b"safe-secr")
        redactor.discard()

        self.assertEqual(emitted, b"safe")


class TextRedactionTest(unittest.TestCase):
    def test_output_values_include_raw_and_json_escaped_forms(self) -> None:
        value = 'opaque\n"unicode-凭据'

        variants = common.output_redact_values((value,))

        self.assertIn(value, variants)
        self.assertIn(json.dumps(value, ensure_ascii=True)[1:-1], variants)
        self.assertIn(json.dumps(value, ensure_ascii=False)[1:-1], variants)

    def test_redacts_raw_repr_and_json_escaped_values(self) -> None:
        value = 'opaque\n"unicode-凭据'
        json_escaped = json.dumps(value, ensure_ascii=True)[1:-1]
        payload = f"raw={value}; json={json_escaped}; repr={value!r}"

        redacted = common.redact_text(payload, (value,))

        self.assertNotIn(value, redacted)
        self.assertNotIn(json_escaped, redacted)
        self.assertIn("*", redacted)

    def test_ignores_empty_and_deduplicates_overlapping_values(self) -> None:
        redacted = common.redact_text(
            "prefix-long prefix",
            ("", "prefix", "prefix-long", "prefix"),
        )

        self.assertNotIn("prefix", redacted)
        self.assertEqual(len(redacted), len("prefix-long prefix"))

    def test_fill_character_cannot_reproduce_the_sensitive_value(self) -> None:
        redacted = common.redact_text("before *** after", ("***",))

        self.assertNotIn("***", redacted)
        self.assertEqual(redacted, "before ### after")

    def test_printable_text_mask_fails_closed_when_all_candidates_exhausted(
        self,
    ) -> None:
        occupied = "".join(common._PRINTABLE_MASK_CHARACTERS)

        with self.assertRaisesRegex(ReviewError, "printable text mask alphabet"):
            common.redact_text(occupied, (occupied,))

    def test_rejects_scalar_and_non_string_redaction_values(self) -> None:
        with self.assertRaisesRegex(ReviewError, "iterable of str values"):
            common.redact_text("payload", "scalar")
        with self.assertRaisesRegex(ReviewError, "entries must be str values"):
            common.redact_text("payload", (object(),))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ReviewError, "must not contain NUL"):
            common.redact_text("payload", ("secret\x00value",))


class AtomicWriteRedactionTest(unittest.TestCase):
    def test_writer_redacts_before_the_first_storage_sink_call(self) -> None:
        value = 'opaque\n"writer-secret'
        escaped = json.dumps(value, ensure_ascii=True)[1:-1]
        stored: list[str] = []

        def store(_path: pathlib.Path, text: str) -> None:
            stored.append(text)

        with (
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
                side_effect=store,
            ) as sink,
            common.atomic_write_redactions((value,)),
        ):
            common.write_json(pathlib.Path("state.json"), {"detail": value})

        sink.assert_called_once()
        self.assertEqual(len(stored), 1)
        self.assertNotIn(value, stored[0])
        self.assertNotIn(escaped, stored[0])
        self.assertNotIn("\x00", stored[0])
        self.assertIsInstance(json.loads(stored[0]), dict)

    def test_json_writer_redacts_only_string_values_before_serialization(
        self,
    ) -> None:
        credentials = ("null", "true", "false", "1")
        stored: list[str] = []
        value = {
            "null": None,
            "true": True,
            "false": False,
            "1": 1,
            "attempt": None,
            "nested": [*credentials, {"detail": "null true false 1"}],
        }

        with (
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
                side_effect=lambda _path, text: stored.append(text),
            ) as sink,
            common.atomic_write_redactions(credentials),
        ):
            common.write_json(pathlib.Path("state.json"), value)

        sink.assert_called_once()
        self.assertEqual(len(stored), 1)
        parsed = json.loads(stored[0])
        self.assertIsNone(parsed["null"])
        self.assertIs(parsed["true"], True)
        self.assertIs(parsed["false"], False)
        self.assertEqual(parsed["1"], 1)
        self.assertIsNone(parsed["attempt"])
        for index, credential in enumerate(credentials):
            self.assertNotEqual(parsed["nested"][index], credential)
            self.assertNotIn(credential, parsed["nested"][-1]["detail"])

    def test_writer_scope_applies_to_worker_threads(self) -> None:
        value = "thread-writer-secret"
        stored: list[str] = []

        with (
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
                side_effect=lambda _path, text: stored.append(text),
            ),
            common.atomic_write_redactions((value,)),
        ):
            worker = threading.Thread(
                target=common.write_text_atomic,
                args=(pathlib.Path("thread.txt"), f"before {value} after"),
            )
            worker.start()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(stored), 1)
        self.assertNotIn(value, stored[0])

    def test_nested_writer_scopes_restore_only_the_exited_scope(self) -> None:
        outer_value = "outer-writer-secret"
        inner_value = "inner-writer-secret"
        stored: list[str] = []
        with mock.patch.object(
            common,
            "_write_text_atomic_unredacted",
            side_effect=lambda _path, text: stored.append(text),
        ):
            with common.atomic_write_redactions((outer_value,)):
                with common.atomic_write_redactions((inner_value,)):
                    common.write_text_atomic(
                        pathlib.Path("nested.txt"),
                        f"both {outer_value} {inner_value}",
                    )
                common.write_text_atomic(
                    pathlib.Path("outer.txt"),
                    f"outer-only {outer_value} {inner_value}",
                )

        self.assertNotIn(outer_value, stored[0])
        self.assertNotIn(inner_value, stored[0])
        self.assertNotIn(outer_value, stored[1])
        self.assertIn(inner_value, stored[1])

    def test_concurrent_writer_scope_exit_keeps_other_scope_active(self) -> None:
        first_value = "first-writer-secret"
        second_value = "second-writer-secret"
        second_entered = threading.Event()
        release_second = threading.Event()
        stored: list[str] = []

        def second_scope() -> None:
            with common.atomic_write_redactions((second_value,)):
                second_entered.set()
                if not release_second.wait(timeout=2):
                    raise AssertionError("concurrent writer test timed out")
                common.write_text_atomic(
                    pathlib.Path("second.txt"),
                    f"second {second_value}",
                )

        with mock.patch.object(
            common,
            "_write_text_atomic_unredacted",
            side_effect=lambda _path, text: stored.append(text),
        ):
            with common.atomic_write_redactions((first_value,)):
                worker = threading.Thread(target=second_scope)
                worker.start()
                self.assertTrue(second_entered.wait(timeout=2))
                common.write_text_atomic(
                    pathlib.Path("both.txt"),
                    f"both {first_value} {second_value}",
                )
            release_second.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(stored), 2)
        self.assertNotIn(first_value, stored[0])
        self.assertNotIn(second_value, stored[0])
        self.assertNotIn(second_value, stored[1])

    def test_enter_signal_after_registration_does_not_leak_scope(self) -> None:
        interrupted_value = "interrupted-writer-secret"
        outer_value = "outer-after-interrupt-secret"
        inner_value = "inner-after-interrupt-secret"
        stored: list[str] = []

        class AppendThenSignal(list):
            interrupted = False

            def append(self, value) -> None:
                super().append(value)
                if not self.interrupted:
                    self.interrupted = True
                    raise common.ForwardedSignal(signal.SIGTERM)

        scopes = AppendThenSignal()
        with (
            mock.patch.object(common, "_ATOMIC_WRITE_REDACTION_SCOPES", scopes),
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
                side_effect=lambda _path, text: stored.append(text),
            ),
        ):
            with self.assertRaises(common.ForwardedSignal):
                with common.atomic_write_redactions((interrupted_value,)):
                    self.fail("interrupted scope body must not run")

            self.assertEqual(scopes, [])
            with common.atomic_write_redactions((outer_value,)):
                with common.atomic_write_redactions((inner_value,)):
                    worker = threading.Thread(
                        target=common.write_text_atomic,
                        args=(
                            pathlib.Path("after-interrupt.txt"),
                            f"{interrupted_value} {outer_value} {inner_value}",
                        ),
                    )
                    worker.start()
                    worker.join(timeout=2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(scopes, [])

        self.assertEqual(len(stored), 1)
        self.assertIn(interrupted_value, stored[0])
        self.assertNotIn(outer_value, stored[0])
        self.assertNotIn(inner_value, stored[0])

    def test_writer_scope_path_filter_preserves_review_inputs(self) -> None:
        value = "review-content-coincidence"
        stored: dict[str, str] = {}
        with (
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
                side_effect=lambda path, text: stored.__setitem__(path.name, text),
            ),
            common.atomic_write_redactions(
                (value,),
                path_filter=lambda path: path.name == "state.txt",
            ),
        ):
            common.write_text_atomic(pathlib.Path("state.txt"), value)
            common.write_text_atomic(pathlib.Path("review.diff"), value)

        self.assertNotIn(value, stored["state.txt"])
        self.assertEqual(stored["review.diff"], value)

    def test_writer_scope_fails_before_sink_when_mask_alphabet_is_exhausted(
        self,
    ) -> None:
        occupied = "".join(common._PRINTABLE_MASK_CHARACTERS)
        with (
            mock.patch.object(
                common,
                "_write_text_atomic_unredacted",
            ) as sink,
            self.assertRaisesRegex(ReviewError, "printable text mask alphabet"),
        ):
            with common.atomic_write_redactions((occupied,)):
                common.write_text_atomic(pathlib.Path("state.txt"), occupied)

        sink.assert_not_called()


def _visible_exception_messages(error: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(seen) < 32:
        seen.add(id(current))
        messages.append(str(current))
        messages.extend(str(note) for note in getattr(current, "__notes__", ()))
        current = current.__cause__ or current.__context__
    return tuple(messages)


class ForwardedSignalMaskTest(unittest.TestCase):
    def test_block_rolls_back_mask_when_signal_arrives_after_syscall(self) -> None:
        current_mask: set[signal.Signals] = set()
        syscall_applied = False
        interruption = common.ForwardedSignal(signal.SIGTERM)

        def pthread_sigmask(
            how: int,
            mask: object,
        ) -> set[signal.Signals]:
            nonlocal syscall_applied
            requested = set(mask)
            previous = set(current_mask)
            if how == signal.SIG_BLOCK:
                current_mask.update(requested)
                syscall_applied = bool(requested)
            elif how == signal.SIG_SETMASK:
                current_mask.clear()
                current_mask.update(requested)
            return previous

        def inject_after_syscall(frame, event, _arg):
            nonlocal syscall_applied
            if (
                event == "return"
                and frame.f_code is pthread_sigmask.__code__
                and syscall_applied
            ):
                syscall_applied = False
                raise interruption
            return inject_after_syscall

        with mock.patch.object(
            common.signal,
            "pthread_sigmask",
            new=pthread_sigmask,
        ):
            sys.settrace(inject_after_syscall)
            try:
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.block_forwarded_signals()
            finally:
                sys.settrace(None)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(current_mask, set())

    def test_owner_restores_mask_after_caller_result_boundary(self) -> None:
        original_mask = {signal.SIGUSR1}
        current_mask = set(original_mask)
        interruption = common.ForwardedSignal(signal.SIGTERM)

        def pthread_sigmask(
            how: int,
            mask: object,
        ) -> set[signal.Signals]:
            requested = set(mask)
            previous = set(current_mask)
            if how == signal.SIG_BLOCK:
                current_mask.update(requested)
            elif how == signal.SIG_SETMASK:
                current_mask.clear()
                current_mask.update(requested)
            return previous

        def call_with_owner() -> None:
            owner = common.ForwardedSignalMaskOwner()
            try:
                common.block_forwarded_signals(signal_mask_owner=owner)
            finally:
                owner.restore()

        instructions = list(dis.get_instructions(call_with_owner))
        call_result_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "block_forwarded_signals":
                continue
            for candidate_index in range(index + 1, len(instructions)):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                call_result_offsets.add(instructions[candidate_index + 1].offset)
                break
        self.assertTrue(call_result_offsets)
        previous_trace = sys.gettrace()
        armed = True

        def trace(frame, event, _arg):
            nonlocal armed
            if frame.f_code is call_with_owner.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti in call_result_offsets:
                    armed = False
                    raise interruption
            return trace

        with mock.patch.object(
            common.signal,
            "pthread_sigmask",
            new=pthread_sigmask,
        ):
            sys.settrace(trace)
            try:
                with self.assertRaises(common.ForwardedSignal) as raised:
                    call_with_owner()
            finally:
                sys.settrace(previous_trace)

        self.assertIs(raised.exception, interruption)
        self.assertFalse(armed)
        self.assertEqual(current_mask, original_mask)

    def test_owner_retains_mask_when_restore_fails(self) -> None:
        previous_mask = {signal.SIGUSR1}
        owner = common.ForwardedSignalMaskOwner()
        owner.publish(previous_mask)
        first_failure = OSError("injected mask restore failure")
        restore = mock.Mock(side_effect=first_failure)

        with self.assertRaises(OSError) as raised:
            owner.restore(restore)

        self.assertIs(raised.exception, first_failure)
        self.assertTrue(owner.active)
        self.assertTrue(owner.restore_attempted)
        self.assertIs(owner.previous_mask, previous_mask)
        restore.assert_called_once_with(previous_mask)

    def test_bounded_owner_restore_retries_once_until_success(self) -> None:
        previous_mask = {signal.SIGUSR1}
        owner = common.ForwardedSignalMaskOwner()
        owner.publish(previous_mask)
        first_failure = OSError("injected mask restore failure")
        restore = mock.Mock(side_effect=(first_failure, None))

        failures = common._restore_forwarded_signal_mask_owner_bounded(
            owner,
            restore=restore,
        )

        self.assertEqual(failures, (first_failure,))
        self.assertFalse(owner.active)
        self.assertTrue(owner.restore_attempted)
        self.assertIs(owner.previous_mask, previous_mask)
        self.assertEqual(restore.call_args_list, [mock.call(previous_mask)] * 2)


class ChildEnvironmentTest(unittest.TestCase):
    def test_file_descriptor_owner_relinquishes_before_close(self) -> None:
        owner = common._FileDescriptorOwner(123)
        close_error = OSError("injected close failure")

        def fail_after_observing_owner(descriptor: int) -> None:
            self.assertEqual(descriptor, 123)
            self.assertIsNone(owner.descriptor)
            raise close_error

        with mock.patch.object(
            common.os, "close", side_effect=fail_after_observing_owner
        ):
            with self.assertRaises(OSError) as raised:
                owner.close()
            owner.close()

        self.assertIs(raised.exception, close_error)

    @unittest.skipUnless(os.name == "posix", "descriptor duplication requires POSIX")
    def test_pipe_normalization_closes_pending_duplicate_on_flag_failure(
        self,
    ) -> None:
        import fcntl

        flag_error = OSError("injected inheritable failure")
        closed: list[int] = []
        with (
            mock.patch.object(common.os, "pipe", return_value=(0, 1)),
            mock.patch.object(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
            mock.patch.object(fcntl, "fcntl", return_value=10),
            mock.patch.object(common.os, "set_inheritable", side_effect=flag_error),
            mock.patch.object(common.os, "close", side_effect=closed.append),
        ):
            with self.assertRaises(OSError) as raised:
                common._pipe_above_standard_descriptors()

        self.assertIs(raised.exception, flag_error)
        self.assertCountEqual(closed, (0, 1, 10))

    @unittest.skipUnless(os.name == "posix", "descriptor duplication requires POSIX")
    def test_pipe_normalization_does_not_retry_ambiguous_source_close(
        self,
    ) -> None:
        import fcntl

        close_error = OSError("injected source close failure")
        closed: list[int] = []

        def close(descriptor: int) -> None:
            closed.append(descriptor)
            if descriptor == 0:
                raise close_error

        with (
            mock.patch.object(common.os, "pipe", return_value=(0, 1)),
            mock.patch.object(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
            mock.patch.object(fcntl, "fcntl", return_value=10),
            mock.patch.object(common.os, "set_inheritable"),
            mock.patch.object(common.os, "close", side_effect=close),
        ):
            with self.assertRaises(OSError) as raised:
                common._pipe_above_standard_descriptors()

        self.assertIs(raised.exception, close_error)
        self.assertEqual(closed.count(0), 1)
        self.assertEqual(closed.count(1), 1)
        self.assertEqual(closed.count(10), 1)

    def test_process_start_owner_transitions_monotonically(self) -> None:
        owner = common.ProcessStartOwner()

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        self.assertFalse(owner.may_have_started())
        self.assertFalse(owner.started())

        owner.publish_starting()

        self.assertEqual(owner.state, common.ProcessStartState.UNKNOWN)
        self.assertTrue(owner.may_have_started())
        self.assertFalse(owner.started())

        owner.publish_started()
        owner.publish_starting()

        self.assertEqual(owner.state, common.ProcessStartState.CONFIRMED)
        self.assertTrue(owner.may_have_started())
        self.assertTrue(owner.started())

    def test_logged_process_owned_spawn_result_interruption_is_reaped(
        self,
    ) -> None:
        instructions = list(dis.get_instructions(common._run_logged_process))
        result_store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "_await_owned_process_spawn":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                result_store = instructions[candidate_index + 1]
                if result_store.opname not in ("STORE_FAST", "STORE_DEREF"):
                    continue
                if result_store.argval != "process":
                    continue
                result_store_offsets.add(result_store.offset)
                break
        self.assertEqual(len(result_store_offsets), 1)

        owner = common.ProcessStartOwner()
        process = mock.Mock(pid=12345, returncode=None)
        process.poll.return_value = 0
        interruption = common.ForwardedSignal(signal.SIGTERM)
        on_process_quiescent = mock.Mock()
        terminate = mock.Mock()
        armed = True

        def trace(frame, event, _arg):
            nonlocal armed
            if frame.f_code is common._run_logged_process.__code__:
                frame.f_trace_opcodes = True
                if (
                    event == "opcode"
                    and armed
                    and frame.f_lasti in result_store_offsets
                ):
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                common.subprocess,
                "Popen",
                return_value=process,
            ) as popen,
            mock.patch.object(common.signal, "signal", return_value=signal.SIG_DFL),
            mock.patch.object(common, "terminate_process_group", terminate),
            mock.patch.object(common, "_process_group_exists", return_value=False),
            mock.patch.object(common, "block_forwarded_signals", return_value=None),
        ):
            root = pathlib.Path(temporary)
            sys.settrace(trace)
            try:
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_starting=owner.publish_starting,
                        on_process_started=owner.publish_started,
                        on_process_quiescent=on_process_quiescent,
                    )
            finally:
                sys.settrace(previous_trace)

        self.assertIs(raised.exception, interruption)
        self.assertFalse(armed)
        popen.assert_called_once()
        self.assertEqual(owner.state, common.ProcessStartState.UNKNOWN)
        self.assertTrue(owner.may_have_started())
        self.assertFalse(owner.started())
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
        )
        on_process_quiescent.assert_called_once_with()

    def test_spawn_thread_start_result_interruption_is_reaped_before_exec(
        self,
    ) -> None:
        interruption = common.ForwardedSignal(signal.SIGTERM)

        class InterruptedStartThread(threading.Thread):
            def start(self) -> None:
                super().start()
                raise interruption

        owner = common.ProcessStartOwner()
        on_process_started = mock.Mock(side_effect=owner.publish_started)
        on_process_quiescent = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "target-executed"
            with (
                mock.patch.object(
                    common,
                    "_PROCESS_SPAWN_THREAD",
                    InterruptedStartThread,
                ),
                mock.patch.object(common.subprocess, "Popen") as popen,
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        (
                            sys.executable,
                            "-c",
                            "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
                            str(marker),
                        ),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_starting=owner.publish_starting,
                        on_process_started=on_process_started,
                        on_process_quiescent=on_process_quiescent,
                    )

        self.assertIs(raised.exception, interruption)
        self.assertFalse(marker.exists())
        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        popen.assert_not_called()
        on_process_started.assert_not_called()
        on_process_quiescent.assert_not_called()

    def test_signal_cancels_blocked_spawn_without_releasing_gate(self) -> None:
        installed: dict[signal.Signals, object] = {}
        popen_entered = threading.Event()
        release_popen = threading.Event()
        terminated = threading.Event()
        process = mock.Mock(pid=12345, returncode=None)
        process.stdin = None
        process.stdout = None
        process.stderr = None

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def blocked_spawn(*args, **kwargs):
            popen_entered.set()
            release_popen.wait()
            return process

        def inject_signal() -> None:
            self.assertTrue(popen_entered.wait(2))
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)

        trigger = threading.Thread(target=inject_signal)
        trigger.start()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(
                    common.subprocess,
                    "Popen",
                    side_effect=blocked_spawn,
                ),
                mock.patch.object(
                    common.signal,
                    "signal",
                    side_effect=install_handler,
                ),
                mock.patch.object(common, "_release_exec_gate") as release_gate,
                mock.patch.object(
                    common,
                    "terminate_process_group",
                    side_effect=lambda *args, **kwargs: terminated.set(),
                ) as terminate,
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                started = time.monotonic()
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )
                elapsed = time.monotonic() - started
                release_popen.set()
                self.assertTrue(terminated.wait(2))

        trigger.join(timeout=2)
        self.assertFalse(trigger.is_alive())
        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertLess(elapsed, 2)
        release_gate.assert_not_called()
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
        )

    def test_timeout_cancels_blocked_spawn_without_releasing_gate(self) -> None:
        popen_entered = threading.Event()
        release_popen = threading.Event()
        terminated = threading.Event()
        process = mock.Mock(pid=12345, returncode=None)
        process.stdin = None
        process.stdout = None
        process.stderr = None

        def blocked_spawn(*args, **kwargs):
            popen_entered.set()
            release_popen.wait()
            return process

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(
                    common.subprocess,
                    "Popen",
                    side_effect=blocked_spawn,
                ),
                mock.patch.object(common, "_release_exec_gate") as release_gate,
                mock.patch.object(
                    common,
                    "terminate_process_group",
                    side_effect=lambda *args, **kwargs: terminated.set(),
                ) as terminate,
            ):
                started = time.monotonic()
                with self.assertRaises(common.ReviewTimeoutError):
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=0.05,
                    )
                elapsed = time.monotonic() - started
                self.assertTrue(popen_entered.is_set())
                release_popen.set()
                self.assertTrue(terminated.wait(2))

        self.assertLess(elapsed, 2)
        release_gate.assert_not_called()
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
        )

    def test_exec_handoff_uses_remaining_operation_deadline(self) -> None:
        read_descriptor, write_descriptor = os.pipe()
        try:
            deadline = time.monotonic() + 0.05
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                common._await_descriptor_exec_handoff(
                    mock.Mock(),
                    read_descriptor,
                    command=("reviewer",),
                    operation_deadline=deadline,
                    timeout_seconds=0.05,
                )
            elapsed = time.monotonic() - started
        finally:
            os.close(read_descriptor)
            os.close(write_descriptor)

        self.assertLess(elapsed, 1)

    def test_logged_process_mask_handoffs_survive_call_result_interruptions(
        self,
    ) -> None:
        instructions = list(dis.get_instructions(common._run_logged_process))
        call_result_offsets_by_line: dict[int, set[int]] = {}
        for index, instruction in enumerate(instructions):
            if instruction.argval != "block_forwarded_signals":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                line = getattr(
                    getattr(instruction, "positions", None),
                    "lineno",
                    None,
                )
                if line is None:
                    line = instruction.starts_line
                assert isinstance(line, int) and not isinstance(line, bool)
                call_result_offsets_by_line.setdefault(line, set()).add(
                    instructions[candidate_index + 1].offset
                )
                break
        self.assertEqual(len(call_result_offsets_by_line), 2)

        for target_index, target_offsets in enumerate(
            call_result_offsets_by_line[line]
            for line in sorted(call_result_offsets_by_line)
        ):
            with (
                self.subTest(target_index=target_index),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                original_mask = {signal.SIGUSR1}
                current_mask = set(original_mask)
                owners: list[common.ForwardedSignalMaskOwner] = []
                interruption = common.ForwardedSignal(signal.SIGTERM)
                armed = True

                def block(
                    *,
                    signal_mask_owner: common.ForwardedSignalMaskOwner | None = None,
                ) -> set[signal.Signals]:
                    previous_mask = set(current_mask)
                    current_mask.update(common.forwarded_signals())
                    if signal_mask_owner is not None:
                        signal_mask_owner.publish(previous_mask)
                        owners.append(signal_mask_owner)
                    return previous_mask

                def restore(previous_mask: set[signal.Signals] | None) -> None:
                    if previous_mask is None:
                        return
                    current_mask.clear()
                    current_mask.update(previous_mask)

                def trace(frame, event, _arg):
                    nonlocal armed
                    if frame.f_code is common._run_logged_process.__code__:
                        frame.f_trace_opcodes = True
                        if (
                            event == "opcode"
                            and armed
                            and frame.f_lasti in target_offsets
                        ):
                            armed = False
                            raise interruption
                    return trace

                previous_trace = sys.gettrace()
                with (
                    mock.patch.object(
                        common,
                        "block_forwarded_signals",
                        side_effect=block,
                    ),
                    mock.patch.object(
                        common,
                        "restore_signal_mask",
                        side_effect=restore,
                    ),
                    mock.patch.object(
                        common,
                        "consume_pending_forwarded_signal",
                        return_value=None,
                    ),
                ):
                    sys.settrace(trace)
                    try:
                        with self.assertRaises(common.ForwardedSignal) as raised:
                            common.run(
                                (sys.executable, "-c", "pass"),
                                stdout_path=root / "stdout.log",
                                stderr_path=root / "stderr.log",
                                timeout_seconds=5,
                                output_file_limit_bytes=4096,
                            )
                    finally:
                        sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed)
                self.assertEqual(current_mask, original_mask)
                self.assertEqual(len(owners), 2)
                self.assertTrue(all(not owner.active for owner in owners))

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

    def test_process_quiescent_callback_runs_once_for_success_and_nonzero(
        self,
    ) -> None:
        for returncode in (0, 7):
            with (
                self.subTest(returncode=returncode),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                callback = mock.Mock()

                completed = common.run(
                    (sys.executable, "-c", f"raise SystemExit({returncode})"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_quiescent=callback,
                )

                self.assertEqual(completed.returncode, returncode)
                callback.assert_called_once_with()

    def test_process_quiescent_callback_precedes_check_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            callback = mock.Mock()

            with self.assertRaisesRegex(ReviewError, r"command failed \(7\)"):
                common.run(
                    (sys.executable, "-c", "raise SystemExit(7)"),
                    check=True,
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_quiescent=callback,
                )

            callback.assert_called_once_with()

    def test_process_quiescent_callback_runs_once_after_timeout_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            callback = mock.Mock()

            with self.assertRaises(common.ReviewTimeoutError):
                common.run(
                    (sys.executable, "-c", "import time; time.sleep(5)"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=0.05,
                    on_process_quiescent=callback,
                )

            callback.assert_called_once_with()

    def test_process_quiescent_callback_runs_after_timeout_group_cleanup(
        self,
    ) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.communicate.side_effect = common.subprocess.TimeoutExpired(
            ("reviewer",),
            0.05,
        )
        process.poll.return_value = 0
        callback = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(
                    common,
                    "_process_group_exists",
                    side_effect=(True, False, False, False),
                ),
                mock.patch.object(common, "signal_process_group") as terminate,
            ):
                with self.assertRaises(common.ReviewTimeoutError):
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=0.05,
                        on_process_quiescent=callback,
                    )

        terminate.assert_called_once_with(process, signal.SIGTERM)
        callback.assert_called_once_with()

    def test_cleanup_failure_preserves_timeout_and_runs_quiescent_callback(
        self,
    ) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.communicate.side_effect = common.subprocess.TimeoutExpired(
            ("reviewer",),
            0.05,
        )
        process.poll.return_value = 0
        callback = mock.Mock()
        cleanup_error = RuntimeError("injected process-group cleanup failure")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(
                    common,
                    "terminate_process_group",
                    side_effect=cleanup_error,
                ),
                mock.patch.object(
                    common,
                    "_process_group_exists",
                    return_value=False,
                ),
                mock.patch.object(common.signal, "signal", return_value=signal.SIG_DFL),
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ReviewTimeoutError) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=0.05,
                        on_process_quiescent=callback,
                    )

        timeout = raised.exception.__cause__
        self.assertIsInstance(timeout, common.subprocess.TimeoutExpired)
        self.assertIn(
            "terminating the supervised process group (RuntimeError): "
            "injected process-group cleanup failure",
            _visible_exception_messages(timeout),
        )
        callback.assert_called_once_with()

    def test_handler_restore_failure_preserves_timeout_and_callback(
        self,
    ) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.communicate.side_effect = common.subprocess.TimeoutExpired(
            ("reviewer",),
            0.05,
        )
        process.poll.return_value = 0
        callback = mock.Mock()

        def signal_handler(signum, handler):
            if not callable(handler) and signum == signal.SIGTERM:
                raise OSError("injected handler restore failure")
            return signal.SIG_DFL

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(
                    common,
                    "_process_group_exists",
                    return_value=False,
                ),
                mock.patch.object(common.signal, "signal", side_effect=signal_handler),
                mock.patch.object(
                    common, "block_forwarded_signals", return_value=set()
                ),
                mock.patch.object(
                    common,
                    "consume_pending_forwarded_signal",
                    return_value=None,
                ),
                mock.patch.object(common, "restore_signal_mask"),
            ):
                with self.assertRaises(common.ReviewTimeoutError) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=0.05,
                        on_process_quiescent=callback,
                    )

        timeout = raised.exception.__cause__
        self.assertIsInstance(timeout, common.subprocess.TimeoutExpired)
        self.assertIn(
            "restoring the SIGTERM signal handler (OSError): "
            "injected handler restore failure",
            _visible_exception_messages(timeout),
        )
        callback.assert_called_once_with()

    def test_cleanup_keyboard_interrupt_replaces_ordinary_primary(self) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.communicate.side_effect = OSError("injected process failure")
        interruption = KeyboardInterrupt("injected cleanup interruption")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
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
                    return_value=None,
                ),
                mock.patch.object(
                    common,
                    "restore_signal_mask",
                    side_effect=interruption,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

        self.assertIs(raised.exception, interruption)
        self.assertIn(
            "process operation failed before cleanup control flow (OSError): "
            "injected process failure",
            _visible_exception_messages(raised.exception),
        )

    def test_later_cleanup_control_flow_replaces_ordinary_cleanup(self) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.communicate.return_value = (None, None)
        cleanup_error = RuntimeError("injected process cleanup failure")
        interruption = common.ForwardedSignal(signal.SIGINT)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common.signal, "signal", return_value=signal.SIG_DFL),
                mock.patch.object(
                    common,
                    "terminate_process_group",
                    side_effect=cleanup_error,
                ),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    return_value=set(),
                ),
                mock.patch.object(
                    common,
                    "consume_pending_forwarded_signal",
                    return_value=None,
                ),
                mock.patch.object(
                    common,
                    "restore_signal_mask",
                    side_effect=interruption,
                ),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(raised.exception.signum, signal.SIGINT)
        self.assertIn(
            "terminating the supervised process group (RuntimeError): "
            "injected process cleanup failure",
            _visible_exception_messages(raised.exception),
        )

    def test_process_quiescent_callback_runs_once_after_output_limit_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            callback = mock.Mock()

            with self.assertRaises(common.ReviewOutputLimitError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        "import os,time; os.write(1, b'x' * 4097); time.sleep(5)",
                    ),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=2,
                    output_file_limit_bytes=4096,
                    on_process_quiescent=callback,
                )

            callback.assert_called_once_with()

    def test_output_limit_remains_primary_when_initial_cleanup_fails(
        self,
    ) -> None:
        callback = mock.Mock()
        real_terminate = common.terminate_process_group
        cleanup_calls = 0

        def fail_initial_cleanup(process, **kwargs):
            nonlocal cleanup_calls
            cleanup_calls += 1
            if cleanup_calls == 1:
                raise RuntimeError("injected initial cleanup failure")
            return real_terminate(process, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with mock.patch.object(
                common,
                "terminate_process_group",
                side_effect=fail_initial_cleanup,
            ):
                with self.assertRaises(common.ReviewOutputLimitError) as raised:
                    common.run(
                        (
                            sys.executable,
                            "-c",
                            (
                                "import os,signal,time; "
                                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                                "os.write(1, b'x' * 4097); time.sleep(5)"
                            ),
                        ),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=2,
                        output_file_limit_bytes=4096,
                        on_process_quiescent=callback,
                    )

        self.assertGreaterEqual(cleanup_calls, 2)
        self.assertIn(
            "terminating the supervised process group (RuntimeError): "
            "injected initial cleanup failure",
            _visible_exception_messages(raised.exception),
        )
        callback.assert_not_called()

    def test_process_secondary_failure_legacy_fallback_preserves_chain(
        self,
    ) -> None:
        class LegacyError(RuntimeError):
            add_note = None

        original_cause = ValueError("original cause")
        primary = LegacyError("primary failure")
        primary.__cause__ = original_cause

        common._attach_process_secondary_failure(
            primary,
            OSError("first secondary"),
            context="first process cleanup",
        )
        common._attach_process_secondary_failure(
            primary,
            RuntimeError("second secondary"),
            context="second process cleanup",
        )

        newest = primary.__cause__
        self.assertIsInstance(
            newest,
            common.ReviewProcessSecondaryFailureDiagnostic,
        )
        self.assertEqual(
            str(newest),
            "second process cleanup (RuntimeError): second secondary",
        )
        first = newest.__cause__
        self.assertIsInstance(
            first,
            common.ReviewProcessSecondaryFailureDiagnostic,
        )
        self.assertEqual(
            str(first),
            "first process cleanup (OSError): first secondary",
        )
        self.assertIs(first.__cause__, original_cause)

    def test_process_secondary_failure_legacy_fallback_keeps_context_suppressed(
        self,
    ) -> None:
        class LegacyError(RuntimeError):
            add_note = None

        sensitive_path = "/fixture/private/suppressed-process-context/auth.json"
        hidden_context = RuntimeError(f"hidden process context at {sensitive_path}")
        primary = LegacyError("primary failure")
        primary.__context__ = hidden_context
        primary.__suppress_context__ = True

        common._attach_process_secondary_failure(
            primary,
            OSError("secondary cleanup failure"),
            context="process cleanup",
        )

        self.assertIsInstance(
            primary.__cause__,
            common.ReviewProcessSecondaryFailureDiagnostic,
        )
        self.assertIsNone(primary.__cause__.__context__)
        self.assertIs(primary.__context__, hidden_context)
        self.assertTrue(primary.__suppress_context__)
        formatted = "".join(
            traceback.format_exception(
                type(primary),
                primary,
                primary.__traceback__,
            )
        )
        self.assertNotIn(sensitive_path, formatted)

    def test_process_secondary_failure_legacy_fallback_keeps_visible_context(
        self,
    ) -> None:
        class LegacyError(RuntimeError):
            add_note = None

        original_context = RuntimeError("visible process context")
        primary = LegacyError("primary failure")
        primary.__context__ = original_context

        common._attach_process_secondary_failure(
            primary,
            OSError("secondary cleanup failure"),
            context="process cleanup",
        )

        diagnostic = primary.__cause__
        self.assertIsInstance(
            diagnostic,
            common.ReviewProcessSecondaryFailureDiagnostic,
        )
        assert diagnostic is not None
        self.assertIs(diagnostic.__context__, original_context)
        self.assertIn(
            "visible process context",
            "".join(
                traceback.format_exception(
                    type(primary),
                    primary,
                    primary.__traceback__,
                )
            ),
        )

    def test_process_quiescent_callback_failure_is_fail_closed(self) -> None:
        marker = RuntimeError("injected quiescent callback failure")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(RuntimeError) as raised:
                common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_quiescent=mock.Mock(side_effect=marker),
                )

        self.assertIs(raised.exception, marker)

    def test_process_quiescent_callback_failure_ignores_outer_exception(
        self,
    ) -> None:
        marker = RuntimeError("injected quiescent callback failure")
        try:
            raise ValueError("outer exception")
        except ValueError:
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                with self.assertRaises(RuntimeError) as raised:
                    common.run(
                        (sys.executable, "-c", "pass"),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_quiescent=mock.Mock(side_effect=marker),
                    )

        self.assertIs(raised.exception, marker)

    def test_process_quiescent_callback_failure_preserves_timeout(self) -> None:
        callback = mock.Mock(
            side_effect=RuntimeError("injected quiescent callback failure")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(common.ReviewTimeoutError):
                common.run(
                    (sys.executable, "-c", "import time; time.sleep(5)"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=0.05,
                    on_process_quiescent=callback,
                )

        callback.assert_called_once_with()

    @mock.patch.object(common.subprocess, "run")
    def test_unlogged_process_starting_callback_is_rejected_before_launch(
        self,
        subprocess_run: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "requires logged output paths"):
            common.run(
                (sys.executable, "-c", "pass"),
                on_process_starting=mock.Mock(),
            )

        subprocess_run.assert_not_called()

    @mock.patch.object(common.subprocess, "Popen")
    def test_empty_logged_command_is_rejected_before_process_start(
        self,
        popen: mock.Mock,
    ) -> None:
        owner = common.ProcessStartOwner()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(ReviewError, "command must not be empty"):
                common.run(
                    (),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_starting=owner.publish_starting,
                    on_process_started=owner.publish_started,
                )

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        popen.assert_not_called()

    @mock.patch.object(common.subprocess, "Popen")
    def test_empty_bounded_capture_command_is_rejected_before_process_start(
        self,
        popen: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "command must not be empty"):
            common.run_bounded_capture(
                (),
                timeout_seconds=5,
                stdout_limit_bytes=4096,
                stderr_limit_bytes=4096,
            )

        popen.assert_not_called()

    @mock.patch.object(common.subprocess, "Popen")
    def test_invalid_gated_environment_is_rejected_before_process_start(
        self,
        popen: mock.Mock,
    ) -> None:
        owner = common.ProcessStartOwner()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(ReviewError, "invalid name"):
                common.run(
                    ("reviewer",),
                    env={"": "value"},
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    on_process_starting=owner.publish_starting,
                )

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        popen.assert_not_called()

    @mock.patch.object(common.subprocess, "run")
    def test_unlogged_process_quiescent_callback_is_rejected_before_launch(
        self,
        subprocess_run: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "requires logged output paths"):
            common.run(
                (sys.executable, "-c", "pass"),
                on_process_quiescent=mock.Mock(),
            )

        subprocess_run.assert_not_called()

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

    def test_logged_command_file_handles_support_lifecycle_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            events: list[str] = []
            with (
                (root / "stdout.log").open("w+b") as stdout_file,
                (root / "stderr.log").open("w+b") as stderr_file,
            ):
                completed = common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_file=stdout_file,
                    stderr_file=stderr_file,
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                    on_process_starting=lambda: events.append("starting"),
                    on_process_started=lambda: events.append("started"),
                    on_process_quiescent=lambda: events.append("quiescent"),
                )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(events, ["starting", "started", "quiescent"])

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "POSIX signal masks are unavailable",
    )
    def test_universal_gated_spawn_preserves_exact_child_signal_mask(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        try:
            for requested_mask in (
                set(original_mask),
                set(original_mask).union({signal.SIGTERM}),
            ):
                with self.subTest(requested_mask=requested_mask):
                    signal.pthread_sigmask(signal.SIG_SETMASK, requested_mask)
                    with tempfile.TemporaryDirectory() as temporary:
                        root = pathlib.Path(temporary)
                        completed = common.run(
                            (
                                sys.executable,
                                "-c",
                                "import json,signal; "
                                "print(json.dumps(sorted(int(item) for item in "
                                "signal.pthread_sigmask(signal.SIG_BLOCK, set()))))",
                            ),
                            stdout_path=root / "stdout.log",
                            stderr_path=root / "stderr.log",
                        )
                    self.assertEqual(
                        set(json.loads(completed.stdout)),
                        {int(item) for item in requested_mask},
                    )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

    @unittest.skipUnless(os.name == "posix", "exec gate requires POSIX")
    def test_exec_gate_ignores_python_startup_environment(self) -> None:
        true_executable = shutil.which("true")
        self.assertIsNotNone(true_executable)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "sitecustomize-executed"
            (root / "sitecustomize.py").write_text(
                f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root)
            completed = common.run(
                (str(true_executable),),
                env=environment,
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
            )

        self.assertEqual(completed.returncode, 0)
        self.assertFalse(marker.exists())

    def test_exec_gate_keeps_target_environment_out_of_bootstrap(self) -> None:
        captured: dict[str, object] = {}
        process = mock.Mock(pid=12345, returncode=0)
        process.stdin = None
        process.stdout = None
        process.stderr = None
        process.communicate.return_value = (None, None)

        def spawn(command, **kwargs):
            captured["command"] = command
            captured["bootstrap_env"] = kwargs["env"]
            return process

        def release_gate(descriptor, environment_frame, **kwargs):
            captured["environment_frame"] = bytes(environment_frame)
            kwargs["before_commit"]()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(
                    common,
                    "_release_exec_gate",
                    side_effect=release_gate,
                ),
                mock.patch.object(common, "_await_descriptor_exec_handoff"),
                mock.patch.object(common, "_process_group_exists", return_value=False),
            ):
                completed = common.run(
                    ("reviewer",),
                    env={"CLAUDE_GATE_SECRET": "private-value"},
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(captured["bootstrap_env"], {})
        self.assertNotIn("private-value", repr(captured["command"]))
        self.assertIn(
            b"CLAUDE_GATE_SECRET=private-value\x00",
            captured["environment_frame"],
        )

    @unittest.skipUnless(os.name == "posix", "exec gate requires POSIX")
    def test_exec_gate_defers_dynamic_loader_environment_until_commit(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("a C compiler is required for the loader boundary test")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "preload.c"
            library = root / (
                "preload.dylib" if sys.platform == "darwin" else "preload.so"
            )
            marker = root / "loader-ran"
            source.write_text(
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "__attribute__((constructor)) static void mark(void) {\n"
                '  const char *path = getenv("CODEX_PRELOAD_MARKER");\n'
                "  if (path != NULL) {\n"
                '    FILE *handle = fopen(path, "wb");\n'
                "    if (handle != NULL) { fclose(handle); }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            compile_arguments = (
                (compiler, "-dynamiclib", "-o", str(library), str(source))
                if sys.platform == "darwin"
                else (
                    compiler,
                    "-shared",
                    "-fPIC",
                    "-o",
                    str(library),
                    str(source),
                )
            )
            compiled = subprocess.run(
                compile_arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                compiled.returncode,
                0,
                compiled.stderr.decode("utf-8", errors="replace"),
            )
            loader_variable = (
                "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
            )
            target_environment = {
                loader_variable: str(library),
                "CODEX_PRELOAD_MARKER": str(marker),
            }
            failure = RuntimeError("injected before gate commit")
            with (
                mock.patch.object(
                    common,
                    "_release_exec_gate",
                    side_effect=failure,
                ),
                self.assertRaises(RuntimeError) as raised,
            ):
                common.run(
                    (sys.executable, "-I", "-S", "-c", "pass"),
                    env=target_environment,
                    stdout_path=root / "blocked.stdout",
                    stderr_path=root / "blocked.stderr",
                )

            self.assertIs(raised.exception, failure)
            self.assertFalse(marker.exists())

            completed = common.run(
                (sys.executable, "-I", "-S", "-c", "pass"),
                env=target_environment,
                stdout_path=root / "committed.stdout",
                stderr_path=root / "committed.stderr",
            )

            self.assertEqual(completed.returncode, 0)
            self.assertTrue(marker.exists())

    @unittest.skipUnless(os.name == "posix", "exec gate requires POSIX")
    def test_exec_gate_streams_environment_larger_than_pipe_capacity(self) -> None:
        environment = {
            f"CODEX_GATE_VALUE_{index:03d}": "x" * 1024 for index in range(64)
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            completed = common.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    (
                        "import os,sys; "
                        "sys.exit(os.environ.get('CODEX_GATE_VALUE_063') != "
                        "'x' * 1024)"
                    ),
                ),
                env=environment,
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
                timeout_seconds=5,
            )

        self.assertEqual(completed.returncode, 0)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "SIGPIPE"),
        "SIGPIPE disposition requires POSIX",
    )
    def test_exec_gate_restores_subprocess_signal_dispositions(self) -> None:
        shell = pathlib.Path("/bin/sh")
        self.assertTrue(shell.is_file())
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "sigpipe-was-ignored"
            completed = common.run(
                (
                    str(shell),
                    "-c",
                    'kill -s PIPE "$$"; : > "$1"',
                    "sh",
                    str(marker),
                ),
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
            )

        self.assertEqual(completed.returncode, -int(signal.SIGPIPE))
        self.assertFalse(marker.exists())

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

    @unittest.skipUnless(os.name == "posix", "descriptor launch requires POSIX")
    def test_guard_bound_descriptor_launcher_executes_bytes_without_path_reopen(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            directory_descriptor = os.open(root, os.O_RDONLY)
            try:
                bound_source = FD_EXEC_SOURCE.read_bytes()
                with (
                    mock.patch.object(common, "FD_EXEC_BYTES", bound_source),
                    mock.patch.object(
                        common.pathlib.Path,
                        "is_file",
                        side_effect=AssertionError("bound launch reopened its path"),
                    ) as is_file,
                ):
                    spawn_command, pass_fds = common._descriptor_cwd_command(
                        (
                            sys.executable,
                            "-c",
                            "import os; os.write(1, os.getcwd().encode())",
                        ),
                        directory_descriptor,
                    )
                is_file.assert_not_called()
                self.assertEqual(
                    spawn_command[:5],
                    (sys.executable, "-I", "-B", "-S", "-c"),
                )
                self.assertEqual(
                    base64.b64decode(spawn_command[6], validate=True),
                    bound_source,
                )
                self.assertNotIn(str(FD_EXEC_SOURCE), spawn_command)
                self.assertEqual(
                    spawn_command[7:9],
                    (str(directory_descriptor), "-"),
                )

                completed = subprocess.run(
                    spawn_command,
                    check=False,
                    pass_fds=pass_fds,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with mock.patch.object(common, "FD_EXEC_BYTES", bound_source):
                    gated_completed = common.run(
                        (
                            sys.executable,
                            "-c",
                            "import os; os.write(1, os.getcwd().encode())",
                        ),
                        cwd_fd=directory_descriptor,
                        stdout_path=root / "gated-stdout.log",
                        stderr_path=root / "gated-stderr.log",
                        timeout_seconds=5,
                        output_file_limit_bytes=4096,
                    )
            finally:
                os.close(directory_descriptor)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, os.fsencode(root))
        self.assertEqual(gated_completed.returncode, 0, gated_completed.stderr)
        self.assertEqual(gated_completed.stdout, os.fsencode(root))

    @unittest.skipUnless(os.name == "posix", "descriptor launch requires POSIX")
    def test_guard_bound_descriptor_launcher_rejects_invalid_source(self) -> None:
        cases = (
            (bytearray(b"pass\n"), "bytes are invalid"),
            (b"", "bytes are invalid"),
            (b"x" * (common.MAX_BOUND_FD_EXEC_BYTES + 1), "bytes are invalid"),
            (b"def invalid syntax\n", "not valid Python source"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory_descriptor = os.open(temporary, os.O_RDONLY)
            try:
                for payload, message in cases:
                    with (
                        self.subTest(message=message),
                        mock.patch.object(common, "FD_EXEC_BYTES", payload),
                        self.assertRaisesRegex(common.ReviewError, message),
                    ):
                        common._descriptor_cwd_command(
                            ("reviewer",),
                            directory_descriptor,
                        )
            finally:
                os.close(directory_descriptor)

    @unittest.skipUnless(os.name == "posix", "descriptor launch requires POSIX")
    def test_guard_bound_descriptor_launcher_exact_max_preserves_gated_argv(
        self,
    ) -> None:
        bound_source = b"#" + b"x" * (common.MAX_BOUND_FD_EXEC_BYTES - 2) + b"\n"
        self.assertEqual(len(bound_source), common.MAX_BOUND_FD_EXEC_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            directory_descriptor = os.open(temporary, os.O_RDONLY)
            try:
                with mock.patch.object(common, "FD_EXEC_BYTES", bound_source):
                    spawn_command, pass_fds = common._descriptor_cwd_command(
                        ("reviewer", "argument"),
                        directory_descriptor,
                        status_fd=101,
                        gate_fd=102,
                    )
            finally:
                os.close(directory_descriptor)

        encoded_source = spawn_command[6]
        self.assertEqual(
            base64.b64decode(encoded_source, validate=True),
            bound_source,
        )
        self.assertEqual(len(encoded_source), 87_384)
        self.assertLess(len(encoded_source) + 1, 128 * 1024)
        self.assertEqual(
            spawn_command[7:],
            (
                "--gated",
                str(directory_descriptor),
                "101",
                "102",
                "reviewer",
                "argument",
            ),
        )
        self.assertEqual(
            pass_fds,
            (directory_descriptor, 101, 102),
        )

    @unittest.skipUnless(os.name == "posix", "descriptor reuse requires POSIX")
    def test_bounded_capture_avoids_closed_standard_descriptor_collisions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            result_path = root / "result"
            script = (
                "import os,pathlib,sys\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "from review_runtime import common\n"
                "os.close(0)\n"
                "os.close(1)\n"
                "completed = common.run_bounded_capture(\n"
                "    (sys.executable, '-c', "
                "'import os; os.write(1, b\\\"hello\\\")'),\n"
                "    timeout_seconds=5,\n"
                "    stdout_limit_bytes=4096,\n"
                "    stderr_limit_bytes=4096,\n"
                ")\n"
                "pathlib.Path(sys.argv[2]).write_bytes(\n"
                "    str(completed.returncode).encode() + b'\\n' + completed.stdout\n"
                ")\n"
            )
            completed = subprocess.run(
                (sys.executable, "-c", script, str(SCRIPTS), str(result_path)),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )

            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            self.assertEqual(result_path.read_bytes(), b"0\nhello")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(select, "poll"),
        "high descriptor polling requires POSIX poll",
    )
    def test_exec_handoff_supports_descriptor_above_fd_setsize(self) -> None:
        import fcntl

        read_descriptor, write_descriptor = os.pipe()
        high_descriptor = -1
        try:
            try:
                high_descriptor = int(
                    fcntl.fcntl(
                        read_descriptor,
                        getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
                        1024,
                    )
                )
            except OSError as error:
                self.skipTest(f"cannot allocate a descriptor above FD_SETSIZE: {error}")
            os.close(read_descriptor)
            read_descriptor = -1
            os.close(write_descriptor)
            write_descriptor = -1

            common._await_descriptor_exec_handoff(
                mock.Mock(),
                high_descriptor,
                command=("reviewer",),
            )
        finally:
            if read_descriptor >= 0:
                os.close(read_descriptor)
            if write_descriptor >= 0:
                os.close(write_descriptor)
            if high_descriptor >= 0:
                os.close(high_descriptor)

    @unittest.skipUnless(os.name == "posix", "exec gate requires POSIX")
    def test_logged_command_preserves_user_pass_fd_through_exec_gate(self) -> None:
        read_descriptor, write_descriptor = os.pipe()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                completed = common.run(
                    (
                        sys.executable,
                        "-c",
                        "import os,sys; os.write(int(sys.argv[1]), b'OK')",
                        str(write_descriptor),
                    ),
                    pass_fds=(write_descriptor,),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                )
            os.close(write_descriptor)
            write_descriptor = -1
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(os.read(read_descriptor, 2), b"OK")
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0:
                os.close(write_descriptor)

    @mock.patch.object(common.threading, "Thread")
    def test_failed_drain_thread_start_is_wrapped_and_not_joined(
        self, thread_factory: mock.Mock
    ) -> None:
        thread = thread_factory.return_value
        thread.start.side_effect = RuntimeError("thread start failed")
        on_process_quiescent = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(
                common.ReviewOutputDrainError, "I/O thread could not start"
            ):
                common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_path=root / "stdout.log",
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                    on_process_quiescent=on_process_quiescent,
                )

        thread.join.assert_not_called()
        on_process_quiescent.assert_not_called()

    @mock.patch.object(common.threading, "Thread")
    def test_failed_drain_thread_start_preserves_control_flow(
        self, thread_factory: mock.Mock
    ) -> None:
        interruptions = (
            common.ForwardedSignal(signal.SIGTERM),
            KeyboardInterrupt("thread start interrupted"),
            SystemExit(7),
        )
        for interruption in interruptions:
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as temporary,
            ):
                thread = thread_factory.return_value
                thread.reset_mock()
                thread.start.side_effect = interruption
                root = pathlib.Path(temporary)
                with self.assertRaises(type(interruption)) as raised:
                    common.run(
                        (sys.executable, "-c", "pass"),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        timeout_seconds=5,
                        output_file_limit_bytes=4096,
                    )

                self.assertIs(raised.exception, interruption)
                thread.join.assert_not_called()

    def test_drain_thread_io_failure_is_propagated(self) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common, "_await_descriptor_exec_handoff"),
                mock.patch.object(common, "_process_group_exists", return_value=False),
                mock.patch.object(common, "signal_process_group") as terminate,
                mock.patch.object(common.os, "set_blocking"),
                mock.patch.object(common, "_wait_descriptor_ready", return_value=True),
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

    def test_unbounded_logged_failure_closes_owned_stdin_stream(self) -> None:
        process = mock.Mock(pid=12345, returncode=None)
        process.poll.return_value = 0
        process.stdout = None
        process.stderr = None
        failure = RuntimeError("injected gate failure")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    common,
                    "_release_exec_gate",
                    side_effect=failure,
                ),
                mock.patch.object(common, "_process_group_exists", return_value=False),
                mock.patch.object(common, "terminate_process_group"),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    common.run(
                        ("reviewer",),
                        stdin=b"prompt",
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                    )

        self.assertIs(raised.exception, failure)
        process.stdin.close.assert_called_once_with()

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

    def test_process_cleanup_reaps_child_after_group_members_exit(self) -> None:
        process = mock.Mock(pid=12345)
        process.poll.return_value = 0
        with (
            mock.patch.object(common, "_process_group_exists", return_value=False),
            mock.patch.object(common, "signal_process_group") as forward,
        ):
            common.terminate_process_group(process)

        process.poll.assert_called_once_with()
        forward.assert_not_called()
        process.wait.assert_not_called()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_logged_command_rejects_descendant_holding_output_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            callback = mock.Mock()
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
                    on_process_quiescent=callback,
                )

        callback.assert_not_called()

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
                mock.patch.object(common, "_release_exec_gate"),
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
                mock.patch.object(common, "_release_exec_gate"),
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
                mock.patch.object(common, "_release_exec_gate") as release_gate,
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
            release_gate.assert_not_called()
            forward.assert_not_called()
            terminate.assert_called_once_with(
                process,
                initial_signal=signal.SIGTERM,
                signal_already_sent=False,
            )

    def test_owned_spawn_signal_never_releases_exec_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            owner = common.ProcessStartOwner()
            process = mock.Mock(pid=12345, returncode=None)
            process.poll.return_value = 0
            on_process_quiescent = mock.Mock()

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
                mock.patch.object(common, "_release_exec_gate") as release_gate,
                mock.patch.object(common, "signal_process_group") as forward,
                mock.patch.object(common, "terminate_process_group") as terminate,
                mock.patch.object(common, "_process_group_exists", return_value=False),
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_starting=owner.publish_starting,
                        on_process_started=owner.publish_started,
                        on_process_quiescent=on_process_quiescent,
                    )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(owner.state, common.ProcessStartState.UNKNOWN)
        self.assertFalse(owner.started())
        release_gate.assert_not_called()
        forward.assert_not_called()
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
        )
        on_process_quiescent.assert_called_once_with()

    def test_pending_signal_remains_primary_when_spawn_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            on_process_quiescent = mock.Mock()

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def spawn(*args, **kwargs):
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)
                raise OSError("injected spawn failure")

            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_quiescent=on_process_quiescent,
                    )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertIn(
            "process operation failed after a signal became pending (OSError): "
            "injected spawn failure",
            _visible_exception_messages(raised.exception),
        )
        on_process_quiescent.assert_not_called()

    def test_pending_signal_remains_primary_when_start_hook_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            process = mock.Mock(pid=12345, returncode=0)
            process.poll.return_value = 0
            on_process_quiescent = mock.Mock()

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def fail_after_signal():
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)
                raise OSError("injected process-start hook failure")

            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(common, "signal_process_group"),
                mock.patch.object(common, "terminate_process_group") as terminate,
                mock.patch.object(
                    common,
                    "_process_group_exists",
                    return_value=False,
                ),
                mock.patch.object(common, "block_forwarded_signals", return_value=None),
            ):
                with self.assertRaises(common.ForwardedSignal) as raised:
                    common.run(
                        ("reviewer",),
                        stdout_path=root / "stdout.log",
                        stderr_path=root / "stderr.log",
                        on_process_started=fail_after_signal,
                        on_process_quiescent=on_process_quiescent,
                    )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertIn(
            "process operation failed after a signal became pending (OSError): "
            "injected process-start hook failure",
            _visible_exception_messages(raised.exception),
        )
        terminate.assert_called_once_with(
            process,
            initial_signal=signal.SIGTERM,
            signal_already_sent=False,
        )
        on_process_quiescent.assert_called_once_with()

    def test_logged_command_keeps_failed_process_start_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()
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
                        on_process_starting=owner.publish_starting,
                        on_process_started=owner.publish_started,
                        on_process_quiescent=on_process_quiescent,
                    )

            self.assertEqual(owner.state, common.ProcessStartState.UNKNOWN)
            self.assertTrue(owner.may_have_started())
            self.assertFalse(owner.started())
            on_process_quiescent.assert_not_called()

    def test_logged_command_pipe_failure_does_not_publish_process_start(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            directory_descriptor = os.open(root, os.O_RDONLY)
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()
            try:
                with (
                    mock.patch.object(
                        common.os,
                        "pipe",
                        side_effect=OSError("pipe failed"),
                    ),
                    mock.patch.object(common.subprocess, "Popen") as popen,
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
                    with self.assertRaisesRegex(OSError, "pipe failed"):
                        common.run(
                            ("reviewer",),
                            cwd_fd=directory_descriptor,
                            stdout_path=root / "stdout.log",
                            stderr_path=root / "stderr.log",
                            on_process_starting=owner.publish_starting,
                            on_process_started=owner.publish_started,
                            on_process_quiescent=on_process_quiescent,
                        )
            finally:
                os.close(directory_descriptor)

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        self.assertFalse(owner.may_have_started())
        popen.assert_not_called()
        on_process_quiescent.assert_not_called()

    def test_logged_command_descriptor_prep_failure_does_not_publish_process_start(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            directory_descriptor = os.open(root, os.O_RDONLY)
            handoff_read_descriptor, handoff_write_descriptor = os.pipe()
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()
            try:
                with (
                    mock.patch.object(
                        common.os,
                        "pipe",
                        return_value=(
                            handoff_read_descriptor,
                            handoff_write_descriptor,
                        ),
                    ),
                    mock.patch.object(
                        common,
                        "_descriptor_cwd_command",
                        side_effect=OSError("descriptor prep failed"),
                    ),
                    mock.patch.object(common.subprocess, "Popen") as popen,
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
                    with self.assertRaisesRegex(OSError, "descriptor prep failed"):
                        common.run(
                            ("reviewer",),
                            cwd_fd=directory_descriptor,
                            stdout_path=root / "stdout.log",
                            stderr_path=root / "stderr.log",
                            on_process_starting=owner.publish_starting,
                            on_process_started=owner.publish_started,
                            on_process_quiescent=on_process_quiescent,
                        )
            finally:
                os.close(directory_descriptor)

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        self.assertFalse(owner.may_have_started())
        popen.assert_not_called()
        on_process_quiescent.assert_not_called()
        for descriptor in (handoff_read_descriptor, handoff_write_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_logged_command_pass_fd_merge_failure_does_not_publish_process_start(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            directory_descriptor = os.open(root, os.O_RDONLY)
            handoff_read_descriptor, handoff_write_descriptor = os.pipe()
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()
            try:
                with (
                    mock.patch.object(
                        common.os,
                        "pipe",
                        return_value=(
                            handoff_read_descriptor,
                            handoff_write_descriptor,
                        ),
                    ),
                    mock.patch.object(
                        common,
                        "_descriptor_cwd_command",
                        return_value=(
                            ("reviewer",),
                            (directory_descriptor, handoff_write_descriptor),
                        ),
                    ),
                    mock.patch.object(
                        common,
                        "_merge_pass_fds",
                        side_effect=OSError("pass fd merge failed"),
                    ),
                    mock.patch.object(common.subprocess, "Popen") as popen,
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
                    with self.assertRaisesRegex(OSError, "pass fd merge failed"):
                        common.run(
                            ("reviewer",),
                            cwd_fd=directory_descriptor,
                            stdout_path=root / "stdout.log",
                            stderr_path=root / "stderr.log",
                            on_process_starting=owner.publish_starting,
                            on_process_started=owner.publish_started,
                            on_process_quiescent=on_process_quiescent,
                        )
            finally:
                os.close(directory_descriptor)

        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        self.assertFalse(owner.may_have_started())
        popen.assert_not_called()
        on_process_quiescent.assert_not_called()
        for descriptor in (handoff_read_descriptor, handoff_write_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_logged_command_signal_during_descriptor_prep_prevents_launch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            directory_descriptor = os.open(root, os.O_RDONLY)
            handoff_read_descriptor, handoff_write_descriptor = os.pipe()
            installed: dict[signal.Signals, object] = {}
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def prepare_after_signal(*_args, **_kwargs):
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)
                return (
                    ("reviewer",),
                    (directory_descriptor, handoff_write_descriptor),
                )

            try:
                with (
                    mock.patch.object(
                        common.os,
                        "pipe",
                        return_value=(
                            handoff_read_descriptor,
                            handoff_write_descriptor,
                        ),
                    ),
                    mock.patch.object(
                        common,
                        "_descriptor_cwd_command",
                        side_effect=prepare_after_signal,
                    ),
                    mock.patch.object(common.subprocess, "Popen") as popen,
                    mock.patch.object(
                        common.signal,
                        "signal",
                        side_effect=install_handler,
                    ),
                    mock.patch.object(
                        common,
                        "block_forwarded_signals",
                        return_value=None,
                    ),
                ):
                    with self.assertRaises(common.ForwardedSignal) as raised:
                        common.run(
                            ("reviewer",),
                            cwd_fd=directory_descriptor,
                            stdout_path=root / "stdout.log",
                            stderr_path=root / "stderr.log",
                            on_process_starting=owner.publish_starting,
                            on_process_started=owner.publish_started,
                            on_process_quiescent=on_process_quiescent,
                        )
            finally:
                os.close(directory_descriptor)

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(owner.state, common.ProcessStartState.NOT_STARTED)
        self.assertFalse(owner.may_have_started())
        popen.assert_not_called()
        on_process_quiescent.assert_not_called()
        for descriptor in (handoff_read_descriptor, handoff_write_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_logged_command_signal_during_start_hook_prevents_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            installed: dict[signal.Signals, object] = {}
            owner = common.ProcessStartOwner()
            on_process_quiescent = mock.Mock()

            def install_handler(signum, handler):
                previous = installed.get(signum, signal.SIG_DFL)
                installed[signum] = handler
                return previous

            def publish_start_after_signal() -> None:
                owner.publish_starting()
                handler = installed[signal.SIGTERM]
                assert callable(handler)
                handler(signal.SIGTERM, None)

            with (
                mock.patch.object(common.subprocess, "Popen") as popen,
                mock.patch.object(
                    common.signal,
                    "signal",
                    side_effect=install_handler,
                ),
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
                        on_process_starting=publish_start_after_signal,
                        on_process_started=owner.publish_started,
                        on_process_quiescent=on_process_quiescent,
                    )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(owner.state, common.ProcessStartState.UNKNOWN)
        self.assertTrue(owner.may_have_started())
        popen.assert_not_called()
        on_process_quiescent.assert_not_called()

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

            on_process_starting = mock.Mock(
                side_effect=lambda: events.append("starting")
            )
            on_process_started = mock.Mock(side_effect=lambda: events.append("started"))
            with (
                mock.patch.object(common.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(
                    common.signal,
                    "signal",
                    return_value=signal.SIG_DFL,
                ),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(common, "_release_exec_gate"),
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
                    on_process_starting=on_process_starting,
                    on_process_started=on_process_started,
                )

            self.assertEqual(
                events,
                ["starting", "spawn", "started", "communicate"],
            )
            on_process_starting.assert_called_once_with()
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
                mock.patch.object(common, "_release_exec_gate"),
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

    @mock.patch.object(common.subprocess, "Popen")
    def test_exhausted_mask_alphabet_fails_before_launch_or_log_creation(
        self,
        popen: mock.Mock,
    ) -> None:
        occupied = b"".join(common._PRINTABLE_MASK_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"

            with self.assertRaisesRegex(ReviewError, "printable byte mask alphabet"):
                common.run(
                    (sys.executable, "-c", "pass"),
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout_seconds=5,
                    output_file_limit_bytes=4096,
                    redact_values=(occupied,),
                )

        popen.assert_not_called()
        self.assertFalse(stdout_path.exists())
        self.assertFalse(stderr_path.exists())

    @mock.patch.object(common.subprocess, "Popen")
    def test_invalid_redaction_arguments_fail_before_launch_or_log_creation(
        self, popen: mock.Mock
    ) -> None:
        cases = (
            (
                {
                    "redact_values": "single-value",
                    "timeout_seconds": 5,
                    "output_file_limit_bytes": 4096,
                },
                "iterable",
            ),
            (
                {
                    "redact_values": (object(),),
                    "timeout_seconds": 5,
                    "output_file_limit_bytes": 4096,
                },
                "entries",
            ),
            (
                {
                    "redact_values": (b"redact-me",),
                    "timeout_seconds": 5,
                },
                "requires output_file_limit_bytes",
            ),
            (
                {
                    "redact_values": (b"redact-me",),
                    "output_file_limit_bytes": 4096,
                },
                "positive finite timeout_seconds",
            ),
        ) + tuple(
            (
                {
                    "redact_values": (b"redact-me",),
                    "timeout_seconds": timeout,
                    "output_file_limit_bytes": 4096,
                },
                "positive finite timeout_seconds",
            )
            for timeout in (0, -1, float("inf"), float("-inf"), float("nan"))
        )
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
                            **arguments,
                        )

                    self.assertEqual(stdout_path.read_bytes(), b"existing stdout")
                    self.assertEqual(stderr_path.read_bytes(), b"existing stderr")

        popen.assert_not_called()

    @mock.patch.object(common.subprocess, "Popen")
    @mock.patch.object(common.subprocess, "run")
    def test_nonempty_redaction_requires_logged_paths_before_launch(
        self, subprocess_run: mock.Mock, popen: mock.Mock
    ) -> None:
        with self.assertRaisesRegex(ReviewError, "requires logged output paths"):
            common.run(
                (sys.executable, "-c", "pass"),
                redact_values=(b"redact-me",),
            )

        subprocess_run.assert_not_called()
        popen.assert_not_called()

    def test_empty_redaction_values_do_not_require_logged_output(self) -> None:
        completed = common.run(
            (sys.executable, "-c", "print('visible')"),
            redact_values=("", b""),
        )

        self.assertEqual(completed.stdout, b"visible\n")

    def test_drain_failure_discards_pending_redaction_tail(self) -> None:
        process = mock.Mock(pid=12345, returncode=0)
        process.stdout.fileno.return_value = 101
        process.stderr.fileno.return_value = 102
        stdout_reads = iter((b"redact-me-prefix", OSError("read failed")))

        def read_output(descriptor: int, _size: int) -> bytes:
            if descriptor == 101:
                value = next(stdout_reads)
                if isinstance(value, Exception):
                    raise value
                return value
            return b""

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common, "_process_group_exists", return_value=False),
                mock.patch.object(common, "signal_process_group"),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common, "_await_descriptor_exec_handoff"),
                mock.patch.object(common.os, "set_blocking"),
                mock.patch.object(
                    common,
                    "_wait_descriptor_ready",
                    return_value=True,
                ),
                mock.patch.object(common.os, "read", side_effect=read_output),
            ):
                with self.assertRaises(common.ReviewOutputDrainError):
                    common.run(
                        ("reviewer",),
                        stdout_path=stdout_path,
                        stderr_path=root / "stderr.log",
                        timeout_seconds=5,
                        output_file_limit_bytes=4096,
                        redact_values=(b"redact-me-prefix-complete",),
                    )

            self.assertEqual(stdout_path.read_bytes(), b"")

    def test_forwarded_signal_discards_pending_redaction_tail(self) -> None:
        process = mock.Mock(pid=12345, returncode=None)
        process.stdout.fileno.return_value = 101
        process.stderr.fileno.return_value = 102
        installed: dict[signal.Signals, object] = {}
        prefix_read = threading.Event()
        stdout_read = False
        cleanup_events: list[str] = []
        original_discard = common._StreamingBytesRedactor.discard

        def install_handler(signum, handler):
            previous = installed.get(signum, signal.SIG_DFL)
            installed[signum] = handler
            return previous

        def wait_output(
            descriptor: int,
            *,
            writable: bool,
            timeout_seconds: float,
        ) -> bool:
            nonlocal stdout_read
            if descriptor == 101 and not stdout_read:
                stdout_read = True
                return True
            if descriptor == 102:
                return True
            time.sleep(0.001)
            return False

        def read_output(descriptor: int, _size: int) -> bytes:
            if descriptor == 101:
                prefix_read.set()
                return b"redact-me-prefix"
            return b""

        def wait_for_signal(*, timeout=None):
            self.assertTrue(prefix_read.wait(timeout=1))
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)

        def block_signals(*, signal_mask_owner=None):
            cleanup_events.append("block")
            return None

        def discard_redactor(redactor):
            cleanup_events.append("discard")
            return original_discard(redactor)

        process.wait.side_effect = wait_for_signal
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            with (
                mock.patch.object(common.subprocess, "Popen", return_value=process),
                mock.patch.object(common.signal, "signal", side_effect=install_handler),
                mock.patch.object(common, "signal_process_group"),
                mock.patch.object(common, "terminate_process_group"),
                mock.patch.object(common, "_release_exec_gate"),
                mock.patch.object(common, "_await_descriptor_exec_handoff"),
                mock.patch.object(
                    common,
                    "block_forwarded_signals",
                    side_effect=block_signals,
                ),
                mock.patch.object(
                    common._StreamingBytesRedactor,
                    "discard",
                    autospec=True,
                    side_effect=discard_redactor,
                ),
                mock.patch.object(common.os, "set_blocking"),
                mock.patch.object(
                    common,
                    "_wait_descriptor_ready",
                    side_effect=wait_output,
                ),
                mock.patch.object(common.os, "read", side_effect=read_output),
            ):
                with self.assertRaises(common.ForwardedSignal):
                    common.run(
                        ("reviewer",),
                        stdout_path=stdout_path,
                        stderr_path=root / "stderr.log",
                        timeout_seconds=5,
                        output_file_limit_bytes=4096,
                        redact_values=(b"redact-me-prefix-complete",),
                    )

            self.assertEqual(stdout_path.read_bytes(), b"")
            self.assertEqual(
                cleanup_events[-3:],
                ["block", "discard", "discard"],
            )

    def test_logged_redaction_covers_stdout_stderr_unicode_and_normal_eof(
        self,
    ) -> None:
        short_value = b"prefix"
        long_value = b"prefix-long"
        unicode_value = "凭据🔒"
        unicode_bytes = os.fsencode(unicode_value)
        stdout_payload = (
            b"stdout:" + long_value + b":" + unicode_bytes + b":trailing-pref"
        )
        stderr_payload = b"ix:stderr:" + short_value + b":" + long_value
        normalized = common._normalize_redact_values(
            (short_value, long_value, unicode_value)
        )

        def redact(payload: bytes) -> bytes:
            for value in normalized:
                payload = payload.replace(value, b"*" * len(value))
            return payload

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; "
                        "os.write(1, bytes.fromhex(sys.argv[1])); "
                        "os.write(2, bytes.fromhex(sys.argv[2]))"
                    ),
                    stdout_payload.hex(),
                    stderr_payload.hex(),
                ),
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout_seconds=5,
                output_file_limit_bytes=4096,
                redact_values=(
                    b"",
                    "",
                    short_value,
                    long_value,
                    long_value,
                    unicode_value,
                    unicode_bytes,
                ),
            )

            expected_stdout = redact(stdout_payload)
            expected_stderr = redact(stderr_payload)
            self.assertEqual(stdout_path.read_bytes(), expected_stdout)
            self.assertEqual(stderr_path.read_bytes(), expected_stderr)
            self.assertEqual(completed.stdout, expected_stdout)
            self.assertEqual(completed.stderr, expected_stderr)
            self.assertEqual(len(completed.stdout), len(stdout_payload))
            self.assertEqual(len(completed.stderr), len(stderr_payload))

    def test_logged_redaction_masks_json_escaped_values_before_disk_write(
        self,
    ) -> None:
        value = 'opaque\n"unicode-凭据'
        escaped = json.dumps(value, ensure_ascii=True)[1:-1].encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    "import os,sys; data=sys.stdin.buffer.read(); "
                    "os.write(1, data); os.write(2, data)",
                ),
                stdin=escaped,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout_seconds=5,
                output_file_limit_bytes=4096,
                redact_values=common.output_redact_values((value,)),
            )

            expected = b"*" * len(escaped)
            self.assertEqual(stdout_path.read_bytes(), expected)
            self.assertEqual(stderr_path.read_bytes(), expected)
            self.assertEqual(completed.stdout, expected)
            self.assertEqual(completed.stderr, expected)

    def test_logged_redaction_masks_union_of_offset_overlaps(self) -> None:
        stdout_payload = b"abcde"
        stderr_payload = b"--abcde--"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; "
                        "os.write(1, bytes.fromhex(sys.argv[1])); "
                        "os.write(2, bytes.fromhex(sys.argv[2]))"
                    ),
                    stdout_payload.hex(),
                    stderr_payload.hex(),
                ),
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout_seconds=5,
                output_file_limit_bytes=4096,
                redact_values=(b"abc", b"bcde"),
            )

            self.assertEqual(stdout_path.read_bytes(), b"*****")
            self.assertEqual(stderr_path.read_bytes(), b"--*****--")
            self.assertEqual(completed.stdout, b"*****")
            self.assertEqual(completed.stderr, b"--*****--")

    def test_timeout_discards_pending_redaction_tail(self) -> None:
        value = b"timeout-secret"
        emitted_prefix = value[:-1]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            with self.assertRaises(common.ReviewTimeoutError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,sys,time; "
                            "os.write(1, b'safe-' * 16 + bytes.fromhex(sys.argv[1])); "
                            "time.sleep(5)"
                        ),
                        emitted_prefix.hex(),
                    ),
                    stdout_path=stdout_path,
                    stderr_path=root / "stderr.log",
                    timeout_seconds=0.5,
                    output_file_limit_bytes=4096,
                    redact_values=(value,),
                )

            logged = stdout_path.read_bytes()
            self.assertIn(b"safe-", logged)
            self.assertNotIn(emitted_prefix, logged)

    def test_output_limit_counts_raw_bytes_and_keeps_redaction(self) -> None:
        value = b"limit-secret"
        payload = b"safe:" + value + b":" + b"x" * 4096
        limit = 64
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            with self.assertRaises(common.ReviewOutputLimitError):
                common.run(
                    (
                        sys.executable,
                        "-c",
                        "import os,sys; os.write(1, bytes.fromhex(sys.argv[1]))",
                        payload.hex(),
                    ),
                    stdout_path=stdout_path,
                    stderr_path=root / "stderr.log",
                    timeout_seconds=5,
                    output_file_limit_bytes=limit,
                    redact_values=(value,),
                )

            logged = stdout_path.read_bytes()
            self.assertNotIn(value, logged)
            self.assertIn(b"*" * len(value), logged)
            self.assertLessEqual(len(logged), limit)

    def test_exact_output_limit_preserves_equal_length_redacted_output(self) -> None:
        value = b"exact-secret"
        limit = 64
        payload = value + b"x" * (limit - len(value))
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stdout_path = root / "stdout.log"
            completed = common.run(
                (
                    sys.executable,
                    "-c",
                    "import os,sys; os.write(1, bytes.fromhex(sys.argv[1]))",
                    payload.hex(),
                ),
                stdout_path=stdout_path,
                stderr_path=root / "stderr.log",
                timeout_seconds=5,
                output_file_limit_bytes=limit,
                redact_values=(value,),
            )

            expected = b"*" * len(value) + b"x" * (limit - len(value))
            self.assertEqual(completed.stdout, expected)
            self.assertEqual(stdout_path.read_bytes(), expected)
            self.assertEqual(len(completed.stdout), limit)


if __name__ == "__main__":
    unittest.main()
