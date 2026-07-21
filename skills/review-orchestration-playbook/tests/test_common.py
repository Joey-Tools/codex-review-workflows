from __future__ import annotations

import json
import os
import pathlib
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
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
                mock.patch.object(common.os, "set_blocking"),
                mock.patch.object(
                    common.select,
                    "select",
                    side_effect=lambda readers, _writers, _errors, _timeout: (
                        readers,
                        (),
                        (),
                    ),
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

        def select_output(readers, _writers, _errors, _timeout):
            nonlocal stdout_read
            descriptor = readers[0]
            if descriptor == 101 and not stdout_read:
                stdout_read = True
                return readers, (), ()
            if descriptor == 102:
                return readers, (), ()
            time.sleep(0.001)
            return (), (), ()

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

        def block_signals():
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
                    common.select,
                    "select",
                    side_effect=select_output,
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
