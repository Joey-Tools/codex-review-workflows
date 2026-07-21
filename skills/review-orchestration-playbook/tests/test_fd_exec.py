from __future__ import annotations

import importlib.util
import os
import pathlib
import select
import struct
import subprocess
import sys
import tempfile
import unittest


LAUNCHER = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "review_runtime"
    / "fd_exec.py"
)
_MODULE_SPEC = importlib.util.spec_from_file_location("review_runtime_fd_exec", LAUNCHER)
if _MODULE_SPEC is None or _MODULE_SPEC.loader is None:
    raise RuntimeError(f"cannot load launcher module: {LAUNCHER}")
FD_EXEC = importlib.util.module_from_spec(_MODULE_SPEC)
_MODULE_SPEC.loader.exec_module(FD_EXEC)

CONTROL_MAGIC = FD_EXEC.CONTROL_MAGIC
MAX_ENVIRONMENT_BYTES = FD_EXEC.MAX_ENVIRONMENT_BYTES
MAX_STATUS_ERROR_BYTES = FD_EXEC.MAX_STATUS_ERROR_BYTES


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _read_to_eof(descriptor: int, limit: int) -> bytes:
    payload = bytearray()
    while True:
        chunk = os.read(descriptor, min(4096, limit + 1 - len(payload)))
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > limit:
            return bytes(payload)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])


def _environment_payload(
    records: tuple[tuple[bytes, bytes], ...] = (),
) -> bytes:
    return b"".join(key + b"=" + value + b"\0" for key, value in records)


def _control_frame(
    payload: bytes = b"",
    *,
    magic: bytes = CONTROL_MAGIC,
    token: bytes = b"G",
) -> bytes:
    return magic + struct.pack(">I", len(payload)) + payload + token


@unittest.skipUnless(os.name == "posix", "inherited descriptors require POSIX")
class FdExecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def _marker_command(self, marker: pathlib.Path) -> tuple[str, ...]:
        return (
            sys.executable,
            "-c",
            "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()",
            str(marker),
        )

    def _run_gated(
        self,
        control_stream: bytes,
        command: tuple[str, ...],
        *,
        launcher_environment: dict[str, str] | None = None,
    ) -> tuple[int, bytes, bytes, bytes]:
        status_read, status_write = os.pipe()
        gate_read, gate_write = os.pipe()
        for descriptor in (status_read, status_write, gate_read, gate_write):
            self.addCleanup(_close_descriptor, descriptor)

        process = subprocess.Popen(
            (
                sys.executable,
                str(LAUNCHER),
                "--gated",
                "-",
                str(status_write),
                str(gate_read),
                *command,
            ),
            pass_fds=(status_write, gate_read),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=launcher_environment,
        )
        try:
            os.close(status_write)
            os.close(gate_read)
            _write_all(gate_write, control_stream)
            os.close(gate_write)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

        status = _read_to_eof(status_read, MAX_STATUS_ERROR_BYTES)
        return process.returncode, stdout, stderr, status

    def _assert_gated_failure(
        self,
        control_stream: bytes,
        expected_message: bytes,
    ) -> None:
        marker = self.root / "failure-marker"
        returncode, stdout, stderr, status = self._run_gated(
            control_stream,
            self._marker_command(marker),
        )

        self.assertEqual(returncode, 126)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        self.assertLessEqual(len(status), MAX_STATUS_ERROR_BYTES)
        self.assertIn(expected_message, status)
        self.assertFalse(marker.exists())

    def test_gate_eof_cancels_without_executing_command(self) -> None:
        marker = self.root / "cancelled-marker"
        gate_read, gate_write = os.pipe()
        self.addCleanup(_close_descriptor, gate_read)
        self.addCleanup(_close_descriptor, gate_write)
        os.close(gate_write)

        result = subprocess.run(
            (
                sys.executable,
                str(LAUNCHER),
                "--gated",
                "-",
                "-",
                str(gate_read),
                *self._marker_command(marker),
            ),
            pass_fds=(gate_read,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(marker.exists())

    def test_gate_go_executes_and_status_descriptor_reaches_eof(self) -> None:
        marker = self.root / "go-marker"
        status_read, status_write = os.pipe()
        gate_read, gate_write = os.pipe()
        hold_read, hold_write = os.pipe()
        for descriptor in (
            status_read,
            status_write,
            gate_read,
            gate_write,
            hold_read,
            hold_write,
        ):
            self.addCleanup(_close_descriptor, descriptor)

        process = subprocess.Popen(
            (
                sys.executable,
                str(LAUNCHER),
                "--gated",
                "-",
                str(status_write),
                str(gate_read),
                sys.executable,
                "-c",
                (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).touch(); "
                    "os.read(int(sys.argv[2]), 1)"
                ),
                str(marker),
                str(hold_read),
            ),
            pass_fds=(status_write, gate_read, hold_read),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            os.close(status_write)
            os.close(gate_read)
            os.close(hold_read)
            _write_all(gate_write, _control_frame())
            os.close(gate_write)

            readable, _, _ = select.select((status_read,), (), (), 5)
            self.assertEqual(readable, [status_read])
            self.assertEqual(os.read(status_read, MAX_STATUS_ERROR_BYTES + 1), b"")
            self.assertIsNone(process.poll())

            self.assertEqual(os.write(hold_write, b"R"), 1)
            os.close(hold_write)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

        self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertEqual(stdout, b"")
        self.assertTrue(marker.exists())

    def test_invalid_gate_token_fails_closed_with_bounded_status(self) -> None:
        self._assert_gated_failure(
            _control_frame(token=b"X"),
            b"invalid gate token",
        )

    def test_empty_environment_does_not_inherit_launcher_environment(self) -> None:
        result_path = self.root / "empty-environment-result"
        launcher_environment = dict(os.environ)
        launcher_environment["FD_EXEC_INHERITED"] = "must-not-survive"

        returncode, stdout, stderr, status = self._run_gated(
            _control_frame(),
            (
                sys.executable,
                "-c",
                (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).write_text("
                    "'present' if b'FD_EXEC_INHERITED' in os.environb else 'absent'"
                    ")"
                ),
                str(result_path),
            ),
            launcher_environment=launcher_environment,
        )

        self.assertEqual(returncode, 0, stderr.decode())
        self.assertEqual(stdout, b"")
        self.assertEqual(status, b"")
        self.assertEqual(result_path.read_text(), "absent")

    def test_environment_round_trip_preserves_bytes_equals_and_empty_value(
        self,
    ) -> None:
        result_path = self.root / "environment-result"
        records = (
            (b"ASCII", b"value=with=equals"),
            (b"NONASCII_\xff", b"snowman=\xe2\x98\x83=caf\xc3\xa9"),
            (b"EMPTY", b""),
        )
        payload = _environment_payload(records)
        expected = b"\0".join(key + b"=" + value for key, value in records)
        key_hex = ",".join(key.hex() for key, _ in records)

        returncode, stdout, stderr, status = self._run_gated(
            _control_frame(payload),
            (
                sys.executable,
                "-c",
                (
                    "import os, pathlib, sys; "
                    "keys=[bytes.fromhex(item) for item in sys.argv[2].split(',')]; "
                    "pathlib.Path(sys.argv[1]).write_bytes("
                    "b'\\0'.join(key+b'='+os.environb[key] for key in keys)"
                    ")"
                ),
                str(result_path),
                key_hex,
            ),
        )

        self.assertEqual(returncode, 0, stderr.decode())
        self.assertEqual(stdout, b"")
        self.assertEqual(status, b"")
        self.assertEqual(result_path.read_bytes(), expected)

    def test_bad_control_magic_fails_closed(self) -> None:
        self._assert_gated_failure(
            _control_frame(magic=b"BAD!"),
            b"invalid control magic",
        )

    def test_eof_at_each_control_stage_cancels(self) -> None:
        payload = _environment_payload(((b"KEY", b"value"),))
        truncated_streams = (
            b"CGR",
            CONTROL_MAGIC + struct.pack(">I", len(payload)) + payload[:-1],
            CONTROL_MAGIC + struct.pack(">I", len(payload)) + payload,
        )

        for index, control_stream in enumerate(truncated_streams):
            with self.subTest(index=index):
                marker = self.root / f"truncated-marker-{index}"
                returncode, stdout, stderr, status = self._run_gated(
                    control_stream,
                    self._marker_command(marker),
                )

                self.assertEqual(returncode, 0, stderr.decode())
                self.assertEqual(stdout, b"")
                self.assertEqual(status, b"")
                self.assertFalse(marker.exists())

    def test_oversize_payload_header_fails_closed_without_reading_payload(
        self,
    ) -> None:
        control_stream = CONTROL_MAGIC + struct.pack(">I", MAX_ENVIRONMENT_BYTES + 1)
        self._assert_gated_failure(
            control_stream,
            b"environment payload exceeds the maximum size",
        )

    def test_environment_payload_size_boundary(self) -> None:
        maximum_payload = b"KEY=" + (b"v" * (MAX_ENVIRONMENT_BYTES - 5)) + b"\0"
        environment = FD_EXEC._parse_environment_payload(maximum_payload)
        self.assertEqual(len(maximum_payload), MAX_ENVIRONMENT_BYTES)
        self.assertEqual(environment[b"KEY"], maximum_payload[4:-1])

        oversize_payload = maximum_payload + b"\0"
        with self.assertRaisesRegex(OSError, "exceeds the maximum size"):
            FD_EXEC._parse_environment_payload(oversize_payload)

    def test_malformed_environment_records_fail_closed(self) -> None:
        malformed_payloads = (
            b"KEY=value",
            b"\0",
            b"KEY=value\0\0",
            b"KEY\0",
            b"=value\0",
        )

        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                self._assert_gated_failure(
                    _control_frame(payload),
                    b"malformed environment",
                )

    def test_duplicate_environment_key_fails_closed(self) -> None:
        payload = _environment_payload(
            (
                (b"DUPLICATE", b"first"),
                (b"DUPLICATE", b"second"),
            )
        )
        self._assert_gated_failure(
            _control_frame(payload),
            b"duplicate environment key",
        )

    def test_legacy_form_still_enters_directory_before_exec(self) -> None:
        directory_fd = os.open(self.root, os.O_RDONLY)
        self.addCleanup(_close_descriptor, directory_fd)

        result = subprocess.run(
            (
                sys.executable,
                str(LAUNCHER),
                str(directory_fd),
                "-",
                sys.executable,
                "-c",
                "import pathlib; pathlib.Path('legacy-marker').touch()",
            ),
            pass_fds=(directory_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.root / "legacy-marker").exists())


if __name__ == "__main__":
    unittest.main()
