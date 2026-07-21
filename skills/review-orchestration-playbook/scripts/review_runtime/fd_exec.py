"""Wait for an optional launch gate and enter an inherited directory."""

from __future__ import annotations

import errno
import os
import signal
import struct
import sys
from collections.abc import Mapping


MAX_STATUS_ERROR_BYTES = 4096
CONTROL_MAGIC = b"CGR1"
MAX_ENVIRONMENT_BYTES = 8 * 1024 * 1024
_CONTROL_HEADER = struct.Struct(">4sI")


def _parse_descriptor(value: str) -> int | None:
    if value == "-":
        return None
    descriptor = int(value)
    if descriptor < 0:
        raise ValueError
    return descriptor


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _write_launch_error(status_fd: int | None, error: OSError) -> None:
    payload = f"{error.errno or errno.EIO}\n{error}".encode(
        "utf-8",
        errors="replace",
    )[:MAX_STATUS_ERROR_BYTES]
    if status_fd is not None:
        try:
            os.write(status_fd, payload)
        except OSError:
            pass
        return
    sys.stderr.buffer.write(b"fd_exec.py: launch-error: " + payload + b"\n")
    sys.stderr.buffer.flush()


def _read_exact_or_cancel(descriptor: int, size: int) -> bytes | None:
    payload = bytearray()
    while len(payload) < size:
        chunk = os.read(descriptor, size - len(payload))
        if not chunk:
            return None
        payload.extend(chunk)
    return bytes(payload)


def _parse_environment_payload(payload: bytes) -> dict[bytes, bytes]:
    if len(payload) > MAX_ENVIRONMENT_BYTES:
        raise OSError(
            errno.EMSGSIZE,
            "fd_exec.py: environment payload exceeds the maximum size",
        )
    if not payload:
        return {}
    if not payload.endswith(b"\0"):
        raise OSError(
            errno.EPROTO,
            "fd_exec.py: malformed environment payload",
        )

    environment: dict[bytes, bytes] = {}
    for record in payload[:-1].split(b"\0"):
        key, separator, value = record.partition(b"=")
        if not record or not separator or not key:
            raise OSError(
                errno.EPROTO,
                "fd_exec.py: malformed environment record",
            )
        if key in environment:
            raise OSError(
                errno.EEXIST,
                "fd_exec.py: duplicate environment key",
            )
        environment[key] = value
    return environment


def _read_gated_environment(descriptor: int) -> dict[bytes, bytes] | None:
    header = _read_exact_or_cancel(descriptor, _CONTROL_HEADER.size)
    if header is None:
        return None
    magic, payload_size = _CONTROL_HEADER.unpack(header)
    if magic != CONTROL_MAGIC:
        raise OSError(errno.EPROTO, "fd_exec.py: invalid control magic")
    if payload_size > MAX_ENVIRONMENT_BYTES:
        raise OSError(
            errno.EMSGSIZE,
            "fd_exec.py: environment payload exceeds the maximum size",
        )
    payload = _read_exact_or_cancel(descriptor, payload_size)
    if payload is None:
        return None
    return _parse_environment_payload(payload)


def _restore_subprocess_signal_dispositions() -> None:
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        candidate = getattr(signal, name, None)
        if candidate is None:
            continue
        try:
            signal.signal(candidate, signal.SIG_DFL)
        except (OSError, ValueError) as error:
            raise OSError(
                errno.EINVAL,
                f"fd_exec.py: cannot restore {name}: {error}",
            ) from error


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "usage: fd_exec.py DIRECTORY_FD STATUS_FD COMMAND [ARG ...]\n"
            "       fd_exec.py --gated DIRECTORY_FD STATUS_FD GATE_FD "
            "COMMAND [ARG ...]",
            file=sys.stderr,
        )
        return 64

    gated_form = sys.argv[1] == "--gated"
    if gated_form and len(sys.argv) < 6:
        print("fd_exec.py: gated launch arguments are incomplete", file=sys.stderr)
        return 64
    try:
        if gated_form:
            directory_fd = _parse_descriptor(sys.argv[2])
            status_fd = _parse_descriptor(sys.argv[3])
            gate_fd = _parse_descriptor(sys.argv[4])
            command = sys.argv[5:]
        else:
            directory_fd = _parse_descriptor(sys.argv[1])
            status_fd = _parse_descriptor(sys.argv[2])
            gate_fd = None
            command = sys.argv[3:]
    except ValueError:
        print(
            "fd_exec.py: descriptor arguments must be non-negative integers or '-'",
            file=sys.stderr,
        )
        return 64
    if gated_form and gate_fd is None:
        print("fd_exec.py: gated launch requires a gate descriptor", file=sys.stderr)
        return 64
    try:
        if status_fd is not None:
            os.set_inheritable(status_fd, False)
        target_environment: Mapping[str, str] | Mapping[bytes, bytes] = os.environ
        if gate_fd is not None:
            gated_environment = _read_gated_environment(gate_fd)
            if gated_environment is None:
                return 0
            gate_token = _read_exact_or_cancel(gate_fd, 1)
            os.close(gate_fd)
            gate_fd = None
            if gate_token is None:
                return 0
            if gate_token != b"G":
                raise OSError(errno.EPROTO, "fd_exec.py: invalid gate token")
            target_environment = gated_environment
        _restore_subprocess_signal_dispositions()
        if directory_fd is not None:
            os.fchdir(directory_fd)
            os.close(directory_fd)
            directory_fd = None
        os.execvpe(command[0], command, target_environment)
    except OSError as error:
        _write_launch_error(status_fd, error)
        return 126
    finally:
        _close_descriptor(gate_fd)
        _close_descriptor(directory_fd)
        _close_descriptor(status_fd)


if __name__ == "__main__":
    raise SystemExit(main())
