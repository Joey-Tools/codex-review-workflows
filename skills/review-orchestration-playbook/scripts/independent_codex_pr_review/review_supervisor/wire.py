from __future__ import annotations

import array
import os
import selectors
import socket
import struct
import time
from typing import Any

from .secureio import canonical_json, decode_json_bytes


MAX_RECORD_BYTES = 1024 * 1024
MAX_FDS = 8


def socket_pair() -> tuple[socket.socket, socket.socket]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    left.set_inheritable(False)
    right.set_inheritable(False)
    return left, right


def _wait(sock: socket.socket, event: int, deadline: float) -> None:
    selector = selectors.DefaultSelector()
    try:
        selector.register(sock, event)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not selector.select(remaining):
            raise TimeoutError("authenticated control-channel deadline expired")
    finally:
        selector.close()


def send_record(
    sock: socket.socket,
    value: dict[str, Any],
    *,
    deadline: float,
    fds: tuple[int, ...] = (),
) -> None:
    data = canonical_json(value)
    if len(data) > MAX_RECORD_BYTES or len(fds) > MAX_FDS:
        raise ValueError("control record exceeds its bound")
    _send_frame(sock, data, deadline=deadline, fds=fds)


def _send_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    deadline: float,
    fds: tuple[int, ...] = (),
) -> None:
    frame = struct.pack(">I", len(payload)) + payload
    view = memoryview(frame)
    first = True
    while view:
        _wait(sock, selectors.EVENT_WRITE, deadline)
        ancillary = []
        if first and fds:
            descriptor_array = array.array("i", fds)
            ancillary = [
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor_array.tobytes())
            ]
        try:
            sent = sock.sendmsg((view,), ancillary, socket.MSG_DONTWAIT)
        except BlockingIOError:
            continue
        if sent <= 0:
            raise OSError("short authenticated control-frame write")
        first = False
        view = view[sent:]


def _receive_frame(
    sock: socket.socket,
    *,
    deadline: float,
    maximum: int,
    expected_fds: int,
) -> tuple[bytes, tuple[int, ...]]:
    header = bytearray()
    payload = bytearray()
    received_fds: list[int] = []
    expected_length: int | None = None
    ancillary_size = socket.CMSG_SPACE(MAX_FDS * array.array("i").itemsize)
    try:
        while expected_length is None or len(payload) < expected_length:
            _wait(sock, selectors.EVENT_READ, deadline)
            remaining = (
                4 - len(header)
                if expected_length is None
                else expected_length - len(payload)
            )
            try:
                data, ancillary, flags, _ = sock.recvmsg(
                    remaining,
                    ancillary_size,
                    socket.MSG_DONTWAIT,
                )
            except BlockingIOError:
                continue
            if not data:
                raise EOFError("authenticated control peer closed")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise ValueError("control frame or descriptor record was truncated")
            for level, kind, descriptor_payload in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    raise ValueError("control frame contains unexpected ancillary data")
                values = array.array("i")
                usable = len(descriptor_payload) - (
                    len(descriptor_payload) % values.itemsize
                )
                values.frombytes(descriptor_payload[:usable])
                received_fds.extend(values.tolist())
                if len(received_fds) > MAX_FDS:
                    raise ValueError("control frame contains too many descriptors")
            if expected_length is None:
                header.extend(data)
                if len(header) == 4:
                    expected_length = struct.unpack(">I", header)[0]
                    if expected_length > maximum:
                        raise ValueError("authenticated control frame is oversized")
                    if expected_length == 0:
                        break
            else:
                payload.extend(data)
        if len(received_fds) != expected_fds:
            raise ValueError("control frame contains an unexpected descriptor count")
        for fd in received_fds:
            os.set_inheritable(fd, False)
        return bytes(payload), tuple(received_fds)
    except BaseException:
        for fd in received_fds:
            os.close(fd)
        raise


def receive_record(
    sock: socket.socket,
    *,
    deadline: float,
    expected_fds: int = 0,
) -> tuple[dict[str, Any], tuple[int, ...]]:
    data, received_fds = _receive_frame(
        sock,
        deadline=deadline,
        maximum=MAX_RECORD_BYTES,
        expected_fds=expected_fds,
    )
    try:
        value = decode_json_bytes(data)
        if not isinstance(value, dict):
            raise ValueError("control record is not an object")
        return value, received_fds
    except BaseException:
        for fd in received_fds:
            os.close(fd)
        raise


def send_blob(
    sock: socket.socket, token: str, value: bytes, *, deadline: float
) -> None:
    if len(token) != 64 or len(value) > 64 * 1024:
        raise ValueError("blob record is malformed or oversized")
    data = b"BLOB1 " + token.encode("ascii") + b"\n" + value
    _send_frame(sock, data, deadline=deadline)


def receive_blob(sock: socket.socket, token: str, *, deadline: float) -> bytes:
    data, _ = _receive_frame(
        sock,
        deadline=deadline,
        maximum=64 * 1024 + 71,
        expected_fds=0,
    )
    prefix = b"BLOB1 " + token.encode("ascii") + b"\n"
    if not data.startswith(prefix):
        raise ValueError("authenticated blob record is malformed")
    return data[len(prefix) :]


def peer_is_open(sock: socket.socket) -> bool:
    try:
        value = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except BlockingIOError:
        return True
    return bool(value)
