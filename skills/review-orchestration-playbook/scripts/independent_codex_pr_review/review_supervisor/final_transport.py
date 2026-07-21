from __future__ import annotations

import os
import pathlib
import queue
import selectors
import socket
import stat
import threading
import time
from typing import Any

from .constants import FINAL_MESSAGE_BYTES
from .secureio import (
    identity_from_stat,
    open_absolute_directory_chain,
    read_fd_exact,
    rename_noreplace,
    sha256_bytes,
    write_all,
)
from .wire import receive_record, send_record


def _reader_worker(
    *,
    fifo: pathlib.Path,
    final_path: pathlib.Path,
    expected_fifo: dict[str, int],
    results: queue.Queue[dict[str, Any]],
) -> None:
    directory_fd: int | None = None
    fifo_fd: int | None = None
    temporary_fd: int | None = None
    temporary_name = (
        f".{final_path.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}".encode("ascii")
    )
    try:
        directory_fd, _ = open_absolute_directory_chain(
            final_path.parent,
            private_leaf=True,
        )
        fifo_fd = os.open(fifo, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptor_identity = identity_from_stat(os.fstat(fifo_fd))
        path_identity = identity_from_stat(os.lstat(fifo))
        if (
            descriptor_identity.to_json() != expected_fifo
            or descriptor_identity != path_identity
        ):
            raise ValueError("final FIFO identity changed during writer handshake")
        if (
            not stat.S_ISFIFO(descriptor_identity.mode)
            or descriptor_identity.uid != os.getuid()
            or descriptor_identity.link_count != 1
            or stat.S_IMODE(descriptor_identity.mode) != 0o600
        ):
            raise ValueError("final FIFO metadata is unsafe")
        os.unlink(os.fsencode(fifo.name), dir_fd=directory_fd)
        try:
            os.stat(os.fsencode(fifo.name), dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("final FIFO pathname still exists after unlink")
        if os.fstat(fifo_fd).st_nlink != 0:
            raise ValueError("open final FIFO still has a filesystem link")
        os.fsync(directory_fd)

        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        content = bytearray()
        remaining = FINAL_MESSAGE_BYTES
        while remaining:
            chunk = os.read(fifo_fd, min(64 * 1024, remaining))
            if not chunk:
                break
            content.extend(chunk)
            write_all(temporary_fd, chunk)
            remaining -= len(chunk)
        if remaining == 0:
            overflow = os.read(fifo_fd, 1)
            if overflow:
                raise OverflowError("final message exceeds its inclusive byte cap")
        os.close(fifo_fd)
        fifo_fd = None
        temporary_identity = identity_from_stat(os.fstat(temporary_fd))
        if (
            not stat.S_ISREG(temporary_identity.mode)
            or temporary_identity.link_count != 1
            or temporary_identity.size != len(content)
            or stat.S_IMODE(temporary_identity.mode) != 0o600
        ):
            raise ValueError("temporary final artifact has invalid metadata")
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        rename_noreplace(
            directory_fd,
            temporary_name,
            directory_fd,
            os.fsencode(final_path.name),
        )
        os.fsync(directory_fd)
        final_fd = os.open(
            os.fsencode(final_path.name),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            final_identity = identity_from_stat(os.fstat(final_fd))
            if final_identity != temporary_identity:
                raise ValueError("published final artifact identity changed")
            readback = read_fd_exact(
                final_fd,
                max_bytes=FINAL_MESSAGE_BYTES,
                expected_size=len(content),
            )
            if readback != bytes(content):
                raise ValueError("published final artifact exact readback failed")
        finally:
            os.close(final_fd)
        results.put(
            {
                "ok": True,
                "identity": final_identity.to_json(),
                "length": len(content),
                "sha256": sha256_bytes(bytes(content)),
            }
        )
    except BaseException as error:
        results.put({"ok": False, "error": f"{type(error).__name__}: {error}"})
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if fifo_fd is not None:
            os.close(fifo_fd)
        if directory_fd is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)


def run_fifo_reader(
    *,
    control_fd: int,
    fifo: pathlib.Path,
    final_path: pathlib.Path,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    control.set_inheritable(False)
    try:
        fifo_identity = identity_from_stat(os.lstat(fifo))
        if (
            not stat.S_ISFIFO(fifo_identity.mode)
            or fifo_identity.uid != os.getuid()
            or fifo_identity.link_count != 1
            or stat.S_IMODE(fifo_identity.mode) != 0o600
        ):
            raise ValueError("final FIFO is not a fresh owner-only FIFO")
        send_record(
            control,
            {"type": "reader-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        release, _ = receive_record(
            control,
            deadline=time.monotonic() + 30,
        )
        if release != {"type": "reader-release", "token": token}:
            raise ValueError("reader release record is invalid")
        results: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        worker = threading.Thread(
            target=_reader_worker,
            kwargs={
                "fifo": fifo,
                "final_path": final_path,
                "expected_fifo": fifo_identity.to_json(),
                "results": results,
            },
            daemon=True,
        )
        worker.start()
        selector = selectors.DefaultSelector()
        selector.register(control, selectors.EVENT_READ)
        try:
            while True:
                try:
                    result = results.get_nowait()
                except queue.Empty:
                    pass
                else:
                    send_record(
                        control,
                        {"type": "reader-result", "token": token, **result},
                        deadline=time.monotonic() + 5,
                    )
                    return 0 if result["ok"] else 1
                if selector.select(0.1):
                    try:
                        data = control.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                    except BlockingIOError:
                        continue
                    if not data:
                        os._exit(125)
                    os._exit(126)
        finally:
            selector.close()
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "reader-result",
                    "token": token,
                    "ok": False,
                    "error": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        control.close()
