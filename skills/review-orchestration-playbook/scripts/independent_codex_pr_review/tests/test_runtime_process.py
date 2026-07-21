from __future__ import annotations

import os
import select
import signal
import time
import unittest
from unittest import mock

from review_supervisor.process import (
    SpawnedProcess,
    process_start_identity,
    reap_anchored_group,
    terminate_anchored_group,
    wait_terminal,
)


def _spawned_process(pid: int) -> SpawnedProcess:
    return SpawnedProcess(
        pid=pid,
        pgid=pid,
        acknowledgement_fd=-1,
        passed_fd_numbers=(),
        start_identity=process_start_identity(pid),
    )


def _profile_state(process: SpawnedProcess) -> dict[str, object]:
    leader = {
        "pid": process.pid,
        "pgid": process.pgid,
        "start_identity": process.start_identity,
    }
    return {
        "leader": leader,
        "no_child_process_profile": {
            "version": 1,
            "authenticated": True,
            "kernel_enforced": True,
            "child_process_limit": 0,
            "leader": leader,
        },
    }


def _kill_and_reap(pid: int | None) -> None:
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


@unittest.skipUnless(os.name == "posix", "POSIX process groups are required")
class AnchoredProcessGroupTests(unittest.TestCase):
    def test_exact_settlement_accepts_authenticated_no_child_profile(self) -> None:
        ready_read, ready_write = os.pipe()
        leader_pid = os.fork()
        if leader_pid == 0:
            os.close(ready_read)
            os.setpgid(0, 0)
            os.write(ready_write, b"L")
            os.close(ready_write)
            while True:
                time.sleep(1)

        os.close(ready_write)
        process: SpawnedProcess | None = None
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read])
            self.assertEqual(os.read(ready_read, 1), b"L")
            process = _spawned_process(leader_pid)

            exit_code = terminate_anchored_group(
                process,
                grace_seconds=0.05,
                deadline=time.monotonic() + 3.0,
                settlement_state=_profile_state(process),
            )

            self.assertEqual(exit_code, -signal.SIGTERM)
            process = None
        finally:
            os.close(ready_read)
            if process is not None:
                _kill_and_reap(leader_pid)

    def test_group_with_children_cannot_settle_without_profile(self) -> None:
        leader_ready_read, leader_ready_write = os.pipe()
        leader_exit_read, leader_exit_write = os.pipe()
        leader_pid = os.fork()
        if leader_pid == 0:
            os.close(leader_ready_read)
            os.close(leader_exit_write)
            os.setpgid(0, 0)
            os.write(leader_ready_write, b"L")
            os.close(leader_ready_write)
            os.read(leader_exit_read, 1)
            os.close(leader_exit_read)
            os._exit(0)

        os.close(leader_ready_write)
        os.close(leader_exit_read)
        member_ready_read, member_ready_write = os.pipe()
        member_pid: int | None = None
        try:
            readable, _, _ = select.select([leader_ready_read], [], [], 5.0)
            self.assertEqual(readable, [leader_ready_read])
            self.assertEqual(os.read(leader_ready_read, 1), b"L")
            process = _spawned_process(leader_pid)
            member_pid = os.fork()
            if member_pid == 0:
                os.close(member_ready_read)
                os.close(leader_exit_write)
                os.setpgid(0, leader_pid)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                os.write(member_ready_write, b"M")
                os.close(member_ready_write)
                while True:
                    time.sleep(1)
            os.close(member_ready_write)
            member_ready_write = -1
            readable, _, _ = select.select([member_ready_read], [], [], 5.0)
            self.assertEqual(readable, [member_ready_read])
            self.assertEqual(os.read(member_ready_read, 1), b"M")
            os.write(leader_exit_write, b"X")
            os.close(leader_exit_write)
            leader_exit_write = -1
            wait_terminal(leader_pid, deadline=time.monotonic() + 5.0)

            with self.assertRaisesRegex(
                ChildProcessError,
                "authenticated profile state",
            ):
                terminate_anchored_group(
                    process,
                    grace_seconds=0.05,
                    deadline=time.monotonic() + 3.0,
                )
        finally:
            os.close(leader_ready_read)
            os.close(member_ready_read)
            if leader_exit_write >= 0:
                os.close(leader_exit_write)
            if member_ready_write >= 0:
                os.close(member_ready_write)
            _kill_and_reap(member_pid)
            _kill_and_reap(leader_pid)

    def test_reaped_leader_prevents_recycled_pgid_signal(self) -> None:
        ready_read, ready_write = os.pipe()
        exit_read, exit_write = os.pipe()
        leader_pid = os.fork()
        if leader_pid == 0:
            os.close(ready_read)
            os.close(exit_write)
            os.setpgid(0, 0)
            os.write(ready_write, b"L")
            os.close(ready_write)
            os.read(exit_read, 1)
            os.close(exit_read)
            os._exit(0)

        os.close(ready_write)
        os.close(exit_read)
        member_ready_read, member_ready_write = os.pipe()
        member_pid: int | None = None
        try:
            readable, _, _ = select.select([ready_read], [], [], 5.0)
            self.assertEqual(readable, [ready_read])
            self.assertEqual(os.read(ready_read, 1), b"L")
            process = _spawned_process(leader_pid)
            member_pid = os.fork()
            if member_pid == 0:
                try:
                    os.close(member_ready_read)
                    os.close(exit_write)
                    os.setpgid(0, leader_pid)
                    os.write(member_ready_write, b"M")
                    os.close(member_ready_write)
                    while True:
                        time.sleep(1)
                except BaseException:
                    os._exit(97)
            os.close(member_ready_write)
            member_ready_write = -1
            readable, _, _ = select.select([member_ready_read], [], [], 5.0)
            self.assertEqual(readable, [member_ready_read])
            self.assertEqual(os.read(member_ready_read, 1), b"M")
            os.write(exit_write, b"X")
            os.close(exit_write)
            exit_write = -1
            os.waitpid(leader_pid, 0)

            with mock.patch("review_supervisor.process.os.killpg") as killpg:
                with self.assertRaisesRegex(
                    ChildProcessError,
                    "unreaped child anchor",
                ):
                    terminate_anchored_group(
                        process,
                        grace_seconds=0,
                        deadline=time.monotonic() + 1.0,
                    )
                killpg.assert_not_called()
            os.kill(member_pid, 0)
        finally:
            os.close(ready_read)
            os.close(member_ready_read)
            if exit_write >= 0:
                os.close(exit_write)
            if member_ready_write >= 0:
                os.close(member_ready_write)
            _kill_and_reap(member_pid)
            try:
                os.waitpid(leader_pid, os.WNOHANG)
            except ChildProcessError:
                pass

    def test_setsid_double_fork_rejects_unprofiled_tree_closure(self) -> None:
        escaped_read, escaped_write = os.pipe()
        leader_pid = os.fork()
        if leader_pid == 0:
            try:
                os.close(escaped_read)
                os.setpgid(0, 0)
                intermediate_pid = os.fork()
                if intermediate_pid == 0:
                    try:
                        os.setsid()
                        escaped_pid = os.fork()
                        if escaped_pid == 0:
                            try:
                                os.write(
                                    escaped_write,
                                    f"{os.getpid()}\n".encode("ascii"),
                                )
                                os.close(escaped_write)
                                while True:
                                    time.sleep(1)
                            except BaseException:
                                os._exit(99)
                        os._exit(0)
                    except BaseException:
                        os._exit(98)
                os.close(escaped_write)
                os.waitpid(intermediate_pid, 0)
                os._exit(0)
            except BaseException:
                os._exit(97)

        os.close(escaped_write)
        escaped_pid: int | None = None
        try:
            process = _spawned_process(leader_pid)
            readable, _, _ = select.select([escaped_read], [], [], 5.0)
            self.assertEqual(readable, [escaped_read])
            escaped_pid = int(os.read(escaped_read, 64).strip())
            wait_terminal(leader_pid, deadline=time.monotonic() + 5.0)
            os.kill(escaped_pid, 0)

            with self.assertRaisesRegex(
                ChildProcessError,
                "authenticated profile state",
            ):
                reap_anchored_group(
                    process,
                    deadline=time.monotonic() + 1.0,
                )
            os.kill(escaped_pid, 0)
        finally:
            os.close(escaped_read)
            _kill_and_reap(leader_pid)
            if escaped_pid is not None:
                try:
                    os.kill(escaped_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
