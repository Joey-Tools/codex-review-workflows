from __future__ import annotations

import os
import pathlib
import select
import signal
import time
import unittest
from unittest import mock

from review_supervisor import gitraw
import review_supervisor.process as process_module
from review_supervisor.gitraw import run_bounded, sanitized_git_environment
from review_supervisor.process import (
    ForkedProcessClosureUnproven,
    SpawnedProcess,
    fork_exec,
    process_start_identity,
    reap_anchored_group,
    terminate_anchored_group,
    wait_terminal,
)
from review_supervisor.runtime import (
    CheckoutWorkerTermination,
    _block_checkout_worker_signals,
    _install_checkout_worker_signal_handlers,
    _restore_checkout_worker_signal_handlers,
)
from review_supervisor.signal_relay import (
    activate_deferred_signal_interrupt,
    deactivate_deferred_signal_interrupt,
)

from tests.support import owned_temporary_directory


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


def _wait_for_identity_exit(pid: int, identity: str, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if process_start_identity(pid) != identity:
                return True
        except (ProcessLookupError, ValueError):
            return True
        time.sleep(0.02)
    return False


@unittest.skipUnless(os.name == "posix", "POSIX process groups are required")
class AnchoredProcessGroupTests(unittest.TestCase):
    def test_post_fork_identity_failure_retains_receipt_after_cleanup_gap(
        self,
    ) -> None:
        with (
            mock.patch.object(process_module, "cloexec_pipe", return_value=(10, 11)),
            mock.patch.object(process_module.os, "fork", return_value=123),
            mock.patch.object(process_module.os, "close"),
            mock.patch.object(
                process_module,
                "process_start_identity",
                side_effect=ValueError("synthetic identity failure"),
            ),
            mock.patch.object(
                process_module,
                "_settle_unidentified_fork",
                side_effect=PermissionError("synthetic cleanup failure"),
            ) as settle,
            self.assertRaises(ForkedProcessClosureUnproven) as raised,
        ):
            fork_exec(
                ("/usr/bin/false",),
                cwd=pathlib.Path("/tmp"),
                stdin_fd=0,
                stdout_fd=1,
                stderr_fd=2,
                own_process_group=True,
            )

        self.assertEqual(settle.call_count, 2)
        self.assertEqual(raised.exception.process.pid, 123)
        self.assertEqual(raised.exception.process.pgid, 123)
        self.assertEqual(raised.exception.process.acknowledgement_fd, -1)
        self.assertIsNone(raised.exception.process.start_identity)

    def test_checkout_worker_signal_settles_independent_git_session(self) -> None:
        for signal_phase in ("active", "binding", "cleanup"):
            with (
                self.subTest(signal_phase=signal_phase),
                owned_temporary_directory("checkout-worker-signal-") as root,
            ):
                overflow = b"printf xx\n" if signal_phase == "cleanup" else b""
                script = (
                    b"#!/bin/sh\n"
                    b"(trap '' TERM; exec /bin/sleep 30) </dev/null >/dev/null 2>&1 &\n"
                    b'printf \'%s %s\\n\' "$$" "$!" > "$0.pids"\n'
                    + overflow
                    + b"trap '' TERM\n"
                    b"exec /bin/sleep 30\n"
                )
                executable = root / "fake-git"
                executable.write_bytes(script)
                executable.chmod(0o700)
                pid_path = pathlib.Path(f"{executable}.pids")
                evidence_path = root / "process-evidence"
                worker_pid = os.fork()
                if worker_pid == 0:
                    try:
                        os.setpgid(0, 0)
                        guard = _install_checkout_worker_signal_handlers()
                        binding = activate_deferred_signal_interrupt(guard.interrupt)
                        original_bind = gitraw._bind_fresh_session
                        original_terminate = gitraw._terminate_process
                        cleanup_signal_sent = False

                        def bind_with_signal(
                            process: object,
                        ) -> SpawnedProcess:
                            deadline = time.monotonic() + 5
                            while not pid_path.exists() and time.monotonic() < deadline:
                                time.sleep(0.01)
                            git_raw, child_raw = pid_path.read_text(
                                encoding="ascii"
                            ).split()
                            git_pid = int(git_raw)
                            child_pid = int(child_raw)
                            evidence_path.write_text(
                                " ".join(
                                    (
                                        str(git_pid),
                                        process_start_identity(git_pid),
                                        str(os.getpgid(git_pid)),
                                        str(child_pid),
                                        process_start_identity(child_pid),
                                        str(os.getpgid(child_pid)),
                                    )
                                ),
                                encoding="ascii",
                            )
                            if signal_phase == "binding":
                                os.kill(os.getpid(), signal.SIGTERM)
                            return original_bind(process)

                        def terminate_with_signal(
                            *args: object, **kwargs: object
                        ) -> int:
                            nonlocal cleanup_signal_sent
                            if signal_phase == "cleanup" and not cleanup_signal_sent:
                                cleanup_signal_sent = True
                                os.kill(os.getpid(), signal.SIGTERM)
                            return original_terminate(*args, **kwargs)

                        exit_code = 96
                        try:
                            with (
                                mock.patch.object(
                                    gitraw,
                                    "_bind_fresh_session",
                                    side_effect=bind_with_signal,
                                ),
                                mock.patch.object(
                                    gitraw,
                                    "_terminate_process",
                                    side_effect=terminate_with_signal,
                                ),
                            ):
                                run_bounded(
                                    (str(executable),),
                                    cwd=root,
                                    environment=sanitized_git_environment(),
                                    timeout=30,
                                    stdout_limit=(
                                        1 if signal_phase == "cleanup" else 8192
                                    ),
                                    stderr_limit=8192,
                                )
                        except CheckoutWorkerTermination:
                            exit_code = 0
                        except BaseException:
                            exit_code = 97
                        finally:
                            _block_checkout_worker_signals(guard)
                            deactivate_deferred_signal_interrupt(binding)
                            _restore_checkout_worker_signal_handlers(guard)
                        os._exit(exit_code)
                    except BaseException:
                        os._exit(98)

                git_pid: int | None = None
                child_pid: int | None = None
                git_identity: str | None = None
                child_identity: str | None = None
                try:
                    deadline = time.monotonic() + 5
                    while not evidence_path.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(
                        evidence_path.exists(),
                        "bounded Git process evidence was not recorded",
                    )
                    (
                        git_raw,
                        git_identity,
                        git_group_raw,
                        child_raw,
                        child_identity,
                        child_group_raw,
                    ) = evidence_path.read_text(encoding="ascii").split()
                    git_pid = int(git_raw)
                    child_pid = int(child_raw)
                    self.assertEqual(int(git_group_raw), git_pid)
                    self.assertEqual(int(child_group_raw), git_pid)

                    if signal_phase == "active":
                        os.killpg(worker_pid, signal.SIGTERM)
                    waited, status = os.waitpid(worker_pid, 0)
                    self.assertEqual(waited, worker_pid)
                    worker_pid = -1
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    self.assertTrue(
                        _wait_for_identity_exit(git_pid, git_identity, timeout=3),
                        "independent Git leader survived checkout-worker termination",
                    )
                    self.assertTrue(
                        _wait_for_identity_exit(child_pid, child_identity, timeout=3),
                        "same-group Git child survived checkout-worker termination",
                    )
                finally:
                    if worker_pid > 0:
                        _kill_and_reap(worker_pid)
                    if git_pid is not None and git_identity is not None:
                        try:
                            if process_start_identity(git_pid) == git_identity:
                                os.killpg(git_pid, signal.SIGKILL)
                        except (ProcessLookupError, ValueError):
                            pass
                    if child_pid is not None and child_identity is not None:
                        try:
                            if process_start_identity(child_pid) == child_identity:
                                os.kill(child_pid, signal.SIGKILL)
                        except (ProcessLookupError, ValueError):
                            pass

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
