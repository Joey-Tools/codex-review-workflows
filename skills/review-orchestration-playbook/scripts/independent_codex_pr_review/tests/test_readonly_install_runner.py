from __future__ import annotations

import contextlib
import dis
import errno
import io
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import time
import unittest
from dataclasses import asdict
from unittest import mock

from review_supervisor import recovery_cleanup
from review_supervisor.process import process_start_identity

from . import run_readonly_install_deterministic_supervisor as runner
from . import support
from .support import owned_temporary_directory


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    @staticmethod
    def _make_private_directory(path: pathlib.Path) -> None:
        path.mkdir(mode=0o700)
        path.chmod(0o700)

    @staticmethod
    def _open_parent_binding(
        result_owner: support._DirectoryParentBindingResultOwner,
        path: pathlib.Path,
        *,
        require_owned_private_parent: bool,
    ) -> support._DirectoryParentBinding:
        try:
            binding = support._open_directory_parent(
                path,
                require_owned_private_parent=require_owned_private_parent,
                result_owner=result_owner,
            )
            result_owner.transfer(binding)
            return binding
        except BaseException as error:
            preserved = (
                support._settle_directory_parent_binding_result_preserving_trigger(
                    result_owner,
                    error,
                )
            )
            if preserved is error:
                raise
            raise preserved

    @staticmethod
    def _bound_directory_factory(
        *paths: pathlib.Path,
    ) -> object:
        remaining = iter(paths)

        def create(
            _parent: pathlib.Path,
            _prefix: str,
            *,
            result_owner: support._PrivateDirectoryCreationResultOwner,
            require_owned_private_parent: bool = True,
        ) -> support._DirectoryParentBinding:
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = ReadOnlyInstallRunnerTests._open_parent_binding(
                parent_result_owner,
                next(remaining),
                require_owned_private_parent=require_owned_private_parent,
            )
            result_owner.publish(binding)
            return binding

        return create

    @staticmethod
    def _close_call_boundary_offsets(function: object) -> tuple[int, int]:
        instructions = tuple(dis.get_instructions(function))
        for index, instruction in enumerate(instructions[:-1]):
            if not instruction.opname.startswith("CALL"):
                continue
            prior = instructions[max(0, index - 8) : index]
            if any(candidate.argval == "close" for candidate in prior):
                return instruction.offset, instructions[index + 1].offset
        raise AssertionError("os.close call boundary was not found")

    @staticmethod
    def _attribute_call_offset(function: object, attribute: str) -> int:
        instructions = tuple(dis.get_instructions(function))
        for index, instruction in enumerate(instructions):
            if not instruction.opname.startswith("CALL"):
                continue
            prior = instructions[max(0, index - 12) : index]
            if any(candidate.argval == attribute for candidate in prior):
                return instruction.offset
        raise AssertionError(f"{attribute} call boundary was not found")

    @staticmethod
    def _local_active_error_store_offsets(function: object) -> tuple[int, int]:
        instructions = tuple(dis.get_instructions(function))
        for index, instruction in enumerate(instructions):
            if (
                instruction.opname != "STORE_FAST"
                or instruction.argval != "local_active_error"
            ):
                continue
            prior = instructions[max(0, index - 4) : index]
            error_store = next(
                (
                    candidate
                    for candidate in reversed(prior)
                    if candidate.opname == "STORE_FAST" and candidate.argval == "error"
                ),
                None,
            )
            if error_store is not None:
                return error_store.offset, instruction.offset
        raise AssertionError("local active-error publication stores were not found")

    @staticmethod
    def _process_group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _require_process_group_absent(
        self,
        process_group: int,
        *,
        timeout: float = 5.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._process_group_exists(process_group):
                return
            time.sleep(0.02)
        self.assertFalse(
            self._process_group_exists(process_group),
            f"process group {process_group} remained live",
        )

    @staticmethod
    def _synthetic_darwin_process_library(
        pid: int,
        inspect_pid: object,
    ) -> object:
        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __init__(self) -> None:
                self.calls = 0

            def __call__(
                self,
                _process_type: object,
                _uid: object,
                buffer: object,
                _buffer_bytes: object,
            ) -> int:
                self.calls += 1
                pid_buffer = runner.ctypes.cast(
                    buffer,
                    runner.ctypes.POINTER(runner.ctypes.c_int),
                )
                pid_buffer[0] = pid
                return runner.ctypes.sizeof(runner.ctypes.c_int)

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.sysctl = inspect_pid

        return SyntheticLibproc()

    @staticmethod
    def _write_synthetic_kinfo(
        buffer: object,
        buffer_size: object,
        *,
        pid: int,
        start_seconds: int = 1_700_000_000,
        start_microseconds: int = 123_456,
        process_state: bytes = b"\x03",
        returned_size: int = 648,
        real_uid: int | None = None,
        effective_uid: int | None = None,
    ) -> None:
        value = runner.ctypes.cast(
            buffer,
            runner.ctypes.POINTER(runner._DarwinKinfoProcScope),
        ).contents
        value.identity.p_starttime.tv_sec = start_seconds
        value.identity.p_starttime.tv_usec = start_microseconds
        value.identity.p_stat = process_state
        value.identity.p_pid = pid
        value.real_uid = runner.os.getuid() if real_uid is None else real_uid
        value.effective_uid = (
            runner.os.getuid() if effective_uid is None else effective_uid
        )
        length = runner.ctypes.cast(
            buffer_size,
            runner.ctypes.POINTER(runner.ctypes.c_size_t),
        )
        length[0] = returned_size

    @staticmethod
    def _require_synthetic_kern_proc_pid_mib(
        mib: object,
        mib_length: object,
        pid: int,
    ) -> None:
        if mib_length != 4:
            raise AssertionError(f"unexpected KERN_PROC_PID MIB length: {mib_length}")
        values = runner.ctypes.cast(
            mib,
            runner.ctypes.POINTER(runner.ctypes.c_int),
        )
        observed = tuple(values[index] for index in range(4))
        expected = (
            runner.DARWIN_CTL_KERN,
            runner.DARWIN_KERN_PROC,
            runner.DARWIN_KERN_PROC_PID,
            pid,
        )
        if observed != expected:
            raise AssertionError(f"unexpected KERN_PROC_PID MIB: {observed}")

    def test_darwin_process_census_rejects_zero_result_with_errno(self) -> None:
        class SyntheticProcListPids:
            argtypes: object = None
            restype: object = None

            def __call__(self, *_args: object) -> int:
                runner.ctypes.set_errno(errno.EIO)
                return 0

        class SyntheticSysctl:
            argtypes: object = None
            restype: object = None

            def __call__(self, *_args: object) -> int:
                raise AssertionError("PID inspection must not start")

        class SyntheticLibproc:
            def __init__(self) -> None:
                self.proc_listpids = SyntheticProcListPids()
                self.sysctl = SyntheticSysctl()

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticLibproc(),
            ),
            self.assertRaisesRegex(
                OSError,
                "cannot enumerate same-UID Darwin processes",
            ),
        ):
            runner._darwin_same_uid_processes()

    def test_darwin_process_census_retries_and_rebinds_disappearing_pid(self) -> None:
        pid = 2_147_483_647
        write_kinfo = self._write_synthetic_kinfo
        require_mib = self._require_synthetic_kern_proc_pid_mib

        class SyntheticSysctl:
            argtypes: object = None
            restype: object = None

            def __init__(self) -> None:
                self.calls = 0

            def __call__(
                self,
                mib: object,
                mib_length: object,
                buffer: object,
                buffer_size: object,
                _new_value: object,
                _new_value_size: object,
            ) -> int:
                self.calls += 1
                require_mib(mib, mib_length, pid)
                if self.calls == 1:
                    runner.ctypes.set_errno(errno.ESRCH)
                    return -1
                if self.calls == 2:
                    length = runner.ctypes.cast(
                        buffer_size,
                        runner.ctypes.POINTER(runner.ctypes.c_size_t),
                    )
                    length[0] = 0
                    return 0
                if self.calls == 3:
                    write_kinfo(
                        buffer,
                        buffer_size,
                        pid=pid,
                        real_uid=runner.os.getuid() + 1,
                        effective_uid=runner.os.getuid() + 1,
                    )
                    return 0
                write_kinfo(
                    buffer,
                    buffer_size,
                    pid=pid,
                    start_seconds=1_700_000_001,
                    start_microseconds=987_654,
                    real_uid=runner.os.getuid(),
                    effective_uid=runner.os.getuid() + 1,
                )
                return 0

        inspect_pid = SyntheticSysctl()
        library = self._synthetic_darwin_process_library(pid, inspect_pid)
        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=library,
            ),
        ):
            observed = runner._darwin_same_uid_processes()

        self.assertEqual(
            observed,
            (
                runner.DarwinProcessIdentity(
                    pid=pid,
                    start_seconds=1_700_000_001,
                    start_microseconds=987_654,
                ),
            ),
        )
        self.assertEqual(library.proc_listpids.calls, 8)
        self.assertEqual(inspect_pid.calls, 4)

    def test_darwin_process_census_includes_zombie_identity(self) -> None:
        pid = 90_001
        write_kinfo = self._write_synthetic_kinfo
        require_mib = self._require_synthetic_kern_proc_pid_mib

        class SyntheticSysctl:
            argtypes: object = None
            restype: object = None

            def __call__(
                self,
                mib: object,
                mib_length: object,
                buffer: object,
                buffer_size: object,
                _new_value: object,
                _new_value_size: object,
            ) -> int:
                require_mib(mib, mib_length, pid)
                write_kinfo(
                    buffer,
                    buffer_size,
                    pid=pid,
                    start_seconds=1_700_000_002,
                    start_microseconds=123_456,
                    process_state=b"\x05",
                    real_uid=502,
                    effective_uid=501,
                )
                return 0

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=self._synthetic_darwin_process_library(
                    pid,
                    SyntheticSysctl(),
                ),
            ),
        ):
            observed = runner._darwin_same_uid_processes()

        self.assertEqual(
            observed,
            (
                runner.DarwinProcessIdentity(
                    pid=pid,
                    start_seconds=1_700_000_002,
                    start_microseconds=123_456,
                ),
            ),
        )
        self.assertEqual(observed[0].process_state, b"\x05")
        self.assertEqual(
            observed[0],
            runner.DarwinProcessIdentity(
                pid=pid,
                start_seconds=1_700_000_002,
                start_microseconds=123_456,
                process_state=b"\x03",
            ),
        )

    def test_darwin_process_census_rejects_malformed_sysctl_identity(self) -> None:
        pid = 90_002
        write_kinfo = self._write_synthetic_kinfo
        require_mib = self._require_synthetic_kern_proc_pid_mib
        self.assertEqual(runner.ctypes.sizeof(runner._DarwinTimeval), 16)
        self.assertEqual(runner._DarwinTimeval.tv_usec.offset, 8)
        self.assertEqual(runner._DarwinKinfoProcPrefix.p_pid.offset, 40)
        self.assertEqual(runner._DarwinKinfoProcScope.real_uid.offset, 392)
        self.assertEqual(runner._DarwinKinfoProcScope.effective_uid.offset, 420)
        malformed_cases = (
            {"pid": pid + 1},
            {
                "pid": pid,
                "returned_size": runner.DARWIN_KINFO_PROC_BYTES - 1,
            },
            {
                "pid": pid,
                "returned_size": runner.DARWIN_KINFO_PROC_BYTES + 1,
            },
            {"pid": pid, "returned_size": runner.DARWIN_KINFO_PROC_BYTES * 2},
            {"pid": pid, "start_seconds": 0},
            {"pid": pid, "start_microseconds": 1_000_000},
        )

        for malformed in malformed_cases:
            with self.subTest(malformed=malformed):

                class SyntheticSysctl:
                    argtypes: object = None
                    restype: object = None

                    def __call__(
                        self,
                        mib: object,
                        mib_length: object,
                        buffer: object,
                        buffer_size: object,
                        _new_value: object,
                        _new_value_size: object,
                    ) -> int:
                        require_mib(mib, mib_length, pid)
                        write_kinfo(buffer, buffer_size, **malformed)
                        return 0

                with (
                    mock.patch.object(runner.sys, "platform", "darwin"),
                    mock.patch.object(
                        runner.ctypes,
                        "CDLL",
                        return_value=self._synthetic_darwin_process_library(
                            pid,
                            SyntheticSysctl(),
                        ),
                    ),
                    self.assertRaisesRegex(
                        OSError,
                        "cannot bind same-UID Darwin process identity",
                    ),
                ):
                    runner._darwin_same_uid_processes()

    def test_darwin_process_census_fails_closed_on_sysctl_permission_error(
        self,
    ) -> None:
        pid = 90_003

        class SyntheticSysctl:
            argtypes: object = None
            restype: object = None

            def __call__(self, *_args: object) -> int:
                runner.ctypes.set_errno(errno.EPERM)
                return -1

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=self._synthetic_darwin_process_library(
                    pid,
                    SyntheticSysctl(),
                ),
            ),
            self.assertRaisesRegex(
                PermissionError,
                "cannot bind same-UID Darwin process identity",
            ),
        ):
            runner._darwin_same_uid_processes()

    def test_darwin_process_census_expires_during_pid_binding(self) -> None:
        clock = {"now": 0.0}
        pid = 90_004
        inspected: list[int] = []
        require_mib = self._require_synthetic_kern_proc_pid_mib

        class SyntheticSysctl:
            argtypes: object = None
            restype: object = None

            def __call__(
                self,
                mib: object,
                _mib_length: object,
                _buffer: object,
                _buffer_size: object,
                _new_value: object,
                _new_value_size: object,
            ) -> int:
                require_mib(mib, _mib_length, pid)
                mib_values = runner.ctypes.cast(
                    mib,
                    runner.ctypes.POINTER(runner.ctypes.c_int),
                )
                inspected.append(mib_values[3])
                clock["now"] = 2.0
                return 0

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=self._synthetic_darwin_process_library(
                    pid,
                    SyntheticSysctl(),
                ),
            ),
            mock.patch.object(
                runner.time,
                "monotonic",
                side_effect=lambda: clock["now"],
            ),
            self.assertRaisesRegex(TimeoutError, "census deadline expired"),
        ):
            runner._darwin_same_uid_processes(deadline=1.0)
        self.assertEqual(inspected, [pid])

    def test_stable_process_baseline_unions_prelaunch_identity_churn(self) -> None:
        existing = runner.DarwinProcessIdentity(101, 1_700_000_001, 1_001)
        departing = runner.DarwinProcessIdentity(102, 1_700_000_002, 1_002)
        arriving = runner.DarwinProcessIdentity(102, 1_700_000_003, 2_002)
        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=((existing, departing), (existing, arriving)),
            ),
            mock.patch.object(runner.time, "sleep"),
        ):
            baseline = runner._stable_same_uid_processes(
                deadline=runner.time.monotonic() + 1.0
            )

        self.assertEqual(baseline, (existing, departing, arriving))

    def test_same_uid_closure_reaps_terminal_child_then_proves_absence(
        self,
    ) -> None:
        supervisor = runner.DarwinProcessIdentity(os.getpid(), 1, 1)
        terminal_child = runner.DarwinProcessIdentity(
            90_005,
            1_700_000_005,
            5_005,
            process_state=b"\x05",
        )
        clock = {"now": 0.0}
        observations = {"count": 0}

        def census(*, deadline: float | None = None) -> tuple[object, ...]:
            del deadline
            observations["count"] += 1
            return (
                (supervisor, terminal_child)
                if observations["count"] in {1, 3}
                else (supervisor,)
            )

        def advance(duration: float) -> None:
            clock["now"] += duration

        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=census,
            ) as census,
            mock.patch.object(
                runner,
                "_reap_terminal_same_uid_children",
            ) as reap_terminal,
            mock.patch.object(
                runner.time,
                "monotonic",
                side_effect=lambda: clock["now"],
            ),
            mock.patch.object(runner.time, "sleep", side_effect=advance),
        ):
            runner._require_no_new_same_uid_processes(
                (supervisor,),
                deadline=1.0,
            )

        self.assertGreaterEqual(census.call_count, 3)
        self.assertEqual(
            reap_terminal.call_args_list,
            [
                mock.call((terminal_child,), deadline=1.0),
                mock.call((terminal_child,), deadline=1.0),
            ],
        )

    def test_same_uid_closure_rejects_persistent_exact_identity(self) -> None:
        supervisor = runner.DarwinProcessIdentity(os.getpid(), 1, 1)
        escaped = runner.DarwinProcessIdentity(
            90_006,
            1_700_000_006,
            6_006,
            process_state=b"\x03",
        )
        clock = {"now": 0.0}

        def advance(duration: float) -> None:
            clock["now"] += duration

        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                return_value=(supervisor, escaped),
            ),
            mock.patch.object(
                runner,
                "_reap_terminal_same_uid_children",
            ),
            mock.patch.object(
                runner.time,
                "monotonic",
                side_effect=lambda: clock["now"],
            ),
            mock.patch.object(runner.time, "sleep", side_effect=advance),
            self.assertRaises(runner.ChildProcessTreeClosureUnproven) as closure,
        ):
            runner._require_no_new_same_uid_processes(
                (supervisor,),
                deadline=0.02,
            )

        self.assertEqual(closure.exception.processes, (escaped,))

    def test_terminal_same_uid_child_reap_binds_exact_identity_under_deadline(
        self,
    ) -> None:
        terminal_child = runner.DarwinProcessIdentity(
            90_007,
            1_700_000_007,
            7_007,
            process_state=b"\x05",
        )
        rebound_child = runner.DarwinProcessIdentity(
            terminal_child.pid,
            terminal_child.start_seconds,
            terminal_child.start_microseconds,
            process_state=b"\x03",
        )
        deadline = 123.0
        events: list[tuple[object, ...]] = []

        def require_time(observed_deadline: float) -> None:
            events.append(("deadline", observed_deadline))

        def waitid(*arguments: object) -> object:
            events.append(("waitid", *arguments))
            return mock.Mock(si_pid=terminal_child.pid)

        def census(*, deadline: float | None = None) -> tuple[object, ...]:
            events.append(("identity", deadline))
            return (rebound_child,)

        def waitpid(*arguments: object) -> tuple[int, int]:
            events.append(("waitpid", *arguments))
            return (terminal_child.pid, 0)

        with (
            mock.patch.object(
                runner.os,
                "waitid",
                side_effect=waitid,
            ),
            mock.patch.object(
                runner.os,
                "waitpid",
                side_effect=waitpid,
            ),
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=census,
            ),
            mock.patch.object(
                runner,
                "_require_process_census_time",
                side_effect=require_time,
            ),
        ):
            runner._reap_terminal_same_uid_children(
                (terminal_child,),
                deadline=deadline,
            )

        self.assertEqual(
            events,
            [
                ("deadline", deadline),
                (
                    "waitid",
                    os.P_PID,
                    terminal_child.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                ),
                ("deadline", deadline),
                ("identity", deadline),
                ("deadline", deadline),
                ("deadline", deadline),
                ("waitpid", terminal_child.pid, os.WNOHANG),
                ("deadline", deadline),
            ],
        )

    def test_terminal_same_uid_child_reap_rejects_missing_identity(self) -> None:
        terminal_child = runner.DarwinProcessIdentity(
            90_009,
            1_700_000_009,
            9_009,
            process_state=b"\x05",
        )
        with (
            mock.patch.object(
                runner.os,
                "waitid",
                return_value=mock.Mock(si_pid=terminal_child.pid),
            ),
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                return_value=(),
            ),
            mock.patch.object(runner.os, "waitpid") as waitpid,
            self.assertRaises(runner.ChildProcessTreeClosureUnproven) as closure,
        ):
            runner._reap_terminal_same_uid_children(
                (terminal_child,),
                deadline=runner.time.monotonic() + 1.0,
            )

        self.assertEqual(closure.exception.processes, (terminal_child,))
        self.assertIsInstance(closure.exception.cause, ProcessLookupError)
        self.assertEqual(closure.exception.cause.errno, errno.ESRCH)
        waitpid.assert_not_called()

    def test_terminal_same_uid_child_reap_rejects_reused_pid_identity(self) -> None:
        terminal_child = runner.DarwinProcessIdentity(
            90_010,
            1_700_000_010,
            10_010,
            process_state=b"\x05",
        )
        mismatches = (
            runner.DarwinProcessIdentity(
                terminal_child.pid,
                terminal_child.start_seconds + 1,
                terminal_child.start_microseconds,
            ),
            runner.DarwinProcessIdentity(
                terminal_child.pid,
                terminal_child.start_seconds,
                terminal_child.start_microseconds + 1,
            ),
        )
        for rebound_child in mismatches:
            with self.subTest(rebound_child=rebound_child):
                with (
                    mock.patch.object(
                        runner.os,
                        "waitid",
                        return_value=mock.Mock(si_pid=terminal_child.pid),
                    ),
                    mock.patch.object(
                        runner,
                        "_darwin_same_uid_processes",
                        return_value=(rebound_child,),
                    ),
                    mock.patch.object(runner.os, "waitpid") as waitpid,
                    self.assertRaises(
                        runner.ChildProcessTreeClosureUnproven
                    ) as closure,
                ):
                    runner._reap_terminal_same_uid_children(
                        (terminal_child,),
                        deadline=runner.time.monotonic() + 1.0,
                    )

                self.assertEqual(closure.exception.processes, (terminal_child,))
                self.assertIsInstance(closure.exception.cause, OSError)
                self.assertEqual(closure.exception.cause.errno, errno.ESTALE)
                waitpid.assert_not_called()

    def test_terminal_same_uid_child_reap_rejects_unreadable_identity(self) -> None:
        terminal_child = runner.DarwinProcessIdentity(
            90_011,
            1_700_000_011,
            11_011,
            process_state=b"\x05",
        )
        identity_error = OSError(errno.EACCES, "identity inspection denied")
        with (
            mock.patch.object(
                runner.os,
                "waitid",
                return_value=mock.Mock(si_pid=terminal_child.pid),
            ),
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=identity_error,
            ),
            mock.patch.object(runner.os, "waitpid") as waitpid,
            self.assertRaises(runner.ChildProcessTreeClosureUnproven) as closure,
        ):
            runner._reap_terminal_same_uid_children(
                (terminal_child,),
                deadline=runner.time.monotonic() + 1.0,
            )

        self.assertEqual(closure.exception.processes, (terminal_child,))
        self.assertIs(closure.exception.cause, identity_error)
        waitpid.assert_not_called()

    def test_exact_identity_absence_accepts_same_pid_reuse(self) -> None:
        old_process = runner.DarwinProcessIdentity(
            90_008,
            1_700_000_008,
            8_008,
            process_state=b"\x05",
        )
        replacement = runner.DarwinProcessIdentity(
            old_process.pid,
            old_process.start_seconds + 1,
            old_process.start_microseconds,
            process_state=b"\x02",
        )
        clock = {"now": 0.0}

        def advance(duration: float) -> None:
            clock["now"] += duration

        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                return_value=(replacement,),
            ) as census,
            mock.patch.object(
                runner,
                "_reap_terminal_same_uid_children",
            ) as reap_terminal,
            mock.patch.object(
                runner.time,
                "monotonic",
                side_effect=lambda: clock["now"],
            ),
            mock.patch.object(runner.time, "sleep", side_effect=advance),
        ):
            runner._require_process_identities_absent(
                (old_process,),
                deadline=1.0,
            )

        self.assertGreaterEqual(census.call_count, 2)
        reap_terminal.assert_not_called()

    def test_exact_identity_absence_passes_same_deadline_to_reaper(self) -> None:
        terminal_child = runner.DarwinProcessIdentity(
            90_012,
            1_700_000_012,
            12_012,
            process_state=b"\x05",
        )
        stop = RuntimeError("stop after observing reaper arguments")
        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                return_value=(terminal_child,),
            ),
            mock.patch.object(
                runner,
                "_reap_terminal_same_uid_children",
                side_effect=stop,
            ) as reap_terminal,
            mock.patch.object(runner.time, "monotonic", return_value=0.0),
            self.assertRaises(RuntimeError) as raised,
        ):
            runner._require_process_identities_absent(
                (terminal_child,),
                deadline=1.0,
            )

        self.assertIs(raised.exception, stop)
        reap_terminal.assert_called_once_with(
            (terminal_child,),
            deadline=1.0,
        )

    def test_isolated_child_account_rejects_admin_membership(self) -> None:
        with (
            mock.patch.object(runner.os, "getuid", return_value=501),
            mock.patch.object(runner.os, "geteuid", return_value=501),
            mock.patch.object(
                runner.grp,
                "getgrnam",
                return_value=mock.Mock(gr_gid=80),
            ),
            mock.patch.object(runner.os, "getgroups", return_value=[20, 80]),
            mock.patch.object(
                runner,
                "_require_job_creation_denied",
            ) as job_creation_denial,
            mock.patch.object(
                runner,
                "_require_sudo_exec_denied",
            ) as sudo_probe,
            self.assertRaisesRegex(PermissionError, "admin group"),
        ):
            runner._require_isolated_child_account()
        job_creation_denial.assert_not_called()
        sudo_probe.assert_not_called()

    def test_sudo_probe_requires_inherited_exec_denial(self) -> None:
        mixed_policy = subprocess.CompletedProcess(
            args=("sudo", "-n", "-l"),
            returncode=1,
            stdout=b"(root) NOPASSWD: /usr/bin/id\n",
            stderr=b"a password is required\n",
        )
        with (
            mock.patch.object(
                runner.subprocess,
                "run",
                return_value=mixed_policy,
            ),
            self.assertRaisesRegex(RuntimeError, "sudo execution was not denied"),
        ):
            runner._require_sudo_exec_denied()

        with mock.patch.object(
            runner.subprocess,
            "run",
            side_effect=PermissionError(errno.EPERM, "sandbox denied exec"),
        ):
            runner._require_sudo_exec_denied()

    def test_job_creation_probe_requires_explicit_seatbelt_denial(self) -> None:
        class SyntheticSandboxCheck:
            argtypes: object = None
            restype: object = None

            def __init__(self, result: int) -> None:
                self.result = result

            def __call__(self, *_args: object) -> int:
                return self.result

        class SyntheticSandbox:
            def __init__(self, result: int) -> None:
                self.sandbox_check = SyntheticSandboxCheck(result)

        with (
            mock.patch.object(runner.sys, "platform", "darwin"),
            mock.patch.object(
                runner.ctypes,
                "CDLL",
                return_value=SyntheticSandbox(1),
            ),
        ):
            runner._require_job_creation_denied()

        for result in (0, -1):
            with (
                self.subTest(result=result),
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner.ctypes,
                    "CDLL",
                    return_value=SyntheticSandbox(result),
                ),
                self.assertRaisesRegex(RuntimeError, "launchd job creation"),
            ):
                runner._require_job_creation_denied()

    def test_runtime_parent_rejects_extended_ancestor_acl(self) -> None:
        with owned_temporary_directory("runtime-parent-acl-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)

            if sys.platform == "darwin":
                subprocess.run(
                    (
                        "/bin/chmod",
                        "+a",
                        "everyone allow read",
                        str(ancestor),
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=5,
                )
                try:
                    self.assertIsNone(
                        support._validated_private_runtime_parent(str(parent))
                    )
                finally:
                    subprocess.run(
                        ("/bin/chmod", "-N", str(ancestor)),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=5,
                    )
            else:
                with mock.patch.object(
                    support,
                    "open_absolute_directory_chain",
                    side_effect=ValueError(
                        "extended ACLs, xattrs, and quarantine are forbidden"
                    ),
                ):
                    self.assertIsNone(
                        support._validated_private_runtime_parent(str(parent))
                    )

    def test_runtime_parent_rejects_sticky_writable_ancestor(self) -> None:
        with owned_temporary_directory("runtime-parent-sticky-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)

            self.assertEqual(
                support._validated_private_runtime_parent(str(parent)),
                parent.resolve(strict=True),
            )
            ancestor.chmod(0o1777)
            try:
                rejection_errors: list[BaseException] = []
                self.assertIsNone(
                    support._validated_private_runtime_parent(
                        str(parent),
                        rejection_errors=rejection_errors,
                    )
                )
                self.assertEqual(len(rejection_errors), 1)
                self.assertIsInstance(rejection_errors[0], OSError)
                self.assertEqual(rejection_errors[0].errno, errno.EPERM)
                with (
                    mock.patch.dict(
                        os.environ,
                        {support._EXPLICIT_RUNTIME_PARENT_ENV: str(parent)},
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        r"errno=1: .*group- or world-writable",
                    ),
                ):
                    support._private_runtime_parent()
            finally:
                ancestor.chmod(0o700)

    def test_runtime_parent_revalidation_rejects_writable_ancestor(self) -> None:
        with owned_temporary_directory("runtime-parent-drift-") as root:
            ancestor = root / "ancestor"
            ancestor.mkdir(mode=0o700)
            parent = ancestor / "parent"
            parent.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                parent,
                require_owned_private_parent=True,
            )
            try:
                ancestor.chmod(0o1777)
                with self.assertRaisesRegex(
                    OSError,
                    "group- or world-writable",
                ):
                    binding.revalidate()
            finally:
                ancestor.chmod(0o700)
                parent_result_owner.close()

    def test_private_directory_creation_rejects_new_child_acl(self) -> None:
        with owned_temporary_directory("runtime-child-acl-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            retained: support._PrivateDirectoryCreationRetentionRequired | None = None

            if sys.platform == "darwin":
                original_mkdir = os.mkdir

                def mkdir_with_acl(
                    name: bytes,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    original_mkdir(name, mode, dir_fd=dir_fd)
                    child = parent / os.fsdecode(name)
                    subprocess.run(
                        (
                            "/bin/chmod",
                            "+a",
                            "everyone allow read,write,execute,"
                            "file_inherit,directory_inherit",
                            str(child),
                        ),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=5,
                    )

                validation_patch = mock.patch.object(
                    support.os,
                    "mkdir",
                    side_effect=mkdir_with_acl,
                )
                rollback_patch = contextlib.nullcontext()
            else:
                validation_patch = mock.patch.object(
                    support,
                    "validate_directory_policy_fd",
                    side_effect=ValueError(
                        "private filesystem object has extended metadata"
                    ),
                )
                rollback_patch = mock.patch.object(
                    support,
                    "quarantine_and_remove_empty_root",
                    side_effect=OSError(
                        errno.EPERM,
                        "synthetic private-metadata rollback rejection",
                    ),
                )

            result_owner = support._PrivateDirectoryCreationResultOwner()
            try:
                with (
                    validation_patch,
                    rollback_patch,
                    self.assertRaises(
                        support._PrivateDirectoryCreationRetentionRequired
                    ) as caught,
                ):
                    support._create_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=result_owner,
                    )
                retained = caught.exception
                self.assertIsInstance(retained.trigger_error, ValueError)
                self.assertIn("extended metadata", str(retained.trigger_error))
                self.assertEqual(retained.evidence.entry_state, "rollback-unproven")
                self.assertEqual(
                    retained.evidence.protected_property,
                    "object-identity",
                )
                self.assertEqual(
                    retained.evidence.access_policy_gate,
                    "private-fail-closed",
                )
                self.assertIsNotNone(retained.recovery.directory_fd)
                self.assertEqual(tuple(parent.iterdir()), (retained.retained_path,))
            finally:
                if retained is not None:
                    retained.close_descriptors_for_recovery()
                    if sys.platform == "darwin" and retained.retained_path.exists():
                        subprocess.run(
                            ("/bin/chmod", "-N", str(retained.retained_path)),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=True,
                            timeout=5,
                        )
                    if retained.retained_path.exists():
                        retained.retained_path.rmdir()

    def test_directory_parent_binding_close_keeps_unproven_fd_evidence(
        self,
    ) -> None:
        call_offset, post_call_offset = self._close_call_boundary_offsets(
            support._DirectoryParentBinding.close
        )
        scenarios = (
            ("pre-call", call_offset, False),
            ("post-call", post_call_offset, True),
        )
        real_close = os.close
        for label, target_offset, syscall_completed in scenarios:
            with (
                self.subTest(boundary=label),
                owned_temporary_directory(f"binding-close-{label}-") as root,
            ):
                parent = root / "parent"
                self._make_private_directory(parent)
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    parent,
                    require_owned_private_parent=True,
                )
                descriptor = binding.fd
                interruption = KeyboardInterrupt(
                    f"synthetic binding close {label} interruption"
                )
                injected = False
                close_calls: list[int] = []

                def record_close(candidate: int) -> None:
                    close_calls.append(candidate)
                    real_close(candidate)

                def interrupt_close_boundary(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is support._DirectoryParentBinding.close.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_close_boundary

                previous_trace = sys.gettrace()
                try:
                    with mock.patch.object(
                        support.os,
                        "close",
                        side_effect=record_close,
                    ):
                        sys.settrace(interrupt_close_boundary)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            binding.close()
                        sys.settrace(previous_trace)
                        calls_after_interruption = tuple(close_calls)
                        binding.close()
                        self.assertEqual(
                            tuple(close_calls),
                            calls_after_interruption,
                        )
                finally:
                    sys.settrace(previous_trace)
                    if descriptor not in close_calls:
                        real_close(descriptor)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(
                    close_calls,
                    [descriptor] if syscall_completed else [],
                )
                self.assertEqual(binding.fd, descriptor)
                self.assertEqual(
                    binding.fd_close_outcome,
                    "close-outcome-unproven",
                )
                self.assertIs(binding.fd_close_error, interruption)
                if syscall_completed:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_directory_parent_result_owner_covers_call_to_store_gap(self) -> None:
        def caller(
            result_owner: support._DirectoryParentBindingResultOwner,
            parent: pathlib.Path,
        ) -> support._DirectoryParentBinding:
            binding = support._open_directory_parent(
                parent,
                require_owned_private_parent=True,
                result_owner=result_owner,
            )
            result_owner.transfer(binding)
            return binding

        instructions = tuple(dis.get_instructions(caller))
        target_offset: int | None = None
        for index, instruction in enumerate(instructions[:-1]):
            if not instruction.opname.startswith("CALL"):
                continue
            prior = instructions[max(0, index - 24) : index]
            following = instructions[index + 1]
            if (
                any(candidate.argval == "_open_directory_parent" for candidate in prior)
                and following.opname == "STORE_FAST"
                and following.argval == "binding"
            ):
                target_offset = following.offset
                break
        self.assertIsNotNone(target_offset)

        for label, interruption in (
            ("interrupt", KeyboardInterrupt("synthetic parent result gap")),
            ("exit", SystemExit(23)),
        ):
            with (
                self.subTest(control_flow=label),
                owned_temporary_directory(f"parent-result-gap-{label}-") as root,
            ):
                parent = root / "parent"
                self._make_private_directory(parent)
                result_owner = support._DirectoryParentBindingResultOwner()
                injected = False

                def interrupt_result_store(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if getattr(frame, "f_code", None) is caller.__code__:
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
                    sys.settrace(interrupt_result_store)
                    with self.assertRaises(type(interruption)) as caught:
                        caller(result_owner, parent)
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertFalse(result_owner.transferred)
                self.assertIsNotNone(result_owner.binding)
                assert result_owner.binding is not None
                descriptor = result_owner.binding.fd
                result_owner.close()
                result_owner.close()
                self.assertTrue(result_owner.settled)
                self.assertEqual(result_owner.binding.fd_close_outcome, "closed")
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)

        with owned_temporary_directory("parent-result-close-entry-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                result_owner,
                parent,
                require_owned_private_parent=True,
            )
            interruption = KeyboardInterrupt("synthetic close pre-entry interrupt")
            close_calls = 0
            real_close = support._DirectoryParentBinding.close

            def interrupt_once(
                candidate: support._DirectoryParentBinding,
            ) -> None:
                nonlocal close_calls
                close_calls += 1
                if close_calls == 1:
                    raise interruption
                real_close(candidate)

            with (
                mock.patch.object(
                    support._DirectoryParentBinding,
                    "close",
                    autospec=True,
                    side_effect=interrupt_once,
                ),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                result_owner.close()

            self.assertIs(caught.exception, interruption)
            self.assertEqual(close_calls, 2)
            self.assertTrue(result_owner.settled)
            self.assertEqual(binding.fd_close_outcome, "closed")

        with owned_temporary_directory("parent-result-close-priority-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                result_owner,
                parent,
                require_owned_private_parent=True,
            )
            ordinary = RuntimeError("synthetic ordinary close entry failure")
            control_flow = KeyboardInterrupt("synthetic later close entry control-flow")
            close_errors = iter((ordinary, control_flow))

            def fail_close_entry(
                _candidate: support._DirectoryParentBinding,
            ) -> None:
                raise next(close_errors)

            with (
                mock.patch.object(
                    support._DirectoryParentBinding,
                    "close",
                    autospec=True,
                    side_effect=fail_close_entry,
                ),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                result_owner.close()
            self.assertIs(caught.exception, control_flow)
            self.assertFalse(result_owner.settled)
            self.assertEqual(binding.fd_close_outcome, "owned")
            result_owner.close()
            self.assertTrue(result_owner.settled)

    def test_private_directory_recovery_closes_parent_after_interruption(
        self,
    ) -> None:
        call_offset, post_call_offset = self._close_call_boundary_offsets(
            support._PrivateDirectoryCreationRecovery.close_descriptors_for_recovery
        )
        recovery_close_code = support._PrivateDirectoryCreationRecovery.close_descriptors_for_recovery.__code__
        scenarios = (
            ("pre-call", call_offset, False),
            ("post-call", post_call_offset, True),
        )
        real_close = os.close
        for label, target_offset, child_close_completed in scenarios:
            with (
                self.subTest(boundary=label),
                owned_temporary_directory(f"recovery-close-{label}-") as root,
            ):
                parent = root / "parent"
                self._make_private_directory(parent)
                child = parent / "child"
                self._make_private_directory(child)
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                parent_binding = self._open_parent_binding(
                    parent_result_owner,
                    parent,
                    require_owned_private_parent=True,
                )
                directory_fd = os.open(
                    child,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                directory_metadata = os.fstat(directory_fd)
                recovery = support._PrivateDirectoryCreationRecovery(
                    parent_binding=parent_binding,
                    name=b"child",
                    path=child,
                    directory_fd=directory_fd,
                    directory_identity=support.identity_from_stat(directory_metadata),
                    directory_object_identity=(
                        support._directory_object_identity_key(directory_metadata)
                    ),
                    observed_identity=None,
                    entry_state="rollback-unproven",
                )
                parent_fd = parent_binding.fd
                interruption = KeyboardInterrupt(
                    f"synthetic recovery close {label} interruption"
                )
                injected = False
                close_calls: list[int] = []

                def record_close(candidate: int) -> None:
                    close_calls.append(candidate)
                    real_close(candidate)

                def interrupt_close_boundary(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if getattr(frame, "f_code", None) is recovery_close_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_close_boundary

                previous_trace = sys.gettrace()
                try:
                    with mock.patch.object(
                        support.os,
                        "close",
                        side_effect=record_close,
                    ):
                        sys.settrace(interrupt_close_boundary)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            recovery.close_descriptors_for_recovery()
                        sys.settrace(previous_trace)
                        calls_after_interruption = tuple(close_calls)
                        recovery.close_descriptors_for_recovery()
                        self.assertEqual(
                            tuple(close_calls),
                            calls_after_interruption,
                        )
                finally:
                    sys.settrace(previous_trace)
                    if directory_fd not in close_calls:
                        real_close(directory_fd)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(
                    getattr(
                        caught.exception,
                        "private_directory_secondary_close_errors",
                    ),
                    (),
                )
                self.assertEqual(
                    close_calls,
                    (
                        [directory_fd, parent_fd]
                        if child_close_completed
                        else [parent_fd]
                    ),
                )
                self.assertEqual(recovery.directory_fd, directory_fd)
                self.assertEqual(
                    recovery.directory_fd_close_outcome,
                    "close-outcome-unproven",
                )
                self.assertIs(
                    recovery.directory_fd_close_error,
                    interruption,
                )
                self.assertEqual(parent_binding.fd, -1)
                self.assertEqual(parent_binding.fd_close_outcome, "closed")
                with self.assertRaises(OSError) as parent_closed:
                    os.fstat(parent_fd)
                self.assertEqual(parent_closed.exception.errno, errno.EBADF)
                if child_close_completed:
                    with self.assertRaises(OSError) as child_closed:
                        os.fstat(directory_fd)
                    self.assertEqual(child_closed.exception.errno, errno.EBADF)

    def test_private_directory_creation_normalizes_restrictive_umask(self) -> None:
        with owned_temporary_directory("runtime-child-umask-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)

            for restrictive_umask in (0o077, 0o177):
                with self.subTest(umask=oct(restrictive_umask)):
                    result_owner = support._PrivateDirectoryCreationResultOwner()
                    previous_umask = os.umask(restrictive_umask)
                    try:
                        child = support._create_owned_private_directory(
                            parent,
                            ".new-child-",
                            result_owner=result_owner,
                        )
                    finally:
                        os.umask(previous_umask)
                    result_owner.close_descriptors_for_recovery()
                    self.assertEqual(
                        stat.S_IMODE(child.stat(follow_symlinks=False).st_mode),
                        0o700,
                    )
                    child.rmdir()

            result_owner = support._PrivateDirectoryCreationResultOwner()
            previous_umask = os.umask(0o777)
            try:
                with self.assertRaises(
                    support._PrivateDirectoryCreationRetentionRequired
                ) as caught:
                    support._create_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=result_owner,
                    )
                retained = caught.exception
            finally:
                os.umask(previous_umask)
            try:
                self.assertEqual(
                    retained.evidence.entry_state,
                    "present-unbound",
                )
                self.assertIsNone(retained.recovery.directory_fd)
                self.assertTrue(retained.retained_path.exists())
            finally:
                retained.close_descriptors_for_recovery()
                retained.retained_path.chmod(0o700)
                retained.retained_path.rmdir()

    def test_private_directory_creation_rollback_preserves_control_flow_during_close(
        self,
    ) -> None:
        with owned_temporary_directory("creation-rollback-close-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            owner = support._PrivateDirectoryCreationResultOwner()
            trigger = KeyboardInterrupt("synthetic creation rollback interruption")
            close_error = OSError(
                errno.EIO,
                "synthetic creation rollback descriptor close failure",
            )
            original_validate = support.validate_directory_policy_fd
            result_owner_type = support._PrivateDirectoryCreationResultOwner
            original_close = result_owner_type.close_descriptors_for_recovery

            def interrupt_private_validation(
                descriptor: int,
                path: pathlib.Path,
                *,
                private: bool,
            ) -> object:
                if private and path.parent == parent:
                    raise trigger
                return original_validate(descriptor, path, private=private)

            def fail_result_owner_close(
                candidate: support._PrivateDirectoryCreationResultOwner,
            ) -> None:
                if candidate is owner:
                    raise close_error
                original_close(candidate)

            try:
                with (
                    mock.patch.object(
                        support,
                        "validate_directory_policy_fd",
                        side_effect=interrupt_private_validation,
                    ),
                    mock.patch.object(
                        result_owner_type,
                        "close_descriptors_for_recovery",
                        autospec=True,
                        side_effect=fail_result_owner_close,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    support._create_bound_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=owner,
                    )
                self.assertIs(caught.exception, trigger)
                self.assertIsNotNone(owner.pending)
                assert owner.pending is not None
                self.assertEqual(owner.pending.entry_state, "rollback-complete")
                self.assertFalse(owner.pending.path.exists())
            finally:
                original_close(owner)

    def test_unstored_private_directory_rollback_preserves_control_flow_during_close(
        self,
    ) -> None:
        with owned_temporary_directory("unstored-rollback-close-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            owner = support._PrivateDirectoryCreationResultOwner()
            binding = support._create_bound_owned_private_directory(
                parent,
                ".new-child-",
                result_owner=owner,
            )
            trigger = KeyboardInterrupt("synthetic result-store interruption")
            close_error = OSError(
                errno.EIO,
                "synthetic unstored rollback descriptor close failure",
            )
            result_owner_type = support._PrivateDirectoryCreationResultOwner
            original_close = result_owner_type.close_descriptors_for_recovery

            def fail_result_owner_close(
                candidate: support._PrivateDirectoryCreationResultOwner,
            ) -> None:
                if candidate is owner:
                    raise close_error
                original_close(candidate)

            try:
                with mock.patch.object(
                    result_owner_type,
                    "close_descriptors_for_recovery",
                    autospec=True,
                    side_effect=fail_result_owner_close,
                ):
                    recovered = support._rollback_unstored_owned_private_directory(
                        owner,
                        trigger,
                    )
                self.assertIs(recovered, trigger)
                self.assertIsNotNone(owner.pending)
                assert owner.pending is not None
                self.assertEqual(owner.pending.entry_state, "rollback-complete")
                self.assertFalse(binding.path.exists())
            finally:
                original_close(owner)

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_private_directory_creation_retains_moved_object(self) -> None:
        with owned_temporary_directory("runtime-child-binding-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            result_owner = support._PrivateDirectoryCreationResultOwner()
            binding = support._create_bound_owned_private_directory(
                parent,
                ".new-child-",
                result_owner=result_owner,
            )
            result_owner.transfer(binding)
            original = binding.path
            moved = parent / "moved-child"
            try:
                original.rename(moved)
                original.mkdir(mode=0o700)

                self.assertEqual(binding.current_path(), moved)
                with self.assertRaisesRegex(OSError, "path changed"):
                    binding.revalidate()
            finally:
                result_owner.close_descriptors_for_recovery()

    def test_private_directory_creation_never_deletes_public_replacement(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-child-replacement-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            displaced = parent / "displaced-original"
            result_owner = support._PrivateDirectoryCreationResultOwner()
            original_validate = support.validate_directory_policy_fd
            replacement_created = False
            retained: support._PrivateDirectoryCreationRetentionRequired | None = None

            def displace_before_private_validation(
                descriptor: int,
                path: pathlib.Path,
                *,
                private: bool,
            ) -> object:
                nonlocal replacement_created
                if (
                    private
                    and not replacement_created
                    and path.parent == parent
                    and path.name.startswith(".new-child-")
                ):
                    path.rename(displaced)
                    path.mkdir(mode=0o700)
                    replacement_created = True
                return original_validate(descriptor, path, private=private)

            try:
                with (
                    mock.patch.object(
                        support,
                        "validate_directory_policy_fd",
                        side_effect=displace_before_private_validation,
                    ),
                    self.assertRaises(
                        support._PrivateDirectoryCreationRetentionRequired
                    ) as caught,
                ):
                    support._create_bound_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=result_owner,
                    )
                retained = caught.exception
                public_replacement = retained.retained_path
                self.assertTrue(replacement_created)
                self.assertTrue(public_replacement.is_dir())
                self.assertTrue(displaced.is_dir())
                self.assertFalse(result_owner.transferred)
                self.assertIsNone(result_owner.binding)
                self.assertEqual(retained.evidence.entry_state, "rollback-unproven")
                self.assertIsNotNone(retained.recovery.directory_fd)
                held = os.fstat(retained.recovery.directory_fd)
                moved = displaced.stat(follow_symlinks=False)
                replacement = public_replacement.stat(follow_symlinks=False)
                self.assertEqual(
                    (held.st_dev, held.st_ino),
                    (moved.st_dev, moved.st_ino),
                )
                self.assertNotEqual(
                    (held.st_dev, held.st_ino),
                    (replacement.st_dev, replacement.st_ino),
                )
                self.assertEqual(retained.quarantined_root_recovery_evidence, ())
                if sys.platform == "darwin":
                    self.assertEqual(
                        retained.recovery.current_directory_path(),
                        displaced,
                    )
                directory_fd = retained.recovery.directory_fd
                parent_fd = retained.recovery.parent_fd
                assert directory_fd is not None
                real_close = os.close
                close_interruption = KeyboardInterrupt(
                    "synthetic retained child close interruption"
                )

                def visible_child_close_failure(descriptor: int) -> None:
                    real_close(descriptor)
                    if descriptor == directory_fd:
                        raise close_interruption

                with (
                    mock.patch.object(
                        support.os,
                        "close",
                        side_effect=visible_child_close_failure,
                    ),
                    self.assertRaises(KeyboardInterrupt) as close_failure,
                ):
                    retained.close_descriptors_for_recovery()
                self.assertIs(close_failure.exception, close_interruption)
                self.assertEqual(
                    getattr(
                        close_failure.exception,
                        "private_directory_secondary_close_errors",
                    ),
                    (),
                )
                for closed_fd in (directory_fd, parent_fd):
                    with self.assertRaises(OSError) as closed:
                        os.fstat(closed_fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
            finally:
                if retained is not None:
                    public_replacement = retained.retained_path
                    retained.close_descriptors_for_recovery()
                    if public_replacement.exists():
                        public_replacement.rmdir()
                if displaced.exists():
                    displaced.rmdir()

    def test_private_directory_creation_mkdir_interrupt_retains_pending_name(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-child-mkdir-interrupt-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            result_owner = support._PrivateDirectoryCreationResultOwner()
            original_mkdir = os.mkdir
            interruption = KeyboardInterrupt("synthetic mkdir result interruption")
            retained: support._PrivateDirectoryCreationRetentionRequired | None = None
            moved_path: pathlib.Path | None = None

            def mkdir_then_interrupt(
                name: bytes,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> None:
                original_mkdir(name, mode, dir_fd=dir_fd)
                raise interruption

            try:
                with (
                    mock.patch.object(
                        support.os,
                        "mkdir",
                        side_effect=mkdir_then_interrupt,
                    ),
                    self.assertRaises(
                        support._PrivateDirectoryCreationRetentionRequired
                    ) as caught,
                ):
                    support._create_bound_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=result_owner,
                    )
                retained = caught.exception
                self.assertIs(retained.trigger_error, interruption)
                self.assertIsNone(retained.rollback_error)
                self.assertEqual(retained.evidence.entry_state, "present-unbound")
                self.assertIsNotNone(retained.evidence.observed_identity)
                self.assertIsNone(retained.recovery.directory_fd)
                self.assertTrue(retained.retained_path.is_dir())
                parent_fd = retained.evidence.parent_fd
                os.fstat(parent_fd)
                moved_parent = parent.with_name(parent.name + "-moved")
                parent.rename(moved_parent)
                self._make_private_directory(parent)
                lexical_replacement = parent / retained.retained_path.name
                self._make_private_directory(lexical_replacement)
                parent_move_failure = (
                    runner._snapshot_private_directory_creation_recovery(retained)
                )
                self.assertTrue(parent_move_failure.retained)
                self.assertEqual(
                    parent_move_failure.path,
                    str(moved_parent / retained.retained_path.name),
                )
                self.assertEqual(
                    parent_move_failure.path_status,
                    "unbound-parent-moved",
                )
                self.assertEqual(
                    parent_move_failure.original_path_status,
                    "different-object",
                )
                self.assertEqual(
                    parent_move_failure.replacement_path,
                    str(retained.retained_path),
                )
                self.assertEqual(
                    parent_move_failure.recovery_evidence["parent_path_status"],
                    "bound-moved",
                )
                lexical_replacement.rmdir()
                parent.rmdir()
                moved_parent.rename(parent)
                moved_path = parent / "moved-pending-object"
                retained.retained_path.rename(moved_path)
                failure = runner._snapshot_private_directory_creation_recovery(retained)
                self.assertIsNone(failure.retained)
                self.assertEqual(failure.path_status, "unbound-missing")
                self.assertEqual(failure.original_path_status, "missing")
                self.assertIsNone(failure.replacement_path)

                self._make_private_directory(retained.retained_path)
                replacement_failure = (
                    runner._snapshot_private_directory_creation_recovery(retained)
                )
                self.assertIsNone(replacement_failure.retained)
                self.assertEqual(
                    replacement_failure.path_status,
                    "unbound-unresolved",
                )
                self.assertEqual(
                    replacement_failure.original_path_status,
                    "different-object",
                )
                self.assertEqual(
                    replacement_failure.replacement_path,
                    str(retained.retained_path),
                )
            finally:
                if retained is not None:
                    retained_path = retained.retained_path
                    parent_fd = retained.evidence.parent_fd
                    retained.close_descriptors_for_recovery()
                    with self.assertRaises(OSError) as closed:
                        os.fstat(parent_fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                    if retained_path.exists():
                        retained_path.rmdir()
                    if moved_path is not None and moved_path.exists():
                        moved_path.rmdir()

    def test_main_reports_creation_retention_and_propagates_control_flow(
        self,
    ) -> None:
        scenarios = (
            ("failure", RuntimeError("synthetic mkdir result failure"), None),
            (
                "interrupt",
                KeyboardInterrupt("synthetic mkdir result interrupt"),
                None,
            ),
            ("exit-zero", SystemExit(0), 1),
            ("exit-seven", SystemExit(7), 7),
        )
        for label, trigger, expected_exit_code in scenarios:
            with (
                self.subTest(scenario=label),
                owned_temporary_directory(f"readonly-main-creation-{label}-") as root,
            ):
                sticky_parent = root / "sticky"
                sticky_parent.mkdir(mode=0o700)
                sticky_parent.chmod(0o1777)
                runtime_home = root / "runtime-home"
                self._make_private_directory(runtime_home)
                cleanup_control = runtime_home / "cleanup-control"
                self._make_private_directory(cleanup_control)

                creation_owner = support._PrivateDirectoryCreationResultOwner()
                original_mkdir = os.mkdir

                def mkdir_then_raise(
                    name: bytes,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    original_mkdir(name, mode, dir_fd=dir_fd)
                    raise trigger

                with (
                    mock.patch.object(
                        support.os,
                        "mkdir",
                        side_effect=mkdir_then_raise,
                    ),
                    self.assertRaises(
                        support._PrivateDirectoryCreationRetentionRequired
                    ) as caught,
                ):
                    support._create_bound_owned_private_directory(
                        sticky_parent,
                        ".retained-creation-",
                        result_owner=creation_owner,
                        require_owned_private_parent=False,
                    )
                retained = caught.exception
                retained_path = retained.retained_path
                retained_parent_fd = retained.evidence.parent_fd
                creation_calls = 0

                def create_for_main(
                    _parent: pathlib.Path,
                    _prefix: str,
                    *,
                    result_owner: support._PrivateDirectoryCreationResultOwner,
                    require_owned_private_parent: bool = True,
                ) -> support._DirectoryParentBinding:
                    nonlocal creation_calls
                    creation_calls += 1
                    if creation_calls == 1:
                        raise retained
                    parent_result_owner = support._DirectoryParentBindingResultOwner()
                    binding = self._open_parent_binding(
                        parent_result_owner,
                        cleanup_control,
                        require_owned_private_parent=require_owned_private_parent,
                    )
                    result_owner.publish(binding)
                    return binding

                stdout = io.StringIO()
                stderr = io.StringIO()
                try:
                    with (
                        mock.patch.object(runner.sys, "platform", "darwin"),
                        mock.patch.object(
                            runner,
                            "READONLY_INSTALL_PARENT",
                            sticky_parent,
                        ),
                        mock.patch.object(
                            runner,
                            "_private_runtime_parent",
                            return_value=runtime_home,
                        ),
                        mock.patch.object(
                            runner,
                            "_create_bound_owned_private_directory",
                            side_effect=create_for_main,
                        ),
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                    ):
                        if isinstance(trigger, Exception):
                            returncode = runner.main()
                        elif isinstance(trigger, KeyboardInterrupt):
                            with self.assertRaises(KeyboardInterrupt) as interrupted:
                                runner.main()
                            self.assertIs(interrupted.exception, trigger)
                            returncode = None
                        else:
                            with self.assertRaises(SystemExit) as exited:
                                runner.main()
                            self.assertEqual(
                                exited.exception.code,
                                expected_exit_code,
                            )
                            if expected_exit_code != 1:
                                self.assertIs(exited.exception, trigger)
                            returncode = None

                    self.assertEqual(creation_calls, 2)
                    self.assertFalse(cleanup_control.exists())
                    self.assertTrue(retained_path.is_dir())
                    with self.assertRaises(OSError) as closed:
                        os.fstat(retained_parent_fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                    if returncode is None:
                        self.assertEqual(stdout.getvalue(), "")
                        self.assertEqual(stderr.getvalue(), "")
                        continue

                    self.assertEqual(returncode, 1)
                    summary = json.loads(stdout.getvalue())
                    self.assertEqual(summary["primary_status"], "failed")
                    self.assertEqual(
                        summary["primary_failure"]["error_kind"],
                        "RuntimeError",
                    )
                    self.assertEqual(
                        summary["primary_failure"]["stage"],
                        "install-container",
                    )
                    self.assertEqual(summary["cleanup_status"], "incomplete")
                    self.assertEqual(summary["retained_paths"], [str(retained_path)])
                    self.assertEqual(len(summary["cleanup_failures"]), 1)
                    cleanup = summary["cleanup_failures"][0]
                    self.assertTrue(cleanup["retained"])
                    self.assertEqual(cleanup["path_status"], "unbound-original")
                    self.assertEqual(
                        cleanup["original_path_status"],
                        "present-unbound",
                    )
                    self.assertEqual(
                        cleanup["recovery_evidence"]["creation"]["protected_property"],
                        "object-identity",
                    )
                finally:
                    retained.close_descriptors_for_recovery()
                    if cleanup_control.exists():
                        cleanup_control.rmdir()
                    if retained_path.exists():
                        retained_path.rmdir()

    def test_main_consumes_owner_retention_when_publication_is_interrupted(
        self,
    ) -> None:
        scenarios = (
            (
                "interrupt",
                RuntimeError("synthetic retained creation failure"),
                KeyboardInterrupt("synthetic retention publication interrupt"),
                None,
            ),
            (
                "exit-zero",
                RuntimeError("synthetic retained creation failure"),
                SystemExit(0),
                1,
            ),
            (
                "earlier-control-flow",
                KeyboardInterrupt("synthetic earlier creation interrupt"),
                SystemExit(9),
                None,
            ),
        )
        for label, trigger, interruption, expected_exit_code in scenarios:
            with (
                self.subTest(scenario=label),
                owned_temporary_directory(f"main-owner-retention-{label}-") as root,
            ):
                sticky_parent = root / "sticky"
                self._make_private_directory(sticky_parent)
                sticky_parent.chmod(0o1777)
                runtime_home = root / "runtime-home"
                self._make_private_directory(runtime_home)
                cleanup_control = runtime_home / "cleanup-control"
                self._make_private_directory(cleanup_control)
                creation_calls = 0
                published_retention: (
                    support._PrivateDirectoryCreationRetentionRequired | None
                ) = None

                def create_for_main(
                    parent: pathlib.Path,
                    _prefix: str,
                    *,
                    result_owner: support._PrivateDirectoryCreationResultOwner,
                    require_owned_private_parent: bool = True,
                ) -> support._DirectoryParentBinding:
                    nonlocal creation_calls, published_retention
                    creation_calls += 1
                    if creation_calls == 1:
                        parent_result_owner = (
                            support._DirectoryParentBindingResultOwner()
                        )
                        parent_binding = self._open_parent_binding(
                            parent_result_owner,
                            parent,
                            require_owned_private_parent=(require_owned_private_parent),
                        )
                        result_owner.publish_creation_parent(parent_binding)
                        name = b".retention-publication-gap"
                        child_path = parent_binding.path / os.fsdecode(name)
                        pending = result_owner.arm_pending(
                            name=name,
                            path=child_path,
                        )
                        os.mkdir(name, 0o700, dir_fd=parent_binding.fd)
                        observed = os.stat(
                            name,
                            dir_fd=parent_binding.fd,
                            follow_symlinks=False,
                        )
                        pending.observed_identity = support.identity_from_stat(observed)
                        pending.entry_state = "present-unbound"
                        published_retention = (
                            support._retained_private_directory_creation(
                                pending=pending,
                                result_owner=result_owner,
                                trigger_error=trigger,
                                observation_error=None,
                                rollback_error=None,
                            )
                        )
                        raise interruption
                    parent_result_owner = support._DirectoryParentBindingResultOwner()
                    binding = self._open_parent_binding(
                        parent_result_owner,
                        cleanup_control,
                        require_owned_private_parent=require_owned_private_parent,
                    )
                    result_owner.publish(binding)
                    return binding

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(runner.sys, "platform", "darwin"),
                    mock.patch.object(
                        runner,
                        "READONLY_INSTALL_PARENT",
                        sticky_parent,
                    ),
                    mock.patch.object(
                        runner,
                        "_private_runtime_parent",
                        return_value=runtime_home,
                    ),
                    mock.patch.object(
                        runner,
                        "_create_bound_owned_private_directory",
                        side_effect=create_for_main,
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    expected_error = (
                        trigger if not isinstance(trigger, Exception) else interruption
                    )
                    if isinstance(expected_error, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            runner.main()
                        self.assertIs(caught.exception, expected_error)
                    else:
                        with self.assertRaises(SystemExit) as caught:
                            runner.main()
                        self.assertEqual(
                            caught.exception.code,
                            expected_exit_code,
                        )
                        if expected_exit_code != 1:
                            self.assertIs(caught.exception, expected_error)

                self.assertEqual(creation_calls, 2)
                self.assertIsNotNone(published_retention)
                assert published_retention is not None
                self.assertEqual(
                    published_retention.recovery.entry_state,
                    "present-unbound",
                )
                retained_path = published_retention.retained_path
                retained_parent_fd = published_retention.recovery.parent_fd
                self.assertTrue(retained_path.is_dir())
                with self.assertRaises(OSError) as closed:
                    os.fstat(retained_parent_fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
                self.assertFalse(cleanup_control.exists())
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
                retained_path.rmdir()

    def test_main_preserves_successful_exit_after_complete_owner_recovery(
        self,
    ) -> None:
        with owned_temporary_directory("main-successful-exit-recovery-") as root:
            sticky_parent = root / "sticky"
            self._make_private_directory(sticky_parent)
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            interruption = SystemExit(0)
            creation_calls = 0

            def create_for_main(
                _parent: pathlib.Path,
                _prefix: str,
                *,
                result_owner: support._PrivateDirectoryCreationResultOwner,
                require_owned_private_parent: bool = True,
            ) -> support._DirectoryParentBinding:
                nonlocal creation_calls
                creation_calls += 1
                selected_path = (
                    install_container if creation_calls == 1 else cleanup_control
                )
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    selected_path,
                    require_owned_private_parent=require_owned_private_parent,
                )
                result_owner.publish(binding)
                if creation_calls == 1:
                    raise interruption
                return binding

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=create_for_main,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as caught,
            ):
                runner.main()

            self.assertIs(caught.exception, interruption)
            self.assertEqual(caught.exception.code, 0)
            self.assertEqual(creation_calls, 2)
            self.assertFalse(install_container.exists())
            self.assertFalse(cleanup_control.exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

    def test_main_closes_all_creation_resources_after_cleanup_control_flow(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-main-cleanup-control-flow-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            remaining_paths = iter((install_container, runtime_parent, cleanup_control))
            owners: list[support._PrivateDirectoryCreationResultOwner] = []
            bindings: list[support._DirectoryParentBinding] = []

            def create_binding(
                _parent: pathlib.Path,
                _prefix: str,
                *,
                result_owner: support._PrivateDirectoryCreationResultOwner,
                require_owned_private_parent: bool = True,
            ) -> support._DirectoryParentBinding:
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    next(remaining_paths),
                    require_owned_private_parent=require_owned_private_parent,
                )
                result_owner.publish(binding)
                owners.append(result_owner)
                bindings.append(binding)
                return binding

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )
            cleanup_interruption = KeyboardInterrupt(
                "synthetic descriptor-bound cleanup interruption"
            )
            cleanup_recovery = {
                "protected_property": (
                    "recovery-object-identity-and-deletion-result-ownership"
                ),
                "manifest": {
                    "path": str(cleanup_control / "install.manifest"),
                    "state": "published",
                },
                "deletion_result": {"roots": []},
                "quarantined_roots": [],
            }
            setattr(
                cleanup_interruption,
                runner._CLEANUP_RECOVERY_EVIDENCE_ATTR,
                cleanup_recovery,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=create_binding,
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    return_value=completed,
                ),
                mock.patch.object(
                    runner,
                    "_list_bound_directory",
                    return_value=(),
                ),
                mock.patch.object(
                    runner,
                    "_cleanup_bound_tree",
                    side_effect=cleanup_interruption,
                ) as cleanup_bound,
                mock.patch.object(
                    runner,
                    "_cleanup_empty_bound_control",
                ) as cleanup_empty,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                runner.main()

            self.assertIs(caught.exception, cleanup_interruption)
            control_flow_cleanup_failures = getattr(
                caught.exception,
                "readonly_cleanup_failures",
            )
            self.assertTrue(
                any(
                    failure["recovery_evidence"] == cleanup_recovery
                    for failure in control_flow_cleanup_failures
                )
            )
            self.assertTrue(
                any(
                    failure["path"] == str(cleanup_control)
                    and failure["error_kind"] == "CleanupControlRetained"
                    and failure["recovery_evidence"]
                    == {
                        "protected_property": ("cleanup-control-object-identity"),
                        "reason": ("cleanup-control-retained-after-control-flow"),
                        "entries": [],
                    }
                    for failure in control_flow_cleanup_failures
                )
            )
            cleanup_bound.assert_called_once()
            cleanup_empty.assert_not_called()
            self.assertEqual(len(bindings), 3)
            self.assertEqual(len(owners), 3)
            self.assertTrue(
                all(binding.fd_close_outcome == "closed" for binding in bindings)
            )
            self.assertTrue(all(owner.transferred for owner in owners))
            self.assertTrue(all(owner.settled for owner in owners))
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

    def test_main_settles_every_binding_and_result_owner_before_control_flow(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-main-close-settlement-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            paths = (
                install_container,
                runtime_parent,
                cleanup_control,
            )
            remaining_paths = iter(paths)
            bindings: dict[pathlib.Path, support._DirectoryParentBinding] = {}

            def create_binding(
                _parent: pathlib.Path,
                _prefix: str,
                *,
                result_owner: support._PrivateDirectoryCreationResultOwner,
                require_owned_private_parent: bool = True,
            ) -> support._DirectoryParentBinding:
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    next(remaining_paths),
                    require_owned_private_parent=require_owned_private_parent,
                )
                bindings[binding.path] = binding
                result_owner.publish(binding)
                return binding

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )
            first_control_flow = KeyboardInterrupt(
                "synthetic install binding close interruption"
            )
            binding_errors: dict[pathlib.Path, BaseException] = {
                install_container: first_control_flow,
                runtime_parent: SystemExit(7),
                cleanup_control: OSError(
                    errno.EIO,
                    "synthetic cleanup binding close failure",
                ),
            }
            owner_errors: dict[pathlib.Path, BaseException] = {
                install_container: GeneratorExit(
                    "synthetic install owner settlement interruption"
                ),
                runtime_parent: RuntimeError(
                    "synthetic runtime owner settlement failure"
                ),
                cleanup_control: SystemExit(9),
            }
            binding_close_calls: list[pathlib.Path] = []
            owner_settlement_calls: list[pathlib.Path] = []
            settled_owners: list[support._PrivateDirectoryCreationResultOwner] = []
            real_binding_close = support._DirectoryParentBinding.close
            result_owner_type = support._PrivateDirectoryCreationResultOwner
            real_owner_settlement = result_owner_type.close_descriptors_for_recovery

            def close_binding(
                binding: support._DirectoryParentBinding,
            ) -> None:
                binding_close_calls.append(binding.path)
                real_binding_close(binding)
                raise binding_errors[binding.path]

            def settle_owner(
                owner: support._PrivateDirectoryCreationResultOwner,
            ) -> None:
                self.assertIsNotNone(owner.binding)
                assert owner.binding is not None
                path = owner.binding.path
                owner_settlement_calls.append(path)
                real_owner_settlement(owner)
                settled_owners.append(owner)
                raise owner_errors[path]

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=create_binding,
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    return_value=completed,
                ),
                mock.patch.object(
                    runner,
                    "_list_bound_directory",
                    return_value=(),
                ),
                mock.patch.object(
                    runner,
                    "_cleanup_bound_tree",
                    return_value=None,
                ),
                mock.patch.object(
                    runner,
                    "_cleanup_empty_bound_control",
                    return_value=None,
                ),
                mock.patch.object(
                    support._DirectoryParentBinding,
                    "close",
                    autospec=True,
                    side_effect=close_binding,
                ),
                mock.patch.object(
                    support._PrivateDirectoryCreationResultOwner,
                    "close_descriptors_for_recovery",
                    autospec=True,
                    side_effect=settle_owner,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                runner.main()

            self.assertIs(caught.exception, first_control_flow)
            self.assertEqual(binding_close_calls, list(paths))
            self.assertEqual(owner_settlement_calls, list(paths))
            self.assertEqual(len(settled_owners), 3)
            self.assertTrue(all(owner.transferred for owner in settled_owners))
            self.assertTrue(all(owner.settled for owner in settled_owners))
            self.assertTrue(
                all(
                    binding.fd_close_outcome == "closed"
                    for binding in bindings.values()
                )
            )
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

    def test_parent_publication_control_flow_outranks_open_failure(self) -> None:
        with owned_temporary_directory("parent-publication-precedence-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            result_owner = support._PrivateDirectoryCreationResultOwner()
            open_failure = RuntimeError("synthetic parent open return failure")
            publication_interruption = KeyboardInterrupt(
                "synthetic parent publication interruption"
            )
            opened_binding: support._DirectoryParentBinding | None = None
            real_open = support._open_directory_parent

            def open_then_fail(
                raw_path: str | pathlib.Path,
                *,
                require_owned_private_parent: bool,
                result_owner: support._DirectoryParentBindingResultOwner,
            ) -> support._DirectoryParentBinding:
                nonlocal opened_binding
                opened_binding = real_open(
                    raw_path,
                    require_owned_private_parent=require_owned_private_parent,
                    result_owner=result_owner,
                )
                raise open_failure

            with (
                mock.patch.object(
                    support,
                    "_open_directory_parent",
                    side_effect=open_then_fail,
                ),
                mock.patch.object(
                    support._PrivateDirectoryCreationResultOwner,
                    "publish_creation_parent",
                    autospec=True,
                    side_effect=publication_interruption,
                ),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                support._create_bound_owned_private_directory(
                    parent,
                    ".new-child-",
                    result_owner=result_owner,
                )

            self.assertIs(caught.exception, publication_interruption)
            self.assertIsNotNone(opened_binding)
            assert opened_binding is not None
            self.assertEqual(opened_binding.fd_close_outcome, "closed")
            self.assertIsNone(result_owner.creation_parent_binding)
            self.assertEqual(tuple(parent.iterdir()), ())

    def test_bound_private_directory_result_owner_covers_call_to_store_gap(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-child-result-owner-") as root:
            parent = root / "parent"
            parent.mkdir(mode=0o700)

            creation_instructions = tuple(
                dis.get_instructions(support._create_bound_owned_private_directory)
            )
            parent_store: int | None = None
            for index, instruction in enumerate(creation_instructions[:-1]):
                if not instruction.opname.startswith("CALL"):
                    continue
                prior = creation_instructions[max(0, index - 32) : index]
                following = creation_instructions[index + 1]
                if (
                    any(
                        candidate.argval == "_open_directory_parent"
                        for candidate in prior
                    )
                    and following.opname == "STORE_FAST"
                    and following.argval == "parent_binding"
                ):
                    parent_store = following.offset
                    break
            self.assertIsNotNone(parent_store)
            parent_owner = support._PrivateDirectoryCreationResultOwner()
            parent_interruption = KeyboardInterrupt(
                "synthetic parent binding CALL-to-STORE interruption"
            )
            parent_injected = False

            def interrupt_parent_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal parent_injected
                if (
                    getattr(frame, "f_code", None)
                    is support._create_bound_owned_private_directory.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not parent_injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == parent_store
                    ):
                        parent_injected = True
                        raise parent_interruption
                return interrupt_parent_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_parent_store)
                with self.assertRaises(KeyboardInterrupt) as parent_caught:
                    support._create_bound_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=parent_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(parent_injected)
            self.assertIs(parent_caught.exception, parent_interruption)
            self.assertIsNotNone(parent_owner.creation_parent_binding)
            assert parent_owner.creation_parent_binding is not None
            parent_fd = parent_owner.creation_parent_binding.fd
            self.assertIsNone(parent_owner.pending)
            self.assertEqual(tuple(parent.iterdir()), ())
            parent_owner.close_descriptors_for_recovery()
            self.assertTrue(parent_owner.settled)
            with self.assertRaises(OSError) as parent_closed:
                os.fstat(parent_fd)
            self.assertEqual(parent_closed.exception.errno, errno.EBADF)

            creation_store: int | None = None
            for index, instruction in enumerate(creation_instructions[:-1]):
                if not instruction.opname.startswith("CALL"):
                    continue
                prior = creation_instructions[max(0, index - 64) : index]
                if not any(
                    candidate.argval == "_DirectoryParentBinding" for candidate in prior
                ):
                    continue
                following = creation_instructions[index + 1]
                if following.opname == "STORE_FAST" and following.argval == "binding":
                    creation_store = following.offset
                    break
            self.assertIsNotNone(creation_store)
            constructor_owner = support._PrivateDirectoryCreationResultOwner()
            constructor_interrupt = KeyboardInterrupt(
                "synthetic binding construction CALL-to-STORE interruption"
            )
            constructor_injected = False
            constructor_fd: int | None = None
            constructor_path: pathlib.Path | None = None

            def interrupt_binding_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal constructor_fd, constructor_injected, constructor_path
                if (
                    getattr(frame, "f_code", None)
                    is support._create_bound_owned_private_directory.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not constructor_injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == creation_store
                    ):
                        constructor_injected = True
                        constructor_fd = getattr(frame, "f_locals")["child_fd"]
                        constructor_path = getattr(frame, "f_locals")["child_path"]
                        raise constructor_interrupt
                return interrupt_binding_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_binding_store)
                with self.assertRaises(KeyboardInterrupt) as construction_caught:
                    support._create_bound_owned_private_directory(
                        parent,
                        ".new-child-",
                        result_owner=constructor_owner,
                    )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(constructor_injected)
            self.assertIs(construction_caught.exception, constructor_interrupt)
            self.assertIsNone(constructor_owner.binding)
            self.assertIsNotNone(constructor_fd)
            assert constructor_fd is not None
            with self.assertRaises(OSError) as constructor_closed:
                os.fstat(constructor_fd)
            self.assertEqual(constructor_closed.exception.errno, errno.EBADF)
            self.assertIsNotNone(constructor_path)
            assert constructor_path is not None
            self.assertFalse(constructor_path.exists())

            result_owner = support._PrivateDirectoryCreationResultOwner()

            def caller() -> support._DirectoryParentBinding:
                binding = support._create_bound_owned_private_directory(
                    parent,
                    ".new-child-",
                    result_owner=result_owner,
                )
                result_owner.transfer(binding)
                return binding

            instructions = tuple(dis.get_instructions(caller))
            target_offset: int | None = None
            for index, instruction in enumerate(instructions[:-1]):
                if not instruction.opname.startswith("CALL"):
                    continue
                prior = instructions[max(0, index - 64) : index]
                if not any(
                    candidate.argval == "_create_bound_owned_private_directory"
                    for candidate in prior
                ):
                    continue
                following = instructions[index + 1]
                if following.opname == "STORE_FAST" and following.argval == "binding":
                    target_offset = following.offset
                    break
            self.assertIsNotNone(target_offset)
            interruption = KeyboardInterrupt(
                "synthetic private-directory result CALL-to-STORE interruption"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is caller.__code__:
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
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    caller()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertIsNotNone(result_owner.binding)
            assert result_owner.binding is not None
            self.assertTrue(result_owner.owns(result_owner.binding))
            self.assertFalse(result_owner.transferred)
            descriptor = result_owner.binding.fd
            created = result_owner.binding.path
            os.fstat(descriptor)
            real_close = os.close

            def visible_result_close_failure(candidate: int) -> None:
                real_close(candidate)
                if candidate == descriptor:
                    raise OSError(
                        errno.EIO,
                        "synthetic result-owner close failure",
                    )

            with (
                mock.patch.object(
                    support.os,
                    "close",
                    side_effect=visible_result_close_failure,
                ),
                self.assertRaises(OSError),
            ):
                result_owner.close_descriptors_for_recovery()
            self.assertTrue(result_owner.settled)
            self.assertEqual(result_owner.binding.fd, descriptor)
            self.assertEqual(
                result_owner.binding.fd_close_outcome,
                "close-outcome-unproven",
            )
            result_owner.close_descriptors_for_recovery()
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            created.rmdir()

    def test_private_directory_retention_publication_gaps_keep_owner_custody(
        self,
    ) -> None:
        retained_instructions = tuple(
            dis.get_instructions(support._retained_private_directory_creation)
        )
        constructor_store: int | None = None
        publish_return: int | None = None
        for index, instruction in enumerate(retained_instructions[:-1]):
            if not instruction.opname.startswith("CALL"):
                continue
            prior = retained_instructions[max(0, index - 48) : index]
            following = retained_instructions[index + 1]
            if (
                any(
                    candidate.argval == "_PrivateDirectoryCreationRetentionRequired"
                    for candidate in prior
                )
                and following.opname == "STORE_FAST"
                and following.argval == "retained"
            ):
                constructor_store = following.offset
            if any(candidate.argval == "publish_retention" for candidate in prior):
                publish_return = following.offset
        self.assertIsNotNone(constructor_store)
        self.assertIsNotNone(publish_return)

        creation_instructions = tuple(
            dis.get_instructions(support._create_bound_owned_private_directory)
        )
        retained_raise: int | None = None
        for index, instruction in enumerate(creation_instructions):
            if instruction.opname != "RAISE_VARARGS":
                continue
            prior = creation_instructions[max(0, index - 48) : index]
            if any(
                candidate.argval == "_retained_private_directory_creation"
                for candidate in prior
            ) and any(
                candidate.opname == "LOAD_FAST" and candidate.argval == "retained"
                for candidate in prior
            ):
                retained_raise = instruction.offset
                break
        self.assertIsNotNone(retained_raise)

        scenarios = (
            (
                "constructor-store",
                support._retained_private_directory_creation.__code__,
                constructor_store,
                False,
            ),
            (
                "publication-return",
                support._retained_private_directory_creation.__code__,
                publish_return,
                True,
            ),
            (
                "raise-retained",
                support._create_bound_owned_private_directory.__code__,
                retained_raise,
                True,
            ),
        )
        original_mkdir = os.mkdir
        for label, code, target_offset, retention_published in scenarios:
            with (
                self.subTest(boundary=label),
                owned_temporary_directory(f"retention-gap-{label}-") as root,
            ):
                parent = root / "parent"
                self._make_private_directory(parent)
                owner = support._PrivateDirectoryCreationResultOwner()
                trigger = RuntimeError(f"synthetic {label} creation failure")
                interruption = KeyboardInterrupt(
                    f"synthetic {label} publication interruption"
                )
                injected = False

                def mkdir_then_fail(
                    name: bytes,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    original_mkdir(name, mode, dir_fd=dir_fd)
                    raise trigger

                def interrupt_publication(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if getattr(frame, "f_code", None) is code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_publication

                previous_trace = sys.gettrace()
                try:
                    with mock.patch.object(
                        support.os,
                        "mkdir",
                        side_effect=mkdir_then_fail,
                    ):
                        sys.settrace(interrupt_publication)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            support._create_bound_owned_private_directory(
                                parent,
                                ".new-child-",
                                result_owner=owner,
                            )
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertIsNotNone(owner.pending)
                self.assertEqual(owner.retention is not None, retention_published)
                retained = owner.retained_creation_for(interruption)
                self.assertIsNotNone(retained)
                assert retained is not None
                self.assertIs(owner.pending, retained.recovery)
                self.assertIs(owner.retention, retained)
                retained_path = retained.retained_path
                parent_fd = retained.recovery.parent_fd
                retained.close_descriptors_for_recovery()
                owner.close_descriptors_for_recovery()
                self.assertTrue(owner.settled)
                with self.assertRaises(OSError) as closed:
                    os.fstat(parent_fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
                retained_path.rmdir()

    def test_result_owner_remains_fallback_after_transfer_store_gap(self) -> None:
        with owned_temporary_directory("result-transfer-store-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            owner = support._PrivateDirectoryCreationResultOwner()

            def caller() -> support._DirectoryParentBinding:
                binding = support._create_bound_owned_private_directory(
                    parent,
                    ".new-child-",
                    result_owner=owner,
                )
                transferred = owner.transfer(binding)
                return transferred

            instructions = tuple(dis.get_instructions(caller))
            target_offset: int | None = None
            for index, instruction in enumerate(instructions[:-1]):
                if not instruction.opname.startswith("CALL"):
                    continue
                prior = instructions[max(0, index - 16) : index]
                following = instructions[index + 1]
                if (
                    any(candidate.argval == "transfer" for candidate in prior)
                    and following.opname == "STORE_FAST"
                    and following.argval == "transferred"
                ):
                    target_offset = following.offset
                    break
            self.assertIsNotNone(target_offset)
            interruption = KeyboardInterrupt(
                "synthetic transfer CALL-to-STORE interruption"
            )
            injected = False

            def interrupt_transfer_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is caller.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_transfer_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_transfer_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    caller()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertTrue(owner.transferred)
            self.assertIsNotNone(owner.binding)
            assert owner.binding is not None
            descriptor = owner.binding.fd
            created = owner.binding.path
            owner.close_descriptors_for_recovery()
            self.assertTrue(owner.settled)
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            created.rmdir()

    def test_private_directory_binding_publication_is_atomic(self) -> None:
        instructions = tuple(
            dis.get_instructions(support._PrivateDirectoryCreationResultOwner.publish)
        )
        store_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "STORE_ATTR"
            and instruction.argval == "_binding_publication"
        )
        boundaries = (
            ("before", instructions[store_index].offset, False),
            ("after", instructions[store_index + 1].offset, True),
        )

        for label, target_offset, published in boundaries:
            with (
                self.subTest(boundary=label),
                owned_temporary_directory(f"binding-publication-{label}-") as root,
            ):
                parent = root / "parent"
                self._make_private_directory(parent)
                binding_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    binding_owner,
                    parent,
                    require_owned_private_parent=True,
                )
                owner = support._PrivateDirectoryCreationResultOwner()
                interruption = KeyboardInterrupt(
                    f"synthetic binding publication {label} interruption"
                )
                injected = False

                def interrupt_publication(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is support._PrivateDirectoryCreationResultOwner.publish.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_publication

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_publication)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        owner.publish(binding)
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(owner.binding is not None, published)
                self.assertEqual(owner.binding_descriptor is not None, published)
                if published:
                    self.assertIs(owner.binding, binding)
                    self.assertEqual(owner.binding_descriptor, binding.fd)
                    owner.close_descriptors_for_recovery()
                binding_owner.close()

    def test_bare_path_result_owner_recovers_caller_store_gap(self) -> None:
        with owned_temporary_directory("path-result-store-") as root:
            parent = root / "parent"
            self._make_private_directory(parent)
            pre_call_owner = support._PrivateDirectoryCreationResultOwner()

            def pre_call() -> pathlib.Path:
                return support._create_owned_private_directory(
                    parent,
                    ".pre-call-child-",
                    result_owner=pre_call_owner,
                )

            pre_call_instructions = tuple(dis.get_instructions(pre_call))
            pre_call_offset = next(
                instruction.offset
                for index, instruction in enumerate(pre_call_instructions)
                if instruction.opname.startswith("CALL")
                and any(
                    candidate.argval == "_create_owned_private_directory"
                    for candidate in pre_call_instructions[max(0, index - 32) : index]
                )
            )
            pre_call_interruption = KeyboardInterrupt(
                "synthetic owner pre-call interruption"
            )
            pre_call_injected = False

            def interrupt_pre_call(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal pre_call_injected
                if getattr(frame, "f_code", None) is pre_call.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not pre_call_injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == pre_call_offset
                    ):
                        pre_call_injected = True
                        raise pre_call_interruption
                return interrupt_pre_call

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_pre_call)
                with self.assertRaises(KeyboardInterrupt) as pre_call_caught:
                    pre_call()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(pre_call_injected)
            self.assertIs(pre_call_caught.exception, pre_call_interruption)
            self.assertIsNone(pre_call_owner.creation_parent_binding)
            self.assertIsNone(pre_call_owner.pending)
            self.assertIsNone(pre_call_owner.binding)
            pre_call_owner.close_descriptors_for_recovery()
            self.assertTrue(pre_call_owner.settled)
            self.assertEqual(tuple(parent.iterdir()), ())

            owner = support._PrivateDirectoryCreationResultOwner()

            def caller() -> pathlib.Path:
                path = support._create_owned_private_directory(
                    parent,
                    ".new-child-",
                    result_owner=owner,
                )
                return path

            instructions = tuple(dis.get_instructions(caller))
            target_offset: int | None = None
            for index, instruction in enumerate(instructions[:-1]):
                if not instruction.opname.startswith("CALL"):
                    continue
                prior = instructions[max(0, index - 32) : index]
                following = instructions[index + 1]
                if (
                    any(
                        candidate.argval == "_create_owned_private_directory"
                        for candidate in prior
                    )
                    and following.opname == "STORE_FAST"
                    and following.argval == "path"
                ):
                    target_offset = following.offset
                    break
            self.assertIsNotNone(target_offset)
            interruption = KeyboardInterrupt(
                "synthetic bare Path CALL-to-STORE interruption"
            )
            injected = False

            def interrupt_path_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if getattr(frame, "f_code", None) is caller.__code__:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_path_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_path_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    caller()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertTrue(owner.transferred)
            self.assertIsNotNone(owner.binding)
            assert owner.binding is not None
            created = owner.binding.path
            descriptor = owner.binding.fd
            recovered = support._rollback_unstored_owned_private_directory(
                owner,
                interruption,
            )
            self.assertIs(recovered, interruption)
            self.assertTrue(owner.settled)
            self.assertFalse(created.exists())
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_runtime_directory_allows_benign_child_churn(self) -> None:
        with owned_temporary_directory("runtime-binding-churn-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                transient = runtime_parent / "transient"
                transient.write_text("temporary", encoding="utf-8")
                transient.unlink()

                self.assertEqual(runner._list_bound_directory(binding), ())
            finally:
                parent_result_owner.close()

    def test_bound_runtime_directory_rejects_path_replacement(self) -> None:
        with owned_temporary_directory("runtime-binding-replace-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)
                runtime_parent.mkdir(mode=0o700)

                with self.assertRaisesRegex(OSError, "path changed"):
                    runner._list_bound_directory(binding)
            finally:
                parent_result_owner.close()

    def test_unproven_closure_reports_unresolved_bound_location_as_unknown(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-binding-unresolved-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                for original_status in ("missing", "unreadable", "replaced"):
                    with (
                        self.subTest(original_path_status=original_status),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "current_path",
                            side_effect=OSError(
                                errno.ESTALE,
                                "synthetic F_GETPATH failure",
                            ),
                        ),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "original_path_identity_status",
                            return_value=original_status,
                        ),
                        mock.patch.object(
                            support._DirectoryParentBinding,
                            "access_policy_status",
                            return_value="same",
                        ),
                    ):
                        evidence = runner._bound_path_evidence(binding)
                        failure = runner._retained_bound_for_unproven_child_closure(
                            binding,
                            None,
                        )

                    self.assertEqual(evidence.path, runtime_parent)
                    self.assertIsNone(evidence.retained)
                    self.assertEqual(evidence.path_status, "bound-unresolved")
                    self.assertEqual(
                        evidence.replacement_path,
                        runtime_parent if original_status == "replaced" else None,
                    )
                    self.assertEqual(
                        evidence.original_path_status,
                        original_status,
                    )
                    self.assertIsNotNone(failure)
                    assert failure is not None
                    payload = json.loads(
                        json.dumps(
                            asdict(failure),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                    self.assertEqual(
                        payload["error_kind"],
                        "ChildProcessClosureUnproven",
                    )
                    self.assertIsNone(payload["retained"])
                    self.assertEqual(
                        payload["original_path_status"],
                        original_status,
                    )
                    self.assertEqual(
                        payload["held_identity"],
                        binding.object_locator(),
                    )
                    retained_paths = [
                        item.path for item in (failure,) if item.retained is not False
                    ]
                    self.assertEqual(retained_paths, [str(runtime_parent)])
            finally:
                parent_result_owner.close()

    def test_bound_runtime_cleanup_rejects_path_replacement(self) -> None:
        with owned_temporary_directory("runtime-cleanup-replace-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            original = root / "original"
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rename(original)
                runtime_parent.mkdir(mode=0o700)

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(original))
                self.assertEqual(failure.error_kind, "OSError")
                self.assertEqual(failure.error_errno, errno.ESTALE)
                self.assertTrue(failure.retained)
                self.assertEqual(failure.original_path, str(runtime_parent))
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertEqual(failure.replacement_path, str(runtime_parent))
                self.assertTrue(original.is_dir())
                self.assertTrue(runtime_parent.is_dir())
            finally:
                parent_result_owner.close()

    def test_bound_cleanup_settlement_control_flow_outranks_body_error(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-precedence-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            primary = RuntimeError("synthetic cleanup body failure")
            interruption = KeyboardInterrupt("synthetic cleanup settlement interrupt")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            real_close = support._DirectoryParentBindingResultOwner.close

            def close_then_interrupt(
                owner: support._DirectoryParentBindingResultOwner,
            ) -> None:
                real_close(owner)
                raise interruption

            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=primary,
                    ),
                    mock.patch.object(
                        runner,
                        "_snapshot_bound_cleanup_recovery",
                    ),
                    mock.patch.object(
                        support._DirectoryParentBindingResultOwner,
                        "close",
                        autospec=True,
                        side_effect=close_then_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    runner._delete_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=root / "cleanup.manifest",
                    )
                self.assertIs(caught.exception, interruption)
                self.assertTrue(
                    any(
                        "cleanup body failure" in note
                        for note in interruption.__notes__
                    )
                )
            finally:
                parent_result_owner.close()

    def test_bound_cleanup_recovery_control_flow_outranks_body_error(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-recovery-precedence-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            body_error = RuntimeError("synthetic cleanup body failure")
            recovery_interruption = KeyboardInterrupt(
                "synthetic cleanup recovery interruption"
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_error,
                    ),
                    mock.patch.object(
                        runner,
                        "_snapshot_bound_cleanup_recovery",
                        side_effect=recovery_interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    runner._delete_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=root / "cleanup.manifest",
                    )
                self.assertIs(caught.exception, recovery_interruption)
                self.assertTrue(
                    any(
                        "cleanup body failure" in note
                        for note in recovery_interruption.__notes__
                    )
                )
            finally:
                parent_result_owner.close()

    def test_bound_cleanup_child_outer_handler_propagates_local_intruder(
        self,
    ) -> None:
        visit_code = next(
            constant
            for constant in runner._restore_owner_write_below_bound_root.__code__.co_consts
            if getattr(constant, "co_name", None) == "visit"
        )
        process_child_code = next(
            constant
            for constant in visit_code.co_consts
            if getattr(constant, "co_name", None) == "process_child"
        )
        visit_instructions = tuple(dis.get_instructions(visit_code))
        process_child_call = next(
            instruction.offset
            for index, instruction in enumerate(visit_instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "process_child"
                for candidate in visit_instructions[max(0, index - 4) : index]
            )
        )
        for hook_kind in ("trace", "profile"):
            with (
                self.subTest(hook=hook_kind),
                owned_temporary_directory(f"cleanup-child-outer-{hook_kind}-") as root,
            ):
                child = root / "child"
                self._make_private_directory(child)
                root_fd = os.open(
                    root,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                ambient_error = KeyboardInterrupt(
                    f"synthetic handled {hook_kind} caller error"
                )
                intruder = SystemExit(f"synthetic child {hook_kind} boundary intruder")
                fired = False
                caught: BaseException | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is visit_code:
                        setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == process_child_call
                        ):
                            fired = True
                            raise injected_error
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and event == "call"
                        and getattr(frame, "f_code", None) is process_child_code
                    ):
                        fired = True
                        raise injected_error

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    try:
                        raise ambient_error
                    except KeyboardInterrupt:
                        if hook_kind == "trace":
                            sys.settrace(trace)
                        else:
                            sys.setprofile(profile)
                        try:
                            runner._restore_owner_write_below_bound_root(root_fd)
                        except BaseException as error:  # noqa: BLE001
                            caught = error
                        finally:
                            sys.setprofile(previous_profile)
                            sys.settrace(previous_trace)
                finally:
                    os.close(root_fd)

                self.assertTrue(fired)
                self.assertIs(caught, intruder)
                self.assertEqual(getattr(ambient_error, "__notes__", []), [])

    def test_bound_cleanup_child_preserves_same_object_local_context(
        self,
    ) -> None:
        visit_code = next(
            constant
            for constant in runner._restore_owner_write_below_bound_root.__code__.co_consts
            if getattr(constant, "co_name", None) == "visit"
        )
        process_child_code = next(
            constant
            for constant in visit_code.co_consts
            if getattr(constant, "co_name", None) == "process_child"
        )
        with owned_temporary_directory("cleanup-child-same-error-") as root:
            child = root / "child"
            self._make_private_directory(child)
            root_fd = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            ambient_and_local_error = KeyboardInterrupt(
                "synthetic handled and locally reraised child error"
            )
            intruder = RuntimeError("synthetic child profile intruder")
            fired = False
            caught: BaseException | None = None

            def profile(frame: object, event: str, _argument: object) -> None:
                nonlocal fired
                if (
                    not fired
                    and event == "call"
                    and getattr(frame, "f_code", None) is process_child_code
                ):
                    fired = True
                    try:
                        raise ambient_and_local_error
                    except KeyboardInterrupt:
                        raise intruder

            previous_profile = sys.getprofile()
            try:
                try:
                    raise ambient_and_local_error
                except KeyboardInterrupt:
                    sys.setprofile(profile)
                    try:
                        runner._restore_owner_write_below_bound_root(root_fd)
                    except BaseException as error:  # noqa: BLE001
                        caught = error
                    finally:
                        sys.setprofile(previous_profile)
            finally:
                os.close(root_fd)

            self.assertTrue(fired)
            self.assertIs(caught, ambient_and_local_error)
            self.assertTrue(
                any(
                    "child traversal caller boundary" in note
                    and "profile intruder" in note
                    for note in ambient_and_local_error.__notes__
                )
            )

    def test_bound_cleanup_outer_handler_does_not_hide_parent_close_intruder(
        self,
    ) -> None:
        instructions = tuple(
            dis.get_instructions(runner._BoundCleanupDeliveryOwner.step)
        )
        parent_close_call = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "parent_result_owner"
                for candidate in instructions[max(0, index - 8) : index]
            )
            and any(
                candidate.argval == "close"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        close_code = support._DirectoryParentBindingResultOwner.close.__code__
        for hook_kind in ("trace", "profile"):
            with (
                self.subTest(hook=hook_kind),
                owned_temporary_directory(f"cleanup-parent-close-{hook_kind}-") as root,
            ):
                runtime_parent = root / "runtime"
                self._make_private_directory(runtime_parent)
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    runtime_parent,
                    require_owned_private_parent=True,
                )
                manifest = mock.Mock()
                manifest.seal = {"sha256": "synthetic"}
                ambient_error = KeyboardInterrupt(
                    f"synthetic handled {hook_kind} cleanup caller error"
                )
                intruder = SystemExit(
                    f"synthetic cleanup parent {hook_kind} close intruder"
                )
                fired = False
                caught: BaseException | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> object:
                    nonlocal fired
                    if (
                        getattr(frame, "f_code", None)
                        is runner._BoundCleanupDeliveryOwner.step.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == parent_close_call
                        ):
                            fired = True
                            raise injected_error
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and event == "call"
                        and getattr(frame, "f_code", None) is close_code
                    ):
                        fired = True
                        raise injected_error

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    with (
                        mock.patch.object(
                            runner,
                            "build_custodied_manifest",
                            return_value=manifest,
                        ),
                        mock.patch.object(runner, "delete_custodied_roots"),
                        mock.patch.object(
                            runner,
                            "remove_published_manifest",
                        ) as remove_manifest,
                    ):
                        try:
                            raise ambient_error
                        except KeyboardInterrupt:
                            if hook_kind == "trace":
                                sys.settrace(trace)
                            else:
                                sys.setprofile(profile)
                            try:
                                runner._delete_bound_tree(
                                    binding,
                                    restore_owner_write=False,
                                    manifest_path=root / "cleanup.manifest",
                                )
                            except BaseException as error:  # noqa: BLE001
                                caught = error
                            finally:
                                sys.setprofile(previous_profile)
                                sys.settrace(previous_trace)

                        self.assertTrue(fired)
                        self.assertIs(caught, intruder)
                        self.assertEqual(
                            getattr(ambient_error, "__notes__", []),
                            [],
                        )
                        remove_manifest.assert_not_called()
                finally:
                    parent_result_owner.close()

    def test_bound_cleanup_same_object_body_error_remains_primary(
        self,
    ) -> None:
        close_code = support._DirectoryParentBindingResultOwner.close.__code__
        with owned_temporary_directory("cleanup-same-body-error-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            ambient_and_body_error = KeyboardInterrupt(
                "synthetic handled and locally reraised cleanup body error"
            )
            settlement_intruder = SystemExit("synthetic cleanup parent close intruder")
            fired = False
            caught: BaseException | None = None

            def profile(frame: object, event: str, _argument: object) -> None:
                nonlocal fired
                if (
                    not fired
                    and event == "call"
                    and getattr(frame, "f_code", None) is close_code
                ):
                    fired = True
                    raise settlement_intruder

            previous_profile = sys.getprofile()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=ambient_and_body_error,
                    ),
                    mock.patch.object(runner, "_snapshot_bound_cleanup_recovery"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                ):
                    try:
                        raise ambient_and_body_error
                    except KeyboardInterrupt:
                        sys.setprofile(profile)
                        try:
                            runner._delete_bound_tree(
                                binding,
                                restore_owner_write=False,
                                manifest_path=root / "cleanup.manifest",
                            )
                        except BaseException as error:  # noqa: BLE001
                            caught = error
                        finally:
                            sys.setprofile(previous_profile)

                    self.assertTrue(fired)
                    self.assertIs(caught, ambient_and_body_error)
                    self.assertTrue(
                        any(
                            "bound-tree cleanup settlement also failed" in note
                            and "parent close intruder" in note
                            for note in ambient_and_body_error.__notes__
                        )
                    )
                    remove_manifest.assert_not_called()
            finally:
                parent_result_owner.close()

    def test_empty_bound_cleanup_outer_handler_propagates_parent_close_intruder(
        self,
    ) -> None:
        instructions = tuple(
            dis.get_instructions(runner._BoundCleanupDeliveryOwner.step)
        )
        parent_close_call = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "parent_result_owner"
                for candidate in instructions[max(0, index - 8) : index]
            )
            and any(
                candidate.argval == "close"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        close_code = support._DirectoryParentBindingResultOwner.close.__code__
        for hook_kind in ("trace", "profile"):
            with (
                self.subTest(hook=hook_kind),
                owned_temporary_directory(
                    f"cleanup-control-close-{hook_kind}-"
                ) as root,
            ):
                cleanup_control = root / "cleanup-control"
                self._make_private_directory(cleanup_control)
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    cleanup_control,
                    require_owned_private_parent=True,
                )
                ambient_error = KeyboardInterrupt(
                    f"synthetic handled {hook_kind} cleanup-control caller error"
                )
                intruder = SystemExit(
                    f"synthetic cleanup-control {hook_kind} close intruder"
                )
                fired = False
                caught: BaseException | None = None

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> object:
                    nonlocal fired
                    if (
                        getattr(frame, "f_code", None)
                        is runner._BoundCleanupDeliveryOwner.step.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == parent_close_call
                        ):
                            fired = True
                            raise injected_error
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    _argument: object,
                    injected_error: BaseException = intruder,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and event == "call"
                        and getattr(frame, "f_code", None) is close_code
                    ):
                        fired = True
                        raise injected_error

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    with mock.patch.object(
                        runner,
                        "quarantine_and_remove_empty_root",
                    ):
                        try:
                            raise ambient_error
                        except KeyboardInterrupt:
                            if hook_kind == "trace":
                                sys.settrace(trace)
                            else:
                                sys.setprofile(profile)
                            try:
                                runner._cleanup_empty_bound_control(binding)
                            except BaseException as error:  # noqa: BLE001
                                caught = error
                            finally:
                                sys.setprofile(previous_profile)
                                sys.settrace(previous_trace)

                    self.assertTrue(fired)
                    self.assertIs(caught, intruder)
                    self.assertEqual(getattr(ambient_error, "__notes__", []), [])
                finally:
                    parent_result_owner.close()

    def test_empty_bound_cleanup_same_object_body_error_remains_primary(
        self,
    ) -> None:
        instructions = tuple(
            dis.get_instructions(runner._BoundCleanupDeliveryOwner.step)
        )
        parent_close_call = next(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "parent_result_owner"
                for candidate in instructions[max(0, index - 8) : index]
            )
            and any(
                candidate.argval == "close"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        with owned_temporary_directory("cleanup-control-same-body-error-") as root:
            cleanup_control = root / "cleanup-control"
            self._make_private_directory(cleanup_control)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                cleanup_control,
                require_owned_private_parent=True,
            )
            ambient_and_body_error = KeyboardInterrupt(
                "synthetic handled and locally reraised cleanup-control body error"
            )
            settlement_intruder = SystemExit("synthetic cleanup-control close intruder")
            fired = False
            caught: BaseException | None = None

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if (
                    getattr(frame, "f_code", None)
                    is runner._BoundCleanupDeliveryOwner.step.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == parent_close_call
                    ):
                        fired = True
                        raise settlement_intruder
                return trace

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    runner,
                    "quarantine_and_remove_empty_root",
                    side_effect=ambient_and_body_error,
                ):
                    try:
                        raise ambient_and_body_error
                    except KeyboardInterrupt:
                        sys.settrace(trace)
                        try:
                            runner._cleanup_empty_bound_control(binding)
                        except BaseException as error:  # noqa: BLE001
                            caught = error
                        finally:
                            sys.settrace(previous_trace)

                self.assertTrue(fired)
                self.assertIs(caught, ambient_and_body_error)
                self.assertTrue(
                    any(
                        "cleanup-control parent settlement also failed" in note
                        and "close intruder" in note
                        for note in ambient_and_body_error.__notes__
                    )
                )
            finally:
                parent_result_owner.close()

    def test_cleanup_body_settlement_stops_at_same_ambient_object_reraise(
        self,
    ) -> None:
        ambient_error = KeyboardInterrupt(
            "synthetic handled and locally reraised body error"
        )
        prior_caller_error = RuntimeError("synthetic prior caller context")

        try:
            raise ambient_error
        except KeyboardInterrupt:
            settlement = runner._CleanupBodyErrorSettlement(
                invocation_ambient_error=ambient_error,
                invocation_ambient_traceback=ambient_error.__traceback__,
            )
            ambient_error.__context__ = prior_caller_error
            try:
                raise ambient_error
            except KeyboardInterrupt:
                settlement.recover_current_exception()

        self.assertIs(settlement.active_error, ambient_error)
        self.assertIsNot(settlement.active_error, prior_caller_error)
        self.assertIsNone(settlement.publication_error)
        self.assertEqual(settlement.publication_observations, [])

    def test_cleanup_body_settlement_ignores_caught_callback_context(self) -> None:
        ambient_error = RuntimeError("synthetic invocation ambient error")
        body_error = ValueError("synthetic cleanup body error")
        caught_callback_error = KeyboardInterrupt(
            "synthetic caught callback interruption"
        )
        outer_boundary_error = OSError("synthetic callback boundary error")
        body_error.__context__ = ambient_error
        caught_callback_error.__context__ = body_error
        outer_boundary_error.__context__ = caught_callback_error
        settlement = runner._CleanupBodyErrorSettlement(
            invocation_ambient_error=ambient_error,
            invocation_ambient_traceback=None,
        )

        with mock.patch.object(
            runner.sys,
            "exception",
            return_value=outer_boundary_error,
        ):
            settlement.recover_current_exception()

        self.assertIs(settlement.active_error, body_error)
        self.assertTrue(settlement.active_error_replaced)
        self.assertIs(settlement.publication_error, outer_boundary_error)
        self.assertEqual(
            settlement.publication_observations,
            [("cleanup body publication boundary", outer_boundary_error)],
        )
        self.assertNotIn(
            id(caught_callback_error),
            settlement.publication_observation_ids,
        )

    def test_cleanup_body_settlement_skips_ambient_callback_context(self) -> None:
        ambient_error = KeyboardInterrupt("synthetic invocation ambient error")
        body_error = ValueError("synthetic cleanup body error")
        outer_boundary_error = OSError("synthetic callback boundary error")

        try:
            raise ambient_error
        except KeyboardInterrupt:
            ambient_context = ambient_error.__context__
            settlement = runner._CleanupBodyErrorSettlement(
                invocation_ambient_error=ambient_error,
                invocation_ambient_traceback=ambient_error.__traceback__,
                invocation_ambient_context=ambient_context,
                invocation_ambient_context_traceback=(
                    ambient_context.__traceback__
                    if isinstance(ambient_context, BaseException)
                    else None
                ),
            )
            try:
                raise body_error
            except ValueError:
                try:
                    raise ambient_error
                except KeyboardInterrupt:
                    try:
                        raise outer_boundary_error
                    except OSError:
                        settlement.recover_current_exception()

        self.assertIs(settlement.active_error, body_error)
        self.assertTrue(settlement.active_error_replaced)
        self.assertIs(settlement.publication_error, outer_boundary_error)
        self.assertEqual(
            settlement.publication_observations,
            [("cleanup body publication boundary", outer_boundary_error)],
        )
        self.assertNotIn(
            id(ambient_error),
            settlement.publication_observation_ids,
        )

    def test_bound_cleanup_preserves_selected_ambient_primary(self) -> None:
        error_store, _local_store = self._local_active_error_store_offsets(
            runner._delete_bound_tree
        )
        target_code = runner._delete_bound_tree.__code__
        with owned_temporary_directory("cleanup-selected-ambient-primary-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            ambient_primary = KeyboardInterrupt(
                "synthetic handled recovery control-flow primary"
            )
            body_trigger = RuntimeError("synthetic cleanup body trigger")
            publication_intruder = OSError(
                "synthetic selected-primary publication intruder"
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == error_store
                    ):
                        fired = True
                        raise publication_intruder
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_trigger,
                    ),
                    mock.patch.object(
                        runner,
                        "_snapshot_bound_cleanup_recovery",
                        side_effect=ambient_primary,
                    ),
                ):
                    try:
                        raise ambient_primary
                    except KeyboardInterrupt:
                        sys.settrace(trace)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            runner._delete_bound_tree(
                                binding,
                                restore_owner_write=False,
                                manifest_path=root / "cleanup.manifest",
                            )
                self.assertTrue(fired)
                self.assertIs(caught.exception, ambient_primary)
                self.assertTrue(
                    any(
                        "body publication boundary" in note
                        and "selected-primary publication intruder" in note
                        for note in ambient_primary.__notes__
                    )
                )
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_cleanup_does_not_revive_secondary_ambient(self) -> None:
        instructions = tuple(dis.get_instructions(runner._delete_bound_tree))
        publish_calls = tuple(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and next(
                (
                    candidate.argval
                    for candidate in reversed(instructions[max(0, index - 10) : index])
                    if candidate.opname in {"LOAD_ATTR", "LOAD_METHOD", "LOAD_GLOBAL"}
                ),
                None,
            )
            == "publish_local_active_error"
        )
        self.assertEqual(len(publish_calls), 3)
        selected_primary_publish = publish_calls[1]
        recover_calls = tuple(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and next(
                (
                    candidate.argval
                    for candidate in reversed(instructions[max(0, index - 10) : index])
                    if candidate.opname in {"LOAD_ATTR", "LOAD_METHOD", "LOAD_GLOBAL"}
                ),
                None,
            )
            == "recover_current_exception"
        )
        outer_recovery = min(
            offset for offset in recover_calls if offset > publish_calls[-1]
        )
        target_code = runner._delete_bound_tree.__code__
        recovery_code = (
            runner._CleanupBodyErrorSettlement.recover_current_exception.__code__
        )
        with owned_temporary_directory("cleanup-secondary-ambient-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            ambient_secondary = KeyboardInterrupt(
                "synthetic handled recovery secondary"
            )
            body_primary = SystemExit("synthetic cleanup body primary")
            first_publication_intruder = OSError(
                "synthetic selected-primary trace intruder"
            )
            second_publication_intruder = RuntimeError(
                "synthetic outer publication profile intruder"
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            trace_fired = False
            profile_fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal trace_fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not trace_fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == selected_primary_publish
                    ):
                        trace_fired = True
                        raise first_publication_intruder
                return trace

            def profile(frame: object, event: str, _argument: object) -> None:
                nonlocal profile_fired
                caller = getattr(frame, "f_back", None)
                if (
                    trace_fired
                    and not profile_fired
                    and event == "call"
                    and getattr(frame, "f_code", None) is recovery_code
                    and getattr(caller, "f_code", None) is target_code
                    and getattr(caller, "f_lasti", None) == outer_recovery
                ):
                    profile_fired = True
                    raise second_publication_intruder

            previous_trace = sys.gettrace()
            previous_profile = sys.getprofile()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_primary,
                    ),
                    mock.patch.object(
                        runner,
                        "_snapshot_bound_cleanup_recovery",
                        side_effect=ambient_secondary,
                    ),
                ):
                    try:
                        raise ambient_secondary
                    except KeyboardInterrupt:
                        sys.setprofile(profile)
                        sys.settrace(trace)
                        with self.assertRaises(SystemExit) as caught:
                            runner._delete_bound_tree(
                                binding,
                                restore_owner_write=False,
                                manifest_path=root / "cleanup.manifest",
                            )
                self.assertTrue(trace_fired)
                self.assertTrue(profile_fired)
                self.assertIs(caught.exception, body_primary)
                self.assertTrue(
                    any(
                        "outer publication profile intruder" in note
                        for note in body_primary.__notes__
                    )
                )
            finally:
                sys.setprofile(previous_profile)
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_cleanup_single_hook_preserves_selected_primary(self) -> None:
        instructions = tuple(dis.get_instructions(runner._delete_bound_tree))
        publish_calls = tuple(
            instruction.offset
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and next(
                (
                    candidate.argval
                    for candidate in reversed(instructions[max(0, index - 10) : index])
                    if candidate.opname in {"LOAD_ATTR", "LOAD_METHOD", "LOAD_GLOBAL"}
                ),
                None,
            )
            == "publish_local_active_error"
        )
        self.assertEqual(len(publish_calls), 3)
        selected_primary_publish = publish_calls[1]
        target_code = runner._delete_bound_tree.__code__
        scenarios = (
            (
                "later-control-flow",
                RuntimeError("synthetic ordinary body trigger"),
                KeyboardInterrupt("synthetic later recovery primary"),
                "recovery",
            ),
            (
                "earlier-control-flow",
                SystemExit("synthetic earlier body primary"),
                KeyboardInterrupt("synthetic later recovery secondary"),
                "body",
            ),
        )
        for label, body_error, recovery_error, expected in scenarios:
            with (
                self.subTest(precedence=label),
                owned_temporary_directory(f"cleanup-single-hook-{label}-") as root,
            ):
                runtime_parent = root / "runtime"
                self._make_private_directory(runtime_parent)
                parent_result_owner = support._DirectoryParentBindingResultOwner()
                binding = self._open_parent_binding(
                    parent_result_owner,
                    runtime_parent,
                    require_owned_private_parent=True,
                )
                publication_intruder = OSError(
                    f"synthetic {label} publication intruder"
                )
                manifest = mock.Mock()
                manifest.seal = {"sha256": "synthetic"}
                fired = False

                def trace(frame: object, event: str, _argument: object) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is target_code:
                        setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None)
                            == selected_primary_publish
                        ):
                            fired = True
                            raise publication_intruder
                    return trace

                previous_trace = sys.gettrace()
                try:
                    with (
                        mock.patch.object(
                            runner,
                            "build_custodied_manifest",
                            return_value=manifest,
                        ),
                        mock.patch.object(
                            runner,
                            "delete_custodied_roots",
                            side_effect=body_error,
                        ),
                        mock.patch.object(
                            runner,
                            "_snapshot_bound_cleanup_recovery",
                            side_effect=recovery_error,
                        ),
                    ):
                        try:
                            raise recovery_error
                        except KeyboardInterrupt:
                            sys.settrace(trace)
                            expected_error = (
                                recovery_error if expected == "recovery" else body_error
                            )
                            with self.assertRaises(type(expected_error)) as caught:
                                runner._delete_bound_tree(
                                    binding,
                                    restore_owner_write=False,
                                    manifest_path=root / "cleanup.manifest",
                                )
                    self.assertTrue(fired)
                    self.assertIs(caught.exception, expected_error)
                finally:
                    sys.settrace(previous_trace)
                    parent_result_owner.close()

    def test_bound_cleanup_retries_return_boundary_before_settlement(self) -> None:
        target_code = (
            runner._CleanupBodyErrorSettlement.settle_current_exception.__code__
        )
        instructions = tuple(dis.get_instructions(target_code))
        return_offset = next(
            instruction.offset
            for instruction in instructions
            if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
        )
        with owned_temporary_directory("cleanup-break-boundary-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            body_error = RuntimeError("synthetic cleanup body failure")
            break_intruder = OSError("synthetic cleanup break intruder")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == return_offset
                    ):
                        fired = True
                        raise break_intruder
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_error,
                    ),
                    mock.patch.object(runner, "_snapshot_bound_cleanup_recovery"),
                ):
                    sys.settrace(trace)
                    with self.assertRaises(RuntimeError) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                manifest.close.assert_called_once_with()
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def _assert_bound_delivery_caller_jump_preserves_primary(
        self,
        *,
        empty_control: bool,
        hook_count: int,
    ) -> None:
        driver = runner._drive_bound_cleanup_delivery
        instructions = tuple(dis.get_instructions(driver))
        step_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "step"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        caller_jump = next(
            instruction.offset
            for instruction in instructions[step_call_index + 1 :]
            if instruction.opname.startswith("JUMP_BACKWARD")
        )
        self.assertFalse(
            any(
                entry.start <= caller_jump < entry.end
                for entry in dis.Bytecode(driver).exception_entries
            ),
            "the regression must target the successful caller jump outside the try",
        )

        prefix = "cleanup-control" if empty_control else "cleanup-tree"
        with owned_temporary_directory(f"{prefix}-caller-jump-{hook_count}-") as root:
            target = root / prefix
            self._make_private_directory(target)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                target,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt(
                f"synthetic {prefix} caller-jump body primary"
            )
            hook_errors = tuple(
                OSError(f"synthetic {prefix} caller-jump hook {index}")
                for index in range(hook_count)
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            real_settle = runner._CleanupBodyErrorSettlement.settle_current_exception
            real_parent_close = support._DirectoryParentBindingResultOwner.close
            fired = 0

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is driver.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        fired < hook_count
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == caller_jump
                    ):
                        interruption = hook_errors[fired]
                        fired += 1
                        raise interruption
                return trace

            def settle_and_rearm(
                settlement: runner._CleanupBodyErrorSettlement,
            ) -> None:
                real_settle(settlement)
                if fired < hook_count:
                    sys.settrace(trace)
                    caller = sys._getframe().f_back
                    while caller is not None:
                        if caller.f_code in {
                            runner._BoundCleanupDeliveryOwner.step.__code__,
                            driver.__code__,
                        }:
                            caller.f_trace = trace
                            caller.f_trace_opcodes = True
                        caller = caller.f_back

            def close_parent(
                owner: support._DirectoryParentBindingResultOwner,
            ) -> None:
                real_parent_close(owner)

            previous_trace = sys.gettrace()
            try:
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch.object(
                            runner._CleanupBodyErrorSettlement,
                            "settle_current_exception",
                            autospec=True,
                            side_effect=settle_and_rearm,
                        )
                    )
                    close_mock = stack.enter_context(
                        mock.patch.object(
                            support._DirectoryParentBindingResultOwner,
                            "close",
                            autospec=True,
                            side_effect=close_parent,
                        )
                    )
                    if empty_control:
                        stack.enter_context(
                            mock.patch.object(
                                runner,
                                "quarantine_and_remove_empty_root",
                                side_effect=body_error,
                            )
                        )
                    else:
                        stack.enter_context(
                            mock.patch.object(
                                runner,
                                "build_custodied_manifest",
                                return_value=manifest,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                runner,
                                "delete_custodied_roots",
                                side_effect=body_error,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                runner,
                                "_snapshot_bound_cleanup_recovery",
                            )
                        )
                        remove_manifest = stack.enter_context(
                            mock.patch.object(
                                runner,
                                "remove_published_manifest",
                            )
                        )

                    sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        if empty_control:
                            runner._cleanup_empty_bound_control(binding)
                        else:
                            runner._delete_bound_tree(
                                binding,
                                restore_owner_write=False,
                                manifest_path=root / "cleanup.manifest",
                            )

                    self.assertEqual(fired, hook_count)
                    self.assertIs(caught.exception, body_error)
                    for hook_error in hook_errors:
                        self.assertTrue(
                            any(
                                str(hook_error) in note
                                for note in getattr(body_error, "__notes__", ())
                            )
                        )
                    close_mock.assert_called_once()
                    if not empty_control:
                        manifest.close.assert_called_once_with()
                        remove_manifest.assert_not_called()
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_delivery_caller_jump_single_hook_preserves_primary(self) -> None:
        self._assert_bound_delivery_caller_jump_preserves_primary(
            empty_control=False,
            hook_count=1,
        )

    def test_bound_delivery_caller_jump_double_hook_preserves_primary(self) -> None:
        self._assert_bound_delivery_caller_jump_preserves_primary(
            empty_control=False,
            hook_count=2,
        )

    def test_empty_delivery_caller_jump_single_hook_preserves_primary(self) -> None:
        self._assert_bound_delivery_caller_jump_preserves_primary(
            empty_control=True,
            hook_count=1,
        )

    def test_empty_delivery_caller_jump_double_hook_preserves_primary(self) -> None:
        self._assert_bound_delivery_caller_jump_preserves_primary(
            empty_control=True,
            hook_count=2,
        )

    def test_bound_delivery_loop_head_store_cannot_skip_settlement(self) -> None:
        target_code = runner._BoundCleanupDeliveryOwner.step.__code__
        store_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(
                runner._BoundCleanupDeliveryOwner.step
            )
            if instruction.opname == "STORE_FAST"
            and instruction.argval == "authoritative"
        )
        with owned_temporary_directory("cleanup-delivery-loop-head-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt("synthetic loop-head body primary")
            hook_error = RuntimeError("synthetic delivery loop-head STORE")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == store_offset
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_error,
                    ),
                    mock.patch.object(runner, "_snapshot_bound_cleanup_recovery"),
                    mock.patch.object(runner, "remove_published_manifest") as remove,
                ):
                    sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                manifest.close.assert_called_once_with()
                remove.assert_not_called()
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_delivery_armed_raise_is_outer_caller_owned(self) -> None:
        driver = runner._drive_bound_cleanup_delivery
        raise_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(driver)
            if instruction.opname == "RAISE_VARARGS" and instruction.arg == 0
        )
        with owned_temporary_directory("cleanup-delivery-armed-raise-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt("synthetic armed-raise body primary")
            hook_error = RuntimeError("synthetic armed bare-raise hook")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is driver.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == raise_offset
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_error,
                    ),
                    mock.patch.object(runner, "_snapshot_bound_cleanup_recovery"),
                ):
                    sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertTrue(
                    any(
                        str(hook_error) in note
                        for note in getattr(body_error, "__notes__", ())
                    )
                )
                manifest.close.assert_called_once_with()
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_delivery_success_return_preserves_removal_proof(self) -> None:
        driver = runner._drive_bound_cleanup_delivery
        return_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(driver)
            if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
        )
        with owned_temporary_directory("cleanup-delivery-success-return-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            hook_error = RuntimeError("synthetic successful driver RETURN hook")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is driver.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == return_offset
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(runner, "delete_custodied_roots"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                ):
                    sys.settrace(trace)
                    with self.assertRaises(RuntimeError) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, hook_error)
                manifest.close.assert_called_once_with()
                remove_manifest.assert_called_once_with(manifest.seal)
                evidence = getattr(
                    hook_error,
                    "_readonly_manifest_removal_evidence",
                )
                self.assertEqual(evidence["state"], "complete")
                self.assertTrue(evidence["proof"]["remove_returned"])
                self.assertTrue(evidence["proof"]["parent_fsync_complete"])
                self.assertTrue(evidence["proof"]["exact_name_absent"])
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_real_manifest_result_owner_closes_call_to_store_publication(
        self,
    ) -> None:
        function = runner._delete_bound_tree
        instructions = tuple(dis.get_instructions(function))
        build_call_index = max(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and instructions[index + 1].opname == "STORE_FAST"
            and instructions[index + 1].argval == "manifest"
            and any(
                candidate.argval == "build_custodied_manifest"
                for candidate in instructions[max(0, index - 80) : index]
            )
        )
        result_store = instructions[build_call_index + 1]
        self.assertEqual(result_store.opname, "STORE_FAST")
        self.assertEqual(result_store.argval, "manifest")

        with owned_temporary_directory("cleanup-real-manifest-store-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            (runtime_parent / "payload.txt").write_text(
                "manifest publication\n",
                encoding="utf-8",
            )
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            real_build = runner.build_custodied_manifest
            published_owners: list[recovery_cleanup.CustodiedManifestResultOwner] = []
            hook_error = OSError("synthetic real manifest CALL-to-STORE boundary")
            fired = False

            def build_manifest(**kwargs: object) -> object:
                manifest = real_build(**kwargs)
                result_owner = kwargs["result_owner"]
                assert isinstance(
                    result_owner,
                    recovery_cleanup.CustodiedManifestResultOwner,
                )
                published_owners.append(result_owner)
                return manifest

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is function.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == result_store.offset
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    runner,
                    "build_custodied_manifest",
                    side_effect=build_manifest,
                ):
                    sys.settrace(trace)
                    with self.assertRaises(OSError) as caught:
                        function(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, hook_error)
                self.assertEqual(len(published_owners), 1)
                manifest_owner = published_owners[0]
                self.assertFalse(manifest_owner.transferred)
                manifest = manifest_owner.manifest
                self.assertIsNotNone(manifest)
                assert manifest is not None
                self.assertTrue(manifest._closed)
                self.assertEqual(manifest.root_fds, [])
                recovery = getattr(
                    hook_error,
                    runner._CLEANUP_RECOVERY_EVIDENCE_ATTR,
                )
                self.assertEqual(recovery["manifest"]["state"], "published")
                self.assertFalse(recovery["manifest"]["result_owner_transferred"])
                self.assertEqual(
                    recovery["manifest"]["sha256"],
                    manifest.seal["sha256"],
                )
                root_slot = manifest._root_fd_slots[0]
                self.assertEqual(root_slot.state, "closed")
                with self.assertRaises(OSError) as closed:
                    os.fstat(root_slot.descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def _assert_public_cleanup_handoff_preserves_body_interrupt(
        self,
        *,
        empty_control: bool,
        boundary: str,
    ) -> None:
        wrapper = (
            runner._cleanup_empty_bound_control
            if empty_control
            else runner._cleanup_bound_tree
        )
        consumer = (
            runner._consume_cleanup_empty_bound_control_endpoint
            if empty_control
            else runner._consume_cleanup_bound_tree_endpoint
        )
        reconcile = runner._reconcile_bound_cleanup_delivery
        profile_return = boundary == "reconcile-profile-return"
        if boundary == "wrapper-bare-raise":
            wrapper_instructions = tuple(dis.get_instructions(wrapper))
            target_offset = max(
                instruction.offset
                for instruction in wrapper_instructions
                if instruction.opname == "RAISE_VARARGS" and instruction.arg == 0
            )
            target_function = wrapper
        else:
            self.assertIn(
                boundary,
                {"reconcile-return", "reconcile-profile-return"},
            )
            target_offset = max(
                instruction.offset
                for instruction in dis.get_instructions(reconcile)
                if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
            )
            target_function = reconcile

        prefix = "cleanup-control" if empty_control else "cleanup-tree"
        with owned_temporary_directory(f"{prefix}-public-{boundary}-") as root:
            target = root / prefix
            self._make_private_directory(target)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                target,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt(f"synthetic {prefix} public handoff body")
            hook_error = RuntimeError(f"synthetic {prefix} {boundary} hook")
            delivery_owner = runner._BoundCleanupDeliveryOwner(
                remove_manifest_on_success=not empty_control,
                settlement_note=(
                    "cleanup-control parent settlement"
                    if empty_control
                    else "bound-tree cleanup settlement"
                ),
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def caller() -> None:
                if empty_control:
                    consumer(
                        binding,
                        _delivery_owner=delivery_owner,
                    )
                else:
                    consumer(
                        binding,
                        restore_owner_write=False,
                        manifest_path=root / "cleanup.manifest",
                        _delivery_owner=delivery_owner,
                    )

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_function.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        fired = True
                        raise hook_error
                return trace

            def profile(
                frame: object,
                event: str,
                _argument: object,
            ) -> None:
                nonlocal fired
                if (
                    not fired
                    and getattr(frame, "f_code", None) is target_function.__code__
                    and event == "return"
                ):
                    fired = True
                    raise hook_error

            previous_trace = sys.gettrace()
            previous_profile = sys.getprofile()
            try:
                if empty_control:
                    patches = (
                        mock.patch.object(
                            runner,
                            "quarantine_and_remove_empty_root",
                            side_effect=body_error,
                        ),
                    )
                else:
                    patches = (
                        mock.patch.object(
                            runner,
                            "build_custodied_manifest",
                            return_value=manifest,
                        ),
                        mock.patch.object(
                            runner,
                            "delete_custodied_roots",
                            side_effect=body_error,
                        ),
                        mock.patch.object(
                            runner,
                            "_snapshot_bound_cleanup_recovery",
                        ),
                    )
                with contextlib.ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    if profile_return:
                        sys.setprofile(profile)
                    else:
                        sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        caller()
                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertIs(delivery_owner.authoritative_error, body_error)
                self.assertTrue(
                    any(
                        str(hook_error) in note
                        for note in getattr(body_error, "__notes__", ())
                    )
                )
            finally:
                sys.setprofile(previous_profile)
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def _assert_cleanup_pre_bind_interrupt_reaches_consumer(
        self,
        *,
        empty_control: bool,
    ) -> None:
        target_function = (
            runner._cleanup_empty_bound_control_operation
            if empty_control
            else runner._delete_bound_tree
        )
        target_offset = self._attribute_call_offset(target_function, "bind")
        delivery_owner = runner._BoundCleanupDeliveryOwner(
            remove_manifest_on_success=not empty_control,
            settlement_note=(
                "cleanup-control parent settlement"
                if empty_control
                else "bound-tree cleanup settlement"
            ),
        )
        binding = mock.Mock()
        binding.path = pathlib.Path("/synthetic/pre-bind-cleanup")
        hook_error = KeyboardInterrupt("synthetic cleanup pre-bind interrupt")
        fired = False

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal fired
            if getattr(frame, "f_code", None) is target_function.__code__:
                setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                if (
                    not fired
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    fired = True
                    raise hook_error
            return trace

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaises(KeyboardInterrupt) as caught:
                if empty_control:
                    runner._consume_cleanup_empty_bound_control_endpoint(
                        binding,
                        _delivery_owner=delivery_owner,
                    )
                else:
                    runner._consume_cleanup_bound_tree_endpoint(
                        binding,
                        restore_owner_write=False,
                        manifest_path=pathlib.Path("/synthetic/cleanup.manifest"),
                        _delivery_owner=delivery_owner,
                    )
            self.assertTrue(fired)
            self.assertIs(caught.exception, hook_error)
            self.assertFalse(delivery_owner.bound)
            self.assertIsNone(delivery_owner.body_error_settlement)
            self.assertIsNone(delivery_owner.parent_result_owner)
            self.assertEqual(delivery_owner._pending_errors, ())
        finally:
            sys.settrace(previous_trace)

    def test_bound_cleanup_pre_bind_interrupt_reaches_consumer(self) -> None:
        self._assert_cleanup_pre_bind_interrupt_reaches_consumer(
            empty_control=False,
        )

    def test_empty_cleanup_pre_bind_interrupt_reaches_consumer(self) -> None:
        self._assert_cleanup_pre_bind_interrupt_reaches_consumer(
            empty_control=True,
        )

    def test_unbound_cleanup_reconciliation_preserves_boundary(self) -> None:
        delivery_owner = runner._BoundCleanupDeliveryOwner(
            remove_manifest_on_success=True,
            settlement_note="bound-tree cleanup settlement",
        )
        boundary_error = KeyboardInterrupt("synthetic unbound boundary")

        selected = runner._reconcile_bound_cleanup_delivery(
            delivery_owner,
            boundary_error,
        )

        self.assertIs(selected, boundary_error)
        self.assertEqual(delivery_owner._pending_errors, ())

    def test_bound_public_bare_raise_crosses_caller_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=False,
            boundary="wrapper-bare-raise",
        )

    def test_empty_public_bare_raise_crosses_caller_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=True,
            boundary="wrapper-bare-raise",
        )

    def test_bound_reconcile_return_crosses_public_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=False,
            boundary="reconcile-return",
        )

    def test_empty_reconcile_return_crosses_public_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=True,
            boundary="reconcile-return",
        )

    def test_bound_reconcile_profile_return_crosses_public_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=False,
            boundary="reconcile-profile-return",
        )

    def test_empty_reconcile_profile_return_crosses_public_handoff(self) -> None:
        self._assert_public_cleanup_handoff_preserves_body_interrupt(
            empty_control=True,
            boundary="reconcile-profile-return",
        )

    def test_manifest_remove_call_boundary_is_never_retried(self) -> None:
        remove_owner_method = runner._PublishedManifestRemovalOwner.remove
        instructions = tuple(dis.get_instructions(remove_owner_method))
        remove_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "remove_published_manifest"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        call_successor = instructions[remove_call_index + 1].offset
        with owned_temporary_directory("cleanup-manifest-remove-call-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            hook_error = OSError("synthetic manifest remove CALL boundary")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is remove_owner_method.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == call_successor
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(runner, "delete_custodied_roots"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                ):
                    sys.settrace(trace)
                    with self.assertRaises(OSError) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                self.assertTrue(fired)
                self.assertIs(caught.exception, hook_error)
                remove_manifest.assert_called_once_with(manifest.seal)
                evidence = getattr(
                    hook_error,
                    "_readonly_manifest_removal_evidence",
                )
                self.assertEqual(evidence["state"], "remove-outcome-unproven")
                self.assertIsNone(evidence["proof"])
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_cleanup_failure_reports_unproven_manifest_removal(self) -> None:
        remove_owner_method = runner._PublishedManifestRemovalOwner.remove
        instructions = tuple(dis.get_instructions(remove_owner_method))
        remove_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "remove_published_manifest"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        call_successor = instructions[remove_call_index + 1].offset
        with owned_temporary_directory("cleanup-failure-remove-unproven-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            hook_error = OSError("synthetic returned removal uncertainty")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            fired = False

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is remove_owner_method.__code__:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == call_successor
                    ):
                        fired = True
                        raise hook_error
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(runner, "delete_custodied_roots"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                ):
                    sys.settrace(trace)
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=root / "cleanup.manifest",
                    )
                self.assertTrue(fired)
                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.error_kind, "OSError")
                self.assertIsNotNone(failure.recovery_evidence)
                assert failure.recovery_evidence is not None
                removal = failure.recovery_evidence["manifest_removal"]
                self.assertEqual(removal["state"], "remove-outcome-unproven")
                self.assertIsNone(removal["proof"])
                remove_manifest.assert_called_once_with(manifest.seal)
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_public_success_return_reports_complete_manifest_removal(
        self,
    ) -> None:
        wrapper = runner._cleanup_bound_tree
        with owned_temporary_directory("cleanup-public-return-evidence-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            hook_error = RuntimeError("synthetic public success RETURN hook")
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            delivery_owner = runner._BoundCleanupDeliveryOwner(
                remove_manifest_on_success=True,
                settlement_note="bound-tree cleanup settlement",
            )
            fired = False

            def profile(
                frame: object,
                event: str,
                _argument: object,
            ) -> None:
                nonlocal fired
                if (
                    not fired
                    and getattr(frame, "f_code", None) is wrapper.__code__
                    and event == "return"
                ):
                    fired = True
                    raise hook_error

            def caller() -> runner.CleanupFailure:
                failure = runner._consume_cleanup_bound_tree_endpoint(
                    binding,
                    restore_owner_write=False,
                    manifest_path=root / "cleanup.manifest",
                    _delivery_owner=delivery_owner,
                )
                if failure is None:
                    raise AssertionError("public RETURN hook did not fire")
                return failure

            previous_profile = sys.getprofile()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(runner, "delete_custodied_roots"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                ):
                    sys.setprofile(profile)
                    failure = caller()
                self.assertTrue(fired)
                self.assertEqual(failure.error_kind, "RuntimeError")
                self.assertIsNotNone(failure.recovery_evidence)
                assert failure.recovery_evidence is not None
                removal = failure.recovery_evidence["manifest_removal"]
                self.assertEqual(removal["state"], "complete")
                self.assertTrue(removal["proof"]["remove_returned"])
                self.assertTrue(removal["proof"]["parent_fsync_complete"])
                manifest_owner = delivery_owner.manifest_result_owner
                self.assertIsNotNone(manifest_owner)
                assert manifest_owner is not None
                self.assertIs(manifest_owner.manifest, manifest)
                self.assertTrue(manifest_owner.transferred)
                manifest.close.assert_called_once_with()
                remove_manifest.assert_called_once_with(manifest.seal)
            finally:
                sys.setprofile(previous_profile)
                parent_result_owner.close()

    def test_cleanup_body_settlement_context_scan_is_bounded(self) -> None:
        limit = runner._CLEANUP_BODY_CONTEXT_SCAN_LIMIT
        within_limit = [RuntimeError(f"within-limit-{index}") for index in range(limit)]
        for current, context in zip(within_limit, within_limit[1:]):
            current.__context__ = context
        accepted = runner._CleanupBodyErrorSettlement(None, None)
        with mock.patch.object(
            runner.sys,
            "exception",
            return_value=within_limit[0],
        ):
            accepted.recover_current_exception()
        self.assertIs(accepted.active_error, within_limit[-1])
        self.assertIs(accepted.publication_error, within_limit[0])

        beyond_limit = [
            RuntimeError(f"beyond-limit-{index}") for index in range(limit + 1)
        ]
        for current, context in zip(beyond_limit, beyond_limit[1:]):
            current.__context__ = context
        rejected = runner._CleanupBodyErrorSettlement(None, None)
        with mock.patch.object(
            runner.sys,
            "exception",
            return_value=beyond_limit[0],
        ):
            rejected.recover_current_exception()
        self.assertIsNone(rejected.active_error)
        self.assertIs(rejected.publication_error, beyond_limit[0])
        self.assertEqual(len(rejected.publication_observations), 1)

        first_cycle_error = RuntimeError("synthetic context cycle first")
        second_cycle_error = RuntimeError("synthetic context cycle second")
        first_cycle_error.__context__ = second_cycle_error
        second_cycle_error.__context__ = first_cycle_error
        cyclic = runner._CleanupBodyErrorSettlement(None, None)
        with mock.patch.object(
            runner.sys,
            "exception",
            return_value=first_cycle_error,
        ):
            cyclic.recover_current_exception()
        self.assertIsNone(cyclic.active_error)
        self.assertIs(cyclic.publication_error, first_cycle_error)
        self.assertEqual(len(cyclic.publication_observations), 1)

    def test_cleanup_publication_dedupe_is_all_or_nothing(self) -> None:
        capture = runner._CleanupBodyErrorSettlement._capture_publication_error
        instructions = tuple(dis.get_instructions(capture))
        id_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "id"
                for candidate in instructions[max(0, index - 8) : index]
            )
        )
        id_result_store = instructions[id_call_index + 1]
        self.assertEqual(id_result_store.opname, "STORE_FAST")
        self.assertEqual(id_result_store.argval, "error_id")

        for hook_kind in ("trace", "profile-c-return"):
            with self.subTest(hook=hook_kind):
                body_error = KeyboardInterrupt(
                    f"synthetic {hook_kind} dedupe body primary"
                )
                candidate = OSError(f"synthetic {hook_kind} publication candidate")
                hook_error = RuntimeError(
                    f"synthetic {hook_kind} pre-publication boundary"
                )
                settlement = runner._CleanupBodyErrorSettlement(None, None)
                settlement.active_error = body_error
                fired = False

                def trace(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is capture.__code__:
                        setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None)
                            == id_result_store.offset
                        ):
                            fired = True
                            raise hook_error
                    return trace

                def profile(
                    frame: object,
                    event: str,
                    argument: object,
                ) -> None:
                    nonlocal fired
                    if (
                        not fired
                        and getattr(frame, "f_code", None) is capture.__code__
                        and event == "c_return"
                        and argument is id
                    ):
                        fired = True
                        raise hook_error

                previous_trace = sys.gettrace()
                previous_profile = sys.getprofile()
                try:
                    if hook_kind == "trace":
                        sys.settrace(trace)
                    else:
                        sys.setprofile(profile)
                    with self.assertRaises(RuntimeError) as caught:
                        capture(
                            settlement,
                            candidate,
                            "synthetic publication candidate",
                        )
                finally:
                    sys.setprofile(previous_profile)
                    sys.settrace(previous_trace)

                self.assertTrue(fired)
                self.assertIs(caught.exception, hook_error)
                self.assertNotIn(
                    id(candidate),
                    settlement.publication_observation_ids,
                )
                self.assertEqual(settlement.publication_observations, [])
                self.assertIsNone(settlement.publication_error)

                capture(
                    settlement,
                    candidate,
                    "synthetic publication candidate",
                )
                self.assertIn(
                    id(candidate),
                    settlement.publication_observation_ids,
                )
                self.assertEqual(
                    settlement.publication_observations,
                    [("synthetic publication candidate", candidate)],
                )
                self.assertIs(settlement.publication_error, candidate)
                delivery_owner = runner._BoundCleanupDeliveryOwner(
                    remove_manifest_on_success=False,
                    settlement_note="synthetic settlement",
                )
                delivery_owner.bind(
                    body_error_settlement=settlement,
                    parent_result_owner=(support._DirectoryParentBindingResultOwner()),
                )
                self.assertIs(delivery_owner.authoritative_error, body_error)

    def _assert_bound_cleanup_store_interrupt_preserves_body_error(
        self,
        store_index: int,
    ) -> None:
        store_offsets = self._local_active_error_store_offsets(
            runner._delete_bound_tree
        )
        target_offset = store_offsets[store_index]
        target_code = runner._delete_bound_tree.__code__
        with owned_temporary_directory("cleanup-store-publication-") as root:
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt("synthetic cleanup body interruption")
            publication_intruder = RuntimeError(
                "synthetic cleanup body publication intruder"
            )
            close_interruption = SystemExit(
                "synthetic cleanup parent close interruption"
            )
            manifest = mock.Mock()
            manifest.seal = {"sha256": "synthetic"}
            real_close = support._DirectoryParentBindingResultOwner.close
            fired = False

            def close_then_interrupt(
                owner: support._DirectoryParentBindingResultOwner,
            ) -> None:
                real_close(owner)
                raise close_interruption

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        fired = True
                        raise publication_intruder
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "build_custodied_manifest",
                        return_value=manifest,
                    ),
                    mock.patch.object(
                        runner,
                        "delete_custodied_roots",
                        side_effect=body_error,
                    ),
                    mock.patch.object(runner, "_snapshot_bound_cleanup_recovery"),
                    mock.patch.object(
                        runner,
                        "remove_published_manifest",
                    ) as remove_manifest,
                    mock.patch.object(
                        support._DirectoryParentBindingResultOwner,
                        "close",
                        autospec=True,
                        side_effect=close_then_interrupt,
                    ),
                ):
                    sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        runner._delete_bound_tree(
                            binding,
                            restore_owner_write=False,
                            manifest_path=root / "cleanup.manifest",
                        )
                    sys.settrace(previous_trace)

                    self.assertTrue(fired)
                    self.assertIs(caught.exception, body_error)
                    self.assertTrue(
                        any("body publication" in note for note in body_error.__notes__)
                    )
                    self.assertTrue(
                        any(
                            "parent close interruption" in note
                            for note in body_error.__notes__
                        )
                    )
                    remove_manifest.assert_not_called()
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def _assert_empty_bound_cleanup_store_interrupt_preserves_body_error(
        self,
        store_index: int,
    ) -> None:
        store_offsets = self._local_active_error_store_offsets(
            runner._cleanup_empty_bound_control_operation
        )
        target_offset = store_offsets[store_index]
        target_code = runner._cleanup_empty_bound_control_operation.__code__
        with owned_temporary_directory("cleanup-control-store-publication-") as root:
            cleanup_control = root / "cleanup-control"
            self._make_private_directory(cleanup_control)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                cleanup_control,
                require_owned_private_parent=True,
            )
            body_error = KeyboardInterrupt(
                "synthetic cleanup-control body interruption"
            )
            publication_intruder = RuntimeError(
                "synthetic cleanup-control body publication intruder"
            )
            close_interruption = SystemExit(
                "synthetic cleanup-control parent close interruption"
            )
            real_close = support._DirectoryParentBindingResultOwner.close
            fired = False

            def close_then_interrupt(
                owner: support._DirectoryParentBindingResultOwner,
            ) -> None:
                real_close(owner)
                raise close_interruption

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal fired
                if getattr(frame, "f_code", None) is target_code:
                    setattr(frame, "f_trace_opcodes", True)  # noqa: B010
                    if (
                        not fired
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        fired = True
                        raise publication_intruder
                return trace

            previous_trace = sys.gettrace()
            try:
                with (
                    mock.patch.object(
                        runner,
                        "quarantine_and_remove_empty_root",
                        side_effect=body_error,
                    ),
                    mock.patch.object(
                        support._DirectoryParentBindingResultOwner,
                        "close",
                        autospec=True,
                        side_effect=close_then_interrupt,
                    ),
                ):
                    sys.settrace(trace)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        runner._cleanup_empty_bound_control(binding)
                    sys.settrace(previous_trace)

                    self.assertTrue(fired)
                    self.assertIs(caught.exception, body_error)
                    self.assertTrue(
                        any("body publication" in note for note in body_error.__notes__)
                    )
                    self.assertTrue(
                        any(
                            "parent close interruption" in note
                            for note in body_error.__notes__
                        )
                    )
            finally:
                sys.settrace(previous_trace)
                parent_result_owner.close()

    def test_bound_cleanup_handler_error_store_preserves_body_error(self) -> None:
        self._assert_bound_cleanup_store_interrupt_preserves_body_error(0)

    def test_bound_cleanup_local_active_store_preserves_body_error(self) -> None:
        self._assert_bound_cleanup_store_interrupt_preserves_body_error(1)

    def test_empty_bound_cleanup_handler_error_store_preserves_body_error(
        self,
    ) -> None:
        self._assert_empty_bound_cleanup_store_interrupt_preserves_body_error(0)

    def test_empty_bound_cleanup_local_active_store_preserves_body_error(
        self,
    ) -> None:
        self._assert_empty_bound_cleanup_store_interrupt_preserves_body_error(1)

    def test_bound_cleanup_capture_call_interrupt_preserves_body_error(
        self,
    ) -> None:
        visit_code = next(
            constant
            for constant in runner._restore_owner_write_below_bound_root.__code__.co_consts
            if getattr(constant, "co_name", None) == "visit"
        )
        process_child_code = next(
            constant
            for constant in visit_code.co_consts
            if getattr(constant, "co_name", None) == "process_child"
        )
        instructions = tuple(dis.get_instructions(process_child_code))
        capture_call_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname.startswith("CALL")
            and any(
                candidate.argval == "bound cleanup child traversal"
                for candidate in instructions[max(0, index - 16) : index]
            )
        )
        capture_call = instructions[capture_call_index].offset
        capture_preludes = tuple(
            instruction.offset
            for instruction in instructions[
                max(0, capture_call_index - 30) : capture_call_index
            ]
            if instruction.opname == "NOP"
        )
        self.assertGreaterEqual(len(capture_preludes), 2)
        scenarios = (
            ("loop-header", capture_preludes[-2]),
            ("try-header", capture_preludes[-1]),
            ("capture-call", capture_call),
        )
        for label, injection_offset in scenarios:
            with (
                self.subTest(boundary=label),
                owned_temporary_directory(f"cleanup-capture-{label}-") as root,
            ):
                child = root / "child"
                self._make_private_directory(child)
                root_fd = os.open(
                    root,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                body_error = ValueError("synthetic child traversal body failure")
                capture_intruder = RuntimeError(
                    f"synthetic child traversal {label} interruption"
                )
                ambient_error = KeyboardInterrupt(
                    f"synthetic handled child traversal {label} caller error"
                )
                fired = False

                def trace(frame: object, event: str, _argument: object) -> object:
                    nonlocal fired
                    if getattr(frame, "f_code", None) is process_child_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not fired
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == injection_offset
                        ):
                            fired = True
                            raise capture_intruder
                    return trace

                previous_trace = sys.gettrace()
                try:
                    with mock.patch.object(
                        runner.os,
                        "fchmod",
                        side_effect=body_error,
                    ):
                        try:
                            raise ambient_error
                        except KeyboardInterrupt:
                            sys.settrace(trace)
                            with self.assertRaises(ValueError) as caught:
                                runner._restore_owner_write_below_bound_root(root_fd)
                finally:
                    sys.settrace(previous_trace)
                    os.close(root_fd)

                self.assertTrue(fired)
                self.assertIs(caught.exception, body_error)
                self.assertEqual(getattr(ambient_error, "__notes__", []), [])
                self.assertTrue(
                    any(
                        "child traversal caller boundary" in note
                        for note in body_error.__notes__
                    )
                )

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_runtime_cleanup_does_not_claim_unlinked_path_retained(self) -> None:
        with owned_temporary_directory("runtime-cleanup-unlinked-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.rmdir()

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(runtime_parent))
                self.assertFalse(failure.retained)
                self.assertEqual(failure.original_path, str(runtime_parent))
                self.assertEqual(failure.path_status, "bound-unresolved")
                self.assertIsNone(failure.replacement_path)
            finally:
                parent_result_owner.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_bound_cleanup_reports_access_policy_drift_separately(self) -> None:
        with owned_temporary_directory("runtime-cleanup-policy-") as root:
            runtime_parent = root / "runtime"
            runtime_parent.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                runtime_parent.chmod(0o500)

                failure = runner._cleanup_bound_tree(
                    binding,
                    restore_owner_write=False,
                )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(runtime_parent))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-original")
                self.assertEqual(failure.original_path_status, "same")
                self.assertEqual(failure.access_policy_status, "changed")
                self.assertIsNone(failure.replacement_path)
                self.assertEqual(failure.held_identity, binding.object_locator())
            finally:
                runtime_parent.chmod(0o700)
                parent_result_owner.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_descriptor_cleanup_retains_original_and_replacement_after_swap(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-swap-") as root:
            target = root / "target"
            target.mkdir(mode=0o700)
            payload = target / "payload"
            payload.write_text("original", encoding="utf-8")
            moved = root / "moved-target"
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                target,
                require_owned_private_parent=True,
            )
            real_delete = runner.delete_custodied_roots

            def swap_before_delete(*args: object, **kwargs: object) -> object:
                target.rename(moved)
                target.mkdir(mode=0o700)
                (target / "sentinel").write_text("replacement", encoding="utf-8")
                return real_delete(*args, **kwargs)

            try:
                with mock.patch.object(
                    runner,
                    "delete_custodied_roots",
                    side_effect=swap_before_delete,
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=control / "manifest.bin",
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertEqual(failure.path, str(moved))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertEqual(failure.original_path_status, "replaced")
                self.assertEqual(failure.replacement_path, str(target))
                self.assertEqual(
                    (moved / payload.name).read_text(encoding="utf-8"),
                    "original",
                )
                self.assertEqual(
                    (target / "sentinel").read_text(encoding="utf-8"),
                    "replacement",
                )
            finally:
                parent_result_owner.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin F_GETPATH")
    def test_descriptor_cleanup_reports_replacement_quarantined_during_rename(
        self,
    ) -> None:
        with owned_temporary_directory("runtime-cleanup-rename-race-") as root:
            target = root / "target"
            target.mkdir(mode=0o700)
            (target / "payload").write_text("original", encoding="utf-8")
            moved = root / "moved-target"
            control = root / "control"
            control.mkdir(mode=0o700)
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                target,
                require_owned_private_parent=True,
            )
            real_rename = os.rename
            swapped = False

            def swap_at_quarantine_rename(
                source: object,
                destination: object,
                *,
                src_dir_fd: int | None = None,
                dst_dir_fd: int | None = None,
            ) -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    real_rename(target, moved)
                    target.mkdir(mode=0o700)
                    (target / "sentinel").write_text(
                        "replacement",
                        encoding="utf-8",
                    )
                real_rename(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            try:
                with mock.patch.object(
                    recovery_cleanup.os,
                    "rename",
                    side_effect=swap_at_quarantine_rename,
                ):
                    failure = runner._cleanup_bound_tree(
                        binding,
                        restore_owner_write=False,
                        manifest_path=control / "manifest.bin",
                    )

                self.assertIsNotNone(failure)
                assert failure is not None
                self.assertTrue(swapped)
                self.assertEqual(failure.path, str(moved))
                self.assertTrue(failure.retained)
                self.assertEqual(failure.path_status, "bound-moved")
                self.assertIsNotNone(failure.recovery_evidence)
                assert failure.recovery_evidence is not None
                recovery = failure.recovery_evidence
                self.assertEqual(
                    recovery["protected_property"],
                    "recovery-object-identity-and-deletion-result-ownership",
                )
                self.assertEqual(
                    recovery["deletion_result"]["published_root_count"],
                    0,
                )
                self.assertEqual(len(recovery["quarantined_roots"]), 1)
                quarantined = recovery["quarantined_roots"][0]
                self.assertEqual(
                    quarantined["stage"],
                    "post-rename-quarantine-revalidation",
                )
                self.assertEqual(
                    quarantined["quarantine_status"],
                    "different-object",
                )
                self.assertEqual(quarantined["deletion_state"], "not-published")
                self.assertTrue(quarantined["retained"])
                self.assertNotEqual(
                    quarantined["held_root_identity"],
                    quarantined["observed_quarantine_locator"],
                )
                quarantine_path = pathlib.Path(quarantined["quarantine_path"])
                self.assertTrue(quarantine_path.is_dir())
                self.assertEqual(
                    (quarantine_path / "sentinel").read_text(encoding="utf-8"),
                    "replacement",
                )
                self.assertEqual(
                    (moved / "payload").read_text(encoding="utf-8"),
                    "original",
                )
            finally:
                parent_result_owner.close()

    def test_snapshot_binds_acl_and_xattr_evidence(self) -> None:
        with owned_temporary_directory("readonly-snapshot-policy-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            acl_entries: dict[pathlib.Path, tuple[bytes, ...]] = {}
            xattrs: dict[pathlib.Path, tuple[tuple[str, str], ...]] = {}

            with (
                mock.patch.object(
                    runner,
                    "_acl_entries",
                    side_effect=lambda path: acl_entries.get(path, ()),
                ),
                mock.patch.object(
                    runner,
                    "_xattr_snapshot",
                    side_effect=lambda path: xattrs.get(path, ()),
                ),
            ):
                baseline = runner._tree_snapshot(root)
                acl_entries[target] = (b" 0: user:synthetic allow write",)
                acl_changed = runner._tree_snapshot(root)
                acl_entries.clear()
                xattrs[target] = ((b"com.apple.synthetic", "digest"),)
                xattr_changed = runner._tree_snapshot(root)

            self.assertNotEqual(baseline[target.name], acl_changed[target.name])
            self.assertNotEqual(baseline[target.name], xattr_changed[target.name])

    def test_snapshot_binds_same_content_object_replacement(self) -> None:
        with owned_temporary_directory("readonly-snapshot-identity-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            target.chmod(0o444)
            before = runner._tree_snapshot(root)

            replacement = root / "replacement"
            replacement.write_text("content", encoding="utf-8")
            replacement.chmod(0o444)
            os.replace(replacement, target)
            after = runner._tree_snapshot(root)

            self.assertEqual(before[target.name].digest, after[target.name].digest)
            self.assertEqual(before[target.name].mode, after[target.name].mode)
            self.assertNotEqual(before[target.name].inode, after[target.name].inode)
            self.assertNotEqual(before[target.name], after[target.name])
            self.assertFalse(runner._tree_property_unchanged(before, after))

    def test_snapshot_rejects_regular_file_external_hardlink_alias(self) -> None:
        with (
            owned_temporary_directory("readonly-snapshot-hardlink-tree-") as root,
            owned_temporary_directory("readonly-snapshot-hardlink-alias-") as outside,
        ):
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            alias = outside / "alias"
            os.link(target, alias)
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "external hardlink alias",
                ):
                    runner._tree_snapshot(root)
            finally:
                alias.unlink()

    def test_property_comparison_ignores_benign_metadata_churn(self) -> None:
        with owned_temporary_directory("readonly-snapshot-metadata-") as root:
            target = root / "target"
            target.write_text("content", encoding="utf-8")
            with (
                mock.patch.object(runner, "_acl_entries", return_value=()),
                mock.patch.object(runner, "_xattr_snapshot", return_value=()),
            ):
                before = runner._tree_snapshot(root)
                prior_mtime_ns = target.stat().st_mtime_ns
                os.utime(
                    target,
                    ns=(prior_mtime_ns + 1_000_000_000,) * 2,
                )
                churn = root / "benign-child-churn"
                churn.write_text("temporary", encoding="utf-8")
                churn.unlink()
                after = runner._tree_snapshot(root)

            self.assertNotEqual(prior_mtime_ns, target.stat().st_mtime_ns)
            self.assertIsNone(before["."].link_count)
            self.assertEqual(before[target.name].link_count, 1)
            self.assertTrue(runner._tree_property_unchanged(before, after))

    def test_cleanup_restores_write_and_removes_tree(self) -> None:
        with owned_temporary_directory("readonly-cleanup-success-") as parent:
            root = parent / "tree"
            root.mkdir()
            nested = root / "nested"
            nested.mkdir()
            target = nested / "target"
            target.write_text("content", encoding="utf-8")
            runner._set_tree_read_only(root)
            self.assertFalse(
                stat.S_IMODE(target.stat().st_mode) & stat.S_IWUSR,
            )

            failure = runner._cleanup_tree(root, restore_owner_write=True)

            self.assertIsNone(failure)
            self.assertFalse(os.path.lexists(root))

    def test_cleanup_failure_retains_exact_machine_visible_path(self) -> None:
        with owned_temporary_directory("readonly-cleanup-failure-") as root:
            with mock.patch.object(
                runner.shutil,
                "rmtree",
                side_effect=PermissionError(
                    errno.EACCES,
                    "synthetic cleanup denial",
                    str(root),
                ),
            ):
                failure = runner._cleanup_tree(
                    root,
                    restore_owner_write=False,
                )

            self.assertIsNotNone(failure)
            assert failure is not None
            self.assertEqual(failure.path, str(root))
            self.assertEqual(failure.error_kind, "PermissionError")
            self.assertEqual(failure.error_errno, errno.EACCES)
            self.assertTrue(failure.retained)
            self.assertTrue(os.path.lexists(root))

    def test_bounded_child_settles_same_group_descendant_after_leader_exit(
        self,
    ) -> None:
        child_script = (
            "import os,pathlib,subprocess,sys\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
        )
        with owned_temporary_directory("readonly-child-descendant-") as root:
            group_file = root / "process-group"
            result = runner._run_bounded_child(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    child_script,
                    str(group_file),
                ),
                cwd=root,
                environment={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                timeout=5,
                stdout_limit=1024,
                stderr_limit=1024,
            )

            process_group = int(group_file.read_text(encoding="ascii"))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            self._require_process_group_absent(process_group)

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin process census")
    def test_bounded_child_rejects_setsid_double_fork_escape(self) -> None:
        child_script = (
            "import os,pathlib,signal,sys,time\n"
            "from review_supervisor.process import process_start_identity\n"
            "marker=pathlib.Path(sys.argv[1])\n"
            "stop=pathlib.Path(sys.argv[2])\n"
            "custody=pathlib.Path(sys.argv[3])\n"
            "marker_delay=float(sys.argv[4])\n"
            "first=os.fork()\n"
            "if first==0:\n"
            " os.setsid()\n"
            " second=os.fork()\n"
            " if second==0:\n"
            "  os.closerange(0,3)\n"
            "  signal.signal(signal.SIGHUP,signal.SIG_IGN)\n"
            "  deadline=time.monotonic()+300\n"
            "  while not stop.is_file() and time.monotonic()<deadline: time.sleep(0.01)\n"
            "  os._exit(0)\n"
            " try:\n"
            "  identity=process_start_identity(second)\n"
            "  custody_temporary=custody.with_name(custody.name+'.tmp')\n"
            "  custody_temporary.write_text(f'{second}\\n{identity}\\n',encoding='ascii')\n"
            "  os.replace(custody_temporary,custody)\n"
            "  time.sleep(marker_delay)\n"
            "  temporary=marker.with_name(marker.name+'.tmp')\n"
            "  temporary.write_text(f'{second}\\n{identity}\\n',encoding='ascii')\n"
            "  os.replace(temporary,marker)\n"
            " except BaseException:\n"
            "  try: os.kill(second,signal.SIGKILL)\n"
            "  except ProcessLookupError: pass\n"
            "  try: os.waitpid(second,0)\n"
            "  except ChildProcessError: pass\n"
            "  os._exit(1)\n"
            " os._exit(0)\n"
            "_,status=os.waitpid(first,0)\n"
            "if os.WIFEXITED(status): os._exit(os.WEXITSTATUS(status))\n"
            "if os.WIFSIGNALED(status): os._exit(128+os.WTERMSIG(status))\n"
            "os._exit(1)\n"
        )
        with owned_temporary_directory("readonly-child-session-escape-") as root:
            marker = root / "escaped-process"
            stop_marker = root / "stop-escaped-process"
            custody_receipt = root / "escaped-process-custody"
            marker_delay_seconds = 0.2
            escaped_identity: runner.DarwinProcessIdentity | None = None

            def parse_identity(
                pid: int,
                raw_identity: str,
            ) -> runner.DarwinProcessIdentity:
                prefix = "darwin-proc-start:"
                if not raw_identity.startswith(prefix):
                    raise AssertionError("fixture process identity is not Darwin")
                identity_fields = raw_identity.removeprefix(prefix).split(":")
                if len(identity_fields) != 2 or not all(
                    field.isdecimal() for field in identity_fields
                ):
                    raise AssertionError("fixture process identity is malformed")
                seconds, microseconds = map(int, identity_fields)
                if seconds <= 0 or not 0 <= microseconds < 1_000_000:
                    raise AssertionError("fixture process identity is out of range")
                return runner.DarwinProcessIdentity(
                    pid,
                    seconds,
                    microseconds,
                )

            def bind_identity(pid: int) -> runner.DarwinProcessIdentity:
                return parse_identity(pid, process_start_identity(pid))

            def read_identity_receipt(
                receipt: pathlib.Path,
            ) -> runner.DarwinProcessIdentity:
                with receipt.open("rb") as receipt_stream:
                    raw_marker = receipt_stream.read(257)
                if not 1 <= len(raw_marker) <= 256:
                    raise ValueError("fixture process marker has an invalid size")
                fields = raw_marker.decode("ascii", "strict").splitlines()
                if len(fields) != 2 or not fields[0].isdecimal():
                    raise ValueError("fixture process marker is malformed")
                pid = int(fields[0])
                if pid <= 0:
                    raise ValueError("fixture process marker has an invalid PID")
                return parse_identity(pid, fields[1])

            def read_marker_identity() -> runner.DarwinProcessIdentity:
                return read_identity_receipt(marker)

            def read_custody_identity() -> runner.DarwinProcessIdentity:
                return read_identity_receipt(custody_receipt)

            supervisor_identity = bind_identity(os.getpid())

            def fixture_census(
                *,
                deadline: float | None = None,
            ) -> tuple[runner.DarwinProcessIdentity, ...]:
                nonlocal escaped_identity
                # The production caller owns the absolute census deadline.
                # This fixture stays scoped to returning its real bound process
                # identity so crossing the deadline inside the test double cannot
                # replace already observed escape evidence with a synthetic timeout.
                del deadline
                observed = [supervisor_identity]
                try:
                    marked_identity = read_marker_identity()
                except FileNotFoundError:
                    return tuple(observed)
                try:
                    rebound_identity = bind_identity(marked_identity.pid)
                except ProcessLookupError:
                    return tuple(observed)
                if rebound_identity == marked_identity:
                    if escaped_identity is None:
                        escaped_identity = rebound_identity
                    elif escaped_identity != rebound_identity:
                        raise AssertionError("fixture process identity changed")
                    observed.append(rebound_identity)
                return tuple(observed)

            # The ordinary developer account can have unrelated same-UID
            # process churn. Keep this live integration on real per-PID Darwin
            # start identities scoped to its exact fixture process; the hosted
            # isolated-account gate runs the unfiltered production census
            # around the complete child suite.
            try:
                with mock.patch.object(
                    runner,
                    "_darwin_same_uid_processes",
                    side_effect=fixture_census,
                ):
                    started = time.monotonic()
                    with self.assertRaises(
                        runner.ChildProcessTreeClosureUnproven
                    ) as escaped:
                        runner._run_bounded_child(
                            (
                                sys.executable,
                                "-B",
                                "-c",
                                child_script,
                                str(marker),
                                str(stop_marker),
                                str(custody_receipt),
                                str(marker_delay_seconds),
                            ),
                            cwd=pathlib.Path(__file__).resolve().parents[1],
                            environment={
                                "LANG": "C",
                                "LC_ALL": "C",
                                "PATH": "/usr/bin:/bin",
                                "PYTHONDONTWRITEBYTECODE": "1",
                            },
                            timeout=10,
                            stdout_limit=1024,
                            stderr_limit=1024,
                        )
                    marked_identity = read_marker_identity()
                    evidence_identity = next(
                        (
                            process
                            for process in escaped.exception.processes
                            if process == marked_identity
                        ),
                        None,
                    )
                    self.assertLess(
                        time.monotonic() - started,
                        runner.DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS + 1.0,
                    )
                    self.assertIsNone(escaped.exception.__cause__)
                    if escaped.exception.cause is not None:
                        self.assertIsInstance(escaped.exception.cause, TimeoutError)
                        self.assertIn(
                            "process census deadline expired",
                            str(escaped.exception.cause),
                        )
                    self.assertIsNotNone(
                        evidence_identity,
                        f"escaped identity {marked_identity!r} absent from "
                        f"closure evidence {escaped.exception.processes!r}; "
                        f"cause={escaped.exception.cause!r}",
                    )
                    self.assertEqual(evidence_identity, escaped_identity)
            finally:
                cleanup_deadline = (
                    time.monotonic() + runner.DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS
                )
                cleanup_identity: runner.DarwinProcessIdentity | None = None
                receipt_error: BaseException | None = None
                while cleanup_identity is None:
                    try:
                        cleanup_identity = read_custody_identity()
                    except FileNotFoundError:
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            receipt_error = TimeoutError(
                                "fixture custody receipt deadline expired"
                            )
                            break
                        time.sleep(min(0.01, remaining))
                    except BaseException as error:
                        receipt_error = error
                        break
                if cleanup_identity is None:
                    closure_error = runner.ChildProcessTreeClosureUnproven(
                        (),
                        receipt_error,
                    )
                    raise closure_error from receipt_error
                identity_mismatch = (
                    escaped_identity is not None
                    and escaped_identity != cleanup_identity
                )
                try:
                    runner._require_process_census_time(cleanup_deadline)
                    rebound_identity = bind_identity(cleanup_identity.pid)
                    runner._require_process_census_time(cleanup_deadline)
                except ProcessLookupError:
                    rebound_identity = None
                except BaseException as error:
                    closure_error = runner.ChildProcessTreeClosureUnproven(
                        (cleanup_identity,),
                        error,
                    )
                    raise closure_error from error
                # The custody receipt binds the protected process-object
                # identity. Only an exact rebind may publish the task-private
                # cooperative stop; the same absolute deadline covers rebind,
                # stop publication, and stable exact-identity absence proof.
                if rebound_identity == cleanup_identity:
                    stop_marker.write_text("stop\n", encoding="ascii")
                    runner._require_process_census_time(cleanup_deadline)
                runner._require_process_identities_absent(
                    (cleanup_identity,),
                    deadline=cleanup_deadline,
                )
                if identity_mismatch:
                    raise AssertionError("fixture marker and custody identities differ")

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin process census")
    def test_double_fork_fixture_recovers_marker_after_unexpected_failure(
        self,
    ) -> None:
        real_absence_proof = runner._require_process_identities_absent
        real_process_census = runner._darwin_same_uid_processes

        def read_exact_receipt(
            receipt: pathlib.Path,
        ) -> runner.DarwinProcessIdentity:
            with receipt.open("rb") as receipt_stream:
                raw_receipt = receipt_stream.read(257)
            self.assertLessEqual(len(raw_receipt), 256)
            fields = raw_receipt.decode("ascii", "strict").splitlines()
            self.assertEqual(len(fields), 2)
            pid = int(fields[0])
            prefix = "darwin-proc-start:"
            self.assertTrue(fields[1].startswith(prefix))
            seconds, microseconds = fields[1].removeprefix(prefix).split(":")
            return runner.DarwinProcessIdentity(
                pid,
                int(seconds),
                int(microseconds),
            )

        def fail_after_marker(
            argv: tuple[str, ...],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            marker_path = pathlib.Path(argv[-4])
            stop_path = pathlib.Path(argv[-3])
            custody_path = pathlib.Path(argv[-2])
            marker_delay = float(argv[-1])
            failed_marker = marker_path.with_name("unpublishable-marker")
            failed_stop = stop_path.with_name("failed-stop-escaped-process")
            failed_custody = custody_path.with_name("failed-escaped-process-custody")
            failed_marker.mkdir()
            failed_argv = (
                *argv[:-4],
                str(failed_marker),
                str(failed_stop),
                str(failed_custody),
                argv[-1],
            )
            failed_returncode, failed_stdout, failed_stderr = runner.run_bounded(
                failed_argv,
                cwd=kwargs["cwd"],
                environment=kwargs["environment"],
                timeout=kwargs["timeout"],
                stdout_limit=kwargs["stdout_limit"],
                stderr_limit=kwargs["stderr_limit"],
            )
            self.assertEqual(failed_returncode, 1)
            self.assertEqual((failed_stdout, failed_stderr), (b"", b""))
            failed_identity = read_exact_receipt(failed_custody)
            self.assertFalse(failed_stop.exists())
            failed_cleanup_deadline = (
                time.monotonic() + runner.DARWIN_PROCESS_CENSUS_TIMEOUT_SECONDS
            )
            with mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                side_effect=real_process_census,
            ):
                real_absence_proof(
                    (failed_identity,),
                    deadline=failed_cleanup_deadline,
                )

            started = time.monotonic()
            returncode, stdout, stderr = runner.run_bounded(
                argv,
                cwd=kwargs["cwd"],
                environment=kwargs["environment"],
                timeout=kwargs["timeout"],
                stdout_limit=kwargs["stdout_limit"],
                stderr_limit=kwargs["stderr_limit"],
            )
            self.assertEqual((returncode, stdout, stderr), (0, b"", b""))
            self.assertGreaterEqual(time.monotonic() - started, marker_delay)
            marker_identity = read_exact_receipt(marker_path)
            custody_identity = read_exact_receipt(custody_path)
            self.assertEqual(marker_identity, custody_identity)
            self.assertEqual(
                process_start_identity(marker_identity.pid),
                "darwin-proc-start:"
                f"{marker_identity.start_seconds}:"
                f"{marker_identity.start_microseconds}",
            )
            raise RuntimeError("synthetic failure after fixture marker publication")

        with (
            mock.patch.object(
                runner,
                "_run_bounded_child",
                side_effect=fail_after_marker,
            ),
            mock.patch.object(
                runner,
                "_require_process_identities_absent",
                wraps=real_absence_proof,
            ) as require_absence,
            self.assertRaisesRegex(
                RuntimeError,
                "failure after fixture marker publication",
            ),
        ):
            self.test_bounded_child_rejects_setsid_double_fork_escape()

        require_absence.assert_called_once()
        recovered = require_absence.call_args.args[0]
        self.assertEqual(len(recovered), 1)
        self.assertGreater(recovered[0].pid, 0)
        self.assertGreater(recovered[0].start_seconds, 0)
        self.assertIsNotNone(require_absence.call_args.kwargs["deadline"])

    def test_bounded_child_output_overflow_settles_same_group_descendant(
        self,
    ) -> None:
        child_script = (
            "import os,pathlib,subprocess,sys,time\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "os.write(1,b'x'*8192)\n"
            "time.sleep(300)\n"
        )
        with owned_temporary_directory("readonly-child-overflow-") as root:
            group_file = root / "process-group"
            with self.assertRaisesRegex(OverflowError, "byte cap"):
                runner._run_bounded_child(
                    (
                        sys.executable,
                        "-B",
                        "-c",
                        child_script,
                        str(group_file),
                    ),
                    cwd=root,
                    environment={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )

            process_group = int(group_file.read_text(encoding="ascii"))
            self._require_process_group_absent(process_group)

    def test_bounded_child_receipt_failure_does_not_skip_closure(self) -> None:
        with owned_temporary_directory("readonly-child-outcome-receipt-") as root:
            baseline = (
                runner.DarwinProcessIdentity(
                    pid=os.getpid(),
                    start_seconds=1_700_000_000,
                    start_microseconds=1,
                ),
            )
            escaped_process = runner.DarwinProcessIdentity(
                pid=os.getpid() + 10_000,
                start_seconds=1_700_000_001,
                start_microseconds=2,
            )
            closure_error = runner.ChildProcessTreeClosureUnproven((escaped_process,))
            previous_outcome = subprocess.CompletedProcess(
                args=("previous",),
                returncode=99,
                stdout="previous stdout",
                stderr="previous stderr",
            )
            outcome_receipt = runner.ChildRunOutcomeReceipt()
            outcome_receipt.publish(previous_outcome)
            closure_proof = runner.ChildProcessClosureProof()

            with (
                mock.patch.object(
                    runner,
                    "_bound_child_signals",
                    return_value=contextlib.nullcontext(),
                ),
                mock.patch.object(
                    runner,
                    "_stable_same_uid_processes",
                    return_value=baseline,
                ),
                mock.patch.object(
                    runner,
                    "run_bounded",
                    return_value=(0, b"current stdout", b"current stderr"),
                ),
                mock.patch.object(
                    runner,
                    "_require_no_new_same_uid_processes",
                    side_effect=closure_error,
                ) as require_closure,
                self.assertRaises(runner.ChildProcessTreeClosureUnproven) as caught,
            ):
                runner._run_bounded_child(
                    (sys.executable, "-B", "-c", "raise SystemExit(0)"),
                    cwd=root,
                    environment={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=closure_proof,
                    outcome_receipt=outcome_receipt,
                )

            self.assertIs(caught.exception, closure_error)
            self.assertIsInstance(caught.exception.__cause__, RuntimeError)
            self.assertRegex(
                str(caught.exception.__cause__),
                "already published",
            )
            require_closure.assert_called_once_with(baseline)
            self.assertIs(outcome_receipt.completed, previous_outcome)
            self.assertTrue(closure_proof.started)
            self.assertFalse(closure_proof.proven)
            self.assertFalse(closure_proof.destructive_cleanup_authorized)

    def test_bounded_child_does_not_claim_closure_before_process_supervision(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-child-pre-supervision-") as root:
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=mock.sentinel.interrupt,
            )
            closure_proof = runner.ChildProcessClosureProof()
            with (
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(
                    runner,
                    "activate_deferred_signal_interrupt",
                    side_effect=TimeoutError("synthetic activation failure"),
                ),
                mock.patch.object(runner, "_restore_child_signal_guard"),
                mock.patch.object(runner, "run_bounded") as run_bounded,
                self.assertRaisesRegex(TimeoutError, "activation failure"),
            ):
                runner._run_bounded_child(
                    (sys.executable, "-B", "-c", "raise SystemExit(0)"),
                    cwd=root,
                    environment={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    timeout=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    closure_proof=closure_proof,
                )

            self.assertFalse(closure_proof.proven)
            self.assertFalse(closure_proof.started)
            self.assertFalse(closure_proof.destructive_cleanup_authorized)
            run_bounded.assert_not_called()

    def test_bounded_child_isolation_preflight_failure_does_not_start(self) -> None:
        with owned_temporary_directory("readonly-child-preflight-") as root:
            foreign_process = runner.DarwinProcessIdentity(
                pid=os.getpid() + 10_000,
                start_seconds=1_700_000_000,
                start_microseconds=123_456,
            )
            preflight_failures = (
                PermissionError(
                    errno.EPERM,
                    "synthetic account isolation failure",
                ),
                runner.ChildProcessTreeClosureUnproven(
                    (foreign_process,),
                    OSError(errno.EBUSY, "synthetic foreign process"),
                ),
                OSError(errno.EIO, "synthetic census failure"),
                TimeoutError("synthetic census timeout"),
                OverflowError("synthetic census overflow"),
            )
            for preflight_error in preflight_failures:
                with self.subTest(error=type(preflight_error).__name__):
                    closure_proof = runner.ChildProcessClosureProof()
                    with (
                        mock.patch.object(
                            runner,
                            "_require_isolated_child_account",
                            side_effect=preflight_error,
                        ),
                        mock.patch.object(runner, "run_bounded") as run_bounded,
                        self.assertRaises(type(preflight_error)),
                    ):
                        runner._run_bounded_child(
                            (sys.executable, "-B", "-c", "raise SystemExit(0)"),
                            cwd=root,
                            environment={
                                "LANG": "C",
                                "LC_ALL": "C",
                                "PATH": "/usr/bin:/bin",
                                "PYTHONDONTWRITEBYTECODE": "1",
                            },
                            timeout=5,
                            stdout_limit=1024,
                            stderr_limit=1024,
                            closure_proof=closure_proof,
                            require_isolated_account=True,
                        )

                    self.assertFalse(closure_proof.started)
                    self.assertFalse(closure_proof.proven)
                    self.assertFalse(closure_proof.destructive_cleanup_authorized)
                    run_bounded.assert_not_called()

        foreign_process = runner.DarwinProcessIdentity(
            pid=os.getpid() + 10_000,
            start_seconds=1_700_000_000,
            start_microseconds=123_456,
        )
        main_preflight_failures = (
            (
                "closure",
                runner.ChildProcessTreeClosureUnproven(
                    (foreign_process,),
                    OSError(
                        errno.EBUSY,
                        "synthetic account isolation failure",
                    ),
                ),
            ),
            ("interrupt", KeyboardInterrupt("synthetic preflight interrupt")),
        )
        for label, preflight_error in main_preflight_failures:
            with (
                self.subTest(error=label),
                owned_temporary_directory(
                    f"readonly-main-preflight-{label}-"
                ) as main_root,
            ):
                sticky_parent = main_root / "sticky"
                sticky_parent.mkdir()
                sticky_parent.chmod(0o1777)
                install_container = sticky_parent / "install"
                self._make_private_directory(install_container)
                runtime_home = main_root / "runtime-home"
                self._make_private_directory(runtime_home)
                runtime_parent = runtime_home / "runtime"
                self._make_private_directory(runtime_parent)

                def fake_copytree(
                    _source: pathlib.Path,
                    destination: pathlib.Path,
                    **_kwargs: object,
                ) -> pathlib.Path:
                    pathlib.Path(destination).mkdir()
                    return pathlib.Path(destination)

                stdout = io.StringIO()
                stderr = io.StringIO()
                retain_bound_function = (
                    runner._retained_bound_for_unproven_child_closure
                )
                with (
                    mock.patch.object(runner.sys, "platform", "darwin"),
                    mock.patch.object(
                        runner,
                        "READONLY_INSTALL_PARENT",
                        sticky_parent,
                    ),
                    mock.patch.object(
                        runner,
                        "_private_runtime_parent",
                        return_value=runtime_home,
                    ),
                    mock.patch.object(
                        runner,
                        "_create_bound_owned_private_directory",
                        side_effect=self._bound_directory_factory(
                            install_container,
                            runtime_parent,
                        ),
                    ),
                    mock.patch.object(
                        runner.shutil,
                        "copytree",
                        side_effect=fake_copytree,
                    ),
                    mock.patch.object(runner, "_set_tree_read_only"),
                    mock.patch.object(runner, "_tree_snapshot", return_value={}),
                    mock.patch.object(
                        runner,
                        "_require_isolated_child_account",
                        side_effect=preflight_error,
                    ),
                    mock.patch.object(runner, "run_bounded") as main_run_bounded,
                    mock.patch.object(
                        runner,
                        "_cleanup_bound_tree",
                    ) as cleanup_bound,
                    mock.patch.object(
                        runner,
                        "_retained_bound_for_unproven_child_closure",
                        wraps=retain_bound_function,
                    ) as retain_bound,
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    if isinstance(preflight_error, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            runner.main()
                        summary = None
                    else:
                        returncode = runner.main()
                        summary = json.loads(stdout.getvalue())

                self.assertTrue(install_container.is_dir())
                self.assertTrue(runtime_parent.is_dir())
                self.assertEqual(retain_bound.call_count, 2)
                main_run_bounded.assert_not_called()
                cleanup_bound.assert_not_called()
                if summary is None:
                    self.assertEqual(stdout.getvalue(), "")
                    continue
                self.assertEqual(returncode, 1)
                self.assertEqual(
                    summary["primary_failure"]["stage"],
                    "child-run",
                )
                self.assertEqual(summary["primary_status"], "closure-unproven")
                self.assertEqual(
                    summary["child_process_closure"],
                    "not-started",
                )
                self.assertEqual(summary["cleanup_status"], "incomplete")
                self.assertEqual(
                    summary["retained_paths"],
                    [str(install_container), str(runtime_parent)],
                    summary["cleanup_failures"],
                )
                self.assertEqual(
                    [failure["error_kind"] for failure in summary["cleanup_failures"]],
                    [
                        "ChildProcessClosureUnproven",
                        "ChildProcessClosureUnproven",
                    ],
                )

    def test_bounded_child_sigterm_settles_group_before_interrupt_returns(
        self,
    ) -> None:
        inner_script = (
            "import os,pathlib,subprocess,sys,time\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpgrp()), encoding='ascii')\n"
            "pathlib.Path(sys.argv[2]).write_text('ready', encoding='ascii')\n"
            "subprocess.Popen((sys.executable,'-B','-c',"
            "'import time; time.sleep(300)'),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "time.sleep(300)\n"
        )
        worker_script = (
            "import os,pathlib,sys\n"
            "from tests import run_readonly_install_deterministic_supervisor as runner\n"
            "root=pathlib.Path(sys.argv[1])\n"
            "try:\n"
            " runner._run_bounded_child("
            "(sys.executable,'-B','-c',sys.argv[2],sys.argv[3],sys.argv[4]),"
            "cwd=root,environment={'LANG':'C','LC_ALL':'C',"
            "'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},"
            "timeout=30,stdout_limit=1024,stderr_limit=1024)\n"
            "except runner.ChildRunInterrupted as error:\n"
            " raise SystemExit(128+error.signal_number)\n"
            "raise SystemExit(3)\n"
        )
        with owned_temporary_directory("readonly-child-sigterm-") as root:
            group_file = root / "process-group"
            ready_file = root / "ready"
            worker = subprocess.Popen(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    worker_script,
                    str(root),
                    inner_script,
                    str(group_file),
                    str(ready_file),
                ),
                cwd=pathlib.Path(__file__).resolve().parents[1],
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready_file.is_file() and time.monotonic() < deadline:
                    if worker.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue(
                    ready_file.is_file(), "bounded child did not become ready"
                )
                process_group = int(group_file.read_text(encoding="ascii"))

                worker.send_signal(signal.SIGTERM)
                stdout, stderr = worker.communicate(timeout=10)

                self.assertEqual(worker.returncode, 128 + signal.SIGTERM)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self._require_process_group_absent(process_group)
            finally:
                if worker.poll() is None:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=5)

    def test_main_preserves_closure_failure_across_signal_teardown(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-main-closure-gap-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            closure_error = runner.GitProcessClosureUnproven(
                None,
                None,
                RuntimeError("synthetic closure failure"),
            )
            signal_guard = runner.ChildSignalGuard(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
                interrupt=mock.sentinel.interrupt,
            )
            deactivate_error = RuntimeError(
                "synthetic deferred-signal teardown failure"
            )
            restore_error = OSError(
                errno.EIO,
                "synthetic signal-guard restore failure",
            )
            process_baseline = (
                runner.DarwinProcessIdentity(
                    pid=os.getpid(),
                    start_seconds=1_700_000_000,
                    start_microseconds=1,
                ),
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                    ),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(
                    runner,
                    "_tree_snapshot",
                    side_effect=({}, FileNotFoundError("install path moved")),
                ),
                mock.patch.object(
                    runner,
                    "_install_child_signal_guard",
                    return_value=signal_guard,
                ),
                mock.patch.object(
                    runner,
                    "activate_deferred_signal_interrupt",
                    return_value=mock.sentinel.binding,
                ),
                mock.patch.object(
                    runner,
                    "deactivate_deferred_signal_interrupt",
                    side_effect=deactivate_error,
                ) as deactivate,
                mock.patch.object(
                    runner,
                    "_restore_child_signal_guard",
                    side_effect=restore_error,
                ) as restore,
                mock.patch.object(
                    runner,
                    "run_bounded",
                    side_effect=closure_error,
                ),
                mock.patch.object(
                    runner,
                    "_require_isolated_child_account",
                    return_value=process_baseline,
                ),
                mock.patch.object(runner, "_require_no_new_same_uid_processes"),
                mock.patch.object(
                    support._DirectoryParentBinding,
                    "current_path",
                    side_effect=OSError(
                        errno.ESTALE,
                        "synthetic F_GETPATH failure",
                    ),
                ),
                mock.patch.object(runner, "_cleanup_tree") as cleanup_tree,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(
                summary["primary_status"],
                "closure-unproven",
                summary,
            )
            self.assertEqual(summary["child_process_closure"], "unproven")
            self.assertEqual(
                summary["primary_failure"]["error_kind"],
                "GitProcessClosureUnproven",
            )
            self.assertEqual(
                [failure["operation"] for failure in summary["secondary_failures"]],
                [
                    "deactivate-deferred-signal-interrupt",
                    "restore-child-signal-guard",
                ],
            )
            self.assertEqual(
                [failure["error_kind"] for failure in summary["secondary_failures"]],
                ["RuntimeError", "OSError"],
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(install_container), str(runtime_parent)],
            )
            cleanup_failures = summary["cleanup_failures"]
            self.assertEqual(len(cleanup_failures), 2)
            self.assertEqual(
                [failure["retained"] for failure in cleanup_failures],
                [None, None],
            )
            self.assertEqual(
                [failure["path_status"] for failure in cleanup_failures],
                ["bound-unresolved", "bound-unresolved"],
            )
            self.assertEqual(
                [failure["original_path_status"] for failure in cleanup_failures],
                ["same", "same"],
            )
            self.assertEqual(
                [failure["recovery_evidence"] for failure in cleanup_failures],
                [None, None],
            )
            self.assertTrue(install_container.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            cleanup_tree.assert_not_called()
            deactivate.assert_called_once_with(mock.sentinel.binding)
            restore.assert_called_once_with(signal_guard)
            error_text = stderr.getvalue()
            self.assertIn("GitProcessClosureUnproven", error_text)
            self.assertIn('"retained":null', error_text)
            self.assertLess(
                error_text.index("primary failure"),
                error_text.index("secondary failures"),
            )
            self.assertLess(
                error_text.index("secondary failures"),
                error_text.index("cleanup incomplete"),
            )

    def test_main_preserves_bounded_outcome_when_same_uid_closure_unproven(
        self,
    ) -> None:
        for child_returncode in (0, 23):
            with (
                self.subTest(child_returncode=child_returncode),
                owned_temporary_directory(
                    f"readonly-main-bounded-outcome-{child_returncode}-"
                ) as root,
            ):
                sticky_parent = root / "sticky"
                sticky_parent.mkdir()
                sticky_parent.chmod(0o1777)
                install_container = sticky_parent / "install"
                self._make_private_directory(install_container)
                runtime_home = root / "runtime-home"
                self._make_private_directory(runtime_home)
                runtime_parent = runtime_home / "runtime"
                self._make_private_directory(runtime_parent)
                bounded_stderr = (
                    f"bounded child stderr for returncode {child_returncode}"
                )

                def fake_copytree(
                    _source: pathlib.Path,
                    destination: pathlib.Path,
                    **_kwargs: object,
                ) -> pathlib.Path:
                    pathlib.Path(destination).mkdir()
                    return pathlib.Path(destination)

                process_baseline = (
                    runner.DarwinProcessIdentity(
                        pid=os.getpid(),
                        start_seconds=1_700_000_000,
                        start_microseconds=1,
                    ),
                )
                escaped_process = runner.DarwinProcessIdentity(
                    pid=os.getpid() + 10_000,
                    start_seconds=1_700_000_001,
                    start_microseconds=2,
                )
                closure_error = runner.ChildProcessTreeClosureUnproven(
                    (escaped_process,)
                )
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(runner.sys, "platform", "darwin"),
                    mock.patch.object(
                        runner,
                        "READONLY_INSTALL_PARENT",
                        sticky_parent,
                    ),
                    mock.patch.object(
                        runner,
                        "_private_runtime_parent",
                        return_value=runtime_home,
                    ),
                    mock.patch.object(
                        runner,
                        "_create_bound_owned_private_directory",
                        side_effect=self._bound_directory_factory(
                            install_container,
                            runtime_parent,
                        ),
                    ),
                    mock.patch.object(
                        runner.shutil,
                        "copytree",
                        side_effect=fake_copytree,
                    ),
                    mock.patch.object(runner, "_set_tree_read_only"),
                    mock.patch.object(runner, "_tree_snapshot", return_value={}),
                    mock.patch.object(
                        runner,
                        "_bound_child_signals",
                        return_value=contextlib.nullcontext(),
                    ),
                    mock.patch.object(
                        runner,
                        "_require_isolated_child_account",
                        return_value=process_baseline,
                    ),
                    mock.patch.object(
                        runner,
                        "run_bounded",
                        return_value=(
                            child_returncode,
                            b"bounded child stdout",
                            bounded_stderr.encode("utf-8"),
                        ),
                    ) as run_bounded,
                    mock.patch.object(
                        runner,
                        "_require_no_new_same_uid_processes",
                        side_effect=closure_error,
                    ),
                    mock.patch.object(runner, "_cleanup_bound_tree") as cleanup_bound,
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = runner.main()

                summary = json.loads(stdout.getvalue())
                self.assertEqual(returncode, 1)
                self.assertEqual(summary["returncode"], child_returncode)
                self.assertEqual(summary["primary_status"], "closure-unproven")
                self.assertEqual(summary["child_process_closure"], "unproven")
                self.assertEqual(
                    summary["primary_failure"]["error_kind"],
                    "ChildProcessTreeClosureUnproven",
                )
                self.assertEqual(summary["cleanup_status"], "incomplete")
                self.assertEqual(
                    summary["retained_paths"],
                    [str(install_container), str(runtime_parent)],
                    summary["cleanup_failures"],
                )
                self.assertTrue(install_container.is_dir())
                self.assertTrue(runtime_parent.is_dir())
                self.assertIn(bounded_stderr, stderr.getvalue())
                run_bounded.assert_called_once()
                cleanup_bound.assert_not_called()

    def test_main_reports_primary_and_cleanup_failures_in_order(self) -> None:
        with owned_temporary_directory("readonly-main-failures-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            cleanup_failure = runner.CleanupFailure(
                path=str(install_container),
                error_kind="PermissionError",
                error_errno=errno.EACCES,
                retained=True,
                restore_error_kind=None,
                restore_error_errno=None,
            )
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="child stdout evidence",
                stderr="child stderr evidence",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(
                    runner,
                    "_tree_snapshot",
                    side_effect=(
                        {},
                        RuntimeError("synthetic post-snapshot failure"),
                    ),
                ),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    return_value=completed,
                ) as run_bounded_child,
                mock.patch.object(
                    runner,
                    "_cleanup_bound_tree",
                    side_effect=(cleanup_failure, None),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            error_text = stderr.getvalue()
            child_environment = run_bounded_child.call_args.kwargs["environment"]
            self.assertEqual(child_environment["TMPDIR"], str(runtime_parent))
            self.assertEqual(
                child_environment[runner.EXPLICIT_RUNTIME_PARENT_ENV],
                str(runtime_parent),
            )
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["returncode"], 0)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "snapshot-after",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(install_container)],
                summary["cleanup_failures"],
            )
            self.assertIn("child stdout evidence", error_text)
            self.assertIn("child stderr evidence", error_text)
            self.assertLess(
                error_text.index("primary failure"),
                error_text.index("cleanup incomplete"),
            )

    def test_main_rejects_replaced_install_container(self) -> None:
        with owned_temporary_directory("readonly-main-install-replace-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            original_install_container = sticky_parent / "original-install"
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            def replace_install_container(
                *_args: object,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                install_container.rename(original_install_container)
                install_container.mkdir(mode=0o700)
                return completed

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(
                    runner,
                    "_tree_snapshot",
                    side_effect=({}, FileNotFoundError("install path moved")),
                ),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    side_effect=replace_install_container,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "install-container-revalidation",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(original_install_container)],
                summary["cleanup_failures"],
            )
            cleanup = summary["cleanup_failures"][0]
            self.assertEqual(cleanup["original_path"], str(install_container))
            self.assertEqual(cleanup["path_status"], "bound-moved")
            self.assertEqual(cleanup["replacement_path"], str(install_container))
            self.assertTrue(original_install_container.is_dir())
            self.assertTrue(install_container.is_dir())

    def test_main_rejects_replaced_runtime_parent(self) -> None:
        with owned_temporary_directory("readonly-main-runtime-replace-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            original_runtime_parent = runtime_home / "original-runtime"
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            completed = subprocess.CompletedProcess(
                args=("python3",),
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_copytree(
                _source: pathlib.Path,
                destination: pathlib.Path,
                **_kwargs: object,
            ) -> pathlib.Path:
                pathlib.Path(destination).mkdir()
                return pathlib.Path(destination)

            def replace_runtime_parent(
                *_args: object,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                runtime_parent.rename(original_runtime_parent)
                runtime_parent.mkdir(mode=0o700)
                return completed

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(runner.sys, "platform", "darwin"),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    return_value=runtime_home,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
                ),
                mock.patch.object(
                    runner.shutil,
                    "copytree",
                    side_effect=fake_copytree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    side_effect=replace_runtime_parent,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = runner.main()

            summary = json.loads(stdout.getvalue())
            self.assertEqual(returncode, 1)
            self.assertEqual(summary["primary_status"], "failed")
            self.assertEqual(
                summary["primary_failure"]["stage"],
                "runtime-residue",
            )
            self.assertEqual(summary["cleanup_status"], "incomplete")
            self.assertEqual(
                summary["retained_paths"],
                [str(original_runtime_parent)],
                summary["cleanup_failures"],
            )
            cleanup = summary["cleanup_failures"][0]
            self.assertEqual(cleanup["original_path"], str(runtime_parent))
            self.assertEqual(cleanup["path_status"], "bound-moved")
            self.assertEqual(cleanup["replacement_path"], str(runtime_parent))
            self.assertTrue(original_runtime_parent.is_dir())
            self.assertTrue(runtime_parent.is_dir())
            self.assertIn("test runtime parent path changed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
