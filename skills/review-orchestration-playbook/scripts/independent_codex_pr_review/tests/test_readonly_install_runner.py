from __future__ import annotations

import contextlib
import dis
import errno
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import pwd
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterator
from dataclasses import asdict, replace
from unittest import mock

from review_supervisor import recovery_cleanup
from review_supervisor.process import process_start_identity

from . import run_readonly_install_deterministic_supervisor as runner
from . import support
from .support import owned_temporary_directory


@contextlib.contextmanager
def _mock_ambient_runtime_parent(parent: pathlib.Path) -> Iterator[None]:
    """Patch the synthetic selector without inheriting an outer explicit path."""

    with (
        mock.patch.dict(os.environ, {}, clear=False),
        mock.patch.object(
            runner,
            "_private_runtime_parent",
            return_value=parent,
        ),
    ):
        os.environ.pop(runner.EXPLICIT_RUNTIME_PARENT_ENV, None)
        yield


def _captured_gate_source_for_nested_tests(path: pathlib.Path) -> str:
    for finder in sys.meta_path:
        sources = getattr(finder, "_sources", None)
        if not isinstance(sources, dict):
            continue
        source = sources.get("tests.trusted_mac_gate")
        payload = getattr(source, "payload", None)
        if isinstance(payload, bytes):
            return payload.decode("utf-8")
    return path.read_text(encoding="utf-8")


class ReadOnlyInstallRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._source_binding = runner.SourceCheckoutBinding(
            repo_root=pathlib.Path("/synthetic/repo"),
            head_sha="a" * 40,
            source_relative_path="source",
            source_manifest_sha256="b" * 64,
            head_subtree_manifest_sha256="c" * 64,
            source_root_gid=os.getgid(),
            source_entries=(),
        )
        self._source_tree_binding = runner.SourceTreeBinding(
            source_manifest_sha256="b" * 64,
            source_root_gid=os.getgid(),
            source_entries=(),
        )

        def copy_bound_tree(
            source: pathlib.Path,
            destination: pathlib.Path,
            _binding: runner.SourceTreeBinding,
            *,
            budget: runner.TreeSnapshotBudget,
            destination_owner_uid: int,
            destination_group_gid: int,
        ) -> str:
            self.assertIsInstance(budget, runner.TreeSnapshotBudget)
            self.assertEqual(destination_owner_uid, destination.parent.stat().st_uid)
            self.assertEqual(destination_group_gid, destination.parent.stat().st_gid)
            runner.shutil.copytree(
                source,
                destination,
                symlinks=True,
                ignore=runner.shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            return self._source_tree_binding.source_manifest_sha256

        patchers = (
            mock.patch.object(
                runner,
                "_bind_source_checkout",
                return_value=self._source_binding,
            ),
            mock.patch.object(
                runner,
                "_bind_source_tree",
                return_value=self._source_tree_binding,
            ),
            mock.patch.object(
                runner,
                "_copy_bound_tree",
                side_effect=copy_bound_tree,
            ),
            mock.patch.object(
                runner,
                "_source_manifest_sha256",
                return_value="b" * 64,
            ),
        )
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

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
            allow_sticky_writable_ancestors: bool | None = None,
        ) -> support._DirectoryParentBinding:
            if allow_sticky_writable_ancestors is not None:
                raise AssertionError(
                    "synthetic ambient runtime creation received explicit policy"
                )
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
            mock.patch.object(runner.os, "kill") as kill,
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
        kill.assert_not_called()

    def test_dedicated_uid_scope_rejects_nonisolated_baseline(self) -> None:
        supervisor = runner.DarwinProcessIdentity(os.getpid(), 1, 1)
        preexisting = runner.DarwinProcessIdentity(90_007, 2, 2)
        account = mock.Mock(
            pw_name="codexreview0123456789ab",
            pw_uid=50_001,
            pw_gid=50_001,
            pw_dir="/var/empty",
            pw_shell="/usr/bin/false",
        )
        with (
            mock.patch.dict(
                os.environ,
                {runner.DEDICATED_ACCOUNT_CUSTODY_ENV: "a" * 64},
            ),
            mock.patch.object(runner.os, "getuid", return_value=50_001),
            mock.patch.object(runner.pwd, "getpwuid", return_value=account),
            self.assertRaisesRegex(PermissionError, "custody is not proven"),
        ):
            runner._dedicated_uid_scope((supervisor, preexisting))

    def test_dedicated_uid_signal_rejects_pid_replacement(self) -> None:
        selected = runner.DarwinProcessIdentity(90_008, 3, 3)
        replacement = runner.DarwinProcessIdentity(selected.pid, 4, 4)
        with (
            mock.patch.object(
                runner,
                "_darwin_same_uid_processes",
                return_value=(replacement,),
            ),
            mock.patch.object(runner.os, "kill") as kill,
            self.assertRaises(runner.ChildProcessTreeClosureUnproven) as closure,
        ):
            runner._signal_dedicated_uid_process(
                selected,
                signal.SIGTERM,
                deadline=runner.time.monotonic() + 1.0,
            )
        self.assertIsInstance(closure.exception.cause, OSError)
        self.assertIn("identity changed before signal", str(closure.exception.cause))
        kill.assert_not_called()

    @unittest.skipUnless(
        sys.platform == "darwin" and hasattr(os, "fork"),
        "requires Darwin process identity and fork",
    )
    def test_dedicated_uid_closure_kills_double_forked_session(self) -> None:
        read_descriptor, write_descriptor = os.pipe()
        leader = os.fork()
        if leader == 0:
            try:
                os.close(read_descriptor)
                os.setsid()
                descendant = os.fork()
                if descendant == 0:
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    os.write(write_descriptor, f"{os.getpid()}\n".encode("ascii"))
                    while True:
                        signal.pause()
                os._exit(0)
            except BaseException:
                os._exit(97)

        os.close(write_descriptor)
        descendant_pid = -1
        original_census = runner._darwin_same_uid_processes
        real_kill = os.kill
        selected_descendant: runner.DarwinProcessIdentity | None = None
        try:
            with os.fdopen(read_descriptor, "rb", closefd=True) as reader:
                descendant_pid = int(reader.readline().decode("ascii"))
            reaped_leader, leader_status = os.waitpid(leader, 0)
            self.assertEqual(reaped_leader, leader)
            self.assertEqual(leader_status, 0)

            initial = original_census(deadline=time.monotonic() + 2.0)
            supervisor = next(item for item in initial if item.pid == os.getpid())
            selected_descendant = next(
                item for item in initial if item.pid == descendant_pid
            )
            baseline = (supervisor,)
            scope = runner.DedicatedUidScope(
                uid=os.getuid(),
                account_name=pwd.getpwuid(os.getuid()).pw_name,
                receipt_sha256="a" * 64,
                baseline=baseline,
            )
            signaled: list[tuple[int, int]] = []

            def scoped_census(
                *, deadline: float | None = None
            ) -> tuple[runner.DarwinProcessIdentity, ...]:
                return tuple(
                    item
                    for item in original_census(deadline=deadline)
                    if item.pid in {os.getpid(), descendant_pid}
                )

            def record_kill(pid: int, signal_number: int) -> None:
                signaled.append((pid, signal_number))
                real_kill(pid, signal_number)

            with (
                mock.patch.object(
                    runner,
                    "_darwin_same_uid_processes",
                    side_effect=scoped_census,
                ),
                mock.patch.object(
                    runner,
                    "_require_dedicated_uid_scope_current",
                ),
                mock.patch.object(
                    runner,
                    "_reap_terminal_same_uid_children",
                ),
                mock.patch.object(runner.os, "kill", side_effect=record_kill),
                mock.patch.object(
                    runner,
                    "DARWIN_DEDICATED_PROCESS_TERMINATE_GRACE_SECONDS",
                    0.02,
                ),
                mock.patch.object(
                    runner,
                    "DARWIN_PROCESS_ABSENCE_STABILITY_SECONDS",
                    0.02,
                ),
            ):
                runner._require_no_new_same_uid_processes(
                    baseline,
                    deadline=time.monotonic() + 5.0,
                    dedicated_scope=scope,
                )

            self.assertIn((descendant_pid, signal.SIGTERM), signaled)
            self.assertIn((descendant_pid, signal.SIGKILL), signaled)
        finally:
            if descendant_pid > 0:
                try:
                    current = original_census(deadline=time.monotonic() + 1.0)
                    if selected_descendant in current:
                        real_kill(descendant_pid, signal.SIGKILL)
                except (OSError, StopIteration, TimeoutError):
                    pass
            try:
                os.waitpid(leader, os.WNOHANG)
            except ChildProcessError:
                pass

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
                self.assertEqual(
                    support._validated_private_runtime_parent(
                        str(parent),
                        allow_sticky_writable_ancestors=True,
                    ),
                    parent.resolve(strict=True),
                )
                ancestor.chmod(0o777)
                self.assertIsNone(
                    support._validated_private_runtime_parent(
                        str(parent),
                        allow_sticky_writable_ancestors=True,
                    )
                )
                ancestor.chmod(0o1777)
                with mock.patch.dict(
                    os.environ,
                    {support._EXPLICIT_RUNTIME_PARENT_ENV: str(parent)},
                ):
                    self.assertEqual(support._private_runtime_parent(), parent)
            finally:
                ancestor.chmod(0o700)

        sticky_root = pathlib.Path(
            "/private/tmp" if pathlib.Path("/private/tmp").is_dir() else "/tmp"
        )
        with tempfile.TemporaryDirectory(
            prefix="codex-explicit-runtime-parent-",
            dir=sticky_root,
        ) as raw_runtime_parent:
            runtime_parent = pathlib.Path(raw_runtime_parent)
            runtime_parent.chmod(0o700)
            strict_owner = support._PrivateDirectoryCreationResultOwner()
            with self.assertRaisesRegex(
                OSError,
                "group- or world-writable",
            ):
                support._create_bound_owned_private_directory(
                    runtime_parent,
                    ".strict-runtime-",
                    result_owner=strict_owner,
                )
            self.assertIsNone(strict_owner.binding)

            with (
                mock.patch.dict(
                    os.environ,
                    {support._EXPLICIT_RUNTIME_PARENT_ENV: str(runtime_parent)},
                ),
                mock.patch.object(support, "_RUNTIME_ROOT_STATE", None),
            ):
                with owned_temporary_directory("sticky-runtime-child-") as child:
                    state = support._RUNTIME_ROOT_STATE
                    self.assertIsNotNone(state)
                    assert state is not None
                    self.assertTrue(state.binding.allow_sticky_writable_ancestors)
                    self.assertTrue(child.is_dir())
                    mismatch_owner = support._PrivateDirectoryCreationResultOwner()
                    with self.assertRaisesRegex(
                        ValueError,
                        "held temporary-directory parent is inconsistent",
                    ):
                        support._create_bound_owned_private_directory(
                            state.path,
                            ".mismatched-policy-",
                            result_owner=mismatch_owner,
                            held_parent_binding=state.binding,
                            allow_sticky_writable_ancestors=False,
                        )
                    self.assertIsNone(mismatch_owner.binding)
                runtime_root = state.path
                support._cleanup_process_runtime_root(state)
                self.assertFalse(runtime_root.exists())
                self.assertIsNone(support._RUNTIME_ROOT_STATE)

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
                        _mock_ambient_runtime_parent(runtime_home),
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
                    _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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
                allow_sticky_writable_ancestors: bool | None = None,
            ) -> support._DirectoryParentBinding:
                nonlocal opened_binding
                self.assertIs(allow_sticky_writable_ancestors, False)
                opened_binding = real_open(
                    raw_path,
                    require_owned_private_parent=require_owned_private_parent,
                    result_owner=result_owner,
                    allow_sticky_writable_ancestors=(allow_sticky_writable_ancestors),
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
            acl_entries: tuple[bytes, ...] = ()
            xattrs: tuple[tuple[bytes, str], ...] = ()

            with (
                mock.patch.object(
                    runner,
                    "_acl_entries",
                    side_effect=lambda _descriptor: acl_entries,
                ),
                mock.patch.object(
                    runner,
                    "_xattr_snapshot",
                    side_effect=lambda _descriptor, **_kwargs: xattrs,
                ),
            ):
                baseline = runner._tree_snapshot(root)
                acl_entries = (b" 0: user:synthetic allow write",)
                acl_changed = runner._tree_snapshot(root)
                acl_entries = ()
                xattrs = ((b"com.apple.synthetic", "digest"),)
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
            # The ordinary developer account is not the hosted isolated account.
            # Scope this fixture's census so unrelated same-UID process churn
            # cannot replace its real process-group settlement assertion.
            with (
                mock.patch.object(
                    runner,
                    "_stable_same_uid_processes",
                    return_value=(),
                ),
                mock.patch.object(
                    runner,
                    "_require_no_new_same_uid_processes",
                ) as require_closure,
            ):
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
            require_closure.assert_called_once_with((), dedicated_scope=None)
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
            # Keep the real overflow/process-group behavior while excluding
            # unrelated same-UID developer-account churn from this fixture.
            with (
                mock.patch.object(
                    runner,
                    "_stable_same_uid_processes",
                    return_value=(),
                ),
                mock.patch.object(
                    runner,
                    "_require_no_new_same_uid_processes",
                ) as require_closure,
                self.assertRaisesRegex(OverflowError, "byte cap"),
            ):
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
            require_closure.assert_called_once_with((), dedicated_scope=None)
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
            require_closure.assert_called_once_with(
                baseline,
                dedicated_scope=None,
            )
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
                    _mock_ambient_runtime_parent(runtime_home),
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
            "from unittest import mock\n"
            "from tests import run_readonly_install_deterministic_supervisor as runner\n"
            "root=pathlib.Path(sys.argv[1])\n"
            "try:\n"
            " with mock.patch.object(runner,'_stable_same_uid_processes',"
            "return_value=()),mock.patch.object("
            "runner,'_require_no_new_same_uid_processes'):\n"
            "  runner._run_bounded_child("
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

                self.assertEqual(
                    worker.returncode,
                    128 + signal.SIGTERM,
                    stderr.decode("utf-8", "replace"),
                )
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
                _mock_ambient_runtime_parent(runtime_home),
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
                    _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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
                _mock_ambient_runtime_parent(runtime_home),
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

    def test_terminal_signal_publication_is_linearized_in_a_real_process(
        self,
    ) -> None:
        self.assertEqual(sys.version_info[:2], (3, 13))
        test_names = unittest.defaultTestLoader.getTestCaseNames(
            TerminalPublicationSignalIntegrationTests
        )
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            TerminalPublicationSignalIntegrationTests
        )
        transcript = io.StringIO()
        result = unittest.TextTestRunner(
            stream=transcript,
            verbosity=2,
        ).run(suite)

        detail = transcript.getvalue()
        self.assertEqual(result.testsRun, len(test_names), detail)
        self.assertGreater(result.testsRun, 0, detail)
        self.assertFalse(
            any(
                (
                    result.failures,
                    result.errors,
                    result.skipped,
                    result.expectedFailures,
                    result.unexpectedSuccesses,
                )
            ),
            detail,
        )
        self.assertTrue(result.wasSuccessful(), detail)

    def test_no_child_suite_python_startup_ignores_site_injection(self) -> None:
        self.assertEqual(sys.version_info[:2], (3, 13))
        with owned_temporary_directory("readonly-python-site-injection-") as root:
            pythonpath_root = root / "pythonpath"
            pythonpath_root.mkdir(mode=0o700)
            user_base = root / "user-base"
            user_site = (
                user_base
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            user_site.mkdir(mode=0o700, parents=True)
            child_cwd = root / "child-cwd"
            child_cwd.mkdir(mode=0o700)
            sitecustomize_marker = root / "sitecustomize-loaded"
            pth_marker = root / "pth-loaded"
            (pythonpath_root / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(sitecustomize_marker)!r}).write_text("
                "'loaded\\n', encoding='ascii')\n"
                "raise RuntimeError('sitecustomize injection executed')\n",
                encoding="ascii",
            )
            (pythonpath_root / "injected_from_pythonpath.py").write_text(
                "VALUE = 'injected'\n",
                encoding="ascii",
            )
            (user_site / "injected.pth").write_text(
                "import pathlib; "
                f"pathlib.Path({str(pth_marker)!r}).write_text("
                "'loaded\\n', encoding='ascii')\n"
                f"{pythonpath_root}\n",
                encoding="ascii",
            )
            child_code = (
                "import json,pathlib,sys\n"
                "user_site=str(pathlib.Path(sys.argv[1]).resolve())\n"
                "pythonpath_root=str(pathlib.Path(sys.argv[2]).resolve())\n"
                "try:\n"
                " import injected_from_pythonpath\n"
                "except ModuleNotFoundError:\n"
                " injected=False\n"
                "else:\n"
                " injected=True\n"
                "record={\n"
                " 'dont_write_bytecode':sys.flags.dont_write_bytecode==1,\n"
                " 'isolated':sys.flags.isolated==1,\n"
                " 'no_site':sys.flags.no_site==1,\n"
                " 'pythonpath_imported':injected,\n"
                " 'pythonpath_on_sys_path':pythonpath_root in sys.path,\n"
                " 'sitecustomize_loaded':'sitecustomize' in sys.modules,\n"
                " 'user_site_on_sys_path':user_site in sys.path,\n"
                "}\n"
                "print(json.dumps(record,sort_keys=True,separators=(',',':')))\n"
            )
            environment = os.environ.copy()
            environment.pop("PYTHONHOME", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = str(pythonpath_root)
            environment["PYTHONUSERBASE"] = str(user_base)
            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    child_code,
                    str(user_site),
                    str(pythonpath_root),
                ),
                cwd=child_cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )

            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", "replace"),
            )
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(
                json.loads(completed.stdout.decode("ascii", "strict")),
                {
                    "dont_write_bytecode": True,
                    "isolated": True,
                    "no_site": True,
                    "pythonpath_imported": False,
                    "pythonpath_on_sys_path": False,
                    "sitecustomize_loaded": False,
                    "user_site_on_sys_path": False,
                },
            )
            self.assertFalse(sitecustomize_marker.exists())
            self.assertFalse(pth_marker.exists())
            self.assertEqual(tuple(root.rglob("*.pyc")), ())
            self.assertEqual(tuple(root.rglob("__pycache__")), ())

    def test_bound_close_failure_never_retains_lexical_replacement(self) -> None:
        with owned_temporary_directory("readonly-bound-close-moved-") as root:
            lexical_path = root / "bound"
            self._make_private_directory(lexical_path)
            (lexical_path / "sentinel").write_text("held\n", encoding="ascii")
            moved_path = root / "moved-bound"
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = self._open_parent_binding(
                parent_result_owner,
                lexical_path,
                require_owned_private_parent=True,
            )
            held_identity = binding.object_locator()
            try:
                lexical_path.rename(moved_path)
                self._make_private_directory(lexical_path)
                (lexical_path / "sentinel").write_text(
                    "replacement\n",
                    encoding="ascii",
                )
                evidence = runner._bound_path_evidence(binding)
                close_error = OSError(
                    errno.EIO,
                    "synthetic moved binding close failure",
                )
                with (
                    mock.patch.object(
                        support._DirectoryParentBinding,
                        "close",
                        autospec=True,
                        side_effect=close_error,
                    ),
                    self.assertRaises(OSError) as caught,
                ):
                    binding.close()

                failure = runner._bound_close_failure(
                    binding,
                    caught.exception,
                    evidence=evidence,
                    evidence_error=None,
                )
                descriptor_uri = (
                    "descriptor-object://"
                    f"{held_identity['device']}/{held_identity['inode']}"
                )
                self.assertIn(failure.path, {str(moved_path), descriptor_uri})
                self.assertNotEqual(failure.path, str(lexical_path))
                self.assertIn(failure.path_status, {"bound-moved", "descriptor-object"})
                self.assertEqual(failure.original_path, str(lexical_path))
                self.assertEqual(failure.replacement_path, str(lexical_path))
                self.assertEqual(failure.held_identity, held_identity)
                self.assertEqual(failure.error_kind, "OSError")
                self.assertEqual(failure.error_errno, errno.EIO)
                self.assertEqual(
                    (moved_path / "sentinel").read_text(encoding="ascii"),
                    "held\n",
                )
                self.assertEqual(
                    (lexical_path / "sentinel").read_text(encoding="ascii"),
                    "replacement\n",
                )
            finally:
                parent_result_owner.close()


class _RunnerFilesystemTestCase(unittest.TestCase):
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

    @classmethod
    def _bound_directory_factory(
        cls,
        *paths: pathlib.Path,
    ) -> object:
        remaining = iter(paths)

        def create(
            _parent: pathlib.Path,
            _prefix: str,
            *,
            result_owner: support._PrivateDirectoryCreationResultOwner,
            require_owned_private_parent: bool = True,
            allow_sticky_writable_ancestors: bool | None = None,
        ) -> support._DirectoryParentBinding:
            if allow_sticky_writable_ancestors is not None:
                raise AssertionError(
                    "synthetic ambient runtime creation received explicit policy"
                )
            parent_result_owner = support._DirectoryParentBindingResultOwner()
            binding = cls._open_parent_binding(
                parent_result_owner,
                next(remaining),
                require_owned_private_parent=require_owned_private_parent,
            )
            result_owner.publish(binding)
            return binding

        return create


class SourceCheckoutBindingIntegrationTests(unittest.TestCase):
    @staticmethod
    def _git(repo: pathlib.Path, *arguments: str) -> str:
        environment = runner.bound_git_environment(
            {
                "HOME": str(repo),
            }
        )
        returncode, stdout, stderr = runner.run_bounded(
            (
                runner.selected_git_executable(),
                "--no-pager",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Codex Test",
                "-c",
                "user.email=codex-test@example.invalid",
                "-C",
                str(repo),
                *arguments,
            ),
            cwd=repo,
            environment=environment,
            timeout=10,
            stdout_limit=1024 * 1024,
            stderr_limit=1024 * 1024,
        )
        if returncode != 0 or stderr:
            detail = stderr.decode("utf-8", "replace")[-2_048:]
            raise AssertionError(
                f"synthetic Git command failed ({returncode}): {detail}"
            )
        return stdout.decode("ascii", "strict").strip()

    def test_synthetic_git_uses_bound_toolchain_and_process_owner(self) -> None:
        repo = pathlib.Path("/synthetic/repo")
        environment = {"BOUND": "1"}
        with (
            mock.patch.object(
                runner,
                "selected_git_executable",
                return_value="/trusted/Xcode/usr/bin/git",
            ) as selected_git,
            mock.patch.object(
                runner,
                "bound_git_environment",
                return_value=environment,
            ) as bound_environment,
            mock.patch.object(
                runner,
                "run_bounded",
                return_value=(0, b"synthetic-output\n", b""),
            ) as run_bounded,
        ):
            self.assertEqual(
                self._git(repo, "status", "--porcelain=v1"),
                "synthetic-output",
            )

        selected_git.assert_called_once_with()
        bound_environment.assert_called_once_with({"HOME": str(repo)})
        argv = run_bounded.call_args.args[0]
        self.assertEqual(argv[0], "/trusted/Xcode/usr/bin/git")
        self.assertEqual(argv[-2:], ("status", "--porcelain=v1"))
        self.assertEqual(run_bounded.call_args.kwargs["environment"], environment)
        self.assertEqual(run_bounded.call_args.kwargs["timeout"], 10)
        self.assertEqual(run_bounded.call_args.kwargs["stdout_limit"], 1024 * 1024)
        self.assertEqual(run_bounded.call_args.kwargs["stderr_limit"], 1024 * 1024)

    @classmethod
    @contextlib.contextmanager
    def _synthetic_repository(
        cls,
    ) -> object:
        with owned_temporary_directory("readonly-source-binding-") as root:
            repo = root / "repo"
            repo.mkdir(mode=0o700)
            source = repo / "source"
            source.mkdir(mode=0o700)
            (source / "payload.txt").write_text("original\n", encoding="ascii")
            (repo / ".gitignore").write_text(
                "source/*.ignored\n",
                encoding="ascii",
            )
            cls._git(repo, "init", "-q")
            cls._git(repo, "add", "--all")
            cls._git(repo, "commit", "-q", "-m", "Initial synthetic tree")
            head_sha = cls._git(repo, "rev-parse", "HEAD")
            yield root, repo, source, head_sha

    @staticmethod
    @contextlib.contextmanager
    def _expected_head(value: str | None) -> object:
        with mock.patch.dict(os.environ, {}, clear=False):
            if value is None:
                os.environ.pop(runner.EXPECTED_HEAD_ENV, None)
            else:
                os.environ[runner.EXPECTED_HEAD_ENV] = value
            yield

    @staticmethod
    def _snapshot_budget(
        *,
        observations: int = 256,
        file_bytes: int = 1024 * 1024,
        access_policy_bytes: int = 1024 * 1024,
        path_bytes: int = 1024 * 1024,
        max_depth: int = 16,
    ) -> runner.TreeSnapshotBudget:
        return runner.TreeSnapshotBudget(
            entry_observations_remaining=observations,
            file_read_bytes_remaining=file_bytes,
            access_policy_read_bytes_remaining=access_policy_bytes,
            path_read_bytes_remaining=path_bytes,
            max_depth=max_depth,
        )

    def test_clean_exact_head_binding_and_stable_copy(self) -> None:
        with self._synthetic_repository() as (root, repo, source, head_sha):
            with self._expected_head(head_sha):
                binding = runner._bind_source_checkout(source)
                source_manifest = binding.source_manifest_sha256
                installed = root / "installed"
                copied_manifest = runner._copy_bound_source(
                    source,
                    installed,
                    binding,
                    source_manifest,
                )

            expected_blob_digest = hashlib.sha256(b"original\n").hexdigest()
            expected_head_manifest = hashlib.sha256(
                f"100644 {expected_blob_digest}\t".encode("ascii") + b"payload.txt\0"
            ).hexdigest()
            self.assertEqual(binding.repo_root, repo.resolve())
            self.assertEqual(binding.head_sha, head_sha)
            self.assertEqual(binding.source_relative_path, "source")
            self.assertEqual(binding.source_manifest_sha256, source_manifest)
            self.assertEqual(
                binding.head_subtree_manifest_sha256,
                expected_head_manifest,
            )
            self.assertEqual(copied_manifest, source_manifest)
            self.assertEqual(
                runner._source_manifest_sha256(installed),
                source_manifest,
            )
            self.assertEqual(
                (installed / "payload.txt").read_text(encoding="ascii"),
                "original\n",
            )

    def test_hosted_root_source_copy_projects_nobody_destination_identity(self) -> None:
        source_entry = runner.TreeEntrySnapshot(
            kind="file",
            size=0,
            device=1,
            inode=2,
            generation=0,
            uid=0,
            gid=0,
            mode=0o444,
            flags=0,
            link_count=1,
            digest=hashlib.sha256(b"").hexdigest(),
            xattrs=(),
            acl_entries=(),
        )
        nobody_uid = 65_534
        nobody_gid = 65_534
        expected_destination_manifest = runner._destination_snapshot_manifest_sha256(
            (("payload.py", source_entry),),
            destination_owner_uid=nobody_uid,
            destination_group_gid=nobody_gid,
        )
        self.assertEqual(
            expected_destination_manifest,
            runner._source_snapshot_manifest_sha256(
                {
                    "payload.py": replace(
                        source_entry,
                        uid=nobody_uid,
                        gid=nobody_gid,
                    )
                }
            ),
        )
        self.assertNotEqual(
            expected_destination_manifest,
            runner._source_snapshot_manifest_sha256(
                {"payload.py": replace(source_entry, uid=501)}
            ),
        )
        self.assertNotEqual(
            expected_destination_manifest,
            runner._source_snapshot_manifest_sha256(
                {"payload.py": replace(source_entry, uid=nobody_uid, gid=0)}
            ),
        )

        destination_state = {"gid": 0}

        def destination_metadata(_descriptor: int) -> object:
            return mock.Mock(st_uid=nobody_uid, st_gid=destination_state["gid"])

        def project_group(_descriptor: int, _uid: int, gid: int) -> None:
            destination_state["gid"] = gid

        with (
            mock.patch.object(
                runner,
                "_stable_access_policy_snapshot",
                return_value=((), ()),
            ),
            mock.patch.object(runner, "_copy_bound_xattrs"),
            mock.patch.object(runner.os, "fstat", side_effect=destination_metadata),
            mock.patch.object(runner.os, "fchown", side_effect=project_group) as chown,
            mock.patch.object(runner.os, "fchmod") as chmod,
        ):
            runner._apply_copied_entry_policy(
                10,
                11,
                source_entry,
                scan=self._snapshot_budget(),
                destination_owner_uid=nobody_uid,
                destination_group_gid=nobody_gid,
            )
        chown.assert_called_once_with(11, -1, nobody_gid)
        chmod.assert_called_once_with(11, source_entry.mode)

        with (
            mock.patch.object(
                runner,
                "_stable_access_policy_snapshot",
                return_value=((), ()),
            ),
            mock.patch.object(runner, "_copy_bound_xattrs"),
            mock.patch.object(
                runner.os,
                "fstat",
                return_value=mock.Mock(st_uid=501, st_gid=0),
            ),
            self.assertRaisesRegex(RuntimeError, "expected destination owner"),
        ):
            runner._apply_copied_entry_policy(
                10,
                11,
                source_entry,
                scan=self._snapshot_budget(),
                destination_owner_uid=nobody_uid,
                destination_group_gid=nobody_gid,
            )

        with (
            mock.patch.object(
                runner,
                "_stable_access_policy_snapshot",
                return_value=((), ()),
            ),
            mock.patch.object(runner, "_copy_bound_xattrs"),
            mock.patch.object(
                runner.os,
                "fstat",
                return_value=mock.Mock(st_uid=nobody_uid, st_gid=0),
            ),
            mock.patch.object(runner.os, "fchown"),
            mock.patch.object(runner.os, "fchmod"),
            self.assertRaisesRegex(RuntimeError, "expected destination group"),
        ):
            runner._apply_copied_entry_policy(
                10,
                11,
                source_entry,
                scan=self._snapshot_budget(),
                destination_owner_uid=nobody_uid,
                destination_group_gid=nobody_gid,
            )

    def test_binding_rejects_missing_invalid_and_mismatched_expected_head(
        self,
    ) -> None:
        with self._synthetic_repository() as (_root, _repo, source, head_sha):
            invalid_values = (
                ("missing", None),
                ("short", "a" * 39),
                ("uppercase", "A" * 40),
                ("non-hex", "g" * 40),
            )
            for label, value in invalid_values:
                with (
                    self.subTest(case=label),
                    self._expected_head(value),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "must be one full lowercase SHA-1",
                    ),
                ):
                    runner._bind_source_checkout(source)

            mismatch = "0" * 40
            self.assertNotEqual(mismatch, head_sha)
            with (
                self._expected_head(mismatch),
                self.assertRaisesRegex(
                    RuntimeError,
                    "HEAD does not match the expected exact head",
                ),
            ):
                runner._bind_source_checkout(source)

    def test_binding_rejects_tracked_untracked_and_ignored_inputs(self) -> None:
        cases = (
            (
                "tracked",
                lambda source: (source / "payload.txt").write_text(
                    "modified\n",
                    encoding="ascii",
                ),
                "does not match the exact HEAD",
            ),
            (
                "untracked",
                lambda source: (source / "untracked.txt").write_text(
                    "untracked\n",
                    encoding="ascii",
                ),
                "does not match the exact HEAD",
            ),
            (
                "ignored",
                lambda source: (source / "payload.ignored").write_text(
                    "ignored\n",
                    encoding="ascii",
                ),
                "does not match the exact HEAD",
            ),
            (
                "untracked-empty-directory",
                lambda source: (source / "empty").mkdir(mode=0o700),
                "does not match the exact HEAD",
            ),
            (
                "tracked-mode",
                lambda source: (source / "payload.txt").chmod(0o755),
                "file mode does not match the exact HEAD",
            ),
        )
        for label, mutate, expected_message in cases:
            with (
                self.subTest(case=label),
                self._synthetic_repository() as (
                    _root,
                    _repo,
                    source,
                    head_sha,
                ),
            ):
                mutate(source)
                with (
                    self._expected_head(head_sha),
                    self.assertRaisesRegex(RuntimeError, expected_message),
                ):
                    runner._bind_source_checkout(source)

    def test_binding_rejects_hidden_index_flags(self) -> None:
        cases = (
            ("assume-unchanged", "--assume-unchanged"),
            ("skip-worktree", "--skip-worktree"),
        )
        for label, option in cases:
            with (
                self.subTest(case=label),
                self._synthetic_repository() as (
                    _root,
                    repo,
                    source,
                    head_sha,
                ),
            ):
                self._git(repo, "update-index", option, "source/payload.txt")
                with (
                    self._expected_head(head_sha),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "assume-unchanged or skip-worktree",
                    ),
                ):
                    runner._bind_source_checkout(source)

    def test_binding_rejects_unsafe_local_git_configuration(self) -> None:
        def configure_include(root: pathlib.Path, repo: pathlib.Path) -> None:
            included = root / "included.config"
            included.write_text("[core]\n\tfileMode = true\n", encoding="ascii")
            self._git(repo, "config", "include.path", str(included))

        cases = (
            (
                "filemode",
                lambda _root, repo: self._git(repo, "config", "core.fileMode", "false"),
                "disables core.fileMode",
            ),
            (
                "filter",
                lambda _root, repo: self._git(
                    repo,
                    "config",
                    "filter.synthetic.clean",
                    "/usr/bin/false",
                ),
                "executable filter or diff",
            ),
            (
                "diff",
                lambda _root, repo: self._git(
                    repo,
                    "config",
                    "diff.synthetic.textconv",
                    "/usr/bin/false",
                ),
                "executable filter or diff",
            ),
            (
                "fsmonitor",
                lambda _root, repo: self._git(
                    repo,
                    "config",
                    "core.fsmonitor",
                    "true",
                ),
                "enables core.fsmonitor",
            ),
            (
                "alias",
                lambda _root, repo: self._git(
                    repo,
                    "config",
                    "alias.synthetic",
                    "!/usr/bin/true",
                ),
                "contains an alias",
            ),
            (
                "include",
                configure_include,
                "contains an include",
            ),
        )
        for label, configure, expected_message in cases:
            with (
                self.subTest(case=label),
                self._synthetic_repository() as (
                    root,
                    repo,
                    source,
                    head_sha,
                ),
            ):
                configure(root, repo)
                with (
                    self._expected_head(head_sha),
                    self.assertRaisesRegex(RuntimeError, expected_message),
                ):
                    runner._bind_source_checkout(source)

    def test_snapshot_budget_is_shared_across_observations_bytes_and_passes(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-snapshot-budget-") as root:
            first = root / "first"
            first.write_bytes(b"1234")
            runner._tree_snapshot(
                root,
                budget=self._snapshot_budget(
                    observations=8,
                    file_bytes=40,
                    max_depth=1,
                ),
            )

            with self.assertRaisesRegex(RuntimeError, "entry-observation bound"):
                runner._tree_snapshot(
                    root,
                    budget=self._snapshot_budget(
                        observations=7,
                        file_bytes=40,
                        max_depth=1,
                    ),
                )

            second = root / "second"
            second.write_bytes(b"5678")
            with self.assertRaisesRegex(RuntimeError, "cumulative file byte bound"):
                runner._tree_snapshot(
                    root,
                    budget=self._snapshot_budget(
                        observations=64,
                        file_bytes=40,
                        max_depth=1,
                    ),
                )

            first.unlink()
            second.unlink()
            sparse = root / "sparse"
            with sparse.open("wb") as stream:
                stream.truncate(1024 * 1024)
            with (
                mock.patch.object(
                    runner.os,
                    "pread",
                    side_effect=AssertionError(
                        "oversized sparse content must fail before pread"
                    ),
                ) as pread,
                self.assertRaisesRegex(RuntimeError, "cumulative file byte bound"),
            ):
                runner._tree_snapshot(
                    root,
                    budget=self._snapshot_budget(
                        observations=128,
                        file_bytes=16,
                        max_depth=1,
                    ),
                )
            pread.assert_not_called()

    def test_snapshot_budget_enforces_depth_and_one_deadline_for_both_passes(
        self,
    ) -> None:
        with owned_temporary_directory("readonly-snapshot-depth-") as root:
            nested = root / "nested"
            nested.mkdir(mode=0o700)
            (nested / "payload").write_bytes(b"x")
            runner._tree_snapshot(
                root,
                budget=self._snapshot_budget(max_depth=2),
            )
            with self.assertRaisesRegex(RuntimeError, "depth bound"):
                runner._tree_snapshot(
                    root,
                    budget=self._snapshot_budget(max_depth=1),
                )

        def one_pass(
            _root: pathlib.Path,
            *,
            scan: runner.TreeSnapshotScan,
            expected_kinds: dict[bytes, str] | None = None,
        ) -> dict[str, runner.TreeEntrySnapshot]:
            del expected_kinds
            scan.checkpoint()
            return {}

        with (
            mock.patch.object(
                runner.time, "monotonic", side_effect=(0.0, 59.999, 60.0)
            ),
            mock.patch.object(runner, "_tree_snapshot_once", side_effect=one_pass),
            self.assertRaisesRegex(RuntimeError, "total deadline"),
        ):
            runner._tree_snapshot(pathlib.Path("/synthetic"))

    def test_head_prefix_expansion_obeys_snapshot_depth_and_entry_budget(
        self,
    ) -> None:
        for failure, budget in (
            (
                "depth bound",
                self._snapshot_budget(observations=256, max_depth=2),
            ),
            (
                "entry-observation bound",
                self._snapshot_budget(observations=2, max_depth=16),
            ),
        ):
            with (
                self.subTest(failure=failure),
                self._synthetic_repository() as (_root, repo, source, _head_sha),
            ):
                nested = source / "one" / "two"
                nested.mkdir(mode=0o700, parents=True)
                (nested / "payload.py").write_text("VALUE = 1\n", encoding="ascii")
                self._git(repo, "add", "--all")
                self._git(repo, "commit", "-q", "-m", "Add nested source")
                head_sha = self._git(repo, "rev-parse", "HEAD")
                with (
                    self._expected_head(head_sha),
                    self.assertRaisesRegex(RuntimeError, failure),
                ):
                    runner._bind_source_checkout(source, budget=budget)

    def test_directory_copy_revalidation_consumes_observation_budget(self) -> None:
        with owned_temporary_directory("readonly-directory-copy-budget-") as root:
            source = root / "source"
            nested = source / "nested"
            nested.mkdir(mode=0o700, parents=True)
            (nested / "payload.py").write_text("VALUE = 1\n", encoding="ascii")
            binding = runner._bind_source_tree(
                source,
                budget=self._snapshot_budget(observations=128),
            )
            with self.assertRaisesRegex(RuntimeError, "entry-observation bound"):
                runner._copy_bound_source_tree(
                    source,
                    root / "insufficient",
                    binding,
                    budget=self._snapshot_budget(observations=4),
                    destination_owner_uid=os.geteuid(),
                    destination_group_gid=os.getegid(),
                )
            runner._copy_bound_source_tree(
                source,
                root / "complete",
                binding,
                budget=self._snapshot_budget(observations=5),
                destination_owner_uid=os.geteuid(),
                destination_group_gid=os.getegid(),
            )
            self.assertEqual(
                (root / "complete" / "nested" / "payload.py").read_text(
                    encoding="ascii"
                ),
                "VALUE = 1\n",
            )

    def test_bounded_copy_ignores_concurrent_extra_until_bounded_revalidation(
        self,
    ) -> None:
        with self._synthetic_repository() as (root, _repo, source, head_sha):
            with self._expected_head(head_sha):
                binding = runner._bind_source_checkout(source)
                source_manifest = binding.source_manifest_sha256
                extra = source / "oversized.ignored"
                with extra.open("wb") as stream:
                    stream.truncate(1024 * 1024)
                extra_identity = (extra.stat().st_dev, extra.stat().st_ino)
                real_pread = runner.os.pread

                def reject_extra_pread(
                    descriptor: int,
                    size: int,
                    offset: int,
                ) -> bytes:
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) == extra_identity:
                        raise AssertionError(
                            "bounded copy read a path absent from the exact receipt"
                        )
                    return real_pread(descriptor, size, offset)

                installed = root / "installed"
                with (
                    mock.patch.object(
                        runner.os, "pread", side_effect=reject_extra_pread
                    ),
                    self.assertRaisesRegex(
                        RuntimeError, "does not match the exact HEAD"
                    ),
                ):
                    runner._copy_bound_source(
                        source,
                        installed,
                        binding,
                        source_manifest,
                        budget=self._snapshot_budget(
                            observations=128,
                            file_bytes=1024,
                        ),
                    )

            self.assertFalse((installed / extra.name).exists())
            self.assertEqual(
                (installed / "payload.txt").read_text(encoding="ascii"),
                "original\n",
            )

    def test_post_copy_fanout_is_stopped_by_shared_observation_budget(self) -> None:
        with self._synthetic_repository() as (root, _repo, source, head_sha):
            with self._expected_head(head_sha):
                binding = runner._bind_source_checkout(source)
                source_manifest = binding.source_manifest_sha256
                real_copy = runner._copy_bound_source_tree

                def copy_then_inject_fanout(
                    source_path: pathlib.Path,
                    destination: pathlib.Path,
                    source_receipt: runner.SourceCheckoutBinding,
                    *,
                    budget: runner.TreeSnapshotBudget,
                    destination_owner_uid: int,
                    destination_group_gid: int,
                ) -> None:
                    real_copy(
                        source_path,
                        destination,
                        source_receipt,
                        budget=budget,
                        destination_owner_uid=destination_owner_uid,
                        destination_group_gid=destination_group_gid,
                    )
                    for index in range(64):
                        (source_path / f"extra-{index:02d}.ignored").write_bytes(b"")

                with (
                    mock.patch.object(
                        runner,
                        "_copy_bound_source_tree",
                        side_effect=copy_then_inject_fanout,
                    ),
                    self.assertRaisesRegex(RuntimeError, "entry-observation bound"),
                ):
                    runner._copy_bound_source(
                        source,
                        root / "installed",
                        binding,
                        source_manifest,
                        budget=self._snapshot_budget(observations=24),
                    )

    def test_copy_rejects_source_mutation_during_copy(self) -> None:
        with self._synthetic_repository() as (root, _repo, source, head_sha):
            with self._expected_head(head_sha):
                binding = runner._bind_source_checkout(source)
                source_manifest = binding.source_manifest_sha256
                real_copy = runner._copy_bound_source_tree

                def copy_then_mutate(
                    source_path: pathlib.Path,
                    destination: pathlib.Path,
                    source_receipt: runner.SourceCheckoutBinding,
                    *,
                    budget: runner.TreeSnapshotBudget,
                    destination_owner_uid: int,
                    destination_group_gid: int,
                ) -> None:
                    real_copy(
                        source_path,
                        destination,
                        source_receipt,
                        budget=budget,
                        destination_owner_uid=destination_owner_uid,
                        destination_group_gid=destination_group_gid,
                    )
                    (pathlib.Path(source_path) / "payload.txt").write_text(
                        "mutated during copy\n",
                        encoding="ascii",
                    )

                with (
                    mock.patch.object(
                        runner,
                        "_copy_bound_source_tree",
                        side_effect=copy_then_mutate,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "does not match the exact HEAD|stable exact-head source",
                    ),
                ):
                    runner._copy_bound_source(
                        source,
                        root / "installed",
                        binding,
                        source_manifest,
                    )


class TrustedMacGateBootstrapTests(unittest.TestCase):
    GATE_PATH = pathlib.Path(runner.__file__).with_name("trusted_mac_gate.py")
    GATE_SOURCE = _captured_gate_source_for_nested_tests(GATE_PATH)
    MANIFEST_PATH = GATE_PATH.parents[1] / "trusted_mac_gate_sources.index"

    @classmethod
    def _manifest_payload(cls, root: pathlib.Path) -> bytes:
        records = []
        for package in ("review_supervisor", "tests"):
            for path in sorted(
                (root / package).rglob("*"),
                key=lambda item: os.fsencode(item.relative_to(root)),
            ):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise AssertionError(
                        f"cannot manifest non-regular test source: {path}"
                    )
                payload = path.read_bytes()
                mode = 0o100755 if metadata.st_mode & 0o111 else 0o100644
                relative = path.relative_to(root).as_posix().encode("ascii")
                records.append(
                    f"{mode:o} {len(payload)} {hashlib.sha256(payload).hexdigest()}\t".encode(
                        "ascii"
                    )
                    + relative
                    + b"\n"
                )
        return b"trusted-mac-gate-source-manifest-v1\n" + b"".join(records)

    @classmethod
    def _write_manifest(cls, root: pathlib.Path) -> pathlib.Path:
        manifest = root / "trusted_mac_gate_sources.index"
        manifest.write_bytes(cls._manifest_payload(root))
        return manifest

    @staticmethod
    @contextlib.contextmanager
    def _synthetic_tool_root() -> object:
        with owned_temporary_directory("trusted-mac-gate-") as root:
            review_supervisor = root / "review_supervisor"
            tests = root / "tests"
            review_supervisor.mkdir(mode=0o700)
            tests.mkdir(mode=0o700)
            (review_supervisor / "__init__.py").write_text("", encoding="ascii")
            (review_supervisor / "captured.py").write_text(
                "VALUE = 'captured'\n",
                encoding="ascii",
            )
            (tests / "__init__.py").write_text("", encoding="ascii")
            (tests / "support.py").write_text(
                "from __future__ import annotations\n"
                "import pathlib\n"
                "SOURCE_FILE = pathlib.Path(__file__)\n"
                "SOURCE_ORIGIN = __spec__.origin\n"
                "SOURCE_HAS_LOCATION = __spec__.has_location\n",
                encoding="ascii",
            )
            (tests / "trusted_mac_gate.py").write_text(
                TrustedMacGateBootstrapTests.GATE_SOURCE,
                encoding="utf-8",
            )
            marker = root / "ambient-marker"
            payload = (
                "import json, os, pathlib, sys\n"
                "from . import support\n"
                f"marker = pathlib.Path({str(marker)!r})\n"
                "print(json.dumps({\n"
                "    'environment': dict(sorted(os.environ.items())),\n"
                "    'flags': {\n"
                "        'isolated': sys.flags.isolated,\n"
                "        'ignore_environment': sys.flags.ignore_environment,\n"
                "        'no_site': sys.flags.no_site,\n"
                "        'no_user_site': sys.flags.no_user_site,\n"
                "        'safe_path': sys.flags.safe_path,\n"
                "        'dont_write_bytecode': sys.dont_write_bytecode,\n"
                "    },\n"
                "    'marker_exists': marker.exists(),\n"
                "    'support_file': str(support.SOURCE_FILE),\n"
                "    'support_has_location': support.SOURCE_HAS_LOCATION,\n"
                "    'support_origin': support.SOURCE_ORIGIN,\n"
                "    'sys_path': sys.path,\n"
                "    'tests_package_path': list(sys.modules['tests'].__path__),\n"
                "}, sort_keys=True))\n"
            )
            (tests / "run_required_no_child_profile.py").write_text(
                payload,
                encoding="ascii",
            )
            (tests / "run_readonly_install_deterministic_supervisor.py").write_text(
                payload,
                encoding="ascii",
            )
            TrustedMacGateBootstrapTests._write_manifest(root)
            yield root, marker

    @staticmethod
    def _run_gate(
        root: pathlib.Path,
        *arguments: str,
        isolated: bool = True,
        extra_environment: dict[str, str] | None = None,
        manifest_digest: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = ["/usr/bin/env", "-i", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"]
        if extra_environment:
            command.extend(
                f"{key}={value}" for key, value in sorted(extra_environment.items())
            )
        command.append(sys.executable)
        command.extend(("-I", "-B", "-S") if isolated else ("-B", "-S"))
        manifest = root / "trusted_mac_gate_sources.index"
        digest = manifest_digest or hashlib.sha256(manifest.read_bytes()).hexdigest()
        command.extend(("-", str(root), str(manifest), digest, *arguments))
        return subprocess.run(
            command,
            cwd=root,
            input=TrustedMacGateBootstrapTests.GATE_SOURCE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=20,
        )

    @classmethod
    def _load_gate_module(cls) -> object:
        spec = importlib.util.spec_from_file_location(
            "_trusted_mac_gate_budget_test",
            cls.GATE_PATH,
        )
        if spec is None or spec.loader is None:
            raise AssertionError("cannot load trusted gate test module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
        return module

    def test_source_only_bootstrap_ignores_ambient_python_startup(self) -> None:
        with self._synthetic_tool_root() as (root, marker):
            hostile = root / "hostile-python"
            hostile.mkdir(mode=0o700)
            marker_script = (
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('executed', encoding='ascii')\n"
            )
            (hostile / "sitecustomize.py").write_text(
                marker_script,
                encoding="ascii",
            )
            (hostile / "usercustomize.py").write_text(
                marker_script,
                encoding="ascii",
            )
            (hostile / "ambient.pth").write_text(
                f"import pathlib; pathlib.Path({str(marker)!r}).write_text('pth')\n",
                encoding="ascii",
            )
            hostile_environment = {
                "HOME": str(hostile),
                "PYTHONHOME": str(hostile),
                "PYTHONPATH": str(hostile),
                "PYTHONUSERBASE": str(hostile),
            }
            cases = (("live", ("live",), "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"),)
            for label, arguments, expected_key in cases:
                with self.subTest(mode=label):
                    completed = self._run_gate(
                        root,
                        *arguments,
                        extra_environment=hostile_environment,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stderr, "")
                    result = json.loads(completed.stdout)
                    self.assertEqual(
                        result["flags"],
                        {
                            "dont_write_bytecode": True,
                            "ignore_environment": 1,
                            "isolated": 1,
                            "no_site": 1,
                            "no_user_site": 1,
                            "safe_path": True,
                        },
                    )
                    self.assertIn(expected_key, result["environment"])
                    self.assertNotEqual(result["environment"]["HOME"], str(hostile))
                    self.assertNotIn(str(hostile), result["sys_path"])
                    self.assertNotIn(str(root), result["sys_path"])
                    self.assertIs(result["marker_exists"], False)
                    support_path = root / "tests" / "support.py"
                    self.assertEqual(result["support_file"], str(support_path))
                    self.assertIs(result["support_has_location"], True)
                    self.assertEqual(result["support_origin"], str(support_path))
                    self.assertEqual(result["tests_package_path"], [])
                    self.assertFalse(marker.exists())
                    self.assertFalse(tuple(root.rglob("__pycache__")))

    def test_hosted_git_receipt_is_closed_and_binds_runtime_environment(self) -> None:
        gate = self._load_gate_module()
        account = pwd.getpwuid(os.getuid())
        paths = {
            "runtime": "/private/runtime",
            "home": "/private/home",
            "developer": "/Applications/Trusted.app/Contents/Developer",
            "executable": "/Applications/Trusted.app/Contents/Developer/usr/bin/git",
            "exec_path": (
                "/Applications/Trusted.app/Contents/Developer/usr/libexec/git-core"
            ),
        }
        record = {
            "developer_dir": paths["developer"],
            "exec_path": paths["exec_path"],
            "exec_path_sha256": "a" * 64,
            "executable": paths["executable"],
            "executable_sha256": "b" * 64,
            "schema": "hosted-git-toolchain-receipt-v2",
            "toolchain_sha256": "c" * 64,
        }

        def toolchain_payload(**overrides: str) -> bytes:
            return (
                json.dumps(
                    {**record, **overrides},
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")

        receipt_payload = toolchain_payload()
        receipt = receipt_payload[:-1].decode("ascii")
        arguments = [
            paths["runtime"],
            paths["home"],
            paths["developer"],
            paths["executable"],
            "b" * 64,
            paths["exec_path"],
            receipt,
            account.pw_name,
            str(account.pw_uid),
            str(account.pw_gid),
            "e" * 64,
        ]
        with mock.patch.object(
            gate,
            "_hosted_git_receipt_payload",
            return_value=receipt_payload,
        ) as measure:
            environment = gate._validate_hosted_git_toolchain(arguments)
        self.assertEqual(
            environment,
            {
                "CODEX_REVIEW_BOUND_GIT_DEVELOPER_DIR": paths["developer"],
                "CODEX_REVIEW_BOUND_GIT_EXECUTABLE": paths["executable"],
                "CODEX_REVIEW_BOUND_GIT_EXEC_PATH": paths["exec_path"],
                "CODEX_REVIEW_BOUND_GIT_RECEIPT_SHA256": hashlib.sha256(
                    receipt_payload
                ).hexdigest(),
                "CODEX_REVIEW_BOUND_GIT_TMPDIR": paths["runtime"],
                "CODEX_REVIEW_DEDICATED_ACCOUNT_CUSTODY_SHA256": "e" * 64,
                "HOME": paths["home"],
                "TMPDIR": paths["runtime"],
            },
        )
        measure.assert_called_once_with(
            [
                paths["developer"],
                paths["executable"],
                "b" * 64,
                paths["exec_path"],
            ]
        )

        bound_environment = {
            key: value
            for key, value in environment.items()
            if key.startswith("CODEX_REVIEW_BOUND_GIT_")
        }
        binding_arguments = [
            paths["runtime"],
            paths["developer"],
            paths["executable"],
            "b" * 64,
            paths["exec_path"],
            receipt,
            "tmpdir-custody-receipt",
        ]
        tmpdir_custody_payload = b"canonical-tmpdir-custody-receipt\n"
        with (
            mock.patch.object(
                gate,
                "_hosted_git_receipt_payload",
                return_value=receipt_payload,
            ),
            mock.patch.object(
                gate,
                "_validate_trusted_git_tmpdir",
                return_value=tmpdir_custody_payload,
            ) as validate_tmpdir,
        ):
            local_environment = gate._validate_bound_git_toolchain(
                binding_arguments,
                profile=gate.TRUSTED_MAC_GIT_BINDING_PROFILE,
            )
        expected_tmpdir_validation = mock.call(
            pathlib.Path(paths["runtime"]),
            "tmpdir-custody-receipt",
        )
        self.assertEqual(
            validate_tmpdir.call_args_list,
            [expected_tmpdir_validation, expected_tmpdir_validation],
        )
        self.assertEqual(
            local_environment["CODEX_REVIEW_BOUND_GIT_RECEIPT_SHA256"],
            hashlib.sha256(
                b"trusted-mac-bound-git-profile-v3\0"
                + hashlib.sha256(receipt_payload).digest()
                + hashlib.sha256(tmpdir_custody_payload).digest()
            ).hexdigest(),
        )
        measurement_failure = RuntimeError("synthetic toolchain measurement failure")
        custody_failure = RuntimeError("synthetic post-measurement custody drift")
        with (
            mock.patch.object(
                gate,
                "_hosted_git_receipt_payload",
                side_effect=measurement_failure,
            ),
            mock.patch.object(
                gate,
                "_validate_trusted_git_tmpdir",
                side_effect=(tmpdir_custody_payload, custody_failure),
            ) as validate_drifting_tmpdir,
            self.assertRaises(RuntimeError) as dual_failure,
        ):
            gate._validate_bound_git_toolchain(
                binding_arguments,
                profile=gate.TRUSTED_MAC_GIT_BINDING_PROFILE,
            )
        self.assertIs(dual_failure.exception, measurement_failure)
        self.assertEqual(
            dual_failure.exception.codex_secondary_failures,
            (custody_failure,),
        )
        self.assertEqual(
            validate_drifting_tmpdir.call_args_list,
            [expected_tmpdir_validation, expected_tmpdir_validation],
        )
        readonly_arguments = ["a" * 40, *binding_arguments]
        cleared_environment: dict[str, str] = {}
        with (
            mock.patch.object(
                gate,
                "_validate_bound_git_toolchain",
                return_value=bound_environment,
            ) as validate,
            mock.patch.object(gate.os, "environ", cleared_environment),
        ):
            module = gate._configure_environment("readonly", readonly_arguments)
            selected_git = runner.selected_git_executable()
            git_environment = runner.bound_git_environment()
        self.assertEqual(
            module,
            "tests.run_readonly_install_deterministic_supervisor",
        )
        validate.assert_called_once_with(
            binding_arguments,
            profile=gate.TRUSTED_MAC_GIT_BINDING_PROFILE,
        )
        self.assertEqual(
            {key: cleared_environment[key] for key in bound_environment},
            bound_environment,
        )
        self.assertEqual(cleared_environment[runner.EXPECTED_HEAD_ENV], "a" * 40)
        self.assertEqual(
            cleared_environment["CODEX_REVIEW_TEST_RUNTIME_PARENT"],
            paths["runtime"],
        )
        self.assertEqual(selected_git, paths["executable"])
        self.assertNotEqual(selected_git, "/usr/bin/git")
        self.assertEqual(git_environment["DEVELOPER_DIR"], paths["developer"])
        self.assertEqual(git_environment["GIT_EXEC_PATH"], paths["exec_path"])
        self.assertEqual(git_environment["TMPDIR"], paths["runtime"])

        with (
            mock.patch.object(gate.os, "environ", {}),
            self.assertRaisesRegex(RuntimeError, "trusted Git binding requires"),
        ):
            gate._configure_environment("readonly", ["a" * 40])
        mismatched_arguments = list(binding_arguments)
        mismatched_arguments[2] = paths["executable"] + "-replacement"
        with self.assertRaisesRegex(RuntimeError, "does not bind"):
            gate._validate_bound_git_toolchain(
                mismatched_arguments[:6],
                profile=gate.HOSTED_GIT_BINDING_PROFILE,
            )
        drifted_payload = toolchain_payload(exec_path_sha256="e" * 64)
        with (
            mock.patch.object(
                gate,
                "_hosted_git_receipt_payload",
                return_value=drifted_payload,
            ) as measure,
            self.assertRaisesRegex(RuntimeError, "does not match its receipt"),
        ):
            gate._validate_bound_git_toolchain(
                binding_arguments[:6],
                profile=gate.HOSTED_GIT_BINDING_PROFILE,
            )
        measure.assert_called_once_with(
            [
                paths["developer"],
                paths["executable"],
                "b" * 64,
                paths["exec_path"],
            ]
        )

        with owned_temporary_directory("trusted-git-tmpdir-") as root:
            trusted_tmp = root / "runtime"
            other_tmp = root / "other"
            replacement_tmp = root / "replacement"
            trusted_tmp.mkdir(mode=0o700)
            other_tmp.mkdir(mode=0o700)
            replacement_tmp.mkdir(mode=0o700)
            with (
                mock.patch.dict(
                    os.environ,
                    {"CODEX_REVIEW_TEST_RUNTIME_PARENT": str(trusted_tmp)},
                ),
                mock.patch.object(
                    support,
                    "_repository_runtime_candidates",
                    side_effect=AssertionError("ambient repository fallback ran"),
                ),
                mock.patch.object(
                    support.shutil,
                    "which",
                    side_effect=AssertionError("unbound Git lookup ran"),
                ),
                mock.patch.object(
                    support.subprocess,
                    "run",
                    side_effect=AssertionError("unbound Git subprocess ran"),
                ),
                mock.patch.object(
                    support,
                    "open_absolute_directory_chain",
                    wraps=support.open_absolute_directory_chain,
                ) as open_runtime_parent,
            ):
                self.assertEqual(support._private_runtime_parent(), trusted_tmp)
            self.assertTrue(open_runtime_parent.call_args_list)
            self.assertTrue(
                all(
                    call.kwargs["allow_sticky_writable_ancestors"]
                    for call in open_runtime_parent.call_args_list
                )
            )

            unsafe_runtime_ancestor = root / "unsafe-runtime-ancestor"
            unsafe_runtime_parent = unsafe_runtime_ancestor / "private"
            unsafe_runtime_ancestor.mkdir(mode=0o700)
            unsafe_runtime_parent.mkdir(mode=0o700)
            unsafe_runtime_ancestor.chmod(0o777)
            try:
                rejection_errors: list[BaseException] = []
                self.assertIsNone(
                    support._validated_private_runtime_parent(
                        str(unsafe_runtime_parent),
                        allow_sticky_writable_ancestors=True,
                        rejection_errors=rejection_errors,
                    )
                )
                self.assertTrue(rejection_errors)
            finally:
                unsafe_runtime_ancestor.chmod(0o700)

            if sys.platform == "darwin" and pathlib.Path("/private/tmp").is_dir():
                with tempfile.TemporaryDirectory(
                    prefix="codex-safe-sticky-runtime-",
                    dir="/private/tmp",
                ) as raw_sticky_runtime:
                    sticky_runtime = pathlib.Path(raw_sticky_runtime)
                    sticky_runtime.chmod(0o700)
                    self.assertEqual(
                        support._validated_private_runtime_parent(
                            str(sticky_runtime),
                            allow_sticky_writable_ancestors=True,
                        ),
                        sticky_runtime,
                    )
            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=0),
                mock.patch.object(gate, "_macos_fd_xattr_names", return_value=()),
            ):
                tmpdir_payload = gate._trusted_git_tmpdir_receipt_payload(
                    [str(trusted_tmp)]
                )
                tmpdir_receipt = tmpdir_payload[:-1].decode("ascii")
                parsed_tmpdir_receipt = json.loads(tmpdir_payload)
                self.assertEqual(
                    parsed_tmpdir_receipt["schema"],
                    "trusted-git-tmpdir-custody-v1",
                )
                self.assertEqual(parsed_tmpdir_receipt["path"], str(trusted_tmp))
                self.assertEqual(
                    parsed_tmpdir_receipt["group_gid"], trusted_tmp.stat().st_gid
                )
                physical_chain = parsed_tmpdir_receipt["physical_chain"]
                self.assertEqual(len(physical_chain), len(trusted_tmp.parts))
                self.assertEqual(
                    set(physical_chain[-1]),
                    {
                        "device",
                        "file_type",
                        "flags",
                        "group_gid",
                        "inode",
                        "mode",
                        "owner_uid",
                    },
                )
                self.assertEqual(physical_chain[-1]["file_type"], stat.S_IFDIR)
                self.assertEqual(physical_chain[-1]["mode"], 0o700)
                self.assertEqual(physical_chain[-1]["inode"], trusted_tmp.stat().st_ino)
                self.assertEqual(
                    gate._validate_trusted_git_tmpdir(
                        trusted_tmp,
                        tmpdir_receipt,
                    ),
                    tmpdir_payload,
                )
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    gate._validate_trusted_git_tmpdir(other_tmp, tmpdir_receipt)
                with self.assertRaisesRegex(RuntimeError, "missing"):
                    gate._trusted_git_tmpdir_receipt_payload([str(root / "missing")])
                with self.assertRaises(RuntimeError):
                    gate._trusted_git_tmpdir_receipt_payload(["/tmp"])

                child = trusted_tmp / "benign-child"
                child.mkdir(mode=0o700)
                self.assertEqual(
                    gate._trusted_git_tmpdir_receipt_payload([str(trusted_tmp)]),
                    tmpdir_payload,
                )
                with mock.patch.object(
                    gate,
                    "_macos_fd_xattr_names",
                    return_value=(b"com.apple.provenance",),
                ):
                    self.assertEqual(
                        gate._trusted_git_tmpdir_receipt_payload([str(trusted_tmp)]),
                        tmpdir_payload,
                    )

                policy_parent = root / "policy-parent"
                stable_leaf = policy_parent / "stable-leaf"
                policy_parent.mkdir(mode=0o700)
                stable_leaf.mkdir(mode=0o700)
                stable_leaf_payload = gate._trusted_git_tmpdir_receipt_payload(
                    [str(stable_leaf)]
                )
                stable_leaf_receipt = stable_leaf_payload[:-1].decode("ascii")
                policy_parent.chmod(0o755)
                try:
                    with self.assertRaisesRegex(RuntimeError, "does not match"):
                        gate._validate_trusted_git_tmpdir(
                            stable_leaf,
                            stable_leaf_receipt,
                        )
                finally:
                    policy_parent.chmod(0o700)

                original_leaf_inode = stable_leaf.stat().st_ino
                retained_parent = root / "retained-policy-parent"
                policy_parent.rename(retained_parent)
                policy_parent.mkdir(mode=0o700)
                (retained_parent / stable_leaf.name).rename(stable_leaf)
                self.assertEqual(stable_leaf.stat().st_ino, original_leaf_inode)
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    gate._validate_trusted_git_tmpdir(
                        stable_leaf,
                        stable_leaf_receipt,
                    )

                unsafe_ancestor = root / "unsafe-ancestor"
                unsafe_target = unsafe_ancestor / "target"
                unsafe_ancestor.mkdir(mode=0o700)
                unsafe_target.mkdir(mode=0o700)
                unsafe_ancestor.chmod(0o777)
                try:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "unsafe writable ancestor",
                    ):
                        gate._trusted_git_tmpdir_receipt_payload([str(unsafe_target)])
                finally:
                    unsafe_ancestor.chmod(0o700)

                trusted_tmp.chmod(0o777)
                try:
                    with self.assertRaisesRegex(RuntimeError, "unsafe access policy"):
                        gate._trusted_git_tmpdir_receipt_payload([str(trusted_tmp)])
                finally:
                    trusted_tmp.chmod(0o700)

                replacement_receipt = gate._trusted_git_tmpdir_receipt_payload(
                    [str(replacement_tmp)]
                )[:-1].decode("ascii")
                retained_tmp = root / "retained-original"
                replacement_tmp.rename(retained_tmp)
                replacement_tmp.mkdir(mode=0o700)
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    gate._validate_trusted_git_tmpdir(
                        replacement_tmp,
                        replacement_receipt,
                    )

            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=1),
                mock.patch.object(gate, "_macos_fd_xattr_names", return_value=()),
                self.assertRaisesRegex(RuntimeError, "unsafe ACL or xattr"),
            ):
                gate._validate_trusted_git_tmpdir(trusted_tmp, tmpdir_receipt)
            if sys.platform == "darwin" and pathlib.Path("/private/tmp").is_dir():
                with tempfile.TemporaryDirectory(
                    prefix="codex-git-custody-physical-",
                    dir="/private/tmp",
                ) as raw_actual_tmp:
                    actual_tmp = pathlib.Path(raw_actual_tmp)
                    actual_tmp.chmod(0o700)
                    actual_metadata_payload = gate._trusted_git_tmpdir_receipt_payload(
                        [str(actual_tmp)]
                    )
                    self.assertIn(
                        b'"schema":"trusted-git-tmpdir-custody-v1"',
                        actual_metadata_payload,
                    )
            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=0),
                mock.patch.object(
                    gate,
                    "_macos_fd_xattr_names",
                    return_value=(b"com.apple.quarantine",),
                ),
                self.assertRaisesRegex(RuntimeError, "unsafe ACL or xattr"),
            ):
                gate._validate_trusted_git_tmpdir(trusted_tmp, tmpdir_receipt)

            root_owned_sticky = os.stat_result(
                (stat.S_IFDIR | 0o1777, 1, 1, 1, 0, 0, 0, 0, 0, 0),
                {"st_flags": 0},
            )
            current_uid_target = os.stat_result(
                (
                    stat.S_IFDIR | 0o700,
                    2,
                    1,
                    1,
                    os.getuid(),
                    os.getgid(),
                    0,
                    0,
                    0,
                    0,
                ),
                {"st_flags": 0},
            )
            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=0),
                mock.patch.object(
                    gate,
                    "_macos_fd_xattr_names",
                    side_effect=lambda descriptor: (
                        (b"com.apple.rootless",) if descriptor == 10 else ()
                    ),
                ),
            ):
                gate._validate_directory_chain_access_policy(
                    [10, 11],
                    (root_owned_sticky, current_uid_target),
                )
            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=0),
                mock.patch.object(
                    gate,
                    "_macos_fd_xattr_names",
                    side_effect=lambda descriptor: (
                        (b"com.apple.rootless",) if descriptor == 11 else ()
                    ),
                ),
                self.assertRaisesRegex(RuntimeError, "unsafe ACL or xattr"),
            ):
                gate._validate_directory_chain_access_policy(
                    [10, 11],
                    (root_owned_sticky, current_uid_target),
                )
            untrusted_owner = os.stat_result(
                (
                    stat.S_IFDIR | 0o755,
                    3,
                    1,
                    1,
                    os.getuid() + 1,
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
                {"st_flags": 0},
            )
            with (
                mock.patch.object(gate, "_macos_acl_entry_count", return_value=0),
                mock.patch.object(gate, "_macos_fd_xattr_names", return_value=()),
                self.assertRaisesRegex(RuntimeError, "untrusted ancestor owner"),
            ):
                gate._validate_directory_chain_access_policy(
                    [10, 11],
                    (untrusted_owner, current_uid_target),
                )

            close_calls: list[int] = []

            def close_all_descriptors(descriptor: int) -> None:
                close_calls.append(descriptor)
                if descriptor == 12:
                    raise OSError(errno.EIO, "synthetic descriptor close failure")

            synthetic_descriptors = [10, 11, 12]
            with mock.patch.object(
                gate.os,
                "close",
                side_effect=close_all_descriptors,
            ):
                close_failures = gate._close_directory_chain(synthetic_descriptors)
            self.assertEqual(close_calls, [12, 11, 10])
            self.assertEqual(synthetic_descriptors, [])
            self.assertEqual(len(close_failures), 1)
            inspection_failure = RuntimeError("synthetic inspection failure")
            try:
                raise inspection_failure
            except RuntimeError:
                with self.assertRaises(RuntimeError) as cleanup_group:
                    gate._raise_directory_chain_cleanup_failures(close_failures)
            self.assertIs(cleanup_group.exception, inspection_failure)
            self.assertEqual(
                cleanup_group.exception.codex_secondary_failures,
                close_failures,
            )

        invalid_records = (
            receipt + "\n",
            receipt.replace('"schema":', '"unknown":"value","schema":'),
            receipt.replace(
                '"toolchain_sha256":"' + "c" * 64,
                '"toolchain_sha256":"' + "C" * 64,
            ),
            receipt.replace("receipt-v2", "receipt-v1"),
            json.dumps(record, ensure_ascii=True),
        )
        for invalid in invalid_records:
            with self.subTest(receipt=invalid[:80]), self.assertRaises(RuntimeError):
                gate._parse_hosted_git_receipt(invalid)

    def test_hosted_git_receipt_payload_is_canonical_and_helper_bound(self) -> None:
        gate = self._load_gate_module()
        arguments = [
            "/Applications/Trusted.app/Contents/Developer",
            "/Applications/Trusted.app/Contents/Developer/usr/bin/git",
            "b" * 64,
            "/Applications/Trusted.app/Contents/Developer/usr/libexec/git-core",
        ]
        with mock.patch.object(
            gate,
            "_measure_hosted_git_toolchain",
            return_value=("a" * 64, "c" * 64),
        ) as measure:
            payload = gate._hosted_git_receipt_payload(arguments)
        self.assertLessEqual(len(payload), gate.GIT_TOOLCHAIN_RECEIPT_LIMIT_BYTES)
        self.assertEqual(payload.count(b"\n"), 1)
        self.assertTrue(payload.endswith(b"\n"))
        parsed = gate._parse_hosted_git_receipt(payload[:-1].decode("ascii"))
        self.assertEqual(
            parsed,
            {
                "developer_dir": arguments[0],
                "exec_path": arguments[3],
                "exec_path_sha256": "a" * 64,
                "executable": arguments[1],
                "executable_sha256": "b" * 64,
                "schema": "hosted-git-toolchain-receipt-v2",
                "toolchain_sha256": "c" * 64,
            },
        )
        measure.assert_called_once_with(arguments)

        with owned_temporary_directory("hosted-git-helper-escape-") as root:
            developer = root / "Developer"
            exec_path = developer / "usr" / "libexec" / "git-core"
            exec_path.mkdir(parents=True)
            outside = root / "outside-helper"
            outside.write_bytes(b"outside")
            (exec_path / "git-helper").symlink_to(outside)

            def readonly_access(_path: object, mode: int) -> bool:
                return not bool(mode & os.W_OK)

            with (
                mock.patch.object(gate.os, "access", side_effect=readonly_access),
                self.assertRaisesRegex(RuntimeError, "escapes the Developer directory"),
            ):
                gate._snapshot_git_exec_path(exec_path, developer_dir=developer)

            (exec_path / "git-helper").unlink()
            executable = developer / "usr" / "bin" / "git"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"first!")
            (exec_path / "git-helper").symlink_to("../../bin/git")
            with mock.patch.object(
                gate.os,
                "access",
                side_effect=readonly_access,
            ):
                before = gate._snapshot_git_exec_path(
                    exec_path,
                    developer_dir=developer,
                )
                executable.write_bytes(b"second")
                after = gate._snapshot_git_exec_path(
                    exec_path,
                    developer_dir=developer,
                )
            self.assertNotEqual(before, after)

            temporary_directory = root / "runtime"
            temporary_directory.mkdir(mode=0o700)
            executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            receipt_arguments = [
                str(developer),
                str(executable),
                executable_digest,
                str(exec_path),
            ]
            with (
                mock.patch.object(
                    gate,
                    "_require_candidate_readonly_physical_chain",
                ),
                mock.patch.object(gate.os, "access", side_effect=readonly_access),
            ):
                fresh_receipt = gate._hosted_git_receipt_payload(receipt_arguments)
                parsed_receipt = gate._parse_hosted_git_receipt(
                    fresh_receipt[:-1].decode("ascii")
                )
                self.assertEqual(
                    parsed_receipt["schema"],
                    "hosted-git-toolchain-receipt-v2",
                )
                self.assertNotIn("version_sha256", parsed_receipt)
                (exec_path / "added-helper").write_bytes(b"additional helper")
                with self.assertRaisesRegex(
                    RuntimeError,
                    "does not match its receipt",
                ):
                    gate._validate_bound_git_toolchain(
                        [
                            str(temporary_directory),
                            *receipt_arguments,
                            fresh_receipt[:-1].decode("ascii"),
                        ],
                        profile=gate.HOSTED_GIT_BINDING_PROFILE,
                    )
                with self.assertRaisesRegex(
                    RuntimeError,
                    "requires Developer, executable, digest, and exec-path",
                ):
                    gate._hosted_git_receipt_payload(
                        [*receipt_arguments, str(temporary_directory)]
                    )

    def test_source_only_bootstrap_rejects_substitutes_and_nonisolated_start(
        self,
    ) -> None:
        mutators = (
            (
                "symlink",
                lambda root: (root / "review_supervisor" / "alias.py").symlink_to(
                    "__init__.py"
                ),
                "contains a symlink",
            ),
            (
                "native-substitute",
                lambda root: (root / "review_supervisor" / "native.so").write_bytes(
                    b"synthetic"
                ),
                "contains a substitute",
            ),
            (
                "bytecode-cache",
                lambda root: (root / "review_supervisor" / "__pycache__").mkdir(),
                "contains __pycache__",
            ),
            (
                "duplicate-module",
                self._create_duplicate_module,
                "maps duplicate module",
            ),
        )
        for label, mutate, expected_message in mutators:
            with (
                self.subTest(case=label),
                self._synthetic_tool_root() as (root, _marker),
            ):
                mutate(root)
                completed = self._run_gate(root, "live")
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(expected_message, completed.stderr)

        with self._synthetic_tool_root() as (root, _marker):
            completed = self._run_gate(root, "live", isolated=False)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("requires -I -B -S", completed.stderr)

            completed = self._run_gate(root, "readonly", "A" * 40)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("requires one full SHA-1", completed.stderr)

            direct = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    str(root / "tests" / "trusted_mac_gate.py"),
                    "live",
                ),
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertNotEqual(direct.returncode, 0)
            self.assertIn("bounded trusted stdin", direct.stderr)

    def test_external_bootstrap_rejects_gate_replacement_before_execution(self) -> None:
        with self._synthetic_tool_root() as (root, marker):
            gate_path = root / "tests" / "trusted_mac_gate.py"
            gate_path.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='ascii')\n",
                encoding="ascii",
            )
            completed = self._run_gate(root, "live")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("does not match the exact manifest", completed.stderr)
            self.assertFalse(marker.exists())

            gate_path.unlink()
            gate_path.symlink_to("run_required_no_child_profile.py")
            completed = self._run_gate(root, "live")
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("contains a symlink", completed.stderr)
            self.assertFalse(marker.exists())

    def test_source_manifest_binds_content_mode_inventory_and_captured_bytes(
        self,
    ) -> None:
        self.assertEqual(
            self.MANIFEST_PATH.read_bytes(),
            self._manifest_payload(self.GATE_PATH.parents[1]),
        )

        cases = (
            (
                "content",
                lambda root: (root / "review_supervisor" / "captured.py").write_text(
                    "VALUE = 'mutated'\n", encoding="ascii"
                ),
                "does not match the exact manifest",
            ),
            (
                "mode",
                lambda root: (root / "review_supervisor" / "captured.py").chmod(0o755),
                "does not match the exact manifest",
            ),
            (
                "extra",
                lambda root: (root / "tests" / "extra.txt").write_text(
                    "extra\n", encoding="ascii"
                ),
                "unexpected file",
            ),
            (
                "missing",
                lambda root: (root / "review_supervisor" / "captured.py").unlink(),
                "missing exact manifest entries",
            ),
        )
        for label, mutate, message in cases:
            with self.subTest(case=label), self._synthetic_tool_root() as (root, _):
                mutate(root)
                completed = self._run_gate(root, "live")
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(message, completed.stderr)

        with self._synthetic_tool_root() as (root, _marker):
            completed = self._run_gate(
                root,
                "live",
                manifest_digest="0" * 64,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("manifest digest mismatch", completed.stderr)

        gate = self._load_gate_module()
        with self._synthetic_tool_root() as (root, _marker):
            manifest_path = root / "trusted_mac_gate_sources.index"
            manifest_payload = gate._read_source_manifest(
                manifest_path,
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            )
            sources = gate._snapshot_sources(
                root,
                gate._parse_source_manifest(manifest_payload),
            )
            (root / "review_supervisor" / "captured.py").write_text(
                "VALUE = 'mutated-after-snapshot'\n",
                encoding="ascii",
            )
            spec = gate._ClosedSourceFinder(sources).find_spec(
                "review_supervisor.captured"
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(module.VALUE, "captured")
            self.assertEqual(
                module.__file__,
                str(root / "review_supervisor" / "captured.py"),
            )
            self.assertIs(module.__spec__.has_location, True)

    def test_gate_file_budget_uses_opened_size_and_link_count(self) -> None:
        gate = self._load_gate_module()
        with owned_temporary_directory("trusted-gate-open-budget-") as root:
            payload = root / "payload.py"
            payload.write_bytes(b"x")
            parent_descriptor = os.open(
                root,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
            )
            real_open = os.open
            try:
                for mutation in ("grow", "hardlink"):
                    with self.subTest(mutation=mutation):
                        payload.write_bytes(b"x")
                        alias = root / "payload-link.py"
                        if alias.exists():
                            alias.unlink()

                        def mutate_then_open(
                            name: str,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            if mutation == "grow":
                                mutation_descriptor = real_open(
                                    payload,
                                    os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC,
                                )
                                try:
                                    os.write(
                                        mutation_descriptor,
                                        b"x" * (gate.SOURCE_FILE_LIMIT_BYTES + 1),
                                    )
                                finally:
                                    os.close(mutation_descriptor)
                            else:
                                os.link(payload, alias)
                            return real_open(name, flags, mode, dir_fd=dir_fd)

                        with (
                            mock.patch.object(
                                gate.os,
                                "open",
                                side_effect=mutate_then_open,
                            ),
                            mock.patch.object(
                                gate.os,
                                "read",
                                side_effect=AssertionError(
                                    "mutated source must fail before read"
                                ),
                            ) as read,
                            self.assertRaisesRegex(
                                OSError,
                                "changed while opening",
                            ),
                        ):
                            gate._read_source_at(
                                parent_descriptor,
                                payload.name,
                                payload,
                                budget=gate._SnapshotBudget(),
                            )
                        read.assert_not_called()
                        if alias.exists():
                            alias.unlink()
            finally:
                os.close(parent_descriptor)

    @staticmethod
    def _create_duplicate_module(root: pathlib.Path) -> None:
        package = root / "review_supervisor"
        (package / "duplicate.py").write_text("", encoding="ascii")
        duplicate = package / "duplicate"
        duplicate.mkdir(mode=0o700)
        (duplicate / "__init__.py").write_text("", encoding="ascii")
        TrustedMacGateBootstrapTests._write_manifest(root)


class RunnerPathSelectionTests(_RunnerFilesystemTestCase):
    SOURCE_HEAD = "a" * 40
    SOURCE_MANIFEST = "b" * 64
    SOURCE_HEAD_MANIFEST = "c" * 64

    def _run_selected_path(
        self,
        *,
        expected_head: str | None,
    ) -> tuple[
        int,
        dict[str, object],
        mock.Mock,
        mock.Mock,
        mock.Mock,
        mock.Mock,
        mock.Mock,
        mock.Mock,
    ]:
        with owned_temporary_directory("readonly-runner-selection-") as root:
            sticky_parent = root / "sticky"
            sticky_parent.mkdir(mode=0o700)
            sticky_parent.chmod(0o1777)
            install_container = sticky_parent / "install"
            self._make_private_directory(install_container)
            runtime_home = root / "runtime-home"
            self._make_private_directory(runtime_home)
            runtime_parent = runtime_home / "runtime"
            self._make_private_directory(runtime_parent)
            cleanup_control = runtime_home / "cleanup-control"
            self._make_private_directory(cleanup_control)
            source_binding = runner.SourceCheckoutBinding(
                repo_root=pathlib.Path("/synthetic/repo"),
                head_sha=self.SOURCE_HEAD,
                source_relative_path="source",
                source_manifest_sha256=self.SOURCE_MANIFEST,
                head_subtree_manifest_sha256=self.SOURCE_HEAD_MANIFEST,
                source_root_gid=os.getgid(),
                source_entries=(),
            )
            source_tree_binding = runner.SourceTreeBinding(
                source_manifest_sha256=self.SOURCE_MANIFEST,
                source_root_gid=os.getgid(),
                source_entries=(),
            )
            completed = subprocess.CompletedProcess(
                args=(sys.executable,),
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_bound_copy(
                _source: pathlib.Path,
                destination: pathlib.Path,
                binding: runner.SourceCheckoutBinding,
                source_manifest: str,
                *,
                budget: runner.TreeSnapshotBudget,
                destination_owner_uid: int,
                destination_group_gid: int,
            ) -> str:
                self.assertEqual(binding, source_binding)
                self.assertEqual(source_manifest, self.SOURCE_MANIFEST)
                self.assertIsInstance(budget, runner.TreeSnapshotBudget)
                self.assertEqual(destination_owner_uid, install_container.stat().st_uid)
                self.assertEqual(destination_group_gid, install_container.stat().st_gid)
                destination.mkdir(mode=0o700)
                return source_manifest

            def fake_bounded_tree_copy(
                _source: pathlib.Path,
                destination: pathlib.Path,
                binding: runner.SourceTreeBinding,
                *,
                budget: runner.TreeSnapshotBudget,
                destination_owner_uid: int,
                destination_group_gid: int,
            ) -> str:
                self.assertEqual(binding, source_tree_binding)
                self.assertIsInstance(budget, runner.TreeSnapshotBudget)
                self.assertEqual(destination_owner_uid, install_container.stat().st_uid)
                self.assertEqual(destination_group_gid, install_container.stat().st_gid)
                destination.mkdir(mode=0o700)
                return binding.source_manifest_sha256

            def complete_no_child(**kwargs: object) -> subprocess.CompletedProcess[str]:
                proof = kwargs["closure_proof"]
                assert isinstance(proof, runner.ChildProcessClosureProof)
                proof.started = True
                proof.proven = True
                proof.destructive_cleanup_authorized = True
                proof.runtime_profile = "production-current"
                return completed

            def complete_hosted(
                *_args: object,
                **kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                proof = kwargs["closure_proof"]
                assert isinstance(proof, runner.ChildProcessClosureProof)
                proof.started = True
                proof.proven = True
                proof.destructive_cleanup_authorized = True
                return completed

            bind_source = mock.Mock(return_value=source_binding)
            bind_source_tree = mock.Mock(return_value=source_tree_binding)
            copy_bound_source = mock.Mock(side_effect=fake_bound_copy)
            copy_bound_tree = mock.Mock(side_effect=fake_bounded_tree_copy)
            run_no_child = mock.Mock(side_effect=complete_no_child)
            run_bounded_child = mock.Mock(side_effect=complete_hosted)
            stdout = io.StringIO()
            stderr = io.StringIO()
            lifecycle_fence = runner.LifecycleSignalFence(
                signals=(),
                previous_handlers=(),
                previous_mask=set(),
            )

            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(
                    runner,
                    "READONLY_INSTALL_PARENT",
                    sticky_parent,
                ),
                _mock_ambient_runtime_parent(runtime_home),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    side_effect=self._bound_directory_factory(
                        install_container,
                        runtime_parent,
                        cleanup_control,
                    ),
                ),
                mock.patch.object(runner, "_bind_source_checkout", bind_source),
                mock.patch.object(
                    runner,
                    "_bind_source_tree",
                    bind_source_tree,
                ),
                mock.patch.object(
                    runner,
                    "_copy_bound_source",
                    copy_bound_source,
                ),
                mock.patch.object(
                    runner,
                    "_copy_bound_tree",
                    copy_bound_tree,
                ),
                mock.patch.object(runner, "_set_tree_read_only"),
                mock.patch.object(runner, "_tree_snapshot", return_value={}),
                mock.patch.object(
                    runner,
                    "_run_no_child_test_suite",
                    run_no_child,
                ),
                mock.patch.object(
                    runner,
                    "_run_bounded_child",
                    run_bounded_child,
                ),
                mock.patch.object(runner, "_list_bound_directory", return_value=()),
                mock.patch.object(
                    runner,
                    "_consume_cleanup_bound_tree_endpoint",
                    return_value=None,
                ),
                mock.patch.object(
                    runner,
                    "_consume_cleanup_empty_bound_control_endpoint",
                    return_value=None,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                os.environ.pop("GITHUB_ACTIONS", None)
                os.environ.pop(runner.RUNNER_ENVIRONMENT_ENV, None)
                os.environ.pop(runner.RUNNER_ARCH_ENV, None)
                if expected_head is None:
                    os.environ.pop(runner.EXPECTED_HEAD_ENV, None)
                else:
                    os.environ[runner.EXPECTED_HEAD_ENV] = expected_head
                returncode = runner._run_main(
                    lifecycle_fence,
                    terminal_process=False,
                )

            self.assertEqual(stderr.getvalue(), "")
            summary = json.loads(stdout.getvalue())
            return (
                returncode,
                summary,
                bind_source,
                bind_source_tree,
                copy_bound_source,
                copy_bound_tree,
                run_no_child,
                run_bounded_child,
            )

    def test_explicit_expected_head_selects_trusted_mac_no_child_path(self) -> None:
        with (
            self.subTest("runner-local explicit runtime parent policy"),
            owned_temporary_directory("runner-explicit-runtime-parent-") as parent,
        ):
            selected_parent = parent.resolve(strict=True)
            result_owner = support._PrivateDirectoryCreationResultOwner()
            expected_binding = mock.sentinel.explicit_runtime_binding
            select_parent = mock.Mock(return_value=selected_parent)
            create_directory = mock.Mock(return_value=expected_binding)
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        runner.EXPLICIT_RUNTIME_PARENT_ENV: str(selected_parent),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    runner,
                    "_private_runtime_parent",
                    select_parent,
                ),
                mock.patch.object(
                    runner,
                    "_create_bound_owned_private_directory",
                    create_directory,
                ),
            ):
                binding = runner._create_bound_owned_private_runtime_directory(
                    ".explicit-runtime-",
                    result_owner=result_owner,
                )
            self.assertIs(binding, expected_binding)
            select_parent.assert_called_once_with()
            create_directory.assert_called_once_with(
                selected_parent,
                ".explicit-runtime-",
                result_owner=result_owner,
                allow_sticky_writable_ancestors=True,
            )

        (
            returncode,
            summary,
            bind_source,
            bind_source_tree,
            copy_bound_source,
            copy_bound_tree,
            run_no_child,
            run_bounded_child,
        ) = self._run_selected_path(expected_head=self.SOURCE_HEAD)

        self.assertEqual(returncode, 0)
        bind_source.assert_called_once()
        bind_source_tree.assert_not_called()
        copy_bound_source.assert_called_once()
        copy_bound_tree.assert_not_called()
        run_no_child.assert_called_once()
        run_bounded_child.assert_not_called()
        self.assertEqual(summary["primary_status"], "complete")
        self.assertEqual(summary["no_child_runtime_profile"], "production-current")
        self.assertIs(summary["source_head_bound"], True)
        self.assertEqual(summary["source_head_sha"], self.SOURCE_HEAD)
        self.assertEqual(
            summary["source_head_subtree_manifest_sha256"],
            self.SOURCE_HEAD_MANIFEST,
        )
        self.assertEqual(summary["source_manifest_sha256"], self.SOURCE_MANIFEST)
        self.assertIs(summary["creation_origin_proven"], False)
        self.assertEqual(
            summary["creation_origin_guarantee"],
            "best-effort-128-bit-leaf-immediate-nofollow-open-same-uid-host-tcb",
        )
        self.assertEqual(
            summary["cleanup_guarantee"],
            "custodied-manifest-quarantine-descriptor-revalidation-"
            "same-uid-final-rename-unlink-host-tcb",
        )

    def test_missing_expected_head_keeps_hosted_isolated_account_path(self) -> None:
        (
            returncode,
            summary,
            bind_source,
            bind_source_tree,
            copy_bound_source,
            copy_bound_tree,
            run_no_child,
            run_bounded_child,
        ) = self._run_selected_path(expected_head=None)

        self.assertEqual(returncode, 0)
        bind_source.assert_not_called()
        bind_source_tree.assert_called_once()
        copy_bound_source.assert_not_called()
        copy_bound_tree.assert_called_once()
        run_no_child.assert_not_called()
        run_bounded_child.assert_called_once()
        call = run_bounded_child.call_args
        self.assertEqual(
            call.args[0],
            (
                sys.executable,
                "-B",
                "-m",
                "tests.run_required_deterministic_supervisor",
            ),
        )
        self.assertIs(call.kwargs["require_isolated_account"], True)
        self.assertEqual(call.kwargs["environment"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(summary["primary_status"], "complete")
        self.assertIs(summary["source_head_bound"], False)
        self.assertIsNone(summary["source_head_sha"])
        self.assertIsNone(summary["source_head_subtree_manifest_sha256"])
        self.assertEqual(summary["source_manifest_sha256"], self.SOURCE_MANIFEST)


class NoChildSuiteContractTests(_RunnerFilesystemTestCase):
    _UNSET = object()

    @staticmethod
    def _closure(
        *,
        authenticated: bool = True,
        closure_proven: bool = True,
        leader_reaped: bool = True,
        stdio_closed: bool = True,
        process_group_used: bool = False,
    ) -> mock.Mock:
        closure = mock.Mock()
        closure.authenticated_no_child_profile = authenticated
        closure.permitted_process_closure_proven = closure_proven
        closure.leader_reaped = leader_reaped
        closure.stdio_closed = stdio_closed
        closure.process_group_emptiness_used_as_descendant_proof = process_group_used
        return closure

    @staticmethod
    def _command_result(
        *,
        closure: object,
        returncode: int = 0,
        stdout: bytes | None = None,
        stderr: bytes = b"",
    ) -> mock.Mock:
        result = mock.Mock()
        result.process_closure = closure
        result.returncode = returncode
        result.stdout = (
            (runner.NO_CHILD_SUCCESS_RECORD + "\n").encode("ascii")
            if stdout is None
            else stdout
        )
        result.stderr = stderr
        return result

    @contextlib.contextmanager
    def _bound_roots(self) -> object:
        with owned_temporary_directory("readonly-no-child-suite-") as root:
            install_container = root / "install"
            self._make_private_directory(install_container)
            installed_root = install_container / "installed"
            self._make_private_directory(installed_root)
            runtime_parent = root / "runtime"
            self._make_private_directory(runtime_parent)
            install_owner = support._DirectoryParentBindingResultOwner()
            runtime_owner = support._DirectoryParentBindingResultOwner()
            install_binding = self._open_parent_binding(
                install_owner,
                install_container,
                require_owned_private_parent=True,
            )
            runtime_binding = self._open_parent_binding(
                runtime_owner,
                runtime_parent,
                require_owned_private_parent=True,
            )
            try:
                yield (
                    installed_root,
                    install_binding,
                    runtime_binding,
                    runtime_parent,
                )
            finally:
                runtime_owner.close()
                install_owner.close()

    def _invoke(
        self,
        outcome: object,
        *,
        proof: runner.ChildProcessClosureProof | None = None,
        prepared: object | None = None,
        error_closure: object = _UNSET,
        timeout: float = 17,
        stdout_limit: int = 1_024,
        stderr_limit: int = 2_048,
    ) -> tuple[
        subprocess.CompletedProcess[str],
        runner.ChildProcessClosureProof,
        mock.Mock,
        mock.Mock,
        object,
        tuple[str, ...],
    ]:
        closure_proof = proof or runner.ChildProcessClosureProof()
        target = mock.Mock()
        target.path = "/trusted/python3.13"
        selected_prepared = prepared or mock.Mock(sandboxed_target=target)
        writable_attestation = mock.sentinel.writable_runtime
        with self._bound_roots() as (
            installed_root,
            install_binding,
            runtime_binding,
            runtime_parent,
        ):
            expected_argv = (
                target.path,
                "-I",
                "-S",
                "-B",
                "-c",
                runner.NO_CHILD_SUITE_CODE,
                str(installed_root),
                str(runtime_parent),
            )
            command_kwargs = (
                {"side_effect": outcome}
                if isinstance(outcome, BaseException)
                else {"return_value": outcome}
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, {}, clear=False))
                for name in (
                    "GITHUB_ACTIONS",
                    runner.RUNNER_ENVIRONMENT_ENV,
                    runner.RUNNER_ARCH_ENV,
                ):
                    os.environ.pop(name, None)
                stack.enter_context(
                    mock.patch.object(
                        runner,
                        "_bound_child_signals",
                        return_value=contextlib.nullcontext(),
                    )
                )
                attest = stack.enter_context(
                    mock.patch.object(
                        runner,
                        "attest_writable_root",
                        return_value=writable_attestation,
                    )
                )
                prepare = stack.enter_context(
                    mock.patch.object(
                        runner,
                        "prepare_sandboxed_python_no_child_profile",
                        return_value=selected_prepared,
                    )
                )
                run_command = stack.enter_context(
                    mock.patch.object(
                        runner,
                        "run_bounded_command",
                        **command_kwargs,
                    )
                )
                if error_closure is not self._UNSET:
                    stack.enter_context(
                        mock.patch.object(
                            runner,
                            "bounded_command_process_closure",
                            return_value=error_closure,
                        )
                    )
                completed = runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    timeout=timeout,
                    stdout_limit=stdout_limit,
                    stderr_limit=stderr_limit,
                    closure_proof=closure_proof,
                )

            attest.assert_called_once_with(
                runtime_parent,
                directory_fd=runtime_binding.fd,
            )
            return (
                completed,
                closure_proof,
                prepare,
                run_command,
                selected_prepared,
                expected_argv,
            )

    def test_exact_production_profile_argv_success_record_and_closure(self) -> None:
        closure = self._closure()
        result = self._command_result(closure=closure)
        (
            completed,
            proof,
            prepare,
            run_command,
            prepared,
            expected_argv,
        ) = self._invoke(result)

        self.assertEqual(completed.args, expected_argv)
        self.assertEqual(
            completed.stdout,
            runner.NO_CHILD_SUCCESS_RECORD + "\n",
        )
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.returncode, 0)
        self.assertTrue(proof.started)
        self.assertTrue(proof.proven)
        self.assertTrue(proof.destructive_cleanup_authorized)
        self.assertEqual(proof.runtime_profile, "production-current")
        prepare.assert_called_once_with(
            additional_seatbelt_rules="(deny file-write*)",
            runtime_pin=runner.no_child_profile.PINNED_RUNTIME,
            writable_roots=(mock.sentinel.writable_runtime,),
        )
        run_command.assert_called_once_with(
            expected_argv,
            timeout_seconds=17,
            max_output_bytes=3_072,
            max_stdout_bytes=1_024,
            max_stderr_bytes=2_048,
            _prepared_no_child_profile=prepared,
        )

    def test_zero_exit_rejects_missing_and_forged_completion_records(self) -> None:
        outputs = (
            ("missing", b""),
            (
                "forged",
                (runner.NO_CHILD_SUCCESS_RECORD + "\nforged\n").encode("ascii"),
            ),
        )
        for label, stdout in outputs:
            proof = runner.ChildProcessClosureProof()
            result = self._command_result(
                closure=self._closure(),
                stdout=stdout,
            )
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(
                    RuntimeError,
                    "lacks its exact completion record",
                ),
            ):
                self._invoke(result, proof=proof)
            self.assertTrue(proof.started)
            self.assertTrue(proof.proven)
            self.assertTrue(proof.destructive_cleanup_authorized)

    def test_result_rejects_unauthenticated_or_nonclosed_closure(self) -> None:
        closures = (
            ("unauthenticated", self._closure(authenticated=False)),
            ("closure-unproven", self._closure(closure_proven=False)),
            ("leader-unreaped", self._closure(leader_reaped=False)),
            ("stdio-open", self._closure(stdio_closed=False)),
            ("process-group-substitute", self._closure(process_group_used=True)),
        )
        for label, closure in closures:
            proof = runner.ChildProcessClosureProof()
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(
                    RuntimeError,
                    "lacks an authenticated no-child proof",
                ),
            ):
                self._invoke(
                    self._command_result(closure=closure),
                    proof=proof,
                )
            self.assertTrue(proof.started)
            self.assertFalse(proof.proven)
            self.assertFalse(proof.destructive_cleanup_authorized)

    def test_output_limit_failures_preserve_exact_scope(self) -> None:
        for scope, limit in (
            ("stdout", 111),
            ("stderr", 222),
            ("aggregate", 333),
        ):
            proof = runner.ChildProcessClosureProof()
            error = runner.BoundedCommandOutputLimitExceeded(
                scope=scope,
                limit=limit,
            )
            with (
                self.subTest(scope=scope),
                self.assertRaises(runner.ChildOutputLimitExceeded) as caught,
            ):
                self._invoke(
                    error,
                    proof=proof,
                    error_closure=self._closure(stdio_closed=False),
                )
            self.assertEqual(caught.exception.scope, scope)
            self.assertEqual(caught.exception.limit, limit)
            self.assertIs(caught.exception.__cause__, error)
            self.assertTrue(proof.proven)
            self.assertTrue(proof.destructive_cleanup_authorized)

        returned_overflow = (
            ("stdout", b"xx", b"", 1, 8),
            ("stderr", b"", b"xx", 8, 1),
        )
        for scope, stdout, stderr, stdout_limit, stderr_limit in returned_overflow:
            proof = runner.ChildProcessClosureProof()
            with (
                self.subTest(returned_scope=scope),
                self.assertRaises(runner.ChildOutputLimitExceeded) as caught,
            ):
                self._invoke(
                    self._command_result(
                        closure=self._closure(),
                        stdout=stdout,
                        stderr=stderr,
                    ),
                    proof=proof,
                    stdout_limit=stdout_limit,
                    stderr_limit=stderr_limit,
                )
            self.assertEqual(caught.exception.scope, scope)
            self.assertEqual(
                caught.exception.limit,
                stdout_limit if scope == "stdout" else stderr_limit,
            )
            self.assertTrue(proof.proven)
            self.assertTrue(proof.destructive_cleanup_authorized)

    def test_timeout_propagates_and_requires_authenticated_error_closure(
        self,
    ) -> None:
        for label, closure, expected_proven in (
            (
                "authenticated",
                self._closure(stdio_closed=False),
                True,
            ),
            ("missing", None, False),
        ):
            proof = runner.ChildProcessClosureProof()
            timeout_error = TimeoutError(f"synthetic {label} timeout")
            with (
                self.subTest(case=label),
                self.assertRaises(TimeoutError) as caught,
            ):
                self._invoke(
                    timeout_error,
                    proof=proof,
                    error_closure=closure,
                )
            self.assertIs(caught.exception, timeout_error)
            self.assertEqual(proof.proven, expected_proven)
            self.assertEqual(proof.destructive_cleanup_authorized, expected_proven)

    def test_signal_after_profile_preparation_precedes_target_read(self) -> None:
        class PreparedTargetTrap:
            accessed = False

            @property
            def sandboxed_target(self) -> object:
                self.accessed = True
                raise AssertionError("sandboxed target was read after pending signal")

        lifecycle_fence = runner.LifecycleSignalFence(
            signals=(),
            previous_handlers=(),
            previous_mask=set(),
        )
        proof = runner.ChildProcessClosureProof()
        prepared = PreparedTargetTrap()

        def prepare_profile(**_kwargs: object) -> PreparedTargetTrap:
            lifecycle_fence.received_signal = signal.SIGTERM
            return prepared

        with self._bound_roots() as (
            installed_root,
            install_binding,
            runtime_binding,
            _runtime_parent,
        ):
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(
                    runner,
                    "_bound_child_signals",
                    return_value=contextlib.nullcontext(),
                ),
                mock.patch.object(
                    runner,
                    "attest_writable_root",
                    return_value=mock.sentinel.writable_runtime,
                ),
                mock.patch.object(
                    runner,
                    "prepare_sandboxed_python_no_child_profile",
                    side_effect=prepare_profile,
                ) as prepare,
                mock.patch.object(runner, "run_bounded_command") as run_command,
                self.assertRaises(runner.ChildRunInterrupted) as caught,
            ):
                os.environ.pop("GITHUB_ACTIONS", None)
                os.environ.pop(runner.RUNNER_ENVIRONMENT_ENV, None)
                os.environ.pop(runner.RUNNER_ARCH_ENV, None)
                runner._run_no_child_test_suite(
                    installed_root=installed_root,
                    install_container_binding=install_binding,
                    runtime_parent_binding=runtime_binding,
                    closure_proof=proof,
                    lifecycle_fence=lifecycle_fence,
                )

        self.assertEqual(caught.exception.signal_number, signal.SIGTERM)
        self.assertFalse(prepared.accessed)
        self.assertEqual(proof.runtime_profile, "production-current")
        self.assertFalse(proof.started)
        self.assertFalse(proof.proven)
        prepare.assert_called_once()
        run_command.assert_not_called()


_TERMINAL_SIGNAL_WORKER = r"""
import contextlib
import errno
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
from unittest import mock

from tests import run_readonly_install_deterministic_supervisor as runner
from tests import support

scenario = sys.argv[1]
signal_number = int(sys.argv[2])
sent = False


def send_signal():
    global sent
    if signal_number and not sent:
        sent = True
        os.kill(os.getpid(), signal_number)


class StreamProxy:
    def __init__(self, stream, phase):
        self._stream = stream
        self._phase = phase

    def __getattr__(self, name):
        return getattr(self._stream, name)

    def flush(self):
        result = self._stream.flush()
        if scenario == self._phase:
            send_signal()
        return result


with tempfile.TemporaryDirectory(prefix="readonly-terminal-signal-") as raw_root:
    root = pathlib.Path(raw_root)
    sticky_parent = root / "sticky"
    sticky_parent.mkdir(mode=0o700)
    sticky_parent.chmod(0o1777)
    install_container = sticky_parent / "install"
    install_container.mkdir(mode=0o700)
    runtime_home = root / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    runtime_parent = runtime_home / "runtime"
    runtime_parent.mkdir(mode=0o700)
    cleanup_control = runtime_home / "cleanup-control"
    cleanup_control.mkdir(mode=0o700)
    remaining = iter(
        (
            (install_container, 101),
            (runtime_parent, 102),
            (cleanup_control, 103),
        )
    )

    def make_binding(path, descriptor):
        binding = mock.Mock(spec=support._DirectoryParentBinding)
        binding.path = path
        binding.fd = descriptor
        binding.fd_close_outcome = "owned"
        binding.fd_close_error = None
        metadata = path.stat()
        binding.policy = mock.Mock(uid=metadata.st_uid, gid=metadata.st_gid)

        def close():
            if binding.fd_close_outcome == "owned":
                binding.fd_close_outcome = "closed"
                binding.fd = -1

        binding.close.side_effect = close
        return binding

    def create_binding(
        _parent,
        _prefix,
        *,
        result_owner,
        require_owned_private_parent=True,
    ):
        del require_owned_private_parent
        path, descriptor = next(remaining)
        binding = make_binding(path, descriptor)
        result_owner.publish(binding)
        return binding

    source_binding = runner.SourceCheckoutBinding(
        repo_root=root,
        head_sha="a" * 40,
        source_relative_path="source",
        source_manifest_sha256="b" * 64,
        head_subtree_manifest_sha256="c" * 64,
        source_root_gid=os.getgid(),
        source_entries=(),
    )
    source_manifest = "b" * 64

    def copy_bound_source(
        _source,
        destination,
        _binding,
        _source_manifest,
        *,
        budget,
        destination_owner_uid,
        destination_group_gid,
    ):
        assert isinstance(budget, runner.TreeSnapshotBudget)
        assert destination_owner_uid == install_container.stat().st_uid
        assert destination_group_gid == install_container.stat().st_gid
        destination.mkdir(mode=0o700)
        return source_manifest

    snapshot_count = 0

    def snapshot(_path, *, budget):
        global snapshot_count
        assert isinstance(budget, runner.TreeSnapshotBudget)
        snapshot_count += 1
        if scenario == "existing-primary-late-signal" and snapshot_count == 2:
            raise RuntimeError("existing primary remains authoritative")
        return {}

    def complete_no_child(**kwargs):
        proof = kwargs["closure_proof"]
        proof.started = True
        proof.proven = True
        proof.destructive_cleanup_authorized = True
        proof.runtime_profile = "production-current"
        if scenario in {
            "pre-seal",
            "publication-failure",
            "publication-restore-failure",
        }:
            send_signal()
        return subprocess.CompletedProcess(
            args=(sys.executable,),
            returncode=0,
            stdout="",
            stderr="",
        )

    real_serialize = runner._serialize_terminal_json

    def serialize(value, *, operation):
        if (
            scenario in {"publication-failure", "publication-restore-failure"}
            and operation == "summary-serialization"
        ):
            raise runner.TerminalPublicationError(
                "summary-serialization",
                RuntimeError("synthetic serialization failure"),
            )
        result = real_serialize(value, operation=operation)
        if operation == "summary-serialization" and scenario in {
            "post-serialization",
            "existing-primary-late-signal",
        }:
            send_signal()
        return result

    real_write_terminal = runner._write_terminal_stdout

    def write_terminal(payload):
        real_write_terminal(payload)
        if scenario == "post-stdout-write":
            send_signal()

    real_os_write = os.write

    def write_with_newline_failure(descriptor, payload):
        raw = bytes(payload)
        if descriptor == 1 and raw == b"\n":
            raise OSError(errno.EIO, "synthetic terminal newline failure")
        written = real_os_write(descriptor, payload)
        if descriptor == 1 and raw.startswith(b"{"):
            send_signal()
        return written

    stdout_proxy = StreamProxy(sys.stdout, "post-stdout-flush")
    stderr_proxy = StreamProxy(sys.stderr, "post-stderr-flush")
    os.environ[runner.EXPECTED_HEAD_ENV] = "a" * 40

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(runner.sys, "platform", "darwin"))
        stack.enter_context(
            mock.patch.object(runner, "READONLY_INSTALL_PARENT", sticky_parent)
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_private_runtime_parent",
                return_value=runtime_home,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_create_bound_owned_private_directory",
                side_effect=create_binding,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_bind_source_checkout",
                return_value=source_binding,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_source_manifest_sha256",
                return_value=source_manifest,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_copy_bound_source",
                side_effect=copy_bound_source,
            )
        )
        stack.enter_context(mock.patch.object(runner, "_set_tree_read_only"))
        stack.enter_context(
            mock.patch.object(runner, "_tree_snapshot", side_effect=snapshot)
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_run_no_child_test_suite",
                side_effect=complete_no_child,
            )
        )
        stack.enter_context(
            mock.patch.object(runner, "_list_bound_directory", return_value=())
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_consume_cleanup_bound_tree_endpoint",
                return_value=None,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "_consume_cleanup_empty_bound_control_endpoint",
                return_value=None,
            )
        )
        stack.enter_context(
            mock.patch.object(runner, "_serialize_terminal_json", side_effect=serialize)
        )
        stack.enter_context(
            mock.patch.object(runner, "_write_terminal_stdout", side_effect=write_terminal)
        )
        if scenario == "post-stdout-flush":
            stack.enter_context(mock.patch.object(runner.sys, "stdout", stdout_proxy))
        if scenario == "post-stderr-flush":
            stack.enter_context(mock.patch.object(runner.sys, "stderr", stderr_proxy))
        if scenario == "newline-failure":
            stack.enter_context(mock.patch.object(runner.os, "write", write_with_newline_failure))
        if scenario == "publication-restore-failure":
            stack.enter_context(
                mock.patch.object(
                    runner,
                    "_restore_lifecycle_signal_fence",
                    side_effect=OSError(errno.EIO, "synthetic restoration failure"),
                )
            )
        returncode = runner.main(_terminal_process=True)

raise SystemExit(returncode)
"""


class TerminalPublicationSignalIntegrationTests(unittest.TestCase):
    SIGNALS = (
        signal.SIGHUP,
        signal.SIGINT,
        signal.SIGQUIT,
        signal.SIGTERM,
    )
    SOURCE_HEAD = "a" * 40
    SOURCE_MANIFEST = "b" * 64
    SOURCE_HEAD_MANIFEST = "c" * 64

    @classmethod
    def setUpClass(cls) -> None:
        if sys.version_info[:2] != (3, 13):
            raise unittest.SkipTest("terminal publication matrix requires Python 3.13")

    @staticmethod
    def _run_worker(
        scenario: str,
        signal_number: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        environment.pop("GITHUB_ACTIONS", None)
        environment.pop(runner.RUNNER_ENVIRONMENT_ENV, None)
        environment.pop(runner.RUNNER_ARCH_ENV, None)
        environment.pop(runner.EXPLICIT_RUNTIME_PARENT_ENV, None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            (
                sys.executable,
                "-B",
                "-c",
                _TERMINAL_SIGNAL_WORKER,
                scenario,
                str(signal_number),
            ),
            cwd=pathlib.Path(__file__).resolve().parents[1],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )

    def _single_summary(
        self,
        completed: subprocess.CompletedProcess[bytes],
    ) -> dict[str, object]:
        stdout = completed.stdout.decode("utf-8", "strict")
        lines = stdout.splitlines()
        self.assertEqual(lines, [stdout.rstrip("\n")])
        self.assertEqual(len(lines), 1)
        return json.loads(lines[0])

    @staticmethod
    def _sealed_exit_decision(summary: dict[str, object]) -> int:
        signal_number = summary["signal_number"]
        if isinstance(signal_number, int):
            return 128 + signal_number
        if (
            summary["primary_status"] == "complete"
            and summary["cleanup_status"] == "complete"
        ):
            return 0
        return 1

    def _assert_source_binding_summary(self, summary: dict[str, object]) -> None:
        self.assertIs(summary["source_head_bound"], True)
        self.assertEqual(summary["source_head_sha"], self.SOURCE_HEAD)
        self.assertEqual(
            summary["source_head_subtree_manifest_sha256"],
            self.SOURCE_HEAD_MANIFEST,
        )
        self.assertEqual(summary["source_manifest_sha256"], self.SOURCE_MANIFEST)
        self.assertIs(summary["creation_origin_proven"], False)
        self.assertEqual(
            summary["creation_origin_guarantee"],
            "best-effort-128-bit-leaf-immediate-nofollow-open-same-uid-host-tcb",
        )
        self.assertEqual(
            summary["cleanup_guarantee"],
            "custodied-manifest-quarantine-descriptor-revalidation-"
            "same-uid-final-rename-unlink-host-tcb",
        )

    def test_preseal_signal_publishes_one_interrupted_summary(self) -> None:
        for signal_number in self.SIGNALS:
            with self.subTest(signal=signal_number.name):
                completed = self._run_worker("pre-seal", signal_number)
                self.assertEqual(completed.returncode, 128 + signal_number)
                summary = self._single_summary(completed)
                self.assertEqual(summary["primary_status"], "interrupted")
                self.assertEqual(summary["signal_number"], signal_number)
                self.assertEqual(
                    summary["primary_failure"]["error_kind"],
                    "ChildRunInterrupted",
                )
                self.assertEqual(
                    completed.returncode,
                    self._sealed_exit_decision(summary),
                )
                self._assert_source_binding_summary(summary)

    def test_late_signal_after_each_publication_phase_keeps_sealed_json(
        self,
    ) -> None:
        phases = (
            "post-serialization",
            "post-stdout-write",
            "post-stdout-flush",
            "post-stderr-flush",
        )
        for phase in phases:
            for signal_number in self.SIGNALS:
                with self.subTest(phase=phase, signal=signal_number.name):
                    completed = self._run_worker(phase, signal_number)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    summary = self._single_summary(completed)
                    self.assertEqual(summary["primary_status"], "complete")
                    self.assertIsNone(summary["signal_number"])
                    self.assertEqual(
                        completed.returncode,
                        self._sealed_exit_decision(summary),
                    )
                    self._assert_source_binding_summary(summary)

    def test_complete_json_is_committed_when_newline_write_fails(self) -> None:
        for signal_number in (0, *self.SIGNALS):
            label = "none" if signal_number == 0 else signal_number.name
            with self.subTest(signal=label):
                completed = self._run_worker("newline-failure", signal_number)
                self.assertEqual(completed.returncode, 0)
                self.assertFalse(completed.stdout.endswith(b"\n"))
                summary = self._single_summary(completed)
                self.assertEqual(summary["primary_status"], "complete")
                self.assertIsNone(summary["signal_number"])
                self.assertEqual(
                    completed.returncode,
                    self._sealed_exit_decision(summary),
                )
                self.assertIn(b"operation=stdout-newline", completed.stderr)

    def test_publication_and_restore_failures_prefer_sealed_signal(self) -> None:
        for scenario in ("publication-failure", "publication-restore-failure"):
            with self.subTest(scenario=scenario, signal="none"):
                completed = self._run_worker(scenario)
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, b"")
                self.assertIn(b"operation=summary-serialization", completed.stderr)
            for signal_number in self.SIGNALS:
                with self.subTest(scenario=scenario, signal=signal_number.name):
                    completed = self._run_worker(scenario, signal_number)
                    self.assertEqual(completed.returncode, 128 + signal_number)
                    self.assertEqual(completed.stdout, b"")
                    self.assertIn(
                        b"operation=summary-serialization",
                        completed.stderr,
                    )
                    if scenario == "publication-restore-failure":
                        self.assertIn(
                            b"operation=signal-fence-restoration",
                            completed.stderr,
                        )

    def test_existing_primary_is_not_replaced_by_late_signal(self) -> None:
        for signal_number in self.SIGNALS:
            with self.subTest(signal=signal_number.name):
                completed = self._run_worker(
                    "existing-primary-late-signal",
                    signal_number,
                )
                self.assertEqual(completed.returncode, 1)
                summary = self._single_summary(completed)
                self.assertEqual(summary["primary_status"], "failed")
                self.assertIsNone(summary["signal_number"])
                self.assertEqual(
                    summary["primary_failure"]["stage"],
                    "snapshot-after",
                )
                self.assertEqual(
                    summary["primary_failure"]["message"],
                    "existing primary remains authoritative",
                )
                self.assertEqual(
                    completed.returncode,
                    self._sealed_exit_decision(summary),
                )


if __name__ == "__main__":
    unittest.main()
