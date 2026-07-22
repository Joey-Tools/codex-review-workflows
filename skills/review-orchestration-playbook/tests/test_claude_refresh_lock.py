from __future__ import annotations

import dis
import errno
import inspect
import os
import pathlib
import signal
import stat
import sys
import tempfile
import threading
import time
import traceback
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_linux, claude_refresh_lock  # noqa: E402


EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS = {
    (
        "2.1.211",
        "darwin-arm64",
        "5a728a76198b6eca7f3c7cdbff43bab44b77b48c2108f7a3107d889773382629",
    ),
    (
        "2.1.211",
        "darwin-x64",
        "33049eb14cf4702b992b7eda41ec077fc6e76539f7fd046e6d32538757235da4",
    ),
    (
        "2.1.211",
        "linux-arm64",
        "1fff7e8f947c07b19d10b1fbf714b7e547e9536253b9b58230d8adbc4624f867",
    ),
    (
        "2.1.211",
        "linux-x64",
        "8272c8a474ac9ea1bc35f19b9f7c7e7dc4dc4eb6d5ad3e484b19335ac72446b2",
    ),
    (
        "2.1.211",
        "linux-arm64-musl",
        "ca094a85ea464b2ebec2ecfcc9e2c056573d4ca95ebe12ffae2c7dccb722e17b",
    ),
    (
        "2.1.211",
        "linux-x64-musl",
        "c99bd7934ac841d5be6ee7d3644cb63bccef2cd495c6c1bb982a1b1deac1b466",
    ),
}


class _TwiceInterruptedOperationLock:
    def __init__(
        self,
        first: BaseException,
        second: BaseException,
    ) -> None:
        self._lock = threading.RLock()
        self._first = first
        self._second = second
        self.release_calls = 0

    def _is_owned(self) -> bool:
        return self._lock._is_owned()

    def acquire(self, *, timeout: float = -1.0) -> bool:
        return self._lock.acquire(timeout=timeout)

    def release(self) -> None:
        self.release_calls += 1
        if self.release_calls == 1:
            raise self._first
        if self.release_calls == 2:
            raise self._second
        self._lock.release()


class ClaudeRefreshLockTest(unittest.TestCase):
    PROTOCOL = claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211

    def _config_dir(self, root: pathlib.Path) -> pathlib.Path:
        config = root / ".claude"
        config.mkdir(mode=0o700)
        return config

    def _lease_descriptors(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> tuple[int, ...]:
        return tuple(
            dict.fromkeys(
                (
                    *(lock.descriptor for lock in lease._locks),
                    lease._legacy_parent_anchor.descriptor,
                    lease._config_anchor.descriptor,
                )
            )
        )

    def _assert_descriptor_only_error_graph(
        self,
        root: BaseException,
        *,
        forbidden_paths: tuple[pathlib.Path, ...],
    ) -> None:
        visiting: set[int] = set()
        visited: set[int] = set()

        def visit(error: BaseException) -> None:
            identity = id(error)
            self.assertNotIn(identity, visiting)
            if identity in visited:
                return
            visiting.add(identity)
            self.assertFalse(hasattr(error, "_codex_claude_refresh_lock_paths"))
            visible = [str(error), *getattr(error, "__notes__", ())]
            detail = getattr(error, "detail", None)
            if isinstance(detail, str):
                visible.append(detail)
            rendered = "\n".join(visible)
            for path in forbidden_paths:
                self.assertNotIn(str(path), rendered)
            for related in (
                error.__cause__,
                error.__context__,
                getattr(
                    error,
                    "_codex_claude_refresh_lock_cleanup_evidence",
                    None,
                ),
            ):
                if isinstance(related, BaseException):
                    visit(related)
            visiting.remove(identity)
            visited.add(identity)

        visit(root)

    def _assert_descriptor_only_recovery(
        self,
        error: BaseException,
        *,
        forbidden_paths: tuple[pathlib.Path, ...],
    ) -> None:
        self.assertTrue(
            claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(error)
        )
        self.assertFalse(hasattr(error, "_codex_claude_refresh_lock_paths"))
        self.assertIsNone(claude_refresh_lock._refresh_lock_recovery_paths(error))
        self._assert_descriptor_only_error_graph(
            error,
            forbidden_paths=forbidden_paths,
        )

    def _operator_cleanup_inconclusive_lease(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        thread = lease._heartbeat_thread
        assert thread is not None
        thread.join(timeout=1.0)
        self.assertFalse(thread.is_alive())
        for path in reversed(lease.paths):
            if path.exists():
                path.rmdir()
        for descriptor in self._lease_descriptors(lease):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _seed_resumable_abandonment_descriptor(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
        descriptor: int,
    ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
        heartbeat = lease._heartbeat_thread
        assert heartbeat is not None
        lease._heartbeat_stop.set()
        heartbeat.join(timeout=1.0)
        self.assertFalse(heartbeat.is_alive())
        with lease._state_lock:
            lease._publish_abandonment_state()
            lease._abandonment_descriptors_pending = []
            lease._abandonment_descriptors_unconfirmed.add(descriptor)
        diagnostic = lease._cleanup_inconclusive
        assert diagnostic is not None
        return diagnostic

    def _join_started_workers(
        self,
        *workers: threading.Thread,
    ) -> list[str]:
        alive: list[str] = []
        for worker in workers:
            if worker.ident is None:
                continue
            worker.join(timeout=2.0)
            if worker.is_alive():
                alive.append(worker.name)
        return alive

    def _acquire_lock(
        self,
        config_dir: os.PathLike[str] | str,
        *,
        protocol: claude_refresh_lock.ClaudeRefreshLockProtocol,
        timeout_seconds: float = (claude_refresh_lock.DEFAULT_LOCK_TIMEOUT_SECONDS),
        retry_interval_seconds: float = (
            claude_refresh_lock.DEFAULT_RETRY_INTERVAL_SECONDS
        ),
        config_dir_fd: int | None = None,
        legacy_parent_dir_fd: int | None = None,
        require_explicit_context_release: bool = False,
    ) -> claude_refresh_lock.ClaudeRefreshLockLease:
        owner = claude_refresh_lock.ClaudeRefreshLockOwner()
        lease = claude_refresh_lock.acquire_claude_refresh_lock(
            config_dir,
            protocol=protocol,
            owner=owner,
            timeout_seconds=timeout_seconds,
            retry_interval_seconds=retry_interval_seconds,
            config_dir_fd=config_dir_fd,
            legacy_parent_dir_fd=legacy_parent_dir_fd,
            require_explicit_context_release=require_explicit_context_release,
        )
        owner.transfer(lease)
        return lease

    def _force_cleanup_test_lease(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        if lease.released:
            return
        if lease._cleanup_inconclusive is not None:
            self._operator_cleanup_inconclusive_lease(lease)
            return
        lease._release(skip_abandoned=False)

    def _raise_before_instruction(
        self,
        function: object,
        *,
        offset: int,
        error: BaseException,
    ) -> mock._patch:
        code = function.__code__
        previous_trace = sys.gettrace()

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if event == "opcode" and frame.f_lasti == offset:
                    raise error
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)

        return TracePatch()

    def _call_before_instruction(
        self,
        function: object,
        *,
        offset: int,
        callback: object,
    ) -> mock._patch:
        code = function.__code__
        previous_trace = sys.gettrace()
        armed = True
        self.assertTrue(callable(callback))

        def trace(frame: object, event: str, _argument: object) -> object:
            nonlocal armed
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti == offset:
                    armed = False
                    callback()
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)

        return TracePatch()

    def _lease_return_offset(self) -> int:
        instructions = tuple(
            dis.get_instructions(claude_refresh_lock.acquire_claude_refresh_lock)
        )
        for index, instruction in enumerate(instructions):
            if instruction.opname != "RETURN_VALUE":
                continue
            for previous in reversed(instructions[max(0, index - 3) : index]):
                if (
                    previous.opname in {"LOAD_FAST", "LOAD_FAST_BORROW"}
                    and previous.argval == "lease"
                ):
                    return previous.offset
        self.fail("acquire_claude_refresh_lock has no lease return boundary")

    def _lease_assignment_offset(self, function: object) -> int:
        stores_before_yield: list[int] = []
        for instruction in dis.get_instructions(function):
            if instruction.opname == "YIELD_VALUE":
                break
            if instruction.opname == "STORE_FAST" and instruction.argval == "lease":
                stores_before_yield.append(instruction.offset)
        if not stores_before_yield:
            self.fail(f"{function.__name__} has no lease assignment boundary")
        return stores_before_yield[-1]

    def _call_result_assignment_offset(
        self,
        function: object,
        *,
        callable_name: str,
        local_name: str,
        occurrence: int = 0,
    ) -> int:
        instructions = tuple(dis.get_instructions(function))
        candidates: list[int] = []
        for index, instruction in enumerate(instructions):
            if (
                instruction.opname != "STORE_FAST"
                or instruction.argval != local_name
                or index == 0
                or not instructions[index - 1].opname.startswith("CALL")
            ):
                continue
            for previous in reversed(instructions[: index - 1]):
                if previous.opname in {
                    "STORE_FAST",
                    "RETURN_VALUE",
                    "RAISE_VARARGS",
                }:
                    break
                if (
                    previous.opname.startswith("LOAD_")
                    and previous.argval == callable_name
                ):
                    candidates.append(instruction.offset)
                    break
        if occurrence >= len(candidates):
            self.fail(
                f"{function.__name__} has no {callable_name} CALL -> "
                f"STORE_FAST {local_name} boundary at occurrence {occurrence}"
            )
        return candidates[occurrence]

    def _raw_call_result_boundary_offset(
        self,
        function: object,
        *,
        callable_name: str,
        next_opname: str,
        next_argval: object = None,
    ) -> int:
        instructions = tuple(dis.get_instructions(function))
        for index, instruction in enumerate(instructions):
            if (
                not instruction.opname.startswith("LOAD_")
                or instruction.argval != callable_name
            ):
                continue
            for call_index in range(index + 1, len(instructions) - 1):
                call = instructions[call_index]
                if call.opname.startswith("CALL"):
                    boundary = instructions[call_index + 1]
                    if boundary.opname == next_opname and (
                        next_argval is None or boundary.argval == next_argval
                    ):
                        return boundary.offset
                    break
                if call.opname in {"STORE_FAST", "RETURN_VALUE"}:
                    break
        self.fail(
            f"{function.__name__} has no {callable_name} CALL -> {next_opname} boundary"
        )

    def _call_entry_and_return_boundary_offsets(
        self,
        function: object,
        *,
        callable_name: str,
    ) -> tuple[int, int]:
        instructions = tuple(dis.get_instructions(function))
        for index, instruction in enumerate(instructions):
            if (
                not instruction.opname.startswith("LOAD_")
                or instruction.argval != callable_name
            ):
                continue
            for call_index in range(index + 1, len(instructions) - 1):
                call = instructions[call_index]
                if call.opname.startswith("CALL"):
                    return call.offset, instructions[call_index + 1].offset
                if call.opname in {"STORE_FAST", "RETURN_VALUE"}:
                    break
        self.fail(f"{function.__name__} has no {callable_name} CALL boundary")

    def _source_call_entry_and_return_boundary_offsets(
        self,
        function: object,
        *,
        statement: str,
        callable_name: str,
        occurrence: int = 0,
    ) -> tuple[int, int]:
        source, first_line = inspect.getsourcelines(function)
        matching_lines = [
            first_line + index for index, line in enumerate(source) if statement in line
        ]
        if occurrence >= len(matching_lines):
            self.fail(
                f"{function.__name__} has no source statement {statement!r} "
                f"at occurrence {occurrence}"
            )
        target_line = matching_lines[occurrence]
        instructions = tuple(dis.get_instructions(function))
        for statement_index, instruction in enumerate(instructions):
            positions = getattr(instruction, "positions", None)
            instruction_line = (
                positions.lineno if positions is not None else instruction.starts_line
            )
            if instruction_line != target_line:
                continue
            for method_index in range(
                statement_index,
                min(statement_index + 12, len(instructions)),
            ):
                if instructions[method_index].argval != callable_name:
                    continue
                for call_index in range(
                    method_index + 1,
                    min(method_index + 12, len(instructions) - 1),
                ):
                    call = instructions[call_index]
                    if call.opname.startswith("CALL"):
                        return (
                            call.offset,
                            instructions[call_index + 1].offset,
                        )
                break
        self.fail(
            f"{function.__name__} has no {callable_name} CALL boundary on "
            f"source line {target_line}"
        )

    def _source_statement_offset(
        self,
        function: object,
        *,
        statement: str,
        occurrence: int = 0,
    ) -> int:
        source, first_line = inspect.getsourcelines(function)
        matching_lines = [
            first_line + index for index, line in enumerate(source) if statement in line
        ]
        if occurrence >= len(matching_lines):
            self.fail(
                f"{function.__name__} has no source statement {statement!r} "
                f"at occurrence {occurrence}"
            )
        target_line = matching_lines[occurrence]
        for instruction in dis.get_instructions(function):
            positions = getattr(instruction, "positions", None)
            instruction_line = (
                positions.lineno if positions is not None else instruction.starts_line
            )
            if instruction_line == target_line:
                return instruction.offset
        self.fail(f"{function.__name__} has no opcode for source line {target_line}")

    def _assert_internal_acquisition_assignment_cleanup(
        self,
        *,
        callable_name: str,
        local_name: str,
        expected_lock_count: int,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        captured_anchors: list[claude_refresh_lock._DirectoryAnchor] = []
        captured_locks: list[claude_refresh_lock._HeldLock] = []
        captured_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        real_open_anchor = claude_refresh_lock._open_directory_anchor
        real_inspect_new_lock = claude_refresh_lock._inspect_new_lock
        real_init = claude_refresh_lock.ClaudeRefreshLockLease.__init__

        def capture_anchor(*args: object, **kwargs: object) -> object:
            anchor = real_open_anchor(*args, **kwargs)
            captured_anchors.append(anchor)
            return anchor

        def capture_lock(*args: object, **kwargs: object) -> object:
            lock = real_inspect_new_lock(*args, **kwargs)
            captured_locks.append(lock)
            return lock

        def capture_lease(
            lease: claude_refresh_lock.ClaudeRefreshLockLease,
            *args: object,
            **kwargs: object,
        ) -> None:
            real_init(lease, *args, **kwargs)
            captured_leases.append(lease)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            offset = self._call_result_assignment_offset(
                claude_refresh_lock.acquire_claude_refresh_lock,
                callable_name=callable_name,
                local_name=local_name,
            )
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_open_directory_anchor",
                        new=capture_anchor,
                    ),
                    mock.patch.object(
                        claude_refresh_lock,
                        "_inspect_new_lock",
                        new=capture_lock,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.ClaudeRefreshLockLease,
                        "__init__",
                        new=capture_lease,
                    ),
                    self._raise_before_instruction(
                        claude_refresh_lock.acquire_claude_refresh_lock,
                        offset=offset,
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured_anchors), 2)
                self.assertEqual(len(captured_locks), expected_lock_count)
                self.assertEqual(len(captured_leases), 1)
                lease = owner.lease
                self.assertIsNotNone(lease)
                assert lease is not None
                self.assertIs(lease, captured_leases[0])
                self.assertTrue(lease.released)
                heartbeat = lease._heartbeat_thread
                self.assertTrue(heartbeat is None or not heartbeat.is_alive())
                self.assertFalse(primary.exists())
                self.assertFalse(legacy.exists())
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
                )
                descriptors = tuple(
                    dict.fromkeys(
                        (
                            *(anchor.descriptor for anchor in captured_anchors),
                            *(lock.descriptor for lock in captured_locks),
                        )
                    )
                )
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            finally:
                for lease in captured_leases:
                    heartbeat = lease._heartbeat_thread
                    if heartbeat is not None and heartbeat.is_alive():
                        lease._heartbeat_stop.set()
                        heartbeat.join(timeout=1.0)
                for descriptor in dict.fromkeys(
                    (
                        *(lock.descriptor for lock in captured_locks),
                        *(anchor.descriptor for anchor in captured_anchors),
                    )
                ):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                for path in (legacy, primary):
                    try:
                        path.rmdir()
                    except FileNotFoundError:
                        pass

    def test_acquires_exact_primary_and_realpath_legacy_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary))
            canonical = config.resolve()
            primary = canonical / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(canonical) + ".lock")

            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            self.assertEqual(lease.paths, (primary, legacy))
            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())
            self.assertEqual(
                tuple(identity.path for identity in lease.identities),
                lease.paths,
            )
            for identity in lease.identities:
                self.assertEqual(identity.uid, os.getuid())
                self.assertEqual(identity.mode, 0o700)
                self.assertGreater(identity.device, 0)
                self.assertGreater(identity.inode, 0)
            lease.assert_held()

            lease.release()
            lease.release()
            self.assertTrue(lease.released)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    def test_signed_artifact_catalog_is_exact_and_cross_platform(self) -> None:
        catalog = claude_refresh_lock.CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS
        self.assertEqual(set(catalog), EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS)
        for (version, platform, checksum), protocol in catalog.items():
            self.assertIs(
                claude_refresh_lock.certified_claude_refresh_lock_protocol(
                    version=version,
                    platform_key=platform,
                    checksum=checksum,
                ),
                protocol,
            )
        sample_version, sample_platform, sample_checksum = next(iter(catalog))
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version="2.9.999",
                platform_key=sample_platform,
                checksum=sample_checksum,
            )
        )
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version=sample_version,
                platform_key="linux-unknown",
                checksum=sample_checksum,
            )
        )
        self.assertIsNone(
            claude_refresh_lock.certified_claude_refresh_lock_protocol(
                version=sample_version,
                platform_key=sample_platform,
                checksum="0" + sample_checksum[1:],
            )
        )

    def test_background_heartbeat_renews_slow_critical_section_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            real_renew = claude_refresh_lock._renew_lock
            real_wait = claude_refresh_lock.threading.Event.wait
            completed_renewals = 0
            completed_renewals_lock = threading.Lock()

            def fast_wait(
                event: object,
                timeout: float | None = None,
            ) -> bool:
                if timeout is None:
                    return real_wait(event, None)
                bounded = min(timeout, 0.01)
                return real_wait(event, bounded)

            def tracked_renew(
                lock: object,
                protocol: claude_refresh_lock.ClaudeRefreshLockProtocol,
            ) -> None:
                nonlocal completed_renewals
                real_renew(lock, protocol)
                with completed_renewals_lock:
                    completed_renewals += 1

            def renewal_count() -> int:
                with completed_renewals_lock:
                    return completed_renewals

            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_renew_lock",
                    side_effect=tracked_renew,
                ),
            ):
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                old_mtime_ns = 1_000_000_000
                for path in lease.paths:
                    os.utime(path, ns=(old_mtime_ns, old_mtime_ns))

                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if renewal_count() >= 4 and all(
                        path.stat().st_mtime_ns > old_mtime_ns for path in lease.paths
                    ):
                        break
                    time.sleep(0.01)
                else:
                    self.fail("Claude refresh-lock heartbeat did not renew both locks")

                calls_before_additional_wait = renewal_count()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if renewal_count() > calls_before_additional_wait:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("Claude refresh-lock heartbeat stopped renewing")

                lease.release()
                heartbeat_thread = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat_thread)
                assert heartbeat_thread is not None
                self.assertFalse(heartbeat_thread.is_alive())

    def test_acquire_return_interruption_cannot_orphan_heartbeat_owner(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        real_init = claude_refresh_lock.ClaudeRefreshLockLease.__init__

        def capture_init(
            lease: claude_refresh_lock.ClaudeRefreshLockLease,
            *args: object,
            **kwargs: object,
        ) -> None:
            real_init(lease, *args, **kwargs)
            captured.append(lease)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock.ClaudeRefreshLockLease,
                        "__init__",
                        new=capture_init,
                    ),
                    self._raise_before_instruction(
                        claude_refresh_lock.acquire_claude_refresh_lock,
                        offset=self._lease_return_offset(),
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                lease = captured[0]
                self.assertTrue(lease.released)
                self.assertTrue(all(not path.exists() for path in lease.paths))
                heartbeat = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat)
                assert heartbeat is not None
                self.assertFalse(
                    heartbeat.is_alive(),
                    "return interruption orphaned a renewing heartbeat",
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(interruption)
                )
                self.assertFalse(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        interruption
                    )
                )
            finally:
                for lease in captured:
                    self._force_cleanup_test_lease(lease)

    def test_primary_acquire_assignment_interruption_cleans_owned_resources(
        self,
    ) -> None:
        self._assert_internal_acquisition_assignment_cleanup(
            callable_name="_acquire_one",
            local_name="primary",
            expected_lock_count=1,
        )

    def test_legacy_acquire_assignment_interruption_cleans_owned_resources(
        self,
    ) -> None:
        self._assert_internal_acquisition_assignment_cleanup(
            callable_name="_acquire_one",
            local_name="legacy",
            expected_lock_count=2,
        )

    def test_lease_construction_assignment_interruption_closes_anchors(
        self,
    ) -> None:
        self._assert_internal_acquisition_assignment_cleanup(
            callable_name="ClaudeRefreshLockLease",
            local_name="lease",
            expected_lock_count=0,
        )

    def test_mkdir_result_interruption_retains_pending_recovery_fence(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        captured_anchors: list[claude_refresh_lock._DirectoryAnchor] = []
        real_open_anchor = claude_refresh_lock._open_directory_anchor

        def capture_anchor(*args: object, **kwargs: object) -> object:
            anchor = real_open_anchor(*args, **kwargs)
            captured_anchors.append(anchor)
            return anchor

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_open_directory_anchor",
                        new=capture_anchor,
                    ),
                    self._raise_before_instruction(
                        claude_refresh_lock._acquire_one,
                        offset=self._raw_call_result_boundary_offset(
                            claude_refresh_lock._acquire_one,
                            callable_name="mkdir",
                            next_opname="POP_TOP",
                        ),
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                lease = owner.lease
                self.assertIsNotNone(lease)
                assert lease is not None
                self.assertFalse(lease.released)
                self.assertIsNotNone(lease._cleanup_inconclusive)
                heartbeat = lease._heartbeat_thread
                self.assertTrue(heartbeat is None or not heartbeat.is_alive())
                self.assertTrue(primary.is_dir())
                self.assertFalse(legacy.exists())
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(interruption)
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        interruption
                    )
                )
                for anchor in captured_anchors:
                    with self.assertRaises(OSError):
                        os.fstat(anchor.descriptor)
            finally:
                for anchor in captured_anchors:
                    try:
                        os.close(anchor.descriptor)
                    except OSError:
                        pass
                try:
                    primary.rmdir()
                except FileNotFoundError:
                    pass

    def test_ambiguous_mkdir_oserror_retains_pending_recovery_fence(
        self,
    ) -> None:
        captured_anchors: list[claude_refresh_lock._DirectoryAnchor] = []
        real_open_anchor = claude_refresh_lock._open_directory_anchor
        real_mkdir = os.mkdir

        def capture_anchor(*args: object, **kwargs: object) -> object:
            anchor = real_open_anchor(*args, **kwargs)
            captured_anchors.append(anchor)
            return anchor

        def create_then_fail(
            path: os.PathLike[str] | str,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            real_mkdir(path, mode, dir_fd=dir_fd)
            raise OSError(5, "ambiguous remote mkdir result")

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_open_directory_anchor",
                        new=capture_anchor,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "mkdir",
                        new=create_then_fail,
                    ),
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockError
                    ) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                lease = owner.lease
                self.assertIsNotNone(lease)
                assert lease is not None
                self.assertFalse(lease.released)
                self.assertIs(
                    lease._cleanup_inconclusive,
                    lease._cleanup_inconclusive_fallback,
                )
                heartbeat = lease._heartbeat_thread
                self.assertTrue(heartbeat is None or not heartbeat.is_alive())
                self.assertTrue(primary.is_dir())
                self.assertFalse(legacy.exists())
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        raised.exception
                    )
                )
                for anchor in captured_anchors:
                    with self.assertRaises(OSError):
                        os.fstat(anchor.descriptor)
            finally:
                for anchor in captured_anchors:
                    try:
                        os.close(anchor.descriptor)
                    except OSError:
                        pass
                try:
                    primary.rmdir()
                except FileNotFoundError:
                    pass

    def test_acquire_cleanup_abandon_call_boundaries_retain_diagnostic(
        self,
    ) -> None:
        boundaries = self._call_entry_and_return_boundary_offsets(
            claude_refresh_lock.acquire_claude_refresh_lock,
            callable_name="abandon",
        )
        real_open_anchor = claude_refresh_lock._open_directory_anchor
        real_mkdir = os.mkdir

        for boundary, offset in zip(("entry", "return"), boundaries):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                captured_anchors: list[claude_refresh_lock._DirectoryAnchor] = []

                def capture_anchor(*args: object, **kwargs: object) -> object:
                    anchor = real_open_anchor(*args, **kwargs)
                    captured_anchors.append(anchor)
                    return anchor

                def create_then_fail(
                    path: os.PathLike[str] | str,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    real_mkdir(path, mode, dir_fd=dir_fd)
                    raise OSError(5, "ambiguous remote mkdir result")

                def prove_pending_path(
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                ) -> tuple[str, ...]:
                    pending = lease._pending_acquisition
                    assert pending is not None
                    return (str(pending.path),)

                config = self._config_dir(pathlib.Path(temporary)).resolve()
                primary = config / self.PROTOCOL.primary_lock_name
                legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
                owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                try:
                    with (
                        mock.patch.object(
                            claude_refresh_lock,
                            "_open_directory_anchor",
                            new=capture_anchor,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "mkdir",
                            new=create_then_fail,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.ClaudeRefreshLockLease,
                            "_prove_authoritative_recovery_paths",
                            autospec=True,
                            side_effect=prove_pending_path,
                        ),
                        self._raise_before_instruction(
                            claude_refresh_lock.acquire_claude_refresh_lock,
                            offset=offset,
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        claude_refresh_lock.acquire_claude_refresh_lock(
                            config,
                            protocol=self.PROTOCOL,
                            owner=owner,
                            timeout_seconds=0,
                        )

                    self.assertIs(raised.exception, interruption)
                    lease = owner.lease
                    self.assertIsNotNone(lease)
                    assert lease is not None
                    self.assertTrue(lease._deletion_prohibited)
                    self.assertTrue(lease._heartbeat_stop.is_set())
                    self.assertFalse(lease.released)
                    self.assertTrue(primary.is_dir())
                    self.assertFalse(legacy.exists())
                    self._assert_descriptor_only_recovery(
                        interruption,
                        forbidden_paths=(primary, legacy),
                    )
                    for anchor in captured_anchors:
                        if boundary == "entry":
                            os.fstat(anchor.descriptor)
                        else:
                            with self.assertRaises(OSError):
                                os.fstat(anchor.descriptor)
                finally:
                    for anchor in captured_anchors:
                        try:
                            os.close(anchor.descriptor)
                        except OSError:
                            pass
                    try:
                        primary.rmdir()
                    except FileNotFoundError:
                        pass

    def test_acquire_cleanup_release_call_boundaries_retain_diagnostic(
        self,
    ) -> None:
        boundaries = self._call_entry_and_return_boundary_offsets(
            claude_refresh_lock.acquire_claude_refresh_lock,
            callable_name="_release",
        )
        real_start_heartbeat = (
            claude_refresh_lock.ClaudeRefreshLockLease._start_heartbeat
        )

        for boundary, offset in zip(("entry", "return"), boundaries):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                startup_error = claude_refresh_lock.ClaudeRefreshLockError(
                    "injected post-start acquisition failure"
                )
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

                def start_then_fail(
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                ) -> None:
                    real_start_heartbeat(lease)
                    raise startup_error

                config = self._config_dir(pathlib.Path(temporary)).resolve()
                owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                with (
                    mock.patch.object(
                        claude_refresh_lock.ClaudeRefreshLockLease,
                        "_start_heartbeat",
                        new=start_then_fail,
                    ),
                    self._raise_before_instruction(
                        claude_refresh_lock.acquire_claude_refresh_lock,
                        offset=offset,
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                lease = owner.lease
                self.assertIsNotNone(lease)
                assert lease is not None
                paths = lease.paths
                descriptors = self._lease_descriptors(lease)
                self.assertTrue(lease._heartbeat_stop.is_set())
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        interruption
                    )
                )
                if boundary == "entry":
                    self.assertFalse(lease.released)
                    self.assertTrue(all(path.is_dir() for path in paths))
                    for descriptor in descriptors:
                        os.fstat(descriptor)
                    lease._release(skip_abandoned=False)
                else:
                    self.assertTrue(lease.released)
                    self.assertTrue(all(not path.exists() for path in paths))
                    for descriptor in descriptors:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)

    def test_open_result_interruption_retains_pending_recovery_fence(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        captured_anchors: list[claude_refresh_lock._DirectoryAnchor] = []
        captured_lock_descriptors: list[int] = []
        real_open_anchor = claude_refresh_lock._open_directory_anchor
        real_open = os.open

        def capture_anchor(*args: object, **kwargs: object) -> object:
            anchor = real_open_anchor(*args, **kwargs)
            captured_anchors.append(anchor)
            return anchor

        def capture_open(
            path: os.PathLike[str] | str,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            descriptor = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == self.PROTOCOL.primary_lock_name:
                captured_lock_descriptors.append(descriptor)
            return descriptor

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_open_directory_anchor",
                        new=capture_anchor,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "open",
                        new=capture_open,
                    ),
                    self._raise_before_instruction(
                        claude_refresh_lock._inspect_new_lock,
                        offset=self._raw_call_result_boundary_offset(
                            claude_refresh_lock._inspect_new_lock,
                            callable_name="open",
                            next_opname="STORE_FAST",
                            next_argval="descriptor",
                        ),
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.acquire_claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        owner=owner,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                lease = owner.lease
                self.assertIsNotNone(lease)
                assert lease is not None
                self.assertFalse(lease.released)
                self.assertIsNotNone(lease._cleanup_inconclusive)
                snapshot = lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(snapshot.verified_closed)
                self.assertIs(
                    snapshot.diagnostic,
                    lease._descriptor_bound_cleanup_fallback,
                )
                self.assertIsNotNone(lease._pending_acquisition)
                heartbeat = lease._heartbeat_thread
                self.assertTrue(heartbeat is None or not heartbeat.is_alive())
                self.assertTrue(primary.is_dir())
                self.assertFalse(legacy.exists())
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(interruption)
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        interruption
                    )
                )
                self.assertEqual(len(captured_lock_descriptors), 1)
                os.fstat(captured_lock_descriptors[0])
                for anchor in captured_anchors:
                    with self.assertRaises(OSError):
                        os.fstat(anchor.descriptor)
            finally:
                for descriptor in captured_lock_descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                for anchor in captured_anchors:
                    try:
                        os.close(anchor.descriptor)
                    except OSError:
                        pass
                try:
                    primary.rmdir()
                except FileNotFoundError:
                    pass

    def test_context_assignment_interruption_cleans_acquirer_owned_lease(
        self,
    ) -> None:
        cases = (
            (
                "default",
                claude_refresh_lock.claude_refresh_lock,
            ),
            (
                "explicit",
                claude_refresh_lock.claude_refresh_lock_release_on_success,
            ),
        )
        real_init = claude_refresh_lock.ClaudeRefreshLockLease.__init__

        for label, factory in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []

                def capture_init(
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                    *args: object,
                    **kwargs: object,
                ) -> None:
                    real_init(lease, *args, **kwargs)
                    captured.append(lease)

                config = self._config_dir(pathlib.Path(temporary)).resolve()
                generator = factory.__wrapped__
                try:
                    with (
                        mock.patch.object(
                            claude_refresh_lock.ClaudeRefreshLockLease,
                            "__init__",
                            new=capture_init,
                        ),
                        self._raise_before_instruction(
                            generator,
                            offset=self._lease_assignment_offset(generator),
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        with factory(
                            config,
                            protocol=self.PROTOCOL,
                            timeout_seconds=0,
                        ):
                            self.fail("assignment interruption reached context body")

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(len(captured), 1)
                    lease = captured[0]
                    paths = lease.paths
                    heartbeat = lease._heartbeat_thread
                    self.assertIsNotNone(heartbeat)
                    assert heartbeat is not None
                    self.assertFalse(
                        heartbeat.is_alive(),
                        "assignment interruption orphaned a renewing heartbeat",
                    )
                    self.assertTrue(lease.released)
                    self.assertTrue(all(not path.exists() for path in paths))
                    self.assertIsNone(
                        claude_refresh_lock._refresh_lock_recovery_paths(interruption)
                    )
                finally:
                    for lease in captured:
                        self._force_cleanup_test_lease(lease)

    def test_abandon_quiesces_and_closes_descriptors_but_retains_locks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            descriptors = self._lease_descriptors(lease)

            diagnostic = lease.abandon("reviewer process is quiescent")

            self.assertIsInstance(
                diagnostic,
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )
            thread = lease._heartbeat_thread
            assert thread is not None
            self.assertFalse(thread.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            self.assertIs(
                lease.abandon("a later reason must not replace the terminal state"),
                diagnostic,
            )
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as release:
                lease.release()
            self.assertIs(release.exception, diagnostic)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.assert_held()

            for path in reversed(lease.paths):
                path.rmdir()

    def test_context_abandon_normal_exit_skips_automatic_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ) as lease:
                diagnostic = lease.abandon("reviewer process is quiescent")

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as release:
                lease.release()
            self.assertIs(release.exception, diagnostic)

            for path in reversed(lease.paths):
                path.rmdir()

    def test_uncommitted_context_normal_exit_reports_descriptor_recovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as raised:
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            self._assert_descriptor_only_recovery(
                raised.exception,
                forbidden_paths=paths,
            )
            for path in reversed(paths):
                path.rmdir()

    def test_uncommitted_context_error_retains_and_attaches_recovery(self) -> None:
        body_error = claude_refresh_lock.ReviewError(
            "injected protected-context failure"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with self.assertRaises(claude_refresh_lock.ReviewError) as raised:
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    raise body_error

            self.assertIs(raised.exception, body_error)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            self._assert_descriptor_only_recovery(
                body_error,
                forbidden_paths=paths,
            )
            for path in reversed(paths):
                path.rmdir()

    def test_uncommitted_context_exit_survives_one_shot_customization_signal(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        real_customize = (
            claude_refresh_lock.ClaudeRefreshLockLease._customize_cleanup_inconclusive
        )
        customization_calls = 0

        def interrupt_customization_once(
            lease: claude_refresh_lock.ClaudeRefreshLockLease,
            diagnostic: claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            reason: str,
        ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
            nonlocal customization_calls
            customization_calls += 1
            if customization_calls == 1:
                raise interruption
            return real_customize(lease, diagnostic, reason)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_customize_cleanup_inconclusive",
                    autospec=True,
                    side_effect=interrupt_customization_once,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)

            self.assertIs(raised.exception, interruption)
            self.assertEqual(customization_calls, 1)
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    interruption
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(interruption)
            )
            self._assert_descriptor_only_error_graph(
                interruption,
                forbidden_paths=paths,
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            for path in reversed(paths):
                path.rmdir()

    def test_first_body_control_flow_wins_persistent_customization_interrupt(
        self,
    ) -> None:
        body_error = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        mark_interruption = KeyboardInterrupt(
            "persistent abandonment diagnostic interruption"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_customize_cleanup_inconclusive",
                    autospec=True,
                    side_effect=mark_interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)
                    raise body_error

            self.assertIs(raised.exception, body_error)
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    body_error
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(body_error)
            )
            self._assert_descriptor_only_error_graph(
                body_error,
                forbidden_paths=paths,
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    mark_interruption
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(mark_interruption)
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            for path in reversed(paths):
                path.rmdir()

    def test_uncommitted_context_exit_survives_customization_memory_error(
        self,
    ) -> None:
        allocation_error = MemoryError(
            "injected abandonment diagnostic allocation failure"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_customize_cleanup_inconclusive",
                    autospec=True,
                    side_effect=allocation_error,
                ),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)

            cause = raised.exception.__cause__
            self.assertIsNotNone(cause)
            assert cause is not None
            self.assertTrue(
                cause is allocation_error or cause.__cause__ is allocation_error
            )
            self._assert_descriptor_only_recovery(
                raised.exception,
                forbidden_paths=paths,
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            for path in reversed(paths):
                path.rmdir()

    def test_uncommitted_context_exit_repairs_publish_latch_interruption(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

        def cache_then_interrupt(
            lease: claude_refresh_lock.ClaudeRefreshLockLease,
        ) -> None:
            lease._cleanup_inconclusive = lease._cleanup_inconclusive_fallback
            raise interruption

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_publish_abandonment_state",
                    autospec=True,
                    side_effect=cache_then_interrupt,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)

            self.assertIs(raised.exception, interruption)
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    interruption
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(interruption)
            )
            self._assert_descriptor_only_error_graph(
                interruption,
                forbidden_paths=paths,
            )
            self.assertTrue(lease._abandoned)
            self.assertTrue(lease._release_started)
            self.assertTrue(lease._cleanup_started)
            self.assertTrue(lease._heartbeat_stop.is_set())
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            for path in reversed(paths):
                path.rmdir()

    def test_double_publish_interruption_cannot_reopen_release_decision(
        self,
    ) -> None:
        publish_interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        reassert_interruption = KeyboardInterrupt(
            "injected abandonment reassert interruption"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_publish_abandonment_state",
                    autospec=True,
                    side_effect=publish_interruption,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_reassert_abandonment_state",
                    autospec=True,
                    side_effect=reassert_interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                ) as lease:
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)

            self.assertIs(raised.exception, publish_interruption)
            self.assertTrue(
                getattr(
                    publish_interruption,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(lease._abandoned)
            self.assertFalse(lease._release_started)
            self.assertFalse(lease._cleanup_started)
            self.assertIsNone(lease._cleanup_inconclusive)
            self.assertTrue(lease._heartbeat_stop.is_set())
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            barrier = threading.Barrier(3)
            outcomes: dict[str, object] = {}
            outcomes_lock = threading.Lock()

            def record_outcome(name: str, outcome: object) -> None:
                with outcomes_lock:
                    outcomes[name] = outcome

            def retry_commit() -> None:
                barrier.wait()
                try:
                    lease.commit_context_release()
                except BaseException as error:
                    record_outcome("commit", error)
                else:
                    record_outcome("commit", None)

            def retry_release() -> None:
                barrier.wait()
                try:
                    lease.release()
                except BaseException as error:
                    record_outcome("release", error)
                else:
                    record_outcome("release", None)

            workers = (
                threading.Thread(target=retry_commit, name="retry-commit"),
                threading.Thread(target=retry_release, name="retry-release"),
            )
            with mock.patch.object(
                lease,
                "_release_once",
                side_effect=AssertionError("double interruption reopened release"),
            ) as release_once:
                for worker in workers:
                    worker.start()
                barrier.wait()
                self.assertEqual(self._join_started_workers(*workers), [])

            release_once.assert_not_called()
            self.assertIsInstance(
                outcomes["commit"],
                claude_refresh_lock.ClaudeRefreshLockCompromised,
            )
            self.assertIsInstance(
                outcomes["release"],
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            for path in reversed(paths):
                path.rmdir()

    def test_default_abandon_double_publish_interruption_then_timeout_retains(
        self,
    ) -> None:
        publish_interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        reassert_interruption = KeyboardInterrupt(
            "injected abandonment reassert interruption"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            descriptors = self._lease_descriptors(lease)
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            self.assertTrue(lease._operation_lock.acquire(timeout=1.0))
            try:
                with (
                    mock.patch.object(
                        lease,
                        "_publish_abandonment_state",
                        side_effect=publish_interruption,
                    ),
                    mock.patch.object(
                        lease,
                        "_reassert_abandonment_state",
                        side_effect=reassert_interruption,
                    ),
                    mock.patch.object(
                        lease,
                        "_shutdown_timeout_seconds",
                        return_value=0.0,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("bounded abandonment cleanup timed out")
            finally:
                lease._operation_lock.release()

            self.assertIs(raised.exception, publish_interruption)
            self.assertTrue(lease._deletion_prohibited)
            self.assertFalse(lease._abandoned)
            self.assertFalse(lease._release_started)
            self.assertFalse(lease._cleanup_started)
            self.assertIsNone(lease._cleanup_inconclusive)
            self.assertTrue(all(path.is_dir() for path in paths))
            for descriptor in descriptors:
                os.fstat(descriptor)

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=AssertionError(
                        "default release reopened prohibited lock deletion"
                    ),
                ) as release_once,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as released,
            ):
                lease.release()

            release_once.assert_not_called()
            self._assert_descriptor_only_recovery(
                released.exception,
                forbidden_paths=paths,
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(publish_interruption)
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    publish_interruption
                )
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as direct_release_once:
                lease._release_once()
            self.assertIs(
                direct_release_once.exception,
                released.exception,
            )
            self.assertTrue(all(path.is_dir() for path in paths))
            for path in reversed(paths):
                path.rmdir()

    def test_explicit_public_commit_and_release_permanently_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
                require_explicit_context_release=True,
            )
            paths = lease.paths

            for _attempt in range(2):
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ):
                    lease.commit_context_release()

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=AssertionError("public release deleted locks"),
                ) as release_once,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as release,
            ):
                lease.release()

            release_once.assert_not_called()
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.commit_context_release()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, release.exception)
            for path in reversed(paths):
                path.rmdir()

    def test_release_on_success_normal_exit_releases_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock_release_on_success(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            paths = lease.paths

            with mock.patch.object(
                lease,
                "_release_once",
                wraps=lease._release_once,
            ) as release_once:
                self.assertFalse(manager.__exit__(None, None, None))

            release_once.assert_called_once_with()
            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in paths))

    def test_release_on_success_body_errors_retain(self) -> None:
        failures = (
            ("ordinary-error", ValueError("injected body failure")),
            (
                "forwarded-signal",
                claude_refresh_lock.ForwardedSignal(signal.SIGTERM),
            ),
            ("memory-error", MemoryError("injected body allocation failure")),
        )

        for label, failure in failures:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                with self.assertRaises(type(failure)) as raised:
                    with claude_refresh_lock.claude_refresh_lock_release_on_success(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    ) as lease:
                        paths = lease.paths
                        descriptors = self._lease_descriptors(lease)
                        raise failure

                self.assertIs(raised.exception, failure)
                self._assert_descriptor_only_recovery(
                    failure,
                    forbidden_paths=paths,
                )
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in paths))
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                with (
                    mock.patch.object(
                        lease,
                        "_release_once",
                        side_effect=AssertionError(
                            "body failure reopened public deletion"
                        ),
                    ) as release_once,
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ),
                ):
                    lease.release()
                release_once.assert_not_called()
                for path in reversed(paths):
                    path.rmdir()

    def test_release_on_success_pre_yield_failure_retains(self) -> None:
        failures = (
            (
                "forwarded-signal",
                claude_refresh_lock.ForwardedSignal(signal.SIGTERM),
            ),
            ("memory-error", MemoryError("injected capability allocation failure")),
        )
        real_acquire = claude_refresh_lock.acquire_claude_refresh_lock

        for label, failure in failures:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                captured_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []

                def capture_lease(
                    *args: object,
                    **kwargs: object,
                ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                    lease = real_acquire(*args, **kwargs)
                    captured_leases.append(lease)
                    return lease

                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_lease,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.ClaudeRefreshLockLease,
                        "assert_held",
                        side_effect=failure,
                    ),
                    self.assertRaises(type(failure)) as raised,
                ):
                    with claude_refresh_lock.claude_refresh_lock_release_on_success(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    ):
                        self.fail("pre-yield initialization unexpectedly completed")

                self.assertIs(raised.exception, failure)
                self.assertEqual(len(captured_leases), 1)
                lease = captured_leases[0]
                paths = lease.paths
                self._assert_descriptor_only_recovery(
                    failure,
                    forbidden_paths=paths,
                )
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in paths))
                self.assertTrue(lease._heartbeat_stop.is_set())
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
                for descriptor in self._lease_descriptors(lease):
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                with (
                    mock.patch.object(
                        lease,
                        "_release_once",
                        side_effect=AssertionError(
                            "pre-yield failure reopened public deletion"
                        ),
                    ) as release_once,
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ),
                ):
                    lease.release()
                release_once.assert_not_called()
                for path in reversed(paths):
                    path.rmdir()

    def test_uncommitted_direct_release_fails_closed_and_retains(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
                require_explicit_context_release=True,
            )
            paths = lease.paths

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as raised:
                lease.release()

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.commit_context_release()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, raised.exception)
            for path in reversed(paths):
                path.rmdir()

    def test_release_on_success_interruption_before_release_body_retains(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock_release_on_success(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            paths = lease.paths
            descriptors = self._lease_descriptors(lease)
            with (
                mock.patch.object(
                    lease,
                    "_release",
                    side_effect=interruption,
                ) as release,
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                manager.__exit__(None, None, None)

            self.assertIs(raised.exception, interruption)
            release.assert_called_once_with(skip_abandoned=False)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in paths))
            self.assertTrue(lease._heartbeat_stop.is_set())
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ):
                lease.release()
            for path in reversed(paths):
                path.rmdir()

    def test_release_on_success_exceptional_cleanup_entry_is_fail_closed(
        self,
    ) -> None:
        for source in ("body", "release"):
            with (
                self.subTest(source=source),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                manager = claude_refresh_lock.claude_refresh_lock_release_on_success(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                lease = manager.__enter__()
                paths = lease.paths
                descriptors = self._lease_descriptors(lease)
                primary = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                cleanup_interruption = KeyboardInterrupt(
                    "injected exceptional cleanup entry interruption"
                )
                if source == "body":
                    try:
                        raise primary
                    except BaseException as error:
                        exit_arguments = (
                            type(error),
                            error,
                            error.__traceback__,
                        )
                else:
                    exit_arguments = (None, None, None)

                release_effect = primary if source == "release" else None
                with (
                    mock.patch.object(
                        lease,
                        "_release",
                        wraps=lease._release,
                        side_effect=release_effect,
                    ) as release,
                    mock.patch.object(
                        lease,
                        "_release_on_context_exit",
                        side_effect=cleanup_interruption,
                    ) as cleanup,
                ):
                    if source == "body":
                        self.assertFalse(manager.__exit__(*exit_arguments))
                        winner = primary
                    else:
                        with self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised:
                            manager.__exit__(*exit_arguments)
                        winner = raised.exception

                self.assertIs(winner, primary)
                self.assertEqual(
                    release.call_count,
                    1 if source == "release" else 0,
                )
                cleanup.assert_called_once_with()
                self.assertTrue(lease._deletion_prohibited)
                self.assertTrue(lease._heartbeat_stop.is_set())
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        primary
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(primary)
                )
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in paths))
                for descriptor in descriptors:
                    os.fstat(descriptor)

                with (
                    mock.patch.object(
                        lease,
                        "_release_once",
                        side_effect=AssertionError(
                            "exceptional cleanup interruption reopened deletion"
                        ),
                    ) as release_once,
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ) as released,
                ):
                    lease.release()

                release_once.assert_not_called()
                self._assert_descriptor_only_recovery(
                    released.exception,
                    forbidden_paths=paths,
                )
                self.assertTrue(all(path.is_dir() for path in paths))
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                for path in reversed(paths):
                    path.rmdir()

    def test_release_on_success_interruption_during_release_stays_terminal(
        self,
    ) -> None:
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        real_remove_owned_lock = claude_refresh_lock._remove_owned_lock
        remove_calls = 0

        def interrupt_first_remove(
            lock: claude_refresh_lock._HeldLock,
        ) -> None:
            nonlocal remove_calls
            remove_calls += 1
            if remove_calls == 1:
                raise interruption
            real_remove_owned_lock(lock)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock_release_on_success(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            paths = lease.paths
            descriptors = self._lease_descriptors(lease)
            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=interrupt_first_remove,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                manager.__exit__(None, None, None)

            self.assertIs(raised.exception, interruption)
            self.assertEqual(remove_calls, 2)
            self.assertFalse(lease.released)
            self.assertEqual(sum(path.is_dir() for path in paths), 1)
            self.assertTrue(lease._heartbeat_stop.is_set())
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=AssertionError("interrupted release was retried"),
                ) as release_once,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ),
            ):
                lease.release()
            release_once.assert_not_called()
            for path in reversed(paths):
                if path.exists():
                    path.rmdir()

    def test_abandon_control_flow_latches_before_diagnostic_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
                require_explicit_context_release=True,
            )
            paths = lease.paths
            interruption = GeneratorExit("injected third control-flow")

            with (
                mock.patch.object(
                    lease,
                    "_customize_cleanup_inconclusive",
                    side_effect=interruption,
                ),
                self.assertRaises(GeneratorExit) as raised,
            ):
                lease._abandon_if_context_release_uncommitted(
                    "diagnostic publication was interrupted"
                )

            self.assertIs(raised.exception, interruption)
            self.assertTrue(lease._abandoned)
            self.assertTrue(lease._release_started)
            self.assertTrue(lease._cleanup_started)
            self.assertTrue(lease._heartbeat_stop.is_set())
            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=AssertionError("retained lease attempted release"),
                ) as release_once,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ),
            ):
                lease.release()
            release_once.assert_not_called()
            self.assertTrue(all(path.is_dir() for path in paths))
            for path in reversed(paths):
                path.rmdir()

    def test_abandon_lifecycle_store_cannot_reopen_racing_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            abandon_holds_release_lock = threading.Event()
            allow_abandon_store = threading.Event()
            first_release_check = threading.Event()
            allow_second_release_check = threading.Event()
            second_release_check = threading.Event()
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            outcomes: dict[str, BaseException | None] = {}
            prepare_calls = 0
            prepare_calls_lock = threading.Lock()
            real_prepare = lease._prepare_abandonment_resume
            real_release_lock = lease._release_lock
            real_heartbeat_stop = lease._heartbeat_stop

            class PausingReleaseLock:
                def __enter__(self) -> object:
                    real_release_lock.acquire()
                    try:
                        if threading.current_thread().name == "interrupting-abandon":
                            abandon_holds_release_lock.set()
                            if not allow_abandon_store.wait(timeout=2.0):
                                raise AssertionError(
                                    "abandonment release-lock pause timed out"
                                )
                    except BaseException:
                        real_release_lock.release()
                        raise
                    return self

                def __exit__(
                    self,
                    _error_type: object,
                    _error: object,
                    _traceback: object,
                ) -> bool:
                    real_release_lock.release()
                    return False

            class InterruptingHeartbeatStop:
                def __init__(self) -> None:
                    self.armed = True

                def set(self) -> None:
                    if (
                        self.armed
                        and threading.current_thread().name == "interrupting-abandon"
                    ):
                        if (
                            lease._abandonment_cleanup_lifecycle
                            is not claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE
                        ):
                            raise AssertionError(
                                "heartbeat stop preceded lifecycle publication"
                            )
                        if real_heartbeat_stop.is_set():
                            raise AssertionError(
                                "heartbeat stop was already published at the "
                                "lifecycle interruption boundary"
                            )
                        self.armed = False
                        raise interruption
                    real_heartbeat_stop.set()

                def is_set(self) -> bool:
                    return real_heartbeat_stop.is_set()

                def wait(self, timeout: float | None = None) -> bool:
                    return real_heartbeat_stop.wait(timeout)

            pausing_release_lock = PausingReleaseLock()
            interrupting_heartbeat_stop = InterruptingHeartbeatStop()

            def observe_prepare() -> bool:
                nonlocal prepare_calls
                result = real_prepare()
                if threading.current_thread().name != "racing-release":
                    return result
                with prepare_calls_lock:
                    prepare_calls += 1
                    call_number = prepare_calls
                if call_number == 1:
                    first_release_check.set()
                    allow_second_release_check.wait(timeout=2.0)
                elif call_number == 2:
                    second_release_check.set()
                return result

            def run_release() -> None:
                try:
                    lease.release()
                except BaseException as error:
                    outcomes["release"] = error
                else:
                    outcomes["release"] = None

            def run_abandon() -> None:
                try:
                    lease.abandon("interrupt lifecycle publication")
                except BaseException as error:
                    outcomes["abandon"] = error
                else:
                    outcomes["abandon"] = None

            release_worker = threading.Thread(
                target=run_release,
                name="racing-release",
            )
            abandon_worker = threading.Thread(
                target=run_abandon,
                name="interrupting-abandon",
            )
            with (
                mock.patch.object(
                    lease,
                    "_prepare_abandonment_resume",
                    side_effect=observe_prepare,
                ),
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=AssertionError(
                        "racing release entered destructive cleanup"
                    ),
                ) as release_once,
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=AssertionError(
                        "racing release removed a retained lock"
                    ),
                ) as remove_owned_lock,
                mock.patch.object(
                    lease,
                    "_release_lock",
                    pausing_release_lock,
                ),
                mock.patch.object(
                    lease,
                    "_heartbeat_stop",
                    interrupting_heartbeat_stop,
                ),
            ):
                release_worker.start()
                self.assertTrue(first_release_check.wait(timeout=2.0))
                abandon_worker.start()
                self.assertTrue(abandon_holds_release_lock.wait(timeout=2.0))
                allow_second_release_check.set()
                self.assertTrue(second_release_check.wait(timeout=2.0))
                allow_abandon_store.set()
                alive = self._join_started_workers(
                    release_worker,
                    abandon_worker,
                )

                self.assertEqual(alive, [])
                self.assertIs(outcomes["abandon"], interruption)
                self.assertIsInstance(
                    outcomes["release"],
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                )
                resumed = lease.abandon("resume interrupted lifecycle publication")
                release_once.assert_not_called()
                remove_owned_lock.assert_not_called()

            self.assertIs(resumed, lease._cleanup_inconclusive)
            self.assertTrue(lease._deletion_prohibited)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            self.assertTrue(all(path.is_dir() for path in paths))
            for path in reversed(paths):
                path.rmdir()

    def test_finish_lock_entry_interruption_preserves_first_control_flow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            real_close = os.close
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            close_interrupted = False
            real_finish = lease._finish_abandonment
            real_state_lock = lease._state_lock

            class InterruptingStateLock:
                def __enter__(self) -> None:
                    raise second

                def __exit__(
                    self,
                    _error_type: object,
                    _error: object,
                    _traceback: object,
                ) -> None:
                    self.fail("unentered interrupting state lock exited")

            def close_then_interrupt(descriptor: int) -> None:
                nonlocal close_interrupted
                real_close(descriptor)
                if not close_interrupted:
                    close_interrupted = True
                    raise first

            def finish_with_lock_entry_interruption(
                diagnostic: claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                errors: list[BaseException],
            ) -> None:
                self.assertIn(first, errors)
                lease._state_lock = InterruptingStateLock()
                try:
                    real_finish(diagnostic, errors)
                finally:
                    lease._state_lock = real_state_lock

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=close_then_interrupt,
                ),
                mock.patch.object(
                    lease,
                    "_finish_abandonment",
                    side_effect=finish_with_lock_entry_interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.abandon("interrupt finish state-lock entry")

            self.assertIs(raised.exception, first)
            self.assertTrue(close_interrupted)
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(first)
            )
            self.assertFalse(hasattr(first, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(claude_refresh_lock._refresh_lock_recovery_paths(first))
            assert first.detail is not None
            for path in paths:
                self.assertNotIn(str(path), first.detail)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )

            resumed = lease.abandon("resume after finish lock interruption")
            self.assertIs(resumed, lease._cleanup_inconclusive)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            for path in reversed(paths):
                path.rmdir()

    def test_abandon_close_control_flow_survives_next_state_lock_signal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            real_close = os.close
            real_state_lock = lease._state_lock
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            interrupt_next_state_lock = False

            class InterruptingStateLock:
                def __enter__(self) -> object:
                    nonlocal interrupt_next_state_lock
                    if interrupt_next_state_lock:
                        interrupt_next_state_lock = False
                        raise second
                    return real_state_lock.__enter__()

                def __exit__(
                    self,
                    error_type: object,
                    error: object,
                    traceback: object,
                ) -> object:
                    return real_state_lock.__exit__(
                        error_type,
                        error,
                        traceback,
                    )

            close_interrupted = False

            def close_then_interrupt(descriptor: int) -> None:
                nonlocal close_interrupted, interrupt_next_state_lock
                real_close(descriptor)
                if not close_interrupted:
                    close_interrupted = True
                    interrupt_next_state_lock = True
                    raise first

            lease._state_lock = InterruptingStateLock()
            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=close_then_interrupt,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("descriptor close then state-lock entry interrupted")
            finally:
                lease._state_lock = real_state_lock

            try:
                self.assertTrue(close_interrupted)
                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
                )

                resumed = lease.abandon(
                    "resume after descriptor-loop state-lock interruption"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                for path in reversed(paths):
                    path.rmdir()
            finally:
                self._operator_cleanup_inconclusive_lease(lease)

    def test_finish_attachment_interruptions_preserve_first_control_flow(
        self,
    ) -> None:
        attachment = claude_refresh_lock._raise_frozen_control_flow_with_cleanup
        entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                attachment,
                statement="_attach_secondary_cleanup(",
                callable_name="_attach_secondary_cleanup",
            )
        )
        _internal_entry, internal_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                claude_refresh_lock._attach_secondary_cleanup,
                statement="attach_claude_refresh_lock_recovery(",
                callable_name="attach_claude_refresh_lock_recovery",
            )
        )

        for boundary, function, offset in (
            ("entry", attachment, entry_offset),
            ("return", attachment, return_offset),
            (
                "internal",
                claude_refresh_lock._attach_secondary_cleanup,
                internal_offset,
            ),
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                with lease._state_lock:
                    lease._publish_abandonment_state()
                diagnostic = lease._cleanup_inconclusive
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None

                with (
                    self._raise_before_instruction(
                        function,
                        offset=offset,
                        error=second,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    try:
                        raise first
                    except BaseException as active_first:
                        self.assertIs(active_first, first)
                        lease._finish_abandonment(
                            diagnostic,
                            [active_first],
                        )

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        first
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(first)
                )
                self.assertFalse(hasattr(first, "_codex_claude_refresh_lock_paths"))
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                resumed = lease.abandon(
                    f"resume after finish attachment {boundary} interruption"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                for path in reversed(paths):
                    path.rmdir()

    def test_finish_ordinary_error_attachment_signal_gets_recovery_evidence(
        self,
    ) -> None:
        finish = claude_refresh_lock.ClaudeRefreshLockLease._finish_abandonment
        attachment_offset, _return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                finish,
                statement=("_attach_secondary_cleanup(primary, recovery_evidence)"),
                callable_name="_attach_secondary_cleanup",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            with lease._state_lock:
                lease._publish_abandonment_state()
            diagnostic = lease._cleanup_inconclusive
            assert diagnostic is not None
            ordinary = claude_refresh_lock.ClaudeRefreshLockError(
                "ordinary abandonment failure"
            )
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                self._raise_before_instruction(
                    finish,
                    offset=attachment_offset,
                    error=first,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease._finish_abandonment(diagnostic, [ordinary])

            self.assertIs(raised.exception, first)
            self.assertIs(
                getattr(
                    first,
                    "_codex_claude_refresh_lock_cleanup_evidence",
                    None,
                ),
                lease._descriptor_bound_cleanup_fallback,
            )
            self._assert_descriptor_only_error_graph(
                first,
                forbidden_paths=paths,
            )
            resumed = lease.abandon("resume after finish attachment signal")
            self.assertIs(resumed, lease._cleanup_inconclusive)
            for path in reversed(paths):
                path.rmdir()

    def test_finish_ordinary_error_state_lock_signal_gets_recovery_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            with lease._state_lock:
                lease._publish_abandonment_state()
            diagnostic = lease._cleanup_inconclusive
            assert diagnostic is not None
            ordinary = claude_refresh_lock.ClaudeRefreshLockError(
                "ordinary abandonment failure"
            )
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            real_state_lock = lease._state_lock
            entries = 0

            class InterruptingStateLock:
                def __enter__(self) -> object:
                    nonlocal entries
                    entries += 1
                    if entries == 2:
                        raise first
                    return real_state_lock.__enter__()

                def __exit__(
                    self,
                    error_type: object,
                    error: object,
                    traceback: object,
                ) -> object:
                    return real_state_lock.__exit__(
                        error_type,
                        error,
                        traceback,
                    )

            lease._state_lock = InterruptingStateLock()
            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    lease._finish_abandonment(diagnostic, [ordinary])
            finally:
                lease._state_lock = real_state_lock

            self.assertEqual(entries, 2)
            self.assertIs(raised.exception, first)
            self.assertIs(
                getattr(
                    first,
                    "_codex_claude_refresh_lock_cleanup_evidence",
                    None,
                ),
                lease._descriptor_bound_cleanup_fallback,
            )
            self._assert_descriptor_only_error_graph(
                first,
                forbidden_paths=paths,
            )
            resumed = lease.abandon("resume after finish state-lock signal")
            self.assertIs(resumed, lease._cleanup_inconclusive)
            for path in reversed(paths):
                path.rmdir()

    def test_finish_lock_boundary_control_flow_survives_attachment_signal(
        self,
    ) -> None:
        attachment = claude_refresh_lock._raise_frozen_control_flow_with_cleanup
        offsets = self._source_call_entry_and_return_boundary_offsets(
            attachment,
            statement="_attach_secondary_cleanup(",
            callable_name="_attach_secondary_cleanup",
        )

        for boundary, offset in zip(("entry", "return"), offsets):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                with lease._state_lock:
                    lease._publish_abandonment_state()
                diagnostic = lease._cleanup_inconclusive
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                ordinary = claude_refresh_lock.ClaudeRefreshLockError(
                    "ordinary cleanup failure"
                )
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                real_state_lock = lease._state_lock

                class InterruptingStateLock:
                    def __enter__(self) -> None:
                        raise first

                    def __exit__(
                        self,
                        _error_type: object,
                        _error: object,
                        _traceback: object,
                    ) -> None:
                        self.fail("unentered interrupting state lock exited")

                lease._state_lock = InterruptingStateLock()
                try:
                    with (
                        self._raise_before_instruction(
                            attachment,
                            offset=offset,
                            error=second,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease._finish_abandonment(diagnostic, [ordinary])
                finally:
                    lease._state_lock = real_state_lock

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        first
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(first)
                )
                self.assertFalse(hasattr(first, "_codex_claude_refresh_lock_paths"))
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                resumed = lease.abandon(
                    f"resume after finish lock-boundary {boundary} signal"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                for path in reversed(paths):
                    path.rmdir()

    def test_finish_caller_boundaries_preserve_first_control_flow(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        offsets = self._source_call_entry_and_return_boundary_offsets(
            abandon,
            statement="self._finish_abandonment(diagnostic, errors)",
            callable_name="_finish_abandonment",
            occurrence=0,
        )

        for boundary, offset in zip(("entry", "return"), offsets):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                lease._heartbeat_stop.set()
                heartbeat.join(timeout=2.0)
                self.assertFalse(heartbeat.is_alive())
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                interrupted_heartbeat = mock.Mock()
                interrupted_heartbeat.join.side_effect = first
                interrupted_heartbeat.is_alive.return_value = True
                lease._heartbeat_thread = interrupted_heartbeat
                real_finish = lease._finish_abandonment

                def bind_then_return(
                    _diagnostic: (
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ),
                    errors: list[BaseException],
                ) -> None:
                    self.assertIn(first, errors)
                    claude_refresh_lock._bind_cleanup_recovery_evidence(
                        first,
                        lease._descriptor_bound_cleanup_fallback,
                    )

                finish_side_effect = (
                    bind_then_return if boundary == "return" else real_finish
                )
                try:
                    with (
                        mock.patch.object(
                            lease,
                            "_finish_abandonment",
                            side_effect=finish_side_effect,
                        ),
                        self._raise_before_instruction(
                            abandon,
                            offset=offset,
                            error=second,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease.abandon(f"finish caller {boundary} interruption")
                finally:
                    lease._heartbeat_thread = heartbeat

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                resumed = lease.abandon(
                    f"resume after finish caller {boundary} interruption"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                for path in reversed(paths):
                    path.rmdir()

    def test_resuming_demotion_failure_attachment_preserves_first_control_flow(
        self,
    ) -> None:
        attachment = claude_refresh_lock._raise_frozen_control_flow_with_cleanup
        offsets = self._source_call_entry_and_return_boundary_offsets(
            attachment,
            statement="_attach_secondary_cleanup(",
            callable_name="_attach_secondary_cleanup",
        )

        for boundary, offset in zip(("entry", "return"), offsets):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                with lease._state_lock:
                    lease._publish_abandonment_state()
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                ordinary = claude_refresh_lock.ClaudeRefreshLockError(
                    "second demotion attempt failed"
                )
                later = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

                with (
                    mock.patch.object(
                        lease,
                        "_demote_cleanup_inconclusive_paths",
                        side_effect=[first, ordinary],
                    ),
                    self._raise_before_instruction(
                        attachment,
                        offset=offset,
                        error=later,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon(f"resuming demotion attachment {boundary} signal")

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, later)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                resumed = lease.abandon(
                    f"complete resuming demotion after {boundary} signal"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                for path in reversed(paths):
                    path.rmdir()

    def test_finish_demotion_failure_attachment_preserves_first_control_flow(
        self,
    ) -> None:
        attachment = claude_refresh_lock._raise_frozen_control_flow_with_cleanup
        offsets = self._source_call_entry_and_return_boundary_offsets(
            attachment,
            statement="_attach_secondary_cleanup(",
            callable_name="_attach_secondary_cleanup",
        )

        for boundary, offset in zip(("entry", "return"), offsets):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                with lease._state_lock:
                    lease._publish_abandonment_state()
                diagnostic = lease._cleanup_inconclusive
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                ordinary = claude_refresh_lock.ClaudeRefreshLockError(
                    "ordinary abandonment failure"
                )
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                later = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

                with (
                    mock.patch.object(
                        lease,
                        "_demote_cleanup_inconclusive_paths",
                        side_effect=first,
                    ),
                    self._raise_before_instruction(
                        attachment,
                        offset=offset,
                        error=later,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease._finish_abandonment(diagnostic, [ordinary])

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, later)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    lease._descriptor_bound_cleanup_fallback,
                )
                self._assert_descriptor_only_error_graph(
                    first,
                    forbidden_paths=paths,
                )
                resumed = lease.abandon(
                    f"complete finish demotion after {boundary} signal"
                )
                self.assertIs(resumed, lease._cleanup_inconclusive)
                for path in reversed(paths):
                    path.rmdir()

    def test_context_release_commit_and_abandon_race_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
                require_explicit_context_release=True,
            )
            paths = lease.paths
            decision_reached = threading.Event()
            allow_abandonment = threading.Event()
            commit_attempted = threading.Event()
            release_attempted = threading.Event()
            outcomes: dict[str, object] = {}
            outcomes_lock = threading.Lock()

            class PausingStateLock:
                def __init__(self, lock: object) -> None:
                    self._lock = lock
                    self._local = threading.local()
                    self._paused = False

                def __enter__(self) -> PausingStateLock:
                    self._lock.acquire()
                    self._local.depth = getattr(self._local, "depth", 0) + 1
                    return self

                def __exit__(
                    self,
                    _error_type: object,
                    _error: object,
                    _traceback: object,
                ) -> None:
                    depth = self._local.depth - 1
                    self._local.depth = depth
                    self._lock.release()
                    if (
                        threading.current_thread().name == "guard-uncommitted-release"
                        and depth == 0
                        and not self._paused
                    ):
                        self._paused = True
                        decision_reached.set()
                        allow_abandonment.wait(timeout=2.0)

            lease._state_lock = PausingStateLock(lease._state_lock)

            def record_outcome(name: str, outcome: object) -> None:
                with outcomes_lock:
                    outcomes[name] = outcome

            def guard_uncommitted_release() -> None:
                try:
                    lease._abandon_if_context_release_uncommitted(
                        "paused uncommitted decision"
                    )
                except BaseException as error:
                    record_outcome("guard", error)
                else:
                    record_outcome("guard", None)

            def commit_release() -> None:
                commit_attempted.set()
                try:
                    lease.commit_context_release()
                except BaseException as error:
                    record_outcome("commit", error)
                else:
                    record_outcome("commit", None)

            def delete_locks() -> None:
                release_attempted.set()
                try:
                    lease.release()
                except BaseException as error:
                    record_outcome("release", error)
                else:
                    record_outcome("release", None)

            workers = (
                threading.Thread(
                    target=guard_uncommitted_release,
                    name="guard-uncommitted-release",
                ),
                threading.Thread(target=commit_release, name="commit-release"),
                threading.Thread(target=delete_locks, name="delete-locks"),
            )
            with mock.patch.object(
                lease,
                "_release_once",
                side_effect=AssertionError("racing release deleted locks"),
            ) as release_once:
                workers[0].start()
                decision_seen = decision_reached.wait(timeout=2.0)
                self.assertTrue(lease._abandoned)
                self.assertTrue(lease._release_started)
                self.assertTrue(lease._cleanup_started)
                self.assertTrue(lease._heartbeat_stop.is_set())
                workers[1].start()
                workers[2].start()
                commit_seen = commit_attempted.wait(timeout=2.0)
                release_seen = release_attempted.wait(timeout=2.0)
                allow_abandonment.set()
                alive = self._join_started_workers(*workers)

            self.assertTrue(decision_seen)
            self.assertTrue(commit_seen)
            self.assertTrue(release_seen)
            self.assertEqual(alive, [])
            release_once.assert_not_called()

            self.assertIsInstance(
                outcomes["guard"],
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            )
            self.assertIsInstance(
                outcomes["commit"],
                claude_refresh_lock.ClaudeRefreshLockCompromised,
            )
            self.assertIs(outcomes["release"], outcomes["guard"])
            self.assertTrue(all(path.is_dir() for path in paths))
            for path in reversed(paths):
                path.rmdir()

    def test_explicit_mode_partial_acquisition_cleanup_remains_unarmed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockTimeout):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                )

            self.assertFalse(primary.exists())
            self.assertTrue(legacy.is_dir())
            legacy.rmdir()

    def test_fallback_preconstruction_failure_precedes_anchor_and_lock_acquire(
        self,
    ) -> None:
        allocation_error = MemoryError(
            "injected pre-acquisition diagnostic allocation failure"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_new_cleanup_inconclusive_fallback",
                    side_effect=allocation_error,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                ) as open_anchor,
                self.assertRaises(MemoryError) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                )

            self.assertIs(raised.exception, allocation_error)
            open_anchor.assert_not_called()
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    def test_explicit_mode_heartbeat_start_failure_cleans_unreturned_lease(
        self,
    ) -> None:
        start_error = claude_refresh_lock.ClaudeRefreshLockError(
            "injected explicit-mode heartbeat start failure"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / self.PROTOCOL.primary_lock_name
            legacy = pathlib.Path(str(config) + self.PROTOCOL.legacy_suffix)

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_start_heartbeat",
                    side_effect=start_error,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    require_explicit_context_release=True,
                )

            self.assertIs(raised.exception, start_error)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    def test_default_context_and_direct_release_need_no_explicit_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            direct_paths = lease.paths

            lease.release()
            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in direct_paths))

            with claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ) as context_lease:
                context_paths = context_lease.paths

            self.assertTrue(context_lease.released)
            self.assertTrue(all(not path.exists() for path in context_paths))

    def test_abandon_ancestor_retarget_uses_descriptor_bound_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None
            lease._heartbeat_stop.set()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            lexical_paths = lease.paths

            retained_home = root / "retained-home"
            home.rename(retained_home)
            home.mkdir(mode=0o700)
            replacement_config = self._config_dir(home)
            replacement_primary = replacement_config / ".oauth_refresh.lock"
            replacement_legacy = pathlib.Path(str(replacement_config) + ".lock")
            replacement_primary.mkdir(mode=0o700)
            replacement_legacy.mkdir(mode=0o700)
            live_marker = replacement_primary / "live-owner"
            live_marker.write_text("replacement\n", encoding="utf-8")
            replacement_identities = tuple(
                (path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (replacement_primary, replacement_legacy)
            )

            diagnostic = lease.abandon("ancestor path was retargeted")

            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            for path in lexical_paths:
                self.assertNotIn(str(path), str(diagnostic))
            self.assertEqual(
                replacement_identities,
                tuple(
                    (path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in (replacement_primary, replacement_legacy)
                ),
            )
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )
            self.assertIs(
                lease.abandon("terminal diagnostic must remain cached"),
                diagnostic,
            )

            retained_config = retained_home / ".claude"
            (retained_home / ".claude.lock").rmdir()
            (retained_config / ".oauth_refresh.lock").rmdir()
            replacement_legacy.rmdir()
            live_marker.unlink()
            replacement_primary.rmdir()

    def test_abandon_post_proof_retarget_never_publishes_lexical_paths(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        teardown_offset = self._source_statement_offset(
            abandon,
            statement="if self._abandonment_descriptors_pending is None:",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            lexical_paths = tuple(str(path) for path in lease.paths)
            self.assertEqual(
                lease._prove_authoritative_recovery_paths(),
                lexical_paths,
            )
            retained_home = root / "retained-home"
            replacement_primary: pathlib.Path | None = None
            replacement_legacy: pathlib.Path | None = None
            live_marker: pathlib.Path | None = None
            retargeted = False

            def retarget_after_proof() -> None:
                nonlocal replacement_primary
                nonlocal replacement_legacy
                nonlocal live_marker
                nonlocal retargeted
                home.rename(retained_home)
                home.mkdir(mode=0o700)
                replacement_config = self._config_dir(home)
                replacement_primary = (
                    replacement_config / self.PROTOCOL.primary_lock_name
                )
                replacement_legacy = pathlib.Path(
                    str(replacement_config) + self.PROTOCOL.legacy_suffix
                )
                replacement_primary.mkdir(mode=0o700)
                replacement_legacy.mkdir(mode=0o700)
                live_marker = replacement_primary / "live-owner"
                live_marker.write_text("replacement\n", encoding="utf-8")
                retargeted = True

            with self._call_before_instruction(
                abandon,
                offset=teardown_offset,
                callback=retarget_after_proof,
            ):
                diagnostic = lease.abandon(
                    "ancestor retargeted after recovery-path proof"
                )

            self.assertTrue(retargeted)
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            self.assertIs(
                lease._retention_recovery_evidence,
                lease._descriptor_bound_cleanup_fallback,
            )
            snapshot = lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertIs(
                snapshot.diagnostic,
                lease._descriptor_bound_cleanup_fallback,
            )
            for path in lexical_paths:
                self.assertNotIn(path, str(diagnostic))

            rendered = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            claude_linux._attach_host_refresh_lock_recovery(
                rendered,
                snapshot.diagnostic,
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(rendered)
            )
            self.assertFalse(hasattr(rendered, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(rendered)
            )
            assert rendered.detail is not None
            for path in lexical_paths:
                self.assertNotIn(path, rendered.detail)

            assert replacement_primary is not None
            assert replacement_legacy is not None
            assert live_marker is not None
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )
            self.assertTrue(replacement_legacy.is_dir())
            retained_config = retained_home / ".claude"
            (retained_home / ".claude.lock").rmdir()
            (retained_config / ".oauth_refresh.lock").rmdir()
            replacement_legacy.rmdir()
            live_marker.unlink()
            replacement_primary.rmdir()

    def test_resumed_abandonment_stays_descriptor_bound_after_retarget(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        _entry_offset, close_return_offset = (
            self._call_entry_and_return_boundary_offsets(
                abandon,
                callable_name="close",
            )
        )
        real_close = os.close
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lexical_paths = lease.paths
            descriptors = self._lease_descriptors(lease)
            interrupted_descriptor = descriptors[0]
            close_counts: dict[int, int] = {}
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            def record_close(descriptor: int) -> None:
                close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=record_close,
                ),
                self._raise_before_instruction(
                    abandon,
                    offset=close_return_offset,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.abandon("promote paths before close interruption")

            self.assertIs(raised.exception, interruption)
            diagnostic = lease._cleanup_inconclusive
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lexical_paths,
            )
            retention = lease.retention_snapshot()
            self.assertFalse(retention.terminal)
            self.assertFalse(retention.verified_closed)
            self.assertIs(
                retention.diagnostic,
                lease._descriptor_bound_cleanup_fallback,
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    retention.diagnostic
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(retention.diagnostic)
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    raised.exception
                )
            )
            self.assertFalse(
                hasattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
            )
            assert raised.exception.detail is not None
            for path in lexical_paths:
                self.assertNotIn(str(path), raised.exception.detail)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )
            self.assertEqual(close_counts[interrupted_descriptor], 1)

            retained_home = root / "retained-home"
            home.rename(retained_home)
            home.mkdir(mode=0o700)
            replacement_config = self._config_dir(home)
            replacement_primary = replacement_config / ".oauth_refresh.lock"
            replacement_legacy = pathlib.Path(str(replacement_config) + ".lock")
            replacement_primary.mkdir(mode=0o700)
            replacement_legacy.mkdir(mode=0o700)
            live_marker = replacement_primary / "live-owner"
            live_marker.write_text("replacement\n", encoding="utf-8")

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=record_close,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=AssertionError(
                        "resumed abandonment removed retained lock"
                    ),
                ) as remove_owned_lock,
            ):
                resumed = lease.abandon("reproof failed after ancestor retarget")

            self.assertIs(resumed, diagnostic)
            remove_owned_lock.assert_not_called()
            self.assertEqual(set(close_counts), set(descriptors))
            self.assertTrue(all(count == 1 for count in close_counts.values()))
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    diagnostic
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            for path in lexical_paths:
                self.assertNotIn(str(path), str(diagnostic))
            attached = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            claude_refresh_lock.attach_claude_refresh_lock_recovery(
                attached,
                diagnostic,
            )
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(attached)
            )
            self.assertFalse(hasattr(attached, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(attached)
            )
            assert attached.detail is not None
            for path in lexical_paths:
                self.assertNotIn(str(path), attached.detail)
                self.assertNotIn(str(path), raised.exception.detail)
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )

            retained_config = retained_home / ".claude"
            self.assertTrue((retained_home / ".claude.lock").is_dir())
            self.assertTrue((retained_config / ".oauth_refresh.lock").is_dir())
            (retained_home / ".claude.lock").rmdir()
            (retained_config / ".oauth_refresh.lock").rmdir()
            replacement_legacy.rmdir()
            live_marker.unlink()
            replacement_primary.rmdir()

    def test_recovery_path_demotion_publishes_descriptor_marker_first(
        self,
    ) -> None:
        demote = claude_refresh_lock.ClaudeRefreshLockLease._demote_cleanup_inconclusive_paths
        demotion_entry, _demotion_return = (
            self._source_call_entry_and_return_boundary_offsets(
                demote,
                statement="delattr(",
                callable_name="delattr",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = tuple(str(path) for path in lease.paths)
            diagnostic = lease._cleanup_inconclusive_fallback
            with lease._state_lock:
                lease._cleanup_inconclusive = diagnostic
            lease._promote_cleanup_inconclusive_paths(
                diagnostic,
                reason="promoted fixture recovery",
                authoritative_paths=paths,
            )
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                self._raise_before_instruction(
                    demote,
                    offset=demotion_entry,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease._demote_cleanup_inconclusive_paths(
                    diagnostic,
                    reason="demoted fixture recovery",
                )

            self.assertIs(raised.exception, interruption)
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertTrue(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            for path in paths:
                self.assertNotIn(path, str(diagnostic))

            demoted = lease._demote_cleanup_inconclusive_paths(
                diagnostic,
                reason="complete fixture demotion",
            )
            self.assertIs(demoted, diagnostic)
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            with lease._state_lock:
                lease._cleanup_inconclusive = None
            lease.release()

    def test_double_demotion_interruption_uses_distinct_descriptor_fallback(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        _entry_offset, close_return_offset = (
            self._call_entry_and_return_boundary_offsets(
                abandon,
                callable_name="close",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = tuple(str(path) for path in lease.paths)
            close_interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            with (
                self._raise_before_instruction(
                    abandon,
                    offset=close_return_offset,
                    error=close_interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as close_raised,
            ):
                lease.abandon("promote paths before demotion failures")

            self.assertIs(close_raised.exception, close_interruption)
            diagnostic = lease._cleanup_inconclusive
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )
            self.assertIsNot(
                lease._descriptor_bound_cleanup_fallback,
                diagnostic,
            )
            first_interruption = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            second_interruption = KeyboardInterrupt(
                "injected second demotion marker interruption"
            )
            interruptions = [first_interruption, second_interruption]
            diagnostic_type = type(diagnostic)
            real_setattr = diagnostic_type.__setattr__

            def interrupt_marker_publication(
                candidate: claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                name: str,
                value: object,
            ) -> None:
                if (
                    candidate is diagnostic
                    and name == "_codex_claude_refresh_lock_descriptor_bound"
                    and interruptions
                ):
                    raise interruptions.pop(0)
                real_setattr(candidate, name, value)

            with (
                mock.patch.object(
                    diagnostic_type,
                    "__setattr__",
                    new=interrupt_marker_publication,
                ),
                self.assertRaises(
                    claude_refresh_lock.ForwardedSignal
                ) as demotion_raised,
            ):
                lease.abandon("both path demotion attempts were interrupted")

            winner = demotion_raised.exception
            self.assertIs(winner, first_interruption)
            self.assertEqual(interruptions, [])
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(winner)
            )
            self.assertFalse(hasattr(winner, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(claude_refresh_lock._refresh_lock_recovery_paths(winner))
            assert winner.detail is not None
            for path in paths:
                self.assertNotIn(path, winner.detail)
                self.assertNotIn(path, str(winner))
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )
            self.assertFalse(lease.retention_snapshot().terminal)

            resumed = lease.abandon("complete demotion after interruptions")
            self.assertIs(resumed, diagnostic)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            for path in reversed(lease.paths):
                path.rmdir()

    def test_abandon_lock_replacement_uses_descriptor_bound_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None
            lease._heartbeat_stop.set()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            lexical_paths = lease.paths
            primary, legacy = lexical_paths

            primary.rmdir()
            primary.mkdir(mode=0o700)
            live_marker = primary / "live-owner"
            live_marker.write_text("replacement\n", encoding="utf-8")
            replacement_metadata = primary.stat()
            replacement_identity = (
                replacement_metadata.st_dev,
                replacement_metadata.st_ino,
                replacement_metadata.st_mtime_ns,
            )

            diagnostic = lease.abandon("primary lock was replaced")

            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            for path in lexical_paths:
                self.assertNotIn(str(path), str(diagnostic))
            replacement_metadata = primary.stat()
            self.assertEqual(
                replacement_identity,
                (
                    replacement_metadata.st_dev,
                    replacement_metadata.st_ino,
                    replacement_metadata.st_mtime_ns,
                ),
            )
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )
            self.assertTrue(legacy.is_dir())
            self.assertIs(
                lease.abandon("terminal diagnostic must remain cached"),
                diagnostic,
            )
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as release:
                lease.release()
            self.assertIs(release.exception, diagnostic)

            legacy.rmdir()
            live_marker.unlink()
            primary.rmdir()

    def test_abandon_late_heartbeat_compromise_cannot_publish_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            late_heartbeat = mock.Mock()

            def publish_late_compromise(*, timeout: float) -> None:
                self.assertGreater(timeout, 0)
                with lease._state_lock:
                    lease._heartbeat_error = (
                        claude_refresh_lock.ClaudeRefreshLockCompromised(
                            "injected late heartbeat compromise"
                        )
                    )

            late_heartbeat.join.side_effect = publish_late_compromise
            late_heartbeat.is_alive.return_value = False
            lease._heartbeat_thread = late_heartbeat

            diagnostic = lease.abandon("heartbeat finished after terminalization")

            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            self.assertIs(
                lease.abandon("terminal diagnostic must remain cached"),
                diagnostic,
            )

            for path in reversed(lease.paths):
                path.rmdir()

    def test_abandon_does_not_republish_identity_proof_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            with mock.patch.object(
                lease,
                "_prove_authoritative_recovery_paths",
                side_effect=AssertionError(
                    "abandonment reproved lexical recovery paths"
                ),
            ) as prove_paths:
                diagnostic = lease.abandon(
                    "terminal recovery must remain descriptor-bound"
                )

            prove_paths.assert_not_called()
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )

            for path in reversed(lease.paths):
                path.rmdir()

    def test_abandon_cache_then_control_flow_completes_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            real_customize = lease._customize_cleanup_inconclusive
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            def customize_then_interrupt(
                diagnostic: claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                reason: str,
            ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
                real_customize(diagnostic, reason)
                raise interruption

            with (
                mock.patch.object(
                    lease,
                    "_customize_cleanup_inconclusive",
                    side_effect=customize_then_interrupt,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.abandon("terminal publication was interrupted")

            self.assertIs(raised.exception, interruption)
            self.assertTrue(lease._abandoned)
            self.assertTrue(lease._release_started)
            self.assertTrue(lease._cleanup_started)
            self.assertTrue(lease._heartbeat_stop.is_set())
            diagnostic = lease.abandon("terminal diagnostic must remain cached")
            self.assertIs(diagnostic, lease._cleanup_inconclusive)
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )

            self._operator_cleanup_inconclusive_lease(lease)

    def test_cached_abandonment_resumes_non_destructive_cleanup(self) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        stages = (
            (
                "before-heartbeat-join",
                self._source_statement_offset(
                    abandon,
                    statement="heartbeat_alive = False",
                ),
            ),
            (
                "after-heartbeat-join",
                self._source_statement_offset(
                    abandon,
                    statement="operation_handoff = _OperationLockHandoff(",
                ),
            ),
            (
                "before-descriptor-close",
                self._source_statement_offset(
                    abandon,
                    statement=("if self._abandonment_descriptors_pending is None:"),
                ),
            ),
            (
                "after-descriptor-close",
                self._source_statement_offset(
                    abandon,
                    statement="self._finish_abandonment(diagnostic, errors)",
                    occurrence=2,
                ),
            ),
        )

        for stage, offset in stages:
            for retry in ("abandon", "release"):
                with (
                    self.subTest(stage=stage, retry=retry),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    config = self._config_dir(pathlib.Path(temporary)).resolve()
                    lease = self._acquire_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)
                    interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                    try:
                        with (
                            self._raise_before_instruction(
                                abandon,
                                offset=offset,
                                error=interruption,
                            ),
                            self.assertRaises(
                                claude_refresh_lock.ForwardedSignal
                            ) as raised,
                        ):
                            lease.abandon(f"interrupted abandonment at {stage}")

                        self.assertIs(raised.exception, interruption)
                        diagnostic = lease._cleanup_inconclusive
                        self.assertIsNotNone(diagnostic)
                        assert diagnostic is not None
                        self.assertTrue(lease._deletion_prohibited)
                        self.assertTrue(all(path.is_dir() for path in paths))

                        with mock.patch.object(
                            lease,
                            "_release_once",
                            side_effect=AssertionError(
                                "abandonment resume attempted lock deletion"
                            ),
                        ) as release_once:
                            if retry == "abandon":
                                resumed = lease.abandon(
                                    "resume cached abandonment cleanup"
                                )
                            else:
                                with self.assertRaises(
                                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                                ) as released:
                                    lease.release()
                                resumed = released.exception

                        release_once.assert_not_called()
                        self.assertIs(resumed, diagnostic)
                        heartbeat = lease._heartbeat_thread
                        assert heartbeat is not None
                        heartbeat.join(timeout=1.0)
                        self.assertFalse(heartbeat.is_alive())
                        self.assertFalse(lease.released)
                        self.assertTrue(all(path.is_dir() for path in paths))
                        for descriptor in descriptors:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        self.assertTrue(
                            getattr(
                                lease,
                                "_abandonment_cleanup_completed",
                                False,
                            )
                        )
                    finally:
                        self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_descriptor_pop_boundaries_settle_without_reclose(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        boundaries = self._call_entry_and_return_boundary_offsets(
            abandon,
            callable_name="pop",
        )
        real_close = os.close

        for boundary, offset in zip(("entry", "return"), boundaries):
            for retry in ("abandon", "release"):
                with (
                    self.subTest(boundary=boundary, retry=retry),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    config = self._config_dir(pathlib.Path(temporary)).resolve()
                    lease = self._acquire_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )
                    paths = lease.paths
                    descriptors = self._lease_descriptors(lease)
                    interrupted_descriptor = descriptors[0]
                    interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                    try:
                        with (
                            self._raise_before_instruction(
                                abandon,
                                offset=offset,
                                error=interruption,
                            ),
                            self.assertRaises(
                                claude_refresh_lock.ForwardedSignal
                            ) as raised,
                        ):
                            lease.abandon(f"descriptor pop {boundary} interruption")

                        self.assertIs(raised.exception, interruption)
                        diagnostic = lease._cleanup_inconclusive
                        self.assertIsNotNone(diagnostic)
                        assert diagnostic is not None
                        os.fstat(interrupted_descriptor)
                        close_calls: list[int] = []

                        def record_close(descriptor: int) -> None:
                            close_calls.append(descriptor)
                            real_close(descriptor)

                        with mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=record_close,
                        ):
                            if retry == "abandon":
                                resumed = lease.abandon(
                                    "settle interrupted descriptor ownership"
                                )
                            else:
                                with self.assertRaises(
                                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                                ) as released:
                                    lease.release()
                                resumed = released.exception

                        self.assertIs(resumed, diagnostic)
                        self.assertNotIn(
                            interrupted_descriptor,
                            close_calls,
                        )
                        os.fstat(interrupted_descriptor)
                        for descriptor in descriptors[1:]:
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        self.assertFalse(lease._abandonment_cleanup_completed)
                        self.assertIs(
                            lease._abandonment_cleanup_lifecycle,
                            claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                        )
                        self.assertIn(
                            interrupted_descriptor,
                            lease._abandonment_descriptors_residue,
                        )
                        self.assertTrue(all(path.is_dir() for path in paths))

                        with (
                            mock.patch.object(
                                claude_refresh_lock.os,
                                "close",
                                side_effect=AssertionError(
                                    "settled descriptor residue was retried"
                                ),
                            ),
                            self.assertRaises(
                                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                            ) as repeated,
                        ):
                            lease.release()
                        self.assertIs(repeated.exception, diagnostic)
                    finally:
                        self._operator_cleanup_inconclusive_lease(lease)

    def test_prearmed_retention_release_promotes_resumable_abandonment(
        self,
    ) -> None:
        lease_type = claude_refresh_lock.ClaudeRefreshLockLease
        entrypoints = (
            ("public", lease_type.release),
            ("internal", lease_type._release),
        )

        for entry_name, entrypoint in entrypoints:
            abandon_entry, _abandon_return = (
                self._call_entry_and_return_boundary_offsets(
                    entrypoint,
                    callable_name="_abandon",
                )
            )
            with (
                self.subTest(entry=entry_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                descriptors = self._lease_descriptors(lease)
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                with lease._state_lock:
                    lease._deletion_prohibited = True
                    lease._heartbeat_stop.set()

                try:
                    with (
                        self._raise_before_instruction(
                            entrypoint,
                            offset=abandon_entry,
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        if entry_name == "public":
                            lease.release()
                        else:
                            lease._release(skip_abandoned=False)

                    self.assertIs(raised.exception, interruption)
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
                    )
                    self.assertFalse(lease._cleanup_started)
                    self.assertIsNone(lease._cleanup_inconclusive)
                    for descriptor in descriptors:
                        os.fstat(descriptor)

                    with self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ) as resumed:
                        lease.release()

                    self.assertIs(
                        resumed.exception,
                        lease._cleanup_inconclusive,
                    )
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                    )
                    self.assertTrue(lease._abandonment_cleanup_completed)
                    self.assertTrue(all(path.is_dir() for path in lease.paths))
                    for descriptor in descriptors:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                finally:
                    self._operator_cleanup_inconclusive_lease(lease)

    def test_retain_only_wrapper_does_not_resume_destructive_cleanup(
        self,
    ) -> None:
        release_once = claude_refresh_lock.ClaudeRefreshLockLease._release_once
        boundaries = self._call_entry_and_return_boundary_offsets(
            release_once,
            callable_name="close",
        )
        real_close = os.close

        for boundary, offset in zip(("entry", "return"), boundaries):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                manager = claude_refresh_lock.claude_refresh_lock_release_on_success(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                lease = manager.__enter__()
                descriptors = self._lease_descriptors(lease)
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                close_counts: dict[int, int] = {}

                def record_close(descriptor: int) -> None:
                    close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                    real_close(descriptor)

                try:
                    with (
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=record_close,
                        ),
                        self._raise_before_instruction(
                            release_once,
                            offset=offset,
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        manager.__exit__(None, None, None)

                    self.assertIs(raised.exception, interruption)
                    self.assertFalse(lease._abandoned)
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.NOT_STARTED,
                    )
                    self.assertIsNone(lease._abandonment_descriptors_pending)
                    self.assertTrue(all(count <= 1 for count in close_counts.values()))
                    diagnostic = lease._cleanup_inconclusive
                    self.assertIsNotNone(diagnostic)
                    assert diagnostic is not None
                    with (
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=AssertionError(
                                "destructive cleanup residue was closed again"
                            ),
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                        ) as released,
                    ):
                        lease.release()
                    self.assertIs(released.exception, diagnostic)
                    self.assertFalse(lease._abandoned)
                    with (
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=AssertionError(
                                "internal destructive residue was closed again"
                            ),
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                        ) as internal_released,
                    ):
                        lease._release(skip_abandoned=False)
                    self.assertIs(internal_released.exception, diagnostic)
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.NOT_STARTED,
                    )
                finally:
                    for descriptor in descriptors:
                        try:
                            real_close(descriptor)
                        except OSError:
                            pass

    def test_abandon_close_return_reused_fd_is_never_closed(self) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        _entry_offset, return_offset = self._call_entry_and_return_boundary_offsets(
            abandon,
            callable_name="close",
        )
        settlement_boundaries = self._source_call_entry_and_return_boundary_offsets(
            abandon,
            statement="_abandonment_descriptors_residue.add(",
            callable_name="add",
            occurrence=2,
        )
        real_close = os.close
        real_fstat = os.fstat

        for boundary, settlement_offset in zip(
            ("entry", "return"), settlement_boundaries
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                paths = lease.paths
                descriptors = self._lease_descriptors(lease)
                interrupted_descriptor = descriptors[0]
                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                settlement_interruption = claude_refresh_lock.ForwardedSignal(
                    signal.SIGINT
                )
                sentinel_descriptors: list[int] = []
                try:
                    with (
                        self._raise_before_instruction(
                            abandon,
                            offset=return_offset,
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease.abandon("descriptor close return was interrupted")

                    self.assertIs(raised.exception, interruption)
                    diagnostic = lease._cleanup_inconclusive
                    self.assertIsNotNone(diagnostic)
                    assert diagnostic is not None
                    for _attempt in range(len(descriptors) + 2):
                        descriptor = os.open(os.devnull, os.O_RDONLY)
                        sentinel_descriptors.append(descriptor)
                        if descriptor == interrupted_descriptor:
                            break
                    self.assertIn(
                        interrupted_descriptor,
                        sentinel_descriptors,
                    )

                    fstat_calls: list[int] = []
                    resumed_close_calls: list[int] = []

                    def record_fstat(descriptor: int) -> os.stat_result:
                        if descriptor == interrupted_descriptor:
                            fstat_calls.append(descriptor)
                        return real_fstat(descriptor)

                    def record_close(descriptor: int) -> None:
                        resumed_close_calls.append(descriptor)
                        real_close(descriptor)

                    with (
                        mock.patch.object(
                            lease,
                            "_prove_authoritative_recovery_paths",
                            return_value=None,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "fstat",
                            side_effect=record_fstat,
                        ),
                        self._raise_before_instruction(
                            abandon,
                            offset=settlement_offset,
                            error=settlement_interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as settlement_raised,
                    ):
                        lease.abandon(f"interrupt reused descriptor residue {boundary}")

                    self.assertIs(
                        settlement_raised.exception,
                        settlement_interruption,
                    )
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
                    )

                    with (
                        mock.patch.object(
                            lease,
                            "_prove_authoritative_recovery_paths",
                            return_value=None,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "fstat",
                            side_effect=record_fstat,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=record_close,
                        ),
                    ):
                        resumed = lease.abandon("settle reused descriptor residue")

                    self.assertIs(resumed, diagnostic)
                    self.assertEqual(
                        fstat_calls.count(interrupted_descriptor),
                        2 if boundary == "entry" else 1,
                    )
                    self.assertNotIn(
                        interrupted_descriptor,
                        resumed_close_calls,
                    )
                    os.fstat(interrupted_descriptor)
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                    )
                    self.assertFalse(lease._abandonment_cleanup_completed)
                    self.assertIn(
                        interrupted_descriptor,
                        lease._abandonment_descriptors_residue,
                    )
                    self.assertTrue(all(path.is_dir() for path in paths))
                    with (
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "fstat",
                            side_effect=AssertionError(
                                "settled reused descriptor was rechecked"
                            ),
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=AssertionError(
                                "settled reused descriptor was reclosed"
                            ),
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                        ) as repeated,
                    ):
                        lease.release()
                    self.assertIs(repeated.exception, diagnostic)
                finally:
                    for descriptor in sentinel_descriptors:
                        try:
                            real_close(descriptor)
                        except OSError:
                            pass
                    self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_non_ebadf_fstat_error_settles_as_residue(self) -> None:
        real_fstat = os.fstat
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            failed_descriptor = self._lease_descriptors(lease)[0]
            diagnostic = self._seed_resumable_abandonment_descriptor(
                lease,
                failed_descriptor,
            )

            fstat_calls: list[int] = []

            def fail_target_fstat(descriptor: int) -> os.stat_result:
                if descriptor != failed_descriptor:
                    return real_fstat(descriptor)
                fstat_calls.append(descriptor)
                raise OSError(
                    errno.EIO,
                    "injected descriptor fstat failure",
                )

            try:
                with (
                    mock.patch.object(
                        lease,
                        "_prove_authoritative_recovery_paths",
                        return_value=None,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "fstat",
                        side_effect=fail_target_fstat,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=AssertionError(
                            "unconfirmed descriptor was closed again"
                        ),
                    ),
                ):
                    resumed = lease.abandon("settle non-EBADF descriptor fstat failure")

                self.assertEqual(fstat_calls, [failed_descriptor])
                self.assertIs(resumed, diagnostic)
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                self.assertFalse(lease._abandonment_cleanup_completed)
                self.assertNotIn(
                    failed_descriptor,
                    lease._abandonment_descriptors_unconfirmed,
                )
                self.assertIn(
                    failed_descriptor,
                    lease._abandonment_descriptors_residue,
                )
            finally:
                self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_residue_publication_is_destination_first(self) -> None:
        source = inspect.getsource(
            claude_refresh_lock.ClaudeRefreshLockLease._abandon
        ).splitlines()
        residue_add_lines = [
            index
            for index, line in enumerate(source)
            if "_abandonment_descriptors_residue.add(" in line
        ]

        self.assertEqual(len(residue_add_lines), 3)
        for add_line in residue_add_lines:
            following_lines = source[add_line + 1 : add_line + 8]
            self.assertTrue(
                any(
                    "_abandonment_descriptors_unconfirmed.discard(" in line
                    for line in following_lines
                ),
                msg=(
                    "descriptor residue must be published before unconfirmed "
                    f"ownership is discarded near source line {add_line + 1}"
                ),
            )

    def test_abandon_base_exception_residue_boundaries_preserve_evidence(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        settlement_boundaries = self._source_call_entry_and_return_boundary_offsets(
            abandon,
            statement="_abandonment_descriptors_residue.add(",
            callable_name="add",
            occurrence=1,
        )
        real_fstat = os.fstat

        for boundary, settlement_offset in zip(
            ("entry", "return"), settlement_boundaries
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                failed_descriptor = self._lease_descriptors(lease)[0]
                diagnostic = self._seed_resumable_abandonment_descriptor(
                    lease,
                    failed_descriptor,
                )
                fstat_calls: list[int] = []

                def fail_target_fstat(descriptor: int) -> os.stat_result:
                    if descriptor != failed_descriptor:
                        return real_fstat(descriptor)
                    fstat_calls.append(descriptor)
                    raise RuntimeError("injected descriptor fstat control flow")

                interruption = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                try:
                    with (
                        mock.patch.object(
                            lease,
                            "_prove_authoritative_recovery_paths",
                            return_value=None,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "fstat",
                            side_effect=fail_target_fstat,
                        ),
                        self._raise_before_instruction(
                            abandon,
                            offset=settlement_offset,
                            error=interruption,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease.abandon(f"interrupt base-exception residue {boundary}")

                    self.assertIs(raised.exception, interruption)
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
                    )
                    with (
                        mock.patch.object(
                            lease,
                            "_prove_authoritative_recovery_paths",
                            return_value=None,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "fstat",
                            side_effect=fail_target_fstat,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=AssertionError(
                                "unconfirmed descriptor was closed again"
                            ),
                        ),
                    ):
                        resumed = lease.abandon(
                            "settle base-exception descriptor residue"
                        )

                    self.assertIs(resumed, diagnostic)
                    self.assertEqual(
                        fstat_calls.count(failed_descriptor),
                        2 if boundary == "entry" else 1,
                    )
                    self.assertIs(
                        lease._abandonment_cleanup_lifecycle,
                        claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                    )
                    self.assertFalse(lease._abandonment_cleanup_completed)
                    self.assertNotIn(
                        failed_descriptor,
                        lease._abandonment_descriptors_unconfirmed,
                    )
                    self.assertIn(
                        failed_descriptor,
                        lease._abandonment_descriptors_residue,
                    )
                finally:
                    self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_never_promotes_paths_and_still_closes_descriptors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            descriptors = self._lease_descriptors(lease)
            with mock.patch.object(
                lease,
                "_promote_cleanup_inconclusive_paths",
                side_effect=AssertionError(
                    "abandonment promoted lexical recovery paths"
                ),
            ) as promote_paths:
                diagnostic = lease.abandon(
                    "terminal recovery must remain descriptor-bound"
                )

            promote_paths.assert_not_called()
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            for path in reversed(lease.paths):
                path.rmdir()

    def test_context_abandon_exception_exit_preserves_body_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            body_error = ValueError("injected credential operation failure")

            with self.assertRaises(ValueError) as raised:
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                ) as lease:
                    diagnostic = lease.abandon("reviewer process is quiescent")
                    raise body_error

            self.assertIs(raised.exception, body_error)
            self.assertFalse(hasattr(body_error, "_codex_claude_refresh_lock_paths"))
            self.assertFalse(getattr(body_error, "__notes__", ()))
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as release:
                lease.release()
            self.assertIs(release.exception, diagnostic)

            for path in reversed(lease.paths):
                path.rmdir()

    def test_abandon_interruption_resumes_terminal_residue_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None
            descriptors = self._lease_descriptors(lease)
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                mock.patch.object(thread, "join", side_effect=forwarded),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.abandon("reviewer cleanup was interrupted")

            self.assertIs(raised.exception, forwarded)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            diagnostic = lease.abandon("must not retry terminal abandonment")
            self.assertIs(
                diagnostic,
                lease._cleanup_inconclusive,
            )
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )
            self.assertTrue(lease._abandonment_cleanup_completed)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_quiescence_failure_retains_descriptors_and_locks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None
            lease._heartbeat_stop.set()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            descriptors = self._lease_descriptors(lease)
            operation_lock = mock.Mock()
            operation_lock.acquire.return_value = False
            lease._operation_lock = operation_lock

            diagnostic = lease.abandon("operations did not quiesce")

            self.assertIs(
                diagnostic,
                lease._cleanup_inconclusive,
            )
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            for descriptor in descriptors:
                os.fstat(descriptor)
            operation_lock.release.assert_not_called()

            self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_descriptor_close_failure_stays_terminal_with_residue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            descriptors = self._lease_descriptors(lease)
            failed_descriptor = descriptors[0]
            real_close = os.close
            failed = False
            close_attempts: dict[int, int] = {}

            def fail_one_close(descriptor: int) -> None:
                nonlocal failed
                close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
                if descriptor == failed_descriptor and not failed:
                    failed = True
                    raise OSError(5, "injected descriptor close failure")
                real_close(descriptor)

            with mock.patch.object(
                claude_refresh_lock.os,
                "close",
                side_effect=fail_one_close,
            ):
                diagnostic = lease.abandon("descriptor cleanup failed")

            self.assertTrue(failed)
            self.assertIs(diagnostic, lease._cleanup_inconclusive)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertTrue(
                claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                    diagnostic
                )
            )
            self.assertFalse(hasattr(diagnostic, "_codex_claude_refresh_lock_paths"))
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
            )
            for path in lease.paths:
                self.assertNotIn(str(path), str(diagnostic))
            os.fstat(failed_descriptor)
            for descriptor in descriptors[1:]:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            with mock.patch.object(
                claude_refresh_lock.os,
                "close",
                side_effect=AssertionError("failed descriptor cleanup was retried"),
            ):
                self.assertIs(
                    lease.abandon("must not retry partial descriptor cleanup"),
                    diagnostic,
                )
            self.assertEqual(close_attempts[failed_descriptor], 1)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            self.assertFalse(lease._abandonment_cleanup_completed)
            self.assertIn(
                failed_descriptor,
                lease._abandonment_descriptors_residue,
            )
            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "fstat",
                    side_effect=AssertionError(
                        "settled retention snapshot rechecked descriptors"
                    ),
                ),
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=AssertionError(
                        "settled retention snapshot reclosed descriptors"
                    ),
                ),
            ):
                first_snapshot = lease.retention_snapshot()
                second_snapshot = lease.retention_snapshot()
            self.assertEqual(first_snapshot, second_snapshot)
            self.assertTrue(first_snapshot.terminal)
            self.assertFalse(first_snapshot.verified_closed)
            self.assertIs(
                first_snapshot.diagnostic,
                lease._descriptor_bound_cleanup_fallback,
            )

            real_close(failed_descriptor)
            for path in reversed(lease.paths):
                path.rmdir()

    def test_resumable_abandonment_is_not_terminal_after_physical_close(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            with lease._state_lock:
                lease._publish_abandonment_state()
            for descriptor in self._lease_descriptors(lease):
                os.close(descriptor)

            snapshot = lease.retention_snapshot()

            self.assertFalse(snapshot.terminal)
            self.assertFalse(snapshot.verified_closed)
            self.assertIs(
                snapshot.diagnostic,
                lease._descriptor_bound_cleanup_fallback,
            )
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )
            for path in reversed(lease.paths):
                path.rmdir()

    def test_settled_publication_interruption_keeps_descriptor_evidence(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        offset = self._source_statement_offset(
            abandon,
            statement="self._retention_recovery_evidence = (",
            occurrence=1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            evidence = lease._descriptor_bound_cleanup_fallback
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                self._raise_before_instruction(
                    abandon,
                    offset=offset,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.abandon("terminal evidence publication was interrupted")

            self.assertIs(raised.exception, interruption)
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
            )
            self.assertIs(lease._retention_recovery_evidence, evidence)
            snapshot = lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertIs(snapshot.diagnostic, evidence)

            diagnostic = lease.abandon("resume terminal evidence publication")
            self.assertIs(diagnostic, lease._cleanup_inconclusive)
            self.assertIsNot(diagnostic, evidence)
            self.assertIs(lease._retention_recovery_evidence, evidence)
            self.assertIs(lease.retention_snapshot().diagnostic, evidence)
            lease._promote_cleanup_inconclusive_paths(
                diagnostic,
                reason="legacy settled recovery state",
                authoritative_paths=tuple(str(path) for path in lease.paths),
            )
            self.assertIs(
                lease.abandon("demote legacy settled recovery state"),
                diagnostic,
            )
            self._assert_descriptor_only_recovery(
                diagnostic,
                forbidden_paths=lease.paths,
            )
            self.assertIs(lease._retention_recovery_evidence, evidence)
            for path in reversed(lease.paths):
                path.rmdir()

    def test_release_publication_interruption_keeps_evidence_until_retry(
        self,
    ) -> None:
        release_once = claude_refresh_lock.ClaudeRefreshLockLease._release_once
        offset = self._source_statement_offset(
            release_once,
            statement="self._retention_recovery_evidence = None",
            occurrence=1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            evidence = lease._descriptor_bound_cleanup_fallback
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                self._raise_before_instruction(
                    release_once,
                    offset=offset,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, interruption)
            self.assertTrue(lease.released)
            self.assertIs(lease._retention_recovery_evidence, evidence)
            snapshot = lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertTrue(snapshot.verified_closed)
            self.assertIs(snapshot.diagnostic, evidence)

            lease.release()
            self.assertIsNone(lease._retention_recovery_evidence)
            self.assertIsNone(lease.retention_snapshot().diagnostic)

    def test_abandon_operation_guard_release_control_flow_is_terminal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            descriptors = self._lease_descriptors(lease)
            interruption = KeyboardInterrupt(
                "injected operation-guard release interruption"
            )
            operation_lock = mock.Mock()
            operation_lock.acquire.return_value = True
            operation_lock.release.side_effect = [interruption, None]
            lease._operation_lock = operation_lock

            with self.assertRaises(KeyboardInterrupt) as raised:
                lease.abandon("operation guard release was interrupted")

            self.assertIs(raised.exception, interruption)
            diagnostic = lease.abandon("terminal diagnostic must remain cached")
            self.assertIs(diagnostic, lease._cleanup_inconclusive)
            self.assertEqual(operation_lock.release.call_count, 2)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

            for path in reversed(lease.paths):
                path.rmdir()

    def test_blocked_heartbeat_cannot_prevent_bounded_release(self) -> None:
        heartbeat_entered = threading.Event()
        allow_heartbeat_exit = threading.Event()
        release_finished = threading.Event()
        release_errors: list[BaseException] = []
        real_wait = claude_refresh_lock.threading.Event.wait

        def fast_wait(
            event: threading.Event,
            timeout: float | None = None,
        ) -> bool:
            bounded = 0.01 if timeout is None else min(timeout, 0.01)
            return real_wait(event, bounded)

        def block_heartbeat_renewal(
            _lease: claude_refresh_lock.ClaudeRefreshLockLease,
        ) -> None:
            heartbeat_entered.set()
            real_wait(allow_heartbeat_exit, 10.0)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_renew_and_assert",
                    autospec=True,
                    side_effect=block_heartbeat_renewal,
                ),
            ):
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                release_thread: threading.Thread | None = None
                try:
                    self.assertTrue(real_wait(heartbeat_entered, 2.0))
                    thread = lease._heartbeat_thread
                    assert thread is not None

                    def release_lease() -> None:
                        try:
                            lease.release()
                        except BaseException as error:
                            release_errors.append(error)
                        finally:
                            release_finished.set()

                    release_thread = threading.Thread(
                        target=release_lease,
                        name="test-refresh-lock-release",
                        daemon=True,
                    )
                    with (
                        mock.patch.object(thread, "join", return_value=None),
                        mock.patch.object(thread, "is_alive", return_value=True),
                    ):
                        release_thread.start()
                        finished_without_rescue = real_wait(release_finished, 1.0)
                        if not finished_without_rescue:
                            allow_heartbeat_exit.set()
                            self.assertTrue(real_wait(release_finished, 2.0))
                    release_thread.join(timeout=2.0)
                    self.assertFalse(release_thread.is_alive())
                    self.assertTrue(
                        finished_without_rescue,
                        "release blocked on heartbeat-held state lock before bounded join",
                    )
                    self.assertEqual(len(release_errors), 1)
                    self.assertIsInstance(
                        release_errors[0],
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                    )
                    self.assertTrue(
                        getattr(
                            release_errors[0],
                            "_codex_claude_refresh_lock_descriptor_bound",
                            False,
                        )
                    )
                    self.assertIsNone(
                        claude_refresh_lock._refresh_lock_recovery_paths(
                            release_errors[0]
                        )
                    )
                finally:
                    allow_heartbeat_exit.set()
                    alive_workers = self._join_started_workers(
                        *((release_thread,) if release_thread is not None else ())
                    )
                    if not alive_workers:
                        self._operator_cleanup_inconclusive_lease(lease)
                    self.assertEqual(alive_workers, [])

    def test_blocked_assert_retains_locks_after_bounded_release(self) -> None:
        assert_entered = threading.Event()
        allow_assert_exit = threading.Event()
        assert_finished = threading.Event()
        release_finished = threading.Event()
        assert_errors: list[BaseException] = []
        release_errors: list[BaseException] = []

        def block_assert_renewal() -> None:
            assert_entered.set()
            allow_assert_exit.wait(timeout=10.0)

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())

            def assert_lease() -> None:
                try:
                    lease.assert_held()
                except BaseException as error:
                    assert_errors.append(error)
                finally:
                    assert_finished.set()

            def release_lease() -> None:
                try:
                    lease.release()
                except BaseException as error:
                    release_errors.append(error)
                finally:
                    release_finished.set()

            assert_thread = threading.Thread(
                target=assert_lease,
                name="test-refresh-lock-assert",
                daemon=True,
            )
            release_thread = threading.Thread(
                target=release_lease,
                name="test-refresh-lock-release",
                daemon=True,
            )
            try:
                with (
                    mock.patch.object(
                        lease,
                        "_renew_and_assert",
                        side_effect=block_assert_renewal,
                    ),
                    mock.patch.object(
                        lease,
                        "_shutdown_timeout_seconds",
                        return_value=0.05,
                    ),
                ):
                    assert_thread.start()
                    self.assertTrue(assert_entered.wait(timeout=2.0))
                    release_thread.start()
                    finished_without_rescue = release_finished.wait(timeout=1.0)
                    if not finished_without_rescue:
                        allow_assert_exit.set()
                        self.assertTrue(release_finished.wait(timeout=2.0))

                release_thread.join(timeout=2.0)
                self.assertFalse(release_thread.is_alive())
                self.assertTrue(
                    finished_without_rescue,
                    "release blocked instead of bounding an active assertion",
                )
                self.assertEqual(len(release_errors), 1)
                self.assertIsInstance(
                    release_errors[0],
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
                )
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                for descriptor in self._lease_descriptors(lease):
                    os.fstat(descriptor)

                allow_assert_exit.set()
                self.assertTrue(assert_finished.wait(timeout=2.0))
                assert_thread.join(timeout=2.0)
                self.assertFalse(assert_thread.is_alive())
                self.assertEqual(len(assert_errors), 1)
                self.assertIsInstance(
                    assert_errors[0],
                    claude_refresh_lock.ClaudeRefreshLockCompromised,
                )
                self.assertIn("release already started", str(assert_errors[0]))
            finally:
                allow_assert_exit.set()
                alive_workers = self._join_started_workers(
                    assert_thread,
                    release_thread,
                )
                if not alive_workers:
                    self._operator_cleanup_inconclusive_lease(lease)
                self.assertEqual(alive_workers, [])

    def test_release_observes_late_heartbeat_failure(self) -> None:
        heartbeat_entered = threading.Event()
        allow_heartbeat_failure = threading.Event()
        release_finished = threading.Event()
        release_errors: list[BaseException] = []
        real_wait = claude_refresh_lock.threading.Event.wait
        compromise = claude_refresh_lock.ClaudeRefreshLockCompromised(
            "injected late heartbeat compromise"
        )

        def fast_wait(
            event: threading.Event,
            timeout: float | None = None,
        ) -> bool:
            bounded = 0.01 if timeout is None else min(timeout, 0.01)
            return real_wait(event, bounded)

        def fail_heartbeat_after_release(
            _lease: claude_refresh_lock.ClaudeRefreshLockLease,
        ) -> None:
            heartbeat_entered.set()
            real_wait(allow_heartbeat_failure, 10.0)
            raise compromise

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.threading.Event,
                    "wait",
                    new=fast_wait,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_renew_and_assert",
                    autospec=True,
                    side_effect=fail_heartbeat_after_release,
                ),
            ):
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

                def release_lease() -> None:
                    try:
                        lease.release()
                    except BaseException as error:
                        release_errors.append(error)
                    finally:
                        release_finished.set()

                release_thread = threading.Thread(
                    target=release_lease,
                    name="test-refresh-lock-late-failure-release",
                    daemon=True,
                )
                try:
                    self.assertTrue(real_wait(heartbeat_entered, 2.0))
                    release_thread.start()
                    release_started = real_wait(lease._heartbeat_stop, 1.0)
                    if not release_started:
                        allow_heartbeat_failure.set()
                        self.assertTrue(real_wait(lease._heartbeat_stop, 2.0))
                    allow_heartbeat_failure.set()
                    self.assertTrue(real_wait(release_finished, 2.0))
                    release_thread.join(timeout=2.0)
                    self.assertFalse(release_thread.is_alive())
                    self.assertTrue(
                        release_started,
                        "release could not publish stop while heartbeat I/O was active",
                    )
                    self.assertEqual(release_errors, [compromise])
                    self.assertTrue(lease.released)
                    self.assertTrue(all(not path.exists() for path in lease.paths))
                finally:
                    allow_heartbeat_failure.set()
                    alive_workers = self._join_started_workers(release_thread)
                    if not alive_workers and not lease.released:
                        self._operator_cleanup_inconclusive_lease(lease)
                    self.assertEqual(alive_workers, [])

    def test_release_observes_late_assert_failure(self) -> None:
        assert_entered = threading.Event()
        allow_assert_failure = threading.Event()
        release_waiting_for_operation = threading.Event()
        assert_finished = threading.Event()
        release_finished = threading.Event()
        assert_errors: list[BaseException] = []
        release_errors: list[BaseException] = []
        compromise = claude_refresh_lock.ClaudeRefreshLockCompromised(
            "injected late assertion compromise"
        )

        class ObservedOperationLock:
            def __init__(self) -> None:
                self._lock = threading.Lock()

            def __enter__(self) -> ObservedOperationLock:
                self._lock.acquire()
                return self

            def __exit__(
                self,
                _error_type: type[BaseException] | None,
                _error: BaseException | None,
                _traceback: object,
            ) -> None:
                self._lock.release()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                release_waiting_for_operation.set()
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self._lock.release()

        def fail_assert_after_release() -> None:
            assert_entered.set()
            allow_assert_failure.wait(timeout=10.0)
            raise compromise

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            lease._operation_lock = ObservedOperationLock()

            def assert_lease() -> None:
                try:
                    lease.assert_held()
                except BaseException as error:
                    assert_errors.append(error)
                finally:
                    assert_finished.set()

            def release_lease() -> None:
                try:
                    lease.release()
                except BaseException as error:
                    release_errors.append(error)
                finally:
                    release_finished.set()

            assert_thread = threading.Thread(
                target=assert_lease,
                name="test-refresh-lock-late-assert-failure",
                daemon=True,
            )
            release_thread = threading.Thread(
                target=release_lease,
                name="test-refresh-lock-late-assert-release",
                daemon=True,
            )
            try:
                with mock.patch.object(
                    lease,
                    "_renew_and_assert",
                    side_effect=fail_assert_after_release,
                ):
                    assert_thread.start()
                    self.assertTrue(assert_entered.wait(timeout=2.0))
                    release_thread.start()
                    self.assertTrue(release_waiting_for_operation.wait(timeout=2.0))
                    allow_assert_failure.set()
                    self.assertTrue(assert_finished.wait(timeout=2.0))
                    self.assertTrue(release_finished.wait(timeout=2.0))

                self.assertEqual(assert_errors, [compromise])
                self.assertEqual(release_errors, [compromise])
                self.assertTrue(lease.released)
                self.assertTrue(all(not path.exists() for path in lease.paths))
            finally:
                allow_assert_failure.set()
                alive_workers = self._join_started_workers(
                    assert_thread,
                    release_thread,
                )
                if not alive_workers and not lease.released:
                    self._operator_cleanup_inconclusive_lease(lease)
                self.assertEqual(alive_workers, [])

    def test_release_retries_cleanup_after_transient_heartbeat_join_timeout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", side_effect=(True, False)),
                self.assertRaisesRegex(
                    claude_refresh_lock.ClaudeRefreshLockError,
                    "heartbeat did not stop",
                ),
            ):
                lease.release()

            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in lease.paths))
            lease.release()

    def test_release_becomes_terminal_after_both_bounded_join_attempts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                lease.release()

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
            )
            with self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockCompromised,
                "release already started",
            ):
                lease.assert_held()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, raised.exception)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

            self._operator_cleanup_inconclusive_lease(lease)

    def test_context_owner_retries_transient_heartbeat_join_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", side_effect=(True, False)),
                self.assertRaisesRegex(
                    claude_refresh_lock.ClaudeRefreshLockError,
                    "heartbeat did not stop",
                ),
            ):
                manager.__exit__(None, None, None)

            self.assertTrue(lease.released)
            self.assertTrue(all(not path.exists() for path in lease.paths))

    def test_context_owner_reports_locks_after_both_join_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                manager.__exit__(None, None, None)

            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
            )

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertIs(repeated.exception, raised.exception)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

            self._operator_cleanup_inconclusive_lease(lease)

    def test_context_body_error_displays_inconclusive_cleanup_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            manager = claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease = manager.__enter__()
            thread = lease._heartbeat_thread
            assert thread is not None
            body_error = claude_refresh_lock.ReviewError(
                "injected credential operation failure"
            )

            with (
                mock.patch.object(thread, "join", return_value=None),
                mock.patch.object(thread, "is_alive", return_value=True),
            ):
                suppressed = manager.__exit__(
                    type(body_error),
                    body_error,
                    None,
                )

            self.assertFalse(suppressed)
            self.assertTrue(
                getattr(
                    body_error,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(body_error)
            )
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self._operator_cleanup_inconclusive_lease(lease)

    def test_release_never_retries_after_descriptor_cleanup_started(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            calls = 0

            def interrupt_after_cleanup_started() -> None:
                nonlocal calls
                calls += 1
                with lease._state_lock:
                    lease._cleanup_started = True
                    lease._heartbeat_stop.set()
                raise interruption

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=interrupt_after_cleanup_started,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, interruption)
            self.assertEqual(calls, 1)
            assert interruption.detail is not None
            self.assertIn("no authoritative pathname", interruption.detail)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertTrue(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_retry_cleanup_gap_publishes_terminal_signal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_timeout = claude_refresh_lock.ClaudeRefreshLockError(
                "Claude refresh-lock heartbeat did not stop"
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            calls = 0

            def timeout_then_interrupt_cleanup() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise first_timeout
                lease._heartbeat_stop.set()
                lease._mark_cleanup_inconclusive("injected second-attempt cleanup gap")
                with lease._state_lock:
                    lease._cleanup_started = True
                raise forwarded

            with (
                mock.patch.object(
                    lease,
                    "_release_once",
                    side_effect=timeout_then_interrupt_cleanup,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, forwarded)
            self.assertEqual(calls, 2)
            assert forwarded.detail is not None
            self.assertIn("no authoritative pathname", forwarded.detail)
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            self.assertTrue(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_cleanup_loop_signal_keeps_partial_release_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            real_remove = claude_refresh_lock._remove_owned_lock
            calls = 0

            def interrupt_first_removal(
                lock: claude_refresh_lock._HeldLock,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise forwarded
                real_remove(lock)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=interrupt_first_removal,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, forwarded)
            self.assertFalse(lease.released)
            assert forwarded.detail is not None
            self.assertIn("no authoritative pathname", forwarded.detail)
            self.assertFalse(lease.paths[0].exists())
            self.assertTrue(lease.paths[1].is_dir())
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()
            self.assertTrue(
                getattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(
                hasattr(
                    repeated.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(repeated.exception)
            )
            self._operator_cleanup_inconclusive_lease(lease)

    def test_partial_remove_failure_never_reuses_a_replacement_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary, legacy = lease.paths
            real_remove = claude_refresh_lock._remove_owned_lock
            removal_error = claude_refresh_lock.ClaudeRefreshLockError(
                "injected partial removal failure"
            )
            removal_calls = 0

            def fail_first_removal(
                lock: claude_refresh_lock._HeldLock,
            ) -> None:
                nonlocal removal_calls
                removal_calls += 1
                if removal_calls == 1:
                    raise removal_error
                real_remove(lock)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_remove_owned_lock",
                    side_effect=fail_first_removal,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, removal_error)
            self.assertFalse(primary.exists())
            self.assertTrue(legacy.is_dir())
            self.assertFalse(
                hasattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
            )

            primary.mkdir(mode=0o700)
            live_marker = primary / "live-owner"
            live_marker.write_text("replacement\n", encoding="utf-8")
            replacement_metadata = primary.stat()
            replacement_identity = (
                replacement_metadata.st_dev,
                replacement_metadata.st_ino,
                replacement_metadata.st_mtime_ns,
            )

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as terminal:
                lease.release()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()

            self.assertIs(repeated.exception, terminal.exception)
            self.assertIs(terminal.exception, lease._cleanup_inconclusive)
            self.assertTrue(
                getattr(
                    terminal.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(
                hasattr(
                    terminal.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(terminal.exception)
            )
            replacement_metadata = primary.stat()
            self.assertEqual(
                replacement_identity,
                (
                    replacement_metadata.st_dev,
                    replacement_metadata.st_ino,
                    replacement_metadata.st_mtime_ns,
                ),
            )
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )

            live_marker.unlink()
            primary.rmdir()
            legacy.rmdir()

    def test_heartbeat_start_failure_does_not_swallow_cleanup_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            start_error = claude_refresh_lock.ClaudeRefreshLockError(
                "injected heartbeat start failure"
            )
            forwarded = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            real_release = claude_refresh_lock.ClaudeRefreshLockLease._release

            def release_then_signal(
                lease: claude_refresh_lock.ClaudeRefreshLockLease,
                *,
                skip_abandoned: bool,
            ) -> None:
                real_release(lease, skip_abandoned=skip_abandoned)
                raise forwarded

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_start_heartbeat",
                    side_effect=start_error,
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_release",
                    autospec=True,
                    side_effect=release_then_signal,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertIs(raised.exception, forwarded)
            self.assertFalse((config / ".oauth_refresh.lock").exists())
            self.assertFalse(pathlib.Path(str(config) + ".lock").exists())

    def test_synchronous_renewal_detects_post_utime_identity_compromise(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = self._config_dir(root).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary = config / ".oauth_refresh.lock"
            primary_descriptor = lease._locks[0].descriptor
            real_utime = os.utime
            replaced = False

            def renew_then_replace(
                path: int | os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> None:
                nonlocal replaced
                real_utime(path, *args, **kwargs)
                if path == primary_descriptor and not replaced:
                    replaced = True
                    primary.rmdir()
                    primary.mkdir(mode=0o700)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "utime",
                    side_effect=renew_then_replace,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised),
            ):
                lease.assert_held()

            self.assertTrue(replaced)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.release()
            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_primary_contention_times_out_without_touching_either_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockTimeout):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertTrue(primary.is_dir())
            self.assertFalse(legacy.exists())

    def test_stale_crash_residue_pauses_without_unsafe_reclaim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            stale_time = time.time() - self.PROTOCOL.stale_seconds - 5.0
            os.utime(primary, (stale_time, stale_time))

            with self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockStale,
                "controlled cleanup",
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertTrue(primary.is_dir())
            self.assertFalse(legacy.exists())

    def test_recovery_removes_only_exact_empty_helper_owned_staged_locks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            recovered = (
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )
            )

            self.assertEqual(recovered, (primary, legacy))
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())
            self.assertTrue(config.is_dir())
            self.assertTrue(carrier.is_dir())

    def test_staged_recovery_requires_quiescence_and_preflights_all_locks(
        self,
    ) -> None:
        for case in ("unproven", "nonempty-legacy"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                carrier = root / "claude-carrier-fixture"
                carrier.mkdir(mode=0o700)
                config = carrier / "config"
                config.mkdir(mode=0o700)
                primary = config / ".oauth_refresh.lock"
                legacy = pathlib.Path(str(config) + ".lock")
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)
                if case == "nonempty-legacy":
                    (legacy / "unexpected").write_text("occupied", encoding="utf-8")

                with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=case != "unproven",
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_host_shaped_config_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary).resolve() / "account-home"
            carrier.mkdir(mode=0o700)
            config = carrier / ".claude"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_wrong_carrier_name_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary).resolve() / "not-a-claude-carrier"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_symlink_lock_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            target = root / "external-lock"
            target.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            primary.symlink_to(target, target_is_directory=True)
            legacy = pathlib.Path(str(config) + ".lock")
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_symlink())
            self.assertTrue(target.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_unsafe_lock_mode_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            carrier = pathlib.Path(temporary).resolve() / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            primary.mkdir(mode=0o700)
            primary.chmod(0o755)
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertEqual(stat.S_IMODE(primary.stat().st_mode), 0o755)
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_requires_exact_private_carrier_modes(self) -> None:
        for unsafe_directory in ("carrier", "config"):
            with (
                self.subTest(unsafe_directory=unsafe_directory),
                tempfile.TemporaryDirectory() as temporary,
            ):
                carrier = pathlib.Path(temporary).resolve() / "claude-carrier-fixture"
                carrier.mkdir(mode=0o700)
                config = carrier / "config"
                config.mkdir(mode=0o700)
                primary = config / ".oauth_refresh.lock"
                legacy = pathlib.Path(str(config) + ".lock")
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)
                unsafe = carrier if unsafe_directory == "carrier" else config
                unsafe.chmod(0o755)

                with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_carrier_and_config_symlinks(self) -> None:
        for symlinked_directory in ("carrier", "config"):
            with (
                self.subTest(symlinked_directory=symlinked_directory),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                if symlinked_directory == "carrier":
                    real_carrier = root / "real-carrier"
                    real_carrier.mkdir(mode=0o700)
                    real_config = real_carrier / "config"
                    real_config.mkdir(mode=0o700)
                    carrier = root / "claude-carrier-link"
                    carrier.symlink_to(real_carrier, target_is_directory=True)
                    config = carrier / "config"
                    primary = real_config / ".oauth_refresh.lock"
                    legacy = real_carrier / "config.lock"
                else:
                    carrier = root / "claude-carrier-fixture"
                    carrier.mkdir(mode=0o700)
                    real_config = root / "real-config"
                    real_config.mkdir(mode=0o700)
                    config = carrier / "config"
                    config.symlink_to(real_config, target_is_directory=True)
                    primary = real_config / ".oauth_refresh.lock"
                    legacy = carrier / "config.lock"
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)

                with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())

    def test_staged_recovery_rejects_symlinked_ancestor_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o700)
            real_carrier = real_parent / "claude-carrier-fixture"
            real_carrier.mkdir(mode=0o700)
            real_config = real_carrier / "config"
            real_config.mkdir(mode=0o700)
            primary = real_config / ".oauth_refresh.lock"
            legacy = real_carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            carrier = linked_parent / real_carrier.name
            config = carrier / "config"

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(linked_parent.is_symlink())
            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_fails_closed_when_carrier_and_config_retarget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary_name = ".oauth_refresh.lock"
            legacy_name = "config.lock"
            (config / primary_name).mkdir(mode=0o700)
            (carrier / legacy_name).mkdir(mode=0o700)

            replacement = root / "replacement-carrier"
            replacement.mkdir(mode=0o700)
            replacement_config = replacement / "config"
            replacement_config.mkdir(mode=0o700)
            (replacement_config / primary_name).mkdir(mode=0o700)
            (replacement / legacy_name).mkdir(mode=0o700)

            retained_carrier = root / "retained-carrier"
            retained_config = root / "retained-config"
            carrier_identity = carrier.stat()
            real_stat = claude_refresh_lock.os.stat
            config_probe_count = 0
            retargeted = False
            restored = False

            def retarget_around_config_probe(
                path: os.PathLike[str] | str | int,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal config_probe_count, restored, retargeted
                raw_path = os.fspath(path) if not isinstance(path, int) else path
                dir_fd = kwargs.get("dir_fd")
                relative_to_carrier = False
                if raw_path == "config" and isinstance(dir_fd, int):
                    parent_metadata = os.fstat(dir_fd)
                    relative_to_carrier = (
                        parent_metadata.st_dev == carrier_identity.st_dev
                        and parent_metadata.st_ino == carrier_identity.st_ino
                    )
                config_probe = (
                    dir_fd is None and pathlib.Path(raw_path) == config
                ) or relative_to_carrier
                if not config_probe:
                    return real_stat(path, *args, **kwargs)

                config_probe_count += 1
                if config_probe_count == 1:
                    carrier.rename(retained_carrier)
                    replacement.rename(carrier)
                    retargeted = True
                metadata = real_stat(path, *args, **kwargs)
                if config_probe_count == 2:
                    carrier.rename(replacement)
                    retained_carrier.rename(carrier)
                    config.rename(retained_config)
                    (replacement / "config").rename(config)
                    restored = True
                return metadata

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "stat",
                    side_effect=retarget_around_config_probe,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError),
            ):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(retargeted)
            self.assertTrue(restored)
            self.assertTrue((retained_config / primary_name).is_dir())
            self.assertTrue((carrier / legacy_name).is_dir())
            self.assertTrue((config / primary_name).is_dir())
            self.assertTrue((replacement / legacy_name).is_dir())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "staged recovery descriptor-chain proof requires POSIX dir_fds",
    )
    def test_staged_recovery_fails_closed_when_chain_close_is_unknown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)
            real_open = os.open
            real_close = os.close
            opened_descriptors: list[int] = []
            close_attempts: dict[int, int] = {}
            failed_descriptor: int | None = None

            def record_open(
                path: os.PathLike[str] | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                opened_descriptors.append(descriptor)
                return descriptor

            def fail_first_close(descriptor: int) -> None:
                nonlocal failed_descriptor
                close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
                if failed_descriptor is None:
                    failed_descriptor = descriptor
                    raise OSError(errno.EIO, "injected close failure")
                real_close(descriptor)

            try:
                with (
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "open",
                        side_effect=record_open,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=fail_first_close,
                    ),
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ) as raised,
                ):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertIn("cannot confirm closure", str(raised.exception))
                self.assertIs(
                    getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        None,
                    ),
                    True,
                )
                self.assertIsNone(
                    getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_paths",
                        None,
                    )
                )
                self.assertIsNotNone(failed_descriptor)
                assert failed_descriptor is not None
                self.assertEqual(close_attempts[failed_descriptor], 1)
                os.fstat(failed_descriptor)
                for descriptor in opened_descriptors:
                    if descriptor == failed_descriptor:
                        continue
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                self.assertTrue(primary.is_dir())
                self.assertTrue(legacy.is_dir())
            finally:
                for descriptor in opened_descriptors:
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass

    def test_staged_recovery_fails_closed_before_open_when_signal_mask_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "block_forwarded_signals",
                    return_value=None,
                ),
                mock.patch.object(
                    claude_refresh_lock.os,
                    "open",
                    side_effect=AssertionError(
                        "opened a recovery descriptor before signal masking"
                    ),
                ),
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ),
            ):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    def test_staged_recovery_legacy_cleanup_control_keeps_mask_restore_failure(
        self,
    ) -> None:
        class LegacyForwardedSignal(claude_refresh_lock.ForwardedSignal):
            add_note = None

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)
            first = LegacyForwardedSignal(signal.SIGTERM)

            def publish_fake_mask(
                *,
                signal_mask_owner: claude_refresh_lock.ForwardedSignalMaskOwner,
            ) -> None:
                signal_mask_owner.publish(None)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "block_forwarded_signals",
                    side_effect=publish_fake_mask,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "consume_pending_forwarded_signal",
                    side_effect=first,
                ),
                mock.patch.object(
                    claude_refresh_lock.ForwardedSignalMaskOwner,
                    "restore",
                    side_effect=(
                        OSError(errno.EIO, "first restore failure"),
                        OSError(errno.EIO, "second restore failure"),
                    ),
                ) as restore,
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertIs(raised.exception, first)
            self.assertEqual(restore.call_count, 2)
            self.assertIsInstance(
                raised.exception.__cause__,
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            )
            self.assertIn(
                "forwarded-signal mask remains active",
                str(raised.exception.__cause__),
            )
            formatted = "".join(
                traceback.format_exception(
                    type(raised.exception),
                    raised.exception,
                    raised.exception.__traceback__,
                )
            )
            self.assertIn("forwarded-signal mask remains active", formatted)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "staged recovery signal-mask proof requires POSIX dir_fds",
    )
    def test_staged_recovery_reports_persistent_signal_mask_restore_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)

            def publish_fake_mask(
                *,
                signal_mask_owner: claude_refresh_lock.ForwardedSignalMaskOwner,
            ) -> None:
                signal_mask_owner.publish(None)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "block_forwarded_signals",
                    side_effect=publish_fake_mask,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "consume_pending_forwarded_signal",
                    return_value=None,
                ),
                mock.patch.object(
                    claude_refresh_lock.ForwardedSignalMaskOwner,
                    "restore",
                    side_effect=(
                        OSError(errno.EIO, "first restore failure"),
                        OSError(errno.EIO, "second restore failure"),
                    ),
                ) as restore,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised,
            ):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertIn(
                "forwarded-signal mask remains active",
                str(raised.exception),
            )
            self.assertEqual(restore.call_count, 2)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())

    def test_staged_recovery_legacy_control_flow_keeps_mask_restore_failure(
        self,
    ) -> None:
        class LegacyForwardedSignal(claude_refresh_lock.ForwardedSignal):
            add_note = None

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)
            first = LegacyForwardedSignal(signal.SIGTERM)
            sensitive_path = (
                "/fixture/private/suppressed-staged-context/.oauth_refresh.lock"
            )
            hidden_context = RuntimeError(
                f"fixture suppressed staged-recovery context at {sensitive_path}"
            )
            first.__context__ = hidden_context
            first.__suppress_context__ = True

            def publish_fake_mask(
                *,
                signal_mask_owner: claude_refresh_lock.ForwardedSignalMaskOwner,
            ) -> None:
                signal_mask_owner.publish(None)

            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "block_forwarded_signals",
                    side_effect=publish_fake_mask,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_absolute_directory_anchor_chain",
                    side_effect=first,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "consume_pending_forwarded_signal",
                    return_value=None,
                ),
                mock.patch.object(
                    claude_refresh_lock.ForwardedSignalMaskOwner,
                    "restore",
                    side_effect=(
                        OSError(errno.EIO, "first restore failure"),
                        OSError(errno.EIO, "second restore failure"),
                    ),
                ) as restore,
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                    carrier,
                    config,
                    protocol=self.PROTOCOL,
                    writer_quiescent=True,
                )

            self.assertIs(raised.exception, first)
            self.assertEqual(restore.call_count, 2)
            self.assertIsInstance(
                raised.exception.__cause__,
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive,
            )
            self.assertIn(
                "forwarded-signal mask remains active",
                str(raised.exception.__cause__),
            )
            self.assertIsNone(raised.exception.__cause__.__context__)
            self.assertIs(raised.exception.__context__, hidden_context)
            self.assertTrue(raised.exception.__suppress_context__)
            formatted = "".join(
                traceback.format_exception(
                    type(raised.exception),
                    raised.exception,
                    raised.exception.__traceback__,
                )
            )
            self.assertNotIn(sensitive_path, formatted)
            self.assertTrue(primary.is_dir())
            self.assertTrue(legacy.is_dir())

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "staged recovery signal deferral requires POSIX signal masks",
    )
    def test_staged_recovery_defers_open_signal_until_all_fds_close(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "claude-carrier-fixture"
            carrier.mkdir(mode=0o700)
            config = carrier / "config"
            config.mkdir(mode=0o700)
            primary = config / ".oauth_refresh.lock"
            legacy = carrier / "config.lock"
            primary.mkdir(mode=0o700)
            legacy.mkdir(mode=0o700)
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            external_descriptor = os.open(carrier, directory_flags)
            real_open = os.open
            real_close = os.close
            opened_descriptors: list[int] = []
            signal_sent = False
            previous_handler = signal.getsignal(signal.SIGTERM)

            def raise_forwarded_signal(signum: int, _frame: object) -> None:
                raise claude_refresh_lock.ForwardedSignal(signal.Signals(signum))

            def open_then_signal(
                path: os.PathLike[str] | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal signal_sent
                descriptor = real_open(
                    path,
                    flags,
                    mode,
                    dir_fd=dir_fd,
                )
                opened_descriptors.append(descriptor)
                if not signal_sent:
                    signal_sent = True
                    os.kill(os.getpid(), signal.SIGTERM)
                return descriptor

            try:
                signal.signal(signal.SIGTERM, raise_forwarded_signal)
                with (
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "open",
                        side_effect=open_then_signal,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                        carrier,
                        config,
                        protocol=self.PROTOCOL,
                        writer_quiescent=True,
                    )

                self.assertEqual(raised.exception.signum, signal.SIGTERM)
                self.assertTrue(signal_sent)
                self.assertFalse(primary.exists())
                self.assertFalse(legacy.exists())
                os.fstat(external_descriptor)
                for descriptor in opened_descriptors:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(closed.exception.errno, errno.EBADF)
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
                for descriptor in opened_descriptors:
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass
                real_close(external_descriptor)

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "staged recovery signal deferral requires POSIX signal masks",
    )
    def test_staged_recovery_defers_close_signal_until_all_fds_close(
        self,
    ) -> None:
        for boundary in ("entry", "result"):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                carrier = root / "claude-carrier-fixture"
                carrier.mkdir(mode=0o700)
                config = carrier / "config"
                config.mkdir(mode=0o700)
                primary = config / ".oauth_refresh.lock"
                legacy = carrier / "config.lock"
                primary.mkdir(mode=0o700)
                legacy.mkdir(mode=0o700)
                directory_flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                external_descriptor = os.open(carrier, directory_flags)
                real_open = os.open
                real_close = os.close
                opened_descriptors: list[int] = []
                interrupted = False
                previous_handler = signal.getsignal(signal.SIGTERM)

                def raise_forwarded_signal(
                    signum: int,
                    _frame: object,
                ) -> None:
                    raise claude_refresh_lock.ForwardedSignal(signal.Signals(signum))

                def record_open(
                    path: os.PathLike[str] | str,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    descriptor = real_open(
                        path,
                        flags,
                        mode,
                        dir_fd=dir_fd,
                    )
                    opened_descriptors.append(descriptor)
                    return descriptor

                def interrupt_parent_close(descriptor: int) -> None:
                    nonlocal interrupted
                    if not interrupted:
                        interrupted = True
                        if boundary == "result":
                            real_close(descriptor)
                        os.kill(os.getpid(), signal.SIGTERM)
                        if boundary == "entry":
                            real_close(descriptor)
                        return
                    real_close(descriptor)

                try:
                    signal.signal(signal.SIGTERM, raise_forwarded_signal)
                    with (
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "open",
                            side_effect=record_open,
                        ),
                        mock.patch.object(
                            claude_refresh_lock.os,
                            "close",
                            side_effect=interrupt_parent_close,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks(
                            carrier,
                            config,
                            protocol=self.PROTOCOL,
                            writer_quiescent=True,
                        )

                    self.assertEqual(raised.exception.signum, signal.SIGTERM)
                    self.assertTrue(interrupted)
                    self.assertGreaterEqual(len(opened_descriptors), 2)
                    self.assertFalse(primary.exists())
                    self.assertFalse(legacy.exists())
                    os.fstat(external_descriptor)
                    for descriptor in opened_descriptors:
                        with self.assertRaises(OSError) as closed:
                            os.fstat(descriptor)
                        self.assertEqual(closed.exception.errno, errno.EBADF)
                finally:
                    signal.signal(signal.SIGTERM, previous_handler)
                    for descriptor in opened_descriptors:
                        try:
                            real_close(descriptor)
                        except OSError:
                            pass
                    real_close(external_descriptor)

    def test_legacy_contention_releases_the_new_primary_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"
            legacy = pathlib.Path(str(config) + ".lock")
            legacy.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockTimeout):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertFalse(primary.exists())
            self.assertTrue(legacy.is_dir())

    def test_assert_held_detects_deleted_replaced_and_symlinked_lock(self) -> None:
        cases = ("deleted", "replaced", "symlinked")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                config = self._config_dir(root).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                primary = config / ".oauth_refresh.lock"
                primary.rmdir()
                if case == "replaced":
                    primary.mkdir(mode=0o700)
                elif case == "symlinked":
                    target = root / "replacement"
                    target.mkdir(mode=0o700)
                    primary.symlink_to(target, target_is_directory=True)

                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ):
                    lease.assert_held()
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ):
                    lease.release()
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as repeated:
                    lease.release()
                self.assertTrue(
                    getattr(
                        repeated.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(repeated.exception)
                )
                for path in lease.paths:
                    self.assertNotIn(str(path), str(repeated.exception))

                if case == "replaced":
                    self.assertTrue(primary.is_dir())
                    primary.rmdir()
                elif case == "symlinked":
                    self.assertTrue(primary.is_symlink())
                    primary.unlink()

    def test_rejects_unsafe_config_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            readable = self._config_dir(root)
            readable.chmod(0o755)
            lease = self._acquire_lock(
                readable,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            lease.release()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            permissive = self._config_dir(root)
            permissive.chmod(0o777)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                self._acquire_lock(
                    permissive,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = self._config_dir(root)
            alias = root / "config-link"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockUnsafe):
                self._acquire_lock(
                    alias,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

    def test_borrowed_directory_anchors_acquire_and_release_exact_locks(
        self,
    ) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary).resolve())
            config_fd = os.open(config, flags)
            parent_fd = os.open(config.parent, flags)
            try:
                with mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=AssertionError("path reopen is forbidden"),
                ):
                    lease = self._acquire_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                        config_dir_fd=config_fd,
                        legacy_parent_dir_fd=parent_fd,
                    )
                self.assertEqual(
                    lease.paths,
                    (
                        config / ".oauth_refresh.lock",
                        pathlib.Path(str(config) + ".lock"),
                    ),
                )
                lease.assert_held()
                lease.release()
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_borrowed_anchor_abandon_uses_descriptor_bound_marker_only(
        self,
    ) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary).resolve())
            config_fd = os.open(config, flags)
            parent_fd = os.open(config.parent, flags)
            try:
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    config_dir_fd=config_fd,
                    legacy_parent_dir_fd=parent_fd,
                )

                diagnostic = lease.abandon("anchored reviewer is quiescent")

                self.assertTrue(
                    getattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(diagnostic)
                )
                self.assertFalse(
                    hasattr(diagnostic, "_codex_claude_refresh_lock_paths")
                )
                self.assertIs(
                    lease.abandon("descriptor diagnostic must remain cached"),
                    diagnostic,
                )
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as release:
                    lease.release()
                self.assertIs(release.exception, diagnostic)
                os.fstat(config_fd)
                os.fstat(parent_fd)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                for path in reversed(lease.paths):
                    path.rmdir()
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_borrowed_directory_anchors_use_retained_tree_after_path_retarget(
        self,
    ) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            replacement_home = root / "replacement-home"
            replacement_home.mkdir(mode=0o700)
            replacement_config = self._config_dir(replacement_home)
            retained_home = root / "retained-home"
            config_fd = os.open(config, flags)
            parent_fd = os.open(home, flags)
            try:
                home.rename(retained_home)
                home.symlink_to(replacement_home, target_is_directory=True)
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    config_dir_fd=config_fd,
                    legacy_parent_dir_fd=parent_fd,
                )
                retained_config = retained_home / ".claude"
                self.assertTrue((retained_config / ".oauth_refresh.lock").is_dir())
                self.assertTrue(pathlib.Path(str(retained_config) + ".lock").is_dir())
                self.assertFalse((replacement_config / ".oauth_refresh.lock").exists())
                self.assertFalse(
                    pathlib.Path(str(replacement_config) + ".lock").exists()
                )
                lease.assert_held()
                lease.release()
                self.assertFalse((retained_config / ".oauth_refresh.lock").exists())
                self.assertFalse(pathlib.Path(str(retained_config) + ".lock").exists())
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_borrowed_anchor_cleanup_failure_omits_retargeted_path(self) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = self._config_dir(home)
            replacement_home = root / "replacement-home"
            replacement_home.mkdir(mode=0o700)
            replacement_config = self._config_dir(replacement_home)
            retained_home = root / "retained-home"
            config_fd = os.open(config, flags)
            parent_fd = os.open(home, flags)
            try:
                home.rename(retained_home)
                home.symlink_to(replacement_home, target_is_directory=True)
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                    config_dir_fd=config_fd,
                    legacy_parent_dir_fd=parent_fd,
                )
                with (
                    mock.patch.object(
                        claude_refresh_lock,
                        "_remove_owned_lock",
                        side_effect=claude_refresh_lock.ClaudeRefreshLockError(
                            "injected descriptor-bound cleanup failure"
                        ),
                    ),
                    self.assertRaises(
                        claude_refresh_lock.ClaudeRefreshLockError
                    ) as raised,
                ):
                    lease.release()

                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
                )
                messages: list[str] = []
                pending: list[BaseException] = [raised.exception]
                seen: set[int] = set()
                while pending:
                    current = pending.pop()
                    if id(current) in seen:
                        continue
                    seen.add(id(current))
                    messages.append(str(current))
                    messages.extend(getattr(current, "__notes__", ()))
                    for chained in (current.__cause__, current.__context__):
                        if isinstance(chained, BaseException):
                            pending.append(chained)
                self.assertTrue(
                    any(
                        "no authoritative pathname is available" in message
                        for message in messages
                    )
                )
                self.assertFalse((replacement_config / ".oauth_refresh.lock").exists())
                self.assertFalse(
                    pathlib.Path(str(replacement_config) + ".lock").exists()
                )
                retained_config = retained_home / ".claude"
                retained_primary = retained_config / ".oauth_refresh.lock"
                retained_legacy = pathlib.Path(str(retained_config) + ".lock")
                self.assertTrue(retained_primary.is_dir())
                self.assertTrue(retained_legacy.is_dir())
                retained_legacy.rmdir()
                retained_primary.rmdir()
            finally:
                os.close(parent_fd)
                os.close(config_fd)

    def test_release_never_removes_a_replacement_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary = config / ".oauth_refresh.lock"
            primary.rmdir()
            primary.mkdir(mode=0o700)

            with self.assertRaises(claude_refresh_lock.ClaudeRefreshLockCompromised):
                lease.release()

            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_body_error_remains_primary_when_release_detects_compromise(self) -> None:
        marker = ValueError("body marker")
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            primary = config / ".oauth_refresh.lock"

            with self.assertRaises(ValueError) as raised:
                with claude_refresh_lock.claude_refresh_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                ):
                    primary.rmdir()
                    primary.mkdir(mode=0o700)
                    raise marker

            self.assertIs(raised.exception, marker)
            notes = getattr(marker, "__notes__", ())
            if notes:
                self.assertTrue(any("cleanup" in note.lower() for note in notes))
            else:
                self.assertIsInstance(
                    marker.__cause__,
                    claude_refresh_lock.ClaudeRefreshLockCleanupDiagnostic,
                )
            self.assertTrue(primary.is_dir())
            primary.rmdir()

    def test_release_interruption_overrides_ordinary_body_error(self) -> None:
        body_error = ValueError("body marker")
        release_error = KeyboardInterrupt("release marker")
        lease = mock.Mock(spec=["_release_on_context_exit"])
        lease._release_on_context_exit.side_effect = release_error

        def publish_mock_lease(
            *args: object,
            **kwargs: object,
        ) -> object:
            del args
            owner = kwargs["owner"]
            assert isinstance(
                owner,
                claude_refresh_lock.ClaudeRefreshLockOwner,
            )
            owner._publish(lease)
            return lease

        with (
            mock.patch.object(
                claude_refresh_lock,
                "acquire_claude_refresh_lock",
                side_effect=publish_mock_lease,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            with claude_refresh_lock.claude_refresh_lock(
                "/fixture/.claude",
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ):
                raise body_error

        self.assertIs(raised.exception, release_error)
        lease._release_on_context_exit.assert_called_once_with()
        notes = getattr(release_error, "__notes__", ())
        if notes:
            self.assertTrue(any("cleanup" in note.lower() for note in notes))

    def test_legacy_acquire_cleanup_interruption_overrides_acquire_error(
        self,
    ) -> None:
        acquire_error = ValueError("legacy acquire marker")
        cleanup_error = KeyboardInterrupt("legacy cleanup marker")
        anchors = (
            mock.Mock(descriptor=101),
            mock.Mock(descriptor=102),
        )

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=anchors,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_acquire_one",
                    side_effect=(mock.Mock(), acquire_error),
                ),
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_release",
                    side_effect=cleanup_error,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        self.assertIs(raised.exception, cleanup_error)

    def test_outer_anchor_close_interruption_overrides_acquire_error(self) -> None:
        acquire_error = ValueError("primary acquire marker")
        cleanup_error = KeyboardInterrupt("anchor close marker")
        anchors = (
            mock.Mock(descriptor=201),
            mock.Mock(descriptor=202),
        )

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock,
                    "_open_directory_anchor",
                    side_effect=anchors,
                ),
                mock.patch.object(
                    claude_refresh_lock,
                    "_acquire_one",
                    side_effect=acquire_error,
                ),
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=(cleanup_error, None),
                ) as close,
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

        self.assertIs(raised.exception, cleanup_error)
        self.assertEqual(close.call_count, 2)

    def test_missing_lock_churn_still_obeys_acquisition_deadline(self) -> None:
        parent = mock.Mock(descriptor=301)
        with (
            mock.patch.object(claude_refresh_lock, "_assert_anchor"),
            mock.patch.object(
                claude_refresh_lock.os,
                "mkdir",
                side_effect=FileExistsError,
            ) as mkdir,
            mock.patch.object(
                claude_refresh_lock,
                "_inspect_existing_lock",
                return_value="missing",
            ) as inspect,
            mock.patch.object(
                claude_refresh_lock.time,
                "monotonic",
                side_effect=(99.5, 100.0),
            ),
            self.assertRaisesRegex(
                claude_refresh_lock.ClaudeRefreshLockTimeout,
                "timed out",
            ),
        ):
            claude_refresh_lock._acquire_one(
                label="primary",
                path=pathlib.Path("/fixture/.oauth_refresh.lock"),
                name=".oauth_refresh.lock",
                parent=parent,
                protocol=self.PROTOCOL,
                deadline=100.0,
                retry_interval_seconds=0.01,
                lease=mock.Mock(),
            )

        self.assertEqual(mkdir.call_count, 2)
        self.assertEqual(inspect.call_count, 2)

    def test_filesystem_failure_does_not_copy_arbitrary_error_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "mkdir",
                    side_effect=OSError(5, "sensitive injected detail"),
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )

            self.assertNotIn("sensitive injected detail", str(raised.exception))
            self.assertIn("errno 5", str(raised.exception))

    def test_close_oserror_is_normalized_as_refresh_lock_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_descriptor = self._lease_descriptors(lease)[0]
            real_close = os.close
            failed = False

            def fail_first_close(descriptor: int) -> None:
                nonlocal failed
                if not failed:
                    failed = True
                    raise OSError(5, "sensitive injected close detail")
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=fail_first_close,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                lease.release()

            real_close(first_descriptor)
            self.assertNotIsInstance(raised.exception, OSError)
            self.assertNotIn("sensitive injected close detail", str(raised.exception))
            self.assertIn("errno 5", str(raised.exception))

    def test_close_only_failure_never_reuses_a_replacement_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            primary, legacy = lease.paths
            first_descriptor = self._lease_descriptors(lease)[0]
            real_close = os.close
            close_failed = False

            def fail_first_close(descriptor: int) -> None:
                nonlocal close_failed
                if not close_failed:
                    close_failed = True
                    raise OSError(5, "injected close-only failure")
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=fail_first_close,
                ),
                self.assertRaises(claude_refresh_lock.ClaudeRefreshLockError) as raised,
            ):
                lease.release()

            self.assertTrue(close_failed)
            self.assertFalse(primary.exists())
            self.assertFalse(legacy.exists())
            self.assertFalse(
                hasattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(raised.exception)
            )

            primary.mkdir(mode=0o700)
            live_marker = primary / "live-owner"
            live_marker.write_text("replacement\n", encoding="utf-8")
            replacement_metadata = primary.stat()
            replacement_identity = (
                replacement_metadata.st_dev,
                replacement_metadata.st_ino,
                replacement_metadata.st_mtime_ns,
            )

            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as terminal:
                lease.release()
            with self.assertRaises(
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
            ) as repeated:
                lease.release()

            self.assertIs(repeated.exception, terminal.exception)
            self.assertIs(terminal.exception, lease._cleanup_inconclusive)
            self.assertTrue(
                getattr(
                    terminal.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(
                hasattr(
                    terminal.exception,
                    "_codex_claude_refresh_lock_paths",
                )
            )
            self.assertIsNone(
                claude_refresh_lock._refresh_lock_recovery_paths(terminal.exception)
            )
            replacement_metadata = primary.stat()
            self.assertEqual(
                replacement_identity,
                (
                    replacement_metadata.st_dev,
                    replacement_metadata.st_ino,
                    replacement_metadata.st_mtime_ns,
                ),
            )
            self.assertEqual(
                live_marker.read_text(encoding="utf-8"),
                "replacement\n",
            )

            real_close(first_descriptor)
            live_marker.unlink()
            primary.rmdir()

    def test_close_control_flow_exception_remains_primary(self) -> None:
        marker = KeyboardInterrupt("close marker")
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            first_descriptor = self._lease_descriptors(lease)[0]
            real_close = os.close
            failed = False

            def interrupt_first_close(descriptor: int) -> None:
                nonlocal failed
                if not failed:
                    failed = True
                    raise marker
                real_close(descriptor)

            with (
                mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=interrupt_first_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                lease.release()

            real_close(first_descriptor)
            self.assertIs(raised.exception, marker)

    def test_abandon_operation_acquire_return_signal_releases_guard(self) -> None:
        acquire_handoff = claude_refresh_lock._OperationLockHandoff.acquire
        assignment_offset = self._call_result_assignment_offset(
            acquire_handoff,
            callable_name="acquire",
            local_name="acquired",
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            try:
                with (
                    self._raise_before_instruction(
                        acquire_handoff,
                        offset=assignment_offset,
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("operation acquire return boundary was interrupted")

                self.assertIs(raised.exception, interruption)
                operation_recovered = lease._operation_lock.acquire(timeout=0.01)
                if operation_recovered:
                    lease._operation_lock.release()
                else:
                    # The pre-fix implementation leaked the lock on this thread.
                    # Release it only so the red test can clean up deterministically.
                    lease._operation_lock.release()
                self.assertTrue(operation_recovered)

                diagnostic = lease.abandon(
                    "resume after operation acquire return interruption"
                )
                self._assert_descriptor_only_recovery(
                    diagnostic,
                    forbidden_paths=paths,
                )
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
            finally:
                self._operator_cleanup_inconclusive_lease(lease)

    def test_release_operation_acquire_return_signal_releases_guard(self) -> None:
        acquire_handoff = claude_refresh_lock._OperationLockHandoff.acquire
        assignment_offset = self._call_result_assignment_offset(
            acquire_handoff,
            callable_name="acquire",
            local_name="acquired",
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            try:
                with (
                    self._raise_before_instruction(
                        acquire_handoff,
                        offset=assignment_offset,
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.release()

                self.assertIs(raised.exception, interruption)
                operation_recovered = lease._operation_lock.acquire(timeout=0.01)
                if operation_recovered:
                    lease._operation_lock.release()
                else:
                    lease._operation_lock.release()
                self.assertTrue(operation_recovered)
                self.assertTrue(lease.released)
                self.assertTrue(all(not path.exists() for path in lease.paths))
            finally:
                if not lease.released:
                    self._force_cleanup_test_lease(lease)

    def test_abandon_operation_handoff_caller_signal_releases_guard(self) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        _entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                abandon,
                statement="operation_handoff.acquire(",
                callable_name="acquire",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            try:
                with (
                    self._raise_before_instruction(
                        abandon,
                        offset=return_offset,
                        error=interruption,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("operation handoff caller boundary was interrupted")

                self.assertIs(raised.exception, interruption)
                self.assertTrue(lease._operation_lock.acquire(timeout=0.01))
                lease._operation_lock.release()
                diagnostic = lease.abandon(
                    "resume after operation handoff caller interruption"
                )
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                self._assert_descriptor_only_recovery(
                    diagnostic,
                    forbidden_paths=paths,
                )
            finally:
                self._operator_cleanup_inconclusive_lease(lease)

    def test_release_operation_handoff_caller_signal_releases_guard(self) -> None:
        release_once = claude_refresh_lock.ClaudeRefreshLockLease._release_once
        _entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                release_once,
                statement="operation_handoff.acquire(",
                callable_name="acquire",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

            with (
                self._raise_before_instruction(
                    release_once,
                    offset=return_offset,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                lease.release()

            self.assertIs(raised.exception, interruption)
            self.assertTrue(lease.released)
            self.assertTrue(lease._operation_lock.acquire(timeout=0.01))
            lease._operation_lock.release()
            self.assertTrue(all(not path.exists() for path in lease.paths))

    def test_operation_handoff_unknown_does_not_release_another_thread(self) -> None:
        acquire_handoff = claude_refresh_lock._OperationLockHandoff.acquire
        entry_offset, _return_offset = self._call_entry_and_return_boundary_offsets(
            acquire_handoff,
            callable_name="acquire",
        )
        operation_lock = threading.RLock()
        holder_started = threading.Event()
        allow_holder_release = threading.Event()
        holder_finished = threading.Event()

        def hold_operation_lock() -> None:
            operation_lock.acquire()
            holder_started.set()
            allow_holder_release.wait(timeout=2.0)
            operation_lock.release()
            holder_finished.set()

        holder = threading.Thread(
            target=hold_operation_lock,
            name="test-operation-handoff-other-owner",
            daemon=True,
        )
        holder.start()
        self.assertTrue(holder_started.wait(timeout=2.0))
        fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
        first_control_flow = claude_refresh_lock._FirstControlFlowWinner(fallback)
        handoff = claude_refresh_lock._OperationLockHandoff(operation_lock)
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        try:
            with (
                self._raise_before_instruction(
                    acquire_handoff,
                    offset=entry_offset,
                    error=interruption,
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                handoff.acquire(
                    timeout=0.01,
                    first_control_flow=first_control_flow,
                )

            self.assertIs(raised.exception, interruption)
            self.assertIs(
                handoff.state,
                claude_refresh_lock._OperationLockHandoffState.RELEASED,
            )
            self.assertFalse(operation_lock.acquire(blocking=False))
        finally:
            allow_holder_release.set()
            holder.join(timeout=2.0)
        self.assertTrue(holder_finished.is_set())
        self.assertFalse(holder.is_alive())
        self.assertTrue(operation_lock.acquire(blocking=False))
        operation_lock.release()

    def test_operation_handoff_rejects_same_thread_reentry(self) -> None:
        operation_lock = threading.RLock()
        operation_lock.acquire()
        fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
        first_control_flow = claude_refresh_lock._FirstControlFlowWinner(fallback)
        handoff = claude_refresh_lock._OperationLockHandoff(operation_lock)

        with self.assertRaisesRegex(
            claude_refresh_lock.ClaudeRefreshLockCompromised,
            "already owned",
        ):
            handoff.acquire(
                timeout=0.01,
                first_control_flow=first_control_flow,
            )

        self.assertIs(
            handoff.state,
            claude_refresh_lock._OperationLockHandoffState.NOT_ACQUIRED,
        )
        handoff.release()
        operation_lock.release()
        self.assertTrue(operation_lock.acquire(blocking=False))
        operation_lock.release()

    def test_operation_handoff_release_return_signal_reconciles_once(self) -> None:
        release_handoff = claude_refresh_lock._OperationLockHandoff.release
        _entry_offset, return_offset = self._call_entry_and_return_boundary_offsets(
            release_handoff,
            callable_name="release",
        )
        operation_lock = threading.RLock()
        fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
        first_control_flow = claude_refresh_lock._FirstControlFlowWinner(fallback)
        handoff = claude_refresh_lock._OperationLockHandoff(operation_lock)
        handoff.acquire(
            timeout=0.01,
            first_control_flow=first_control_flow,
        )
        interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)

        with (
            self._raise_before_instruction(
                release_handoff,
                offset=return_offset,
                error=interruption,
            ),
            self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
        ):
            handoff.release()

        self.assertIs(raised.exception, interruption)
        self.assertIs(
            handoff.state,
            claude_refresh_lock._OperationLockHandoffState.RELEASED,
        )
        self.assertTrue(operation_lock.acquire(blocking=False))
        operation_lock.release()

    def test_operation_handoff_does_not_swallow_acquired_release_failure(
        self,
    ) -> None:
        operation_lock = mock.Mock()
        operation_lock.acquire.return_value = True
        operation_lock.release.side_effect = RuntimeError(
            "injected owned release failure"
        )
        fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
        first_control_flow = claude_refresh_lock._FirstControlFlowWinner(fallback)
        handoff = claude_refresh_lock._OperationLockHandoff(operation_lock)
        handoff.acquire(
            timeout=0.01,
            first_control_flow=first_control_flow,
        )

        with self.assertRaisesRegex(RuntimeError, "owned release failure"):
            handoff.release()

        self.assertIs(
            handoff.state,
            claude_refresh_lock._OperationLockHandoffState.ACQUIRED,
        )
        operation_lock.release.assert_called_once_with()

    def test_abandon_body_signal_precedes_operation_release_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            real_state_lock = lease._state_lock
            operation_lock = mock.Mock()
            operation_lock.acquire.return_value = True
            operation_lock.release.side_effect = second

            class InterruptingSettlementStateLock:
                def __enter__(self) -> object:
                    return real_state_lock.__enter__()

                def __exit__(
                    self,
                    error_type: object,
                    error: object,
                    traceback: object,
                ) -> object:
                    result = real_state_lock.__exit__(
                        error_type,
                        error,
                        traceback,
                    )
                    if (
                        lease._abandonment_cleanup_lifecycle
                        is claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED
                    ):
                        raise first
                    return result

            lease._state_lock = InterruptingSettlementStateLock()
            lease._operation_lock = operation_lock
            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    lease.abandon(
                        "settlement exit then operation release were interrupted"
                    )
            finally:
                lease._state_lock = real_state_lock
                lease._operation_lock = threading.Lock()

            try:
                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self._assert_descriptor_only_recovery(
                    first,
                    forbidden_paths=paths,
                )
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
            finally:
                self._operator_cleanup_inconclusive_lease(lease)

    def test_abandon_final_selector_signal_cannot_replace_existing_winner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            paths = lease.paths
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            interrupted_heartbeat = mock.Mock()
            interrupted_heartbeat.join.return_value = None
            interrupted_heartbeat.is_alive.return_value = True
            lease._heartbeat_thread = interrupted_heartbeat
            real_observe = claude_refresh_lock._FirstControlFlowWinner.observe
            selector_armed = False
            selector_interrupted = False

            def raise_first_from_finish(*_arguments: object) -> None:
                nonlocal selector_armed
                selector_armed = True
                raise first

            def interrupt_final_selector(
                winner: claude_refresh_lock._FirstControlFlowWinner,
                error: BaseException,
            ) -> None:
                nonlocal selector_interrupted
                real_observe(winner, error)
                if selector_armed and not selector_interrupted:
                    selector_interrupted = True
                    raise second

            try:
                with (
                    mock.patch.object(
                        lease,
                        "_finish_abandonment",
                        side_effect=raise_first_from_finish,
                    ),
                    mock.patch.object(
                        claude_refresh_lock._FirstControlFlowWinner,
                        "observe",
                        autospec=True,
                        side_effect=interrupt_final_selector,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("final control-flow selection was interrupted")

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertTrue(selector_interrupted)
                self._assert_descriptor_only_recovery(
                    first,
                    forbidden_paths=paths,
                )
            finally:
                lease._heartbeat_thread = heartbeat
                self._operator_cleanup_inconclusive_lease(lease)

    def test_first_control_flow_winner_survives_opcode_boundaries(self) -> None:
        observe = claude_refresh_lock._FirstControlFlowWinner.observe
        _bind_entry, bind_return = self._source_call_entry_and_return_boundary_offsets(
            observe,
            statement="_bind_cleanup_recovery_evidence(",
            callable_name="_bind_cleanup_recovery_evidence",
        )
        raise_if_set = claude_refresh_lock._FirstControlFlowWinner.raise_if_set
        raise_entry, _raise_return = (
            self._source_call_entry_and_return_boundary_offsets(
                raise_if_set,
                statement="_raise_frozen_control_flow_with_cleanup(",
                callable_name="_raise_frozen_control_flow_with_cleanup",
            )
        )

        for boundary, function, offset in (
            ("evidence-return", observe, bind_return),
            ("raise-entry", raise_if_set, raise_entry),
        ):
            with self.subTest(boundary=boundary):
                fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
                winner = claude_refresh_lock._FirstControlFlowWinner(fallback)
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                if boundary == "raise-entry":
                    winner.observe(first)

                with self._raise_before_instruction(
                    function,
                    offset=offset,
                    error=second,
                ):
                    if boundary == "evidence-return":
                        winner.observe(first)
                    with self.assertRaises(
                        claude_refresh_lock.ForwardedSignal
                    ) as raised:
                        winner.raise_if_set()

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self.assertIs(winner.winner, first)
                self.assertIs(
                    getattr(
                        first,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    fallback,
                )

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "POSIX signal-mask pending proof requires pthread_sigmask and sigwait",
    )
    def test_first_control_flow_winner_keeps_masked_signal_pending_at_raise(
        self,
    ) -> None:
        raise_if_set = claude_refresh_lock._FirstControlFlowWinner.raise_if_set
        raise_entry, _raise_return = (
            self._source_call_entry_and_return_boundary_offsets(
                raise_if_set,
                statement="_raise_frozen_control_flow_with_cleanup(",
                callable_name="_raise_frozen_control_flow_with_cleanup",
            )
        )
        pending_signal = signal.SIGINT
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {pending_signal},
        )
        try:
            while pending_signal in signal.sigpending():
                signal.sigwait({pending_signal})
            fallback = claude_refresh_lock._new_cleanup_inconclusive_fallback()
            winner = claude_refresh_lock._FirstControlFlowWinner(fallback)
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            winner.observe(first)

            with (
                self._call_before_instruction(
                    raise_if_set,
                    offset=raise_entry,
                    callback=lambda: os.kill(os.getpid(), pending_signal),
                ),
                self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
            ):
                winner.raise_if_set()

            self.assertIs(raised.exception, first)
            self.assertIn(pending_signal, signal.sigpending())
            self.assertEqual(signal.sigwait({pending_signal}), pending_signal)
            self.assertNotIn(pending_signal, signal.sigpending())
        finally:
            while pending_signal in signal.sigpending():
                signal.sigwait({pending_signal})
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def test_abandon_winner_store_signal_recovers_earlier_control_flow(self) -> None:
        observe = claude_refresh_lock._FirstControlFlowWinner.observe
        winner_store = next(
            instruction.offset
            for instruction in dis.get_instructions(observe)
            if instruction.opname == "STORE_ATTR" and instruction.argval == "_winner"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            interrupted_heartbeat = mock.Mock()
            interrupted_heartbeat.join.side_effect = first
            interrupted_heartbeat.is_alive.return_value = True
            lease._heartbeat_thread = interrupted_heartbeat

            try:
                with (
                    self._raise_before_instruction(
                        observe,
                        offset=winner_store,
                        error=second,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.abandon("winner publication was interrupted")

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
                self._assert_descriptor_only_recovery(
                    first,
                    forbidden_paths=lease.paths,
                )
            finally:
                lease._heartbeat_thread = heartbeat
                self._operator_cleanup_inconclusive_lease(lease)

    def test_release_winner_store_signal_recovers_earlier_control_flow(self) -> None:
        observe = claude_refresh_lock._FirstControlFlowWinner.observe
        winner_store = next(
            instruction.offset
            for instruction in dis.get_instructions(observe)
            if instruction.opname == "STORE_ATTR" and instruction.argval == "_winner"
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            interrupted_heartbeat = mock.Mock()
            interrupted_heartbeat.join.side_effect = first
            interrupted_heartbeat.is_alive.return_value = False
            lease._heartbeat_thread = interrupted_heartbeat

            try:
                with (
                    self._raise_before_instruction(
                        observe,
                        offset=winner_store,
                        error=second,
                    ),
                    self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised,
                ):
                    lease.release()

                self.assertIs(raised.exception, first)
                self.assertIsNot(raised.exception, second)
            finally:
                lease._heartbeat_thread = heartbeat
                if not lease.released:
                    self._force_cleanup_test_lease(lease)

    def test_abandon_double_release_signal_resumes_persistent_handoff(
        self,
    ) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

        class TwiceInterruptedOperationLock:
            def __init__(self) -> None:
                self._lock = threading.RLock()
                self.release_calls = 0

            def _is_owned(self) -> bool:
                return self._lock._is_owned()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self.release_calls += 1
                if self.release_calls == 1:
                    raise first
                if self.release_calls == 2:
                    raise second
                self._lock.release()

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            operation_lock = TwiceInterruptedOperationLock()
            lease._operation_lock = operation_lock

            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    lease.abandon("operation release was interrupted twice")

                self.assertIs(raised.exception, first)
                self.assertEqual(operation_lock.release_calls, 2)
                pending_snapshot = lease.retention_snapshot()
                self.assertFalse(pending_snapshot.terminal)
                self.assertFalse(pending_snapshot.verified_closed)
                self.assertIsNotNone(lease._pending_operation_handoff)
                diagnostic = lease.abandon(
                    "resume persistent operation release handoff"
                )
                self.assertIs(diagnostic, lease._cleanup_inconclusive)
                self.assertEqual(operation_lock.release_calls, 3)

                acquired_by_other_thread: list[bool] = []

                def acquire_from_other_thread() -> None:
                    acquired = operation_lock.acquire(timeout=0.1)
                    acquired_by_other_thread.append(acquired)
                    if acquired:
                        operation_lock.release()

                contender = threading.Thread(
                    target=acquire_from_other_thread,
                    name="test-resumed-operation-handoff-contender",
                    daemon=True,
                )
                contender.start()
                contender.join(timeout=2.0)
                self.assertFalse(contender.is_alive())
                self.assertEqual(acquired_by_other_thread, [True])
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                settled_snapshot = lease.retention_snapshot()
                self.assertTrue(settled_snapshot.terminal)
                self.assertTrue(settled_snapshot.verified_closed)
            finally:
                if operation_lock._is_owned():
                    operation_lock._lock.release()
                self._operator_cleanup_inconclusive_lease(lease)

    def test_operation_handoff_mixed_release_signals_remain_unresolved(
        self,
    ) -> None:
        first = KeyboardInterrupt("first release interruption")
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
        operation_lock = mock.Mock()
        operation_lock.acquire.return_value = True
        operation_lock.release.side_effect = [first, second]
        winner = claude_refresh_lock._FirstControlFlowWinner(
            claude_refresh_lock._new_cleanup_inconclusive_fallback()
        )
        handoff = claude_refresh_lock._OperationLockHandoff(operation_lock)
        handoff.acquire(timeout=0.01, first_control_flow=winner)

        with self.assertRaises(KeyboardInterrupt) as raised:
            handoff.release()

        self.assertIs(raised.exception, first)
        self.assertIs(
            handoff.state,
            claude_refresh_lock._OperationLockHandoffState.RELEASE_UNKNOWN,
        )

    def test_pending_operation_handoff_rejects_different_thread_recovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            handoff = claude_refresh_lock._OperationLockHandoff(lease._operation_lock)
            lease._publish_operation_handoff(handoff)
            handoff.acquire(
                timeout=0.01,
                first_control_flow=claude_refresh_lock._FirstControlFlowWinner(
                    lease._descriptor_bound_cleanup_fallback
                ),
            )
            outcomes: list[BaseException] = []

            def attempt_different_thread_recovery() -> None:
                try:
                    lease._reconcile_pending_operation_handoff()
                except BaseException as error:
                    outcomes.append(error)
                replacement = claude_refresh_lock._OperationLockHandoff(
                    lease._operation_lock
                )
                try:
                    lease._publish_operation_handoff(replacement)
                except BaseException as error:
                    outcomes.append(error)

            worker = threading.Thread(
                target=attempt_different_thread_recovery,
                name="test-different-thread-handoff-recovery",
                daemon=True,
            )
            try:
                worker.start()
                worker.join(timeout=2.0)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(outcomes), 2)
                self.assertTrue(
                    all(
                        isinstance(
                            outcome,
                            claude_refresh_lock.ClaudeRefreshLockCompromised,
                        )
                        for outcome in outcomes
                    )
                )
                self.assertIs(lease._pending_operation_handoff, handoff)
                self.assertTrue(handoff.acquired)
                self.assertTrue(lease._operation_lock._is_owned())

                lease._reconcile_pending_operation_handoff()
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertFalse(lease._operation_lock._is_owned())
            finally:
                if lease._operation_lock._is_owned():
                    lease._operation_lock.release()
                self._force_cleanup_test_lease(lease)

    def test_release_double_signal_reconciles_handoff_before_propagation(
        self,
    ) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

        class TwiceInterruptedOperationLock:
            def __init__(self) -> None:
                self._lock = threading.RLock()
                self.release_calls = 0

            def _is_owned(self) -> bool:
                return self._lock._is_owned()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self.release_calls += 1
                if self.release_calls == 1:
                    raise first
                if self.release_calls == 2:
                    raise second
                self._lock.release()

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            lease = self._acquire_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            operation_lock = TwiceInterruptedOperationLock()
            lease._operation_lock = operation_lock

            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    lease.release()

                self.assertIs(raised.exception, first)
                self.assertTrue(lease.released)
                self.assertEqual(operation_lock.release_calls, 3)
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertIsNone(lease._cleanup_inconclusive)
                self.assertFalse(operation_lock._is_owned())
                released_snapshot = lease.retention_snapshot()
                self.assertTrue(released_snapshot.terminal)
                self.assertTrue(released_snapshot.verified_closed)

                resolved_handoff = claude_refresh_lock._OperationLockHandoff(
                    operation_lock
                )
                lease._publish_operation_handoff(resolved_handoff)
                self.assertTrue(resolved_handoff.resolved)
                resolved_pointer_snapshot = lease.retention_snapshot()
                self.assertFalse(resolved_pointer_snapshot.terminal)
                self.assertFalse(resolved_pointer_snapshot.verified_closed)

                lease.release()
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertTrue(lease.retention_snapshot().terminal)
            finally:
                if operation_lock._is_owned():
                    operation_lock._lock.release()
                self._force_cleanup_test_lease(lease)

    def test_context_cleanup_reconciles_released_pending_handoff(self) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

        class TwiceInterruptedOperationLock:
            def __init__(self) -> None:
                self._lock = threading.RLock()
                self.release_calls = 0

            def _is_owned(self) -> bool:
                return self._lock._is_owned()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self.release_calls += 1
                if self.release_calls == 1:
                    raise first
                if self.release_calls == 2:
                    raise second
                self._lock.release()

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            operation_lock = TwiceInterruptedOperationLock()

            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    with claude_refresh_lock.claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    ) as lease:
                        heartbeat = lease._heartbeat_thread
                        assert heartbeat is not None
                        lease._heartbeat_stop.set()
                        heartbeat.join(timeout=2.0)
                        self.assertFalse(heartbeat.is_alive())
                        lease._operation_lock = operation_lock
                        lease.release()

                self.assertIs(raised.exception, first)
                self.assertTrue(lease.released)
                self.assertEqual(operation_lock.release_calls, 3)
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertIsNone(lease._cleanup_inconclusive)
                self.assertTrue(lease.retention_snapshot().terminal)

                acquired_by_other_thread: list[bool] = []

                def acquire_from_other_thread() -> None:
                    acquired = operation_lock.acquire(timeout=0.1)
                    acquired_by_other_thread.append(acquired)
                    if acquired:
                        operation_lock.release()

                contender = threading.Thread(
                    target=acquire_from_other_thread,
                    name="test-context-cleanup-handoff-contender",
                    daemon=True,
                )
                contender.start()
                contender.join(timeout=2.0)
                self.assertFalse(contender.is_alive())
                self.assertEqual(acquired_by_other_thread, [True])
            finally:
                if operation_lock._is_owned():
                    operation_lock._lock.release()

    def test_context_normal_exit_reconciles_released_pending_handoff(
        self,
    ) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
        operation_lock = _TwiceInterruptedOperationLock(first, second)
        lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    with claude_refresh_lock.claude_refresh_lock(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    ) as lease:
                        heartbeat = lease._heartbeat_thread
                        assert heartbeat is not None
                        lease._heartbeat_stop.set()
                        heartbeat.join(timeout=2.0)
                        self.assertFalse(heartbeat.is_alive())
                        lease._operation_lock = operation_lock

                assert lease is not None
                self.assertIs(raised.exception, first)
                self.assertTrue(lease.released)
                self.assertEqual(operation_lock.release_calls, 3)
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertIsNone(lease._cleanup_inconclusive)
                self.assertTrue(lease.retention_snapshot().terminal)

                acquired_by_other_thread: list[bool] = []

                def acquire_from_other_thread() -> None:
                    acquired = operation_lock.acquire(timeout=0.1)
                    acquired_by_other_thread.append(acquired)
                    if acquired:
                        operation_lock.release()

                contender = threading.Thread(
                    target=acquire_from_other_thread,
                    name="test-normal-exit-handoff-contender",
                    daemon=True,
                )
                contender.start()
                contender.join(timeout=2.0)
                self.assertFalse(contender.is_alive())
                self.assertEqual(acquired_by_other_thread, [True])
            finally:
                if lease is not None and lease._pending_operation_handoff is not None:
                    lease.release()
                if operation_lock._is_owned():
                    operation_lock._lock.release()

    def test_release_on_success_normal_exit_reconciles_released_pending_handoff(
        self,
    ) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
        operation_lock = _TwiceInterruptedOperationLock(first, second)
        lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()

            try:
                with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
                    with claude_refresh_lock.claude_refresh_lock_release_on_success(
                        config,
                        protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    ) as lease:
                        heartbeat = lease._heartbeat_thread
                        assert heartbeat is not None
                        lease._heartbeat_stop.set()
                        heartbeat.join(timeout=2.0)
                        self.assertFalse(heartbeat.is_alive())
                        lease._operation_lock = operation_lock

                assert lease is not None
                self.assertIs(raised.exception, first)
                self.assertTrue(lease.released)
                self.assertEqual(operation_lock.release_calls, 3)
                self.assertIsNone(lease._pending_operation_handoff)
                self.assertIsNone(lease._cleanup_inconclusive)
                self.assertTrue(lease.retention_snapshot().terminal)

                acquired_by_other_thread: list[bool] = []

                def acquire_from_other_thread() -> None:
                    acquired = operation_lock.acquire(timeout=0.1)
                    acquired_by_other_thread.append(acquired)
                    if acquired:
                        operation_lock.release()

                contender = threading.Thread(
                    target=acquire_from_other_thread,
                    name="test-release-on-success-handoff-contender",
                    daemon=True,
                )
                contender.start()
                contender.join(timeout=2.0)
                self.assertFalse(contender.is_alive())
                self.assertEqual(acquired_by_other_thread, [True])
            finally:
                if lease is not None and lease._pending_operation_handoff is not None:
                    lease.release()
                if operation_lock._is_owned():
                    operation_lock._lock.release()

    def test_control_flow_chain_prefers_context_and_bounds_cycles(self) -> None:
        later = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
        earlier = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        unrelated = KeyboardInterrupt("presentation-only cause")
        later.__context__ = earlier
        later.__cause__ = unrelated

        self.assertIs(
            claude_refresh_lock._earliest_context_control_flow(later),
            earlier,
        )

        earlier.__context__ = later
        self.assertIs(
            claude_refresh_lock._earliest_context_control_flow(later),
            earlier,
        )

        wrapper = RuntimeError("explicit wrapper")
        cause = KeyboardInterrupt("cause fallback")
        wrapper.__cause__ = cause
        self.assertIs(
            claude_refresh_lock._earliest_context_control_flow(wrapper),
            cause,
        )

    def test_final_enforcement_prefers_raw_chronology_to_active_error(
        self,
    ) -> None:
        first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
        second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
        winner = claude_refresh_lock._FirstControlFlowWinner(
            claude_refresh_lock._new_cleanup_inconclusive_fallback()
        )

        with self.assertRaises(claude_refresh_lock.ForwardedSignal) as raised:
            winner.enforce([first], second)

        self.assertIs(raised.exception, first)
        self.assertIsNot(raised.exception, second)

    def test_abandon_final_selector_boundaries_preserve_first_control_flow(
        self,
    ) -> None:
        abandon = claude_refresh_lock.ClaudeRefreshLockLease._abandon
        entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                abandon,
                statement="first_control_flow.observe(error)",
                callable_name="observe",
            )
        )

        for boundary, offset in (
            ("entry", entry_offset),
            ("return", return_offset),
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                lease._heartbeat_stop.set()
                heartbeat.join(timeout=2.0)
                self.assertFalse(heartbeat.is_alive())
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

                try:
                    with (
                        mock.patch.object(
                            lease,
                            "_finish_abandonment",
                            side_effect=first,
                        ),
                        self._raise_before_instruction(
                            abandon,
                            offset=offset,
                            error=second,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease.abandon(
                            "final abandonment selector boundary was interrupted"
                        )

                    self.assertIs(raised.exception, first)
                    self.assertIsNot(raised.exception, second)
                    self._assert_descriptor_only_recovery(
                        first,
                        forbidden_paths=lease.paths,
                    )
                finally:
                    self._operator_cleanup_inconclusive_lease(lease)

    def test_finish_abandonment_selector_boundaries_preserve_first_control_flow(
        self,
    ) -> None:
        finish = claude_refresh_lock.ClaudeRefreshLockLease._finish_abandonment
        entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                finish,
                statement="first_control_flow.observe(error)",
                callable_name="observe",
            )
        )

        for boundary, offset in (
            ("entry", entry_offset),
            ("return", return_offset),
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                first_control_flow = claude_refresh_lock._FirstControlFlowWinner(
                    lease._descriptor_bound_cleanup_fallback
                )
                errors = claude_refresh_lock._ControlFlowErrorLog(first_control_flow)
                errors.append(
                    claude_refresh_lock.ClaudeRefreshLockError(
                        "seed non-control-flow cleanup error"
                    )
                )
                real_primary_error = claude_refresh_lock._primary_error
                primary_calls = 0

                def interrupt_primary_selection(
                    candidates: list[BaseException],
                ) -> BaseException | None:
                    nonlocal primary_calls
                    primary_calls += 1
                    if primary_calls == 1:
                        raise first
                    return real_primary_error(candidates)

                try:
                    with (
                        mock.patch.object(
                            claude_refresh_lock,
                            "_primary_error",
                            side_effect=interrupt_primary_selection,
                        ),
                        self._raise_before_instruction(
                            finish,
                            offset=offset,
                            error=second,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease._finish_abandonment(
                            claude_refresh_lock._new_cleanup_inconclusive_fallback(),
                            errors,
                        )

                    self.assertGreaterEqual(primary_calls, 1)
                    self.assertIs(raised.exception, first)
                    self.assertIsNot(raised.exception, second)
                    self._assert_descriptor_only_recovery(
                        first,
                        forbidden_paths=lease.paths,
                    )
                finally:
                    self._force_cleanup_test_lease(lease)

    def test_release_final_selector_boundaries_preserve_first_control_flow(
        self,
    ) -> None:
        release_once = claude_refresh_lock.ClaudeRefreshLockLease._release_once
        entry_offset, return_offset = (
            self._source_call_entry_and_return_boundary_offsets(
                release_once,
                statement="first_control_flow.observe(body_error)",
                callable_name="observe",
            )
        )

        for boundary, offset in (
            ("entry", entry_offset),
            ("return", return_offset),
        ):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary,
            ):
                config = self._config_dir(pathlib.Path(temporary)).resolve()
                lease = self._acquire_lock(
                    config,
                    protocol=self.PROTOCOL,
                    timeout_seconds=0,
                )
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)

                try:
                    with (
                        mock.patch.object(
                            lease,
                            "_mark_cleanup_inconclusive",
                            side_effect=first,
                        ),
                        self._raise_before_instruction(
                            release_once,
                            offset=offset,
                            error=second,
                        ),
                        self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as raised,
                    ):
                        lease._release_once()

                    self.assertIs(raised.exception, first)
                    self.assertIsNot(raised.exception, second)
                finally:
                    self._force_cleanup_test_lease(lease)

    def test_identity_mode_is_permission_bits_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self._config_dir(pathlib.Path(temporary)).resolve()
            with claude_refresh_lock.claude_refresh_lock(
                config,
                protocol=self.PROTOCOL,
                timeout_seconds=0,
            ) as lease:
                for identity in lease.identities:
                    self.assertEqual(identity.mode, stat.S_IMODE(identity.mode))


if __name__ == "__main__":
    unittest.main()
