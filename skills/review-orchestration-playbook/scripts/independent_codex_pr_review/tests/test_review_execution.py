from __future__ import annotations

import dis
import errno
import json
import os
import pathlib
import signal
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import Mock, patch

import review_supervisor.recovery_cleanup as recovery_cleanup
import review_supervisor.codex_executable as codex_executable
import review_supervisor.no_child_profile as no_child_profile

from review_supervisor.appserver_protocol import (
    AppServerSessionResult,
)
from review_supervisor.auth_carrier import AuthCarrierRefreshRequired
from review_supervisor.auth_refresh import (
    ManagedAuthRefreshClosureReceipt,
    ManagedAuthRefreshLaunchRequest,
    ManagedAuthRefreshResult,
)
from review_supervisor.direct_gate import AppServerProcessResult, ProcessCustodyState
from review_supervisor.errors import UnprovenDirectHelperClosure
from review_supervisor.no_child_profile import LaunchedNoChildProcess
from review_supervisor.recovery_cleanup import (
    CustodiedManifest,
    QuarantinedRootRecoveryEvidence,
)
from review_supervisor import review_execution as execution


def _exec_sleep_test_child(
    _prepared: object,
    sandbox_argv: tuple[str, ...],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    pass_fds: tuple[int, ...],
    error_write_fd: int,
) -> None:
    del _prepared, pass_fds
    try:
        os.setsid()
        os.chdir(cwd)
        for source, destination in (
            (stdin_fd, 0),
            (stdout_fd, 1),
            (stderr_fd, 2),
        ):
            if source != destination:
                os.dup2(source, destination)
        os.execve(sandbox_argv[3], list(sandbox_argv[3:]), environment)
    except BaseException as error:
        no_child_profile._exit_child_launch_failure(error_write_fd, error)


def _call_followup_offsets(
    function: object,
    *,
    called_name: str,
    following_opname: str,
    following_argval: str | None = None,
) -> tuple[int, ...]:
    instructions = tuple(dis.get_instructions(function))
    offsets: list[int] = []
    for load_index, instruction in enumerate(instructions):
        if instruction.argval != called_name:
            continue
        for call_index in range(load_index + 1, len(instructions) - 1):
            candidate = instructions[call_index]
            if not candidate.opname.startswith("CALL"):
                continue
            following = instructions[call_index + 1]
            if following.opname != following_opname:
                continue
            if following_argval is not None and following.argval != following_argval:
                continue
            offsets.append(following.offset)
            break
    return tuple(dict.fromkeys(offsets))


def _call_followup_offset(
    function: object,
    *,
    called_name: str,
    following_opname: str,
    following_argval: str | None = None,
) -> int:
    offsets = _call_followup_offsets(
        function,
        called_name=called_name,
        following_opname=following_opname,
        following_argval=following_argval,
    )
    if offsets:
        return offsets[0]
    raise AssertionError(
        f"cannot find {called_name} CALL-to-{following_opname} boundary"
    )


def _instruction_after_offset(function: object, offset: int) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions[:-1]):
        if instruction.offset == offset:
            return instructions[index + 1].offset
    raise AssertionError(f"cannot find instruction after offset {offset}")


def _published_launch(
    process: LaunchedNoChildProcess,
) -> Callable[..., LaunchedNoChildProcess]:
    def launch(
        _launch_function: object,
        _prepared: object,
        _argv: tuple[str, ...],
        *,
        result_owner: execution._RefreshLaunchCapability,
        cwd: pathlib.Path,
        environment: dict[str, str],
        stdin_fd: int,
        stdout_fd: int,
        stderr_fd: int,
    ) -> LaunchedNoChildProcess:
        del (
            _launch_function,
            _prepared,
            _argv,
            cwd,
            environment,
            stdin_fd,
            stdout_fd,
            stderr_fd,
        )
        result_owner.publish(process)
        if not result_owner.owns(process):
            raise AssertionError("test launch result owner is incomplete")
        return process

    return launch


class _Lifecycle:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []

    def begin(self, stage: str) -> None:
        self.events.append(("begin", stage))

    def launched(self, stage: str, process: LaunchedNoChildProcess) -> None:
        self.events.append(("launched", stage, process.pid))

    def closed(self, stage: str, exit_code: int) -> None:
        self.events.append(("closed", stage, exit_code))


class _Lease:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.retained = False
        self.cleaned = False
        self.deleted = False

    def retain(self) -> None:
        self.retained = True

    def make_directory(self, name: str) -> pathlib.Path:
        path = self.root / name
        path.mkdir(parents=True, mode=0o700)
        return path

    def cleanup(self) -> None:
        self.cleaned = True
        if not self.retained:
            self.deleted = True


class _Custody:
    def __init__(
        self,
        fd: int,
        snapshot_path: pathlib.Path,
        *,
        fail_parent_revalidation: bool = False,
    ) -> None:
        self.executable_fd = fd
        self.snapshot_path = snapshot_path
        self.evidence = SimpleNamespace(sha256="1" * 64)
        self.events: list[str] = []
        self.fail_parent_revalidation = fail_parent_revalidation

    def parent_revalidate_after_exec_handoff(
        self,
        target: object,
        *,
        process_id: int,
    ) -> None:
        del target, process_id
        self.events.append("parent")
        if self.fail_parent_revalidation:
            raise RuntimeError("synthetic post-launch revalidation failure")

    def confirm_process_quiescence(self, evidence: object) -> None:
        del evidence
        self.events.append("quiescent")

    def cleanup(self) -> None:
        self.events.append("cleanup")


def _process(final_text: str = "STATUS: clean") -> AppServerProcessResult:
    session = AppServerSessionResult(
        review_status="clean",
        final_text=final_text,
        attestation={
            "approval_policy": "never",
            "approvals_reviewer": "user",
            "cli_version": "1.0",
            "ephemeral": True,
            "external_auth": "accepted",
            "instruction_sources": [],
            "model": "gpt-5.6-sol",
            "model_attempt": "primary",
            "model_provider": "openai",
            "reasoning_effort": "xhigh",
            "remote_control": "disabled-notification-observed",
            "runtime_workspace_roots": [],
            "sandbox": {"networkAccess": False, "type": "readOnly"},
            "session_source": "exec",
            "thread_path": None,
        },
        streamed_message_bytes=64,
    )
    return AppServerProcessResult(
        session=session,
        stdout_bytes=100,
        stdout_sha256="2" * 64,
        stderr_bytes=0,
        stderr_sha256="3" * 64,
        exit_code=0,
        elapsed_seconds=0.25,
        profile_sha256="4" * 64,
    )


def _launched(pid: int = 424242) -> LaunchedNoChildProcess:
    return LaunchedNoChildProcess(
        pid=pid,
        pgid=pid,
        session_id=pid,
        start_identity="synthetic-start",
        profile_sha256="a" * 64,
        passed_fd_numbers=(),
        executable=Mock(),
        evidence=Mock(),
        parent_nproc_before=(1, 1),
        parent_nproc_after=(1, 1),
    )


class ReviewExecutionTests(unittest.TestCase):
    def test_projected_review_environment_matches_runtime_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            with patch.object(
                execution.secrets,
                "token_hex",
                return_value="0" * 32,
            ):
                lease = execution._allocate_runtime_lease(runtime_root)
            try:
                actual = execution._isolated_environment(
                    codex_home=lease.root / "review-home",
                    temp_dir=lease.root / "review-tmp",
                )
                projected = execution.projected_isolated_review_environment(
                    runtime_root
                )
                self.assertEqual(projected, actual)
            finally:
                lease.cleanup()

    def test_runtime_lease_removes_its_empty_container_after_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            lease.make_directory("temporary")
            lease.cleanup()
            self.assertFalse(runtime_root.exists())

    def test_retained_runtime_lease_preserves_its_container(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            lease.retain()
            lease.cleanup()
            self.assertTrue(runtime_root.is_dir())
            lease.close_descriptors_for_recovery()

    def test_runtime_cleanup_retains_original_and_replacement_after_race(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            original_marker = lease.root / "original.txt"
            original_marker.write_text("original evidence", encoding="ascii")
            replacement_stage = runtime_root / "replacement-stage"
            replacement_stage.mkdir(mode=0o700)
            replacement_marker = replacement_stage / "replacement.txt"
            replacement_marker.write_text("replacement evidence", encoding="ascii")
            displaced = runtime_root / "original-evidence"
            original_require = CustodiedManifest.require_live_custody
            swapped = False

            def swap_after_validation(manifest: CustodiedManifest) -> None:
                nonlocal swapped
                original_require(manifest)
                if not swapped:
                    swapped = True
                    os.rename(lease.root, displaced)
                    os.rename(replacement_stage, lease.root)

            with (
                patch.object(
                    CustodiedManifest,
                    "require_live_custody",
                    new=swap_after_validation,
                ),
                self.assertRaisesRegex(
                    execution.CodexExecutableRetentionRequired,
                    "runtime cleanup could not prove",
                ),
            ):
                lease.cleanup()

            self.assertTrue(swapped)
            self.assertTrue(lease.retained)
            self.assertEqual(
                (displaced / original_marker.name).read_text(encoding="ascii"),
                "original evidence",
            )
            self.assertEqual(
                (lease.root / replacement_marker.name).read_text(encoding="ascii"),
                "replacement evidence",
            )
            self.assertTrue(runtime_root.is_dir())
            lease.close_descriptors_for_recovery()

    def test_runtime_recursive_cleanup_failure_retains_manifest_custody(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            for name in ("first.txt", "second.txt"):
                payload = lease.root / name
                payload.write_text(name, encoding="ascii")
                payload.chmod(0o600)
            real_unlink = recovery_cleanup.os.unlink
            unlink_calls = 0
            injected = OSError("synthetic runtime recursive deletion failure")

            def fail_second_unlink(name: bytes, *, dir_fd: int) -> None:
                nonlocal unlink_calls
                if name not in {b"first.txt", b"second.txt"}:
                    real_unlink(name, dir_fd=dir_fd)
                    return
                unlink_calls += 1
                if unlink_calls == 2:
                    raise injected
                real_unlink(name, dir_fd=dir_fd)

            retained_manifests: tuple[CustodiedManifest, ...] = ()
            try:
                with (
                    patch.object(
                        recovery_cleanup.os,
                        "unlink",
                        side_effect=fail_second_unlink,
                    ),
                    self.assertRaises(
                        execution.CodexExecutableRetentionRequired
                    ) as caught,
                ):
                    lease.cleanup()

                self.assertIs(caught.exception.__cause__, injected)
                quarantine_evidence = tuple(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if isinstance(evidence, QuarantinedRootRecoveryEvidence)
                )
                self.assertEqual(len(quarantine_evidence), 1)
                self.assertEqual(quarantine_evidence[0].stage, "recursive-delete")
                self.assertEqual(
                    quarantine_evidence[0].original_name,
                    os.fsencode(lease.root.name),
                )
                self.assertEqual(
                    quarantine_evidence[0].parent_fd,
                    lease.container_fd,
                )
                retained_manifests = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(resource, CustodiedManifest)
                )
                self.assertEqual(len(retained_manifests), 1)
                self.assertIn(
                    quarantine_evidence[0].root_fd,
                    retained_manifests[0].root_fds,
                )
                os.fstat(quarantine_evidence[0].root_fd)
                quarantine = lease.container / os.fsdecode(
                    quarantine_evidence[0].quarantine_name
                )
                self.assertFalse(lease.root.exists())
                self.assertEqual(len(tuple(quarantine.iterdir())), 1)
            finally:
                for manifest in retained_manifests:
                    manifest.close()
                lease.close_descriptors_for_recovery()

    def test_runtime_manifest_call_to_store_interrupt_retains_result_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            (lease.root / "evidence.txt").write_text(
                "retained evidence",
                encoding="ascii",
            )
            target_offset = _call_followup_offset(
                execution._RuntimeLease.cleanup,
                called_name="build_custodied_manifest",
                following_opname="STORE_FAST",
                following_argval="manifest",
            )
            interruption = KeyboardInterrupt(
                "injected runtime manifest CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_manifest_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is execution._RuntimeLease.cleanup.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_manifest_store

            retained_manifests: tuple[CustodiedManifest, ...] = ()
            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_manifest_store)
                with self.assertRaises(
                    execution.CodexExecutableRetentionRequired
                ) as caught:
                    lease.cleanup()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, interruption)
                retained_manifests = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(resource, CustodiedManifest)
                )
                self.assertEqual(len(retained_manifests), 1)
                self.assertEqual(len(retained_manifests[0].root_fds), 1)
                os.fstat(retained_manifests[0].root_fds[0])
                self.assertTrue(lease.root.is_dir())
                self.assertTrue(lease.retained)
            finally:
                for manifest in retained_manifests:
                    manifest.close()
                lease.close_descriptors_for_recovery()

    def test_runtime_deletion_call_to_store_interrupt_preserves_full_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            target_offset = _call_followup_offset(
                execution._RuntimeLease.cleanup,
                called_name="delete_custodied_roots",
                following_opname="STORE_FAST",
                following_argval="deletion_proof",
            )
            interruption = KeyboardInterrupt(
                "injected runtime deletion CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_deletion_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is execution._RuntimeLease.cleanup.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_deletion_store

            retained_manifests: tuple[CustodiedManifest, ...] = ()
            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_deletion_store)
                with self.assertRaises(
                    execution.CodexExecutableRetentionRequired
                ) as caught:
                    lease.cleanup()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, interruption)
                deletion_owner = caught.exception.custodied_deletion_result_owner
                self.assertTrue(deletion_owner.finished)
                self.assertIs(
                    caught.exception.completed_deletion_proof,
                    deletion_owner.proof,
                )
                self.assertEqual(len(deletion_owner.root_outcomes), 1)
                self.assertEqual(deletion_owner.root_outcomes[0].state, "complete")
                self.assertFalse(lease.root.exists())
                retained_manifests = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(resource, CustodiedManifest)
                )
                self.assertEqual(len(retained_manifests), 1)
            finally:
                for manifest in retained_manifests:
                    manifest.close()
                lease.close_descriptors_for_recovery()

    def test_runtime_manifest_close_failure_keeps_typed_retention_primary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            close_calls = 0
            injected = recovery_cleanup.CustodyLostError(
                "synthetic manifest close ambiguity"
            )
            close_evidence: object | None = None

            def fail_manifest_close(manifest: CustodiedManifest) -> None:
                nonlocal close_calls, close_evidence
                close_calls += 1
                descriptor = manifest.root_fds[0]
                close_evidence = recovery_cleanup.CustodiedManifestCloseEvidence(
                    root_index=0,
                    descriptor=descriptor,
                    state="ownership-ambiguous-live-same-object",
                    expected_identity=manifest.roots[0].expected_identity,
                    observed_identity=execution.identity_from_stat(
                        os.fstat(descriptor)
                    ),
                    reason="synthetic close ambiguity",
                )
                setattr(
                    injected,
                    "custodied_manifest_close_evidence",
                    close_evidence,
                )
                raise injected

            retained_manifests: tuple[CustodiedManifest, ...] = ()
            try:
                with (
                    patch.object(
                        CustodiedManifest,
                        "close",
                        new=fail_manifest_close,
                    ),
                    self.assertRaises(
                        execution.CodexExecutableRetentionRequired
                    ) as caught,
                ):
                    lease.cleanup()

                self.assertIs(caught.exception.__cause__, injected)
                self.assertEqual(
                    caught.exception.failure.code, "runtime-cleanup-retained"
                )
                self.assertEqual(close_calls, 1)
                self.assertIn(
                    close_evidence,
                    caught.exception.recovery_evidence,
                )
                retained_manifests = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(resource, CustodiedManifest)
                )
                self.assertEqual(len(retained_manifests), 1)
                os.fstat(retained_manifests[0].root_fds[0])
            finally:
                for manifest in retained_manifests:
                    manifest.close()
                lease.close_descriptors_for_recovery()

    def test_runtime_child_creation_failure_rolls_back_fd_and_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            real_validate = execution.validate_private_directory_fd
            child_fd: int | None = None

            def fail_child_validation(
                descriptor: int,
                path: pathlib.Path,
            ) -> object:
                nonlocal child_fd
                if path == lease.root / "broken":
                    child_fd = descriptor
                    raise OSError("injected child validation failure")
                return real_validate(descriptor, path)

            with (
                patch.object(
                    execution,
                    "validate_private_directory_fd",
                    side_effect=fail_child_validation,
                ),
                self.assertRaisesRegex(OSError, "child validation failure"),
            ):
                lease.make_directory("broken")

            assert child_fd is not None
            with self.assertRaises(OSError):
                os.fstat(child_fd)
            self.assertFalse((lease.root / "broken").exists())
            self.assertEqual(lease.make_directory("broken"), lease.root / "broken")
            lease.cleanup()

    def test_runtime_lease_allocation_failure_rolls_back_and_can_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            real_validate = execution.validate_private_directory_fd
            allocated_fd: int | None = None

            def fail_allocated_root(
                descriptor: int,
                path: pathlib.Path,
            ) -> object:
                nonlocal allocated_fd
                if path.name.startswith(execution._RUNTIME_LEASE_PREFIX):
                    allocated_fd = descriptor
                    raise OSError("injected allocation validation failure")
                return real_validate(descriptor, path)

            with (
                patch.object(
                    execution,
                    "validate_private_directory_fd",
                    side_effect=fail_allocated_root,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "allocation validation failure",
                ),
            ):
                execution._allocate_runtime_lease(runtime_root)

            assert allocated_fd is not None
            with self.assertRaises(OSError):
                os.fstat(allocated_fd)
            self.assertEqual(tuple(runtime_root.iterdir()), ())
            lease = execution._allocate_runtime_lease(runtime_root)
            lease.cleanup()

    def test_runtime_lease_mkdir_result_interrupt_retains_pending_allocation_fds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            result_discard_offset = _call_followup_offset(
                execution._allocate_runtime_lease,
                called_name="mkdir",
                following_opname="POP_TOP",
            )
            target_offset = _instruction_after_offset(
                execution._allocate_runtime_lease,
                result_discard_offset,
            )
            interruption = KeyboardInterrupt(
                "injected runtime lease mkdir result interrupt"
            )
            injected = False

            def interrupt_mkdir_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is execution._allocate_runtime_lease.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_mkdir_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_mkdir_result)
                with self.assertRaises(
                    execution.CodexExecutableRetentionRequired
                ) as caught:
                    execution._allocate_runtime_lease(runtime_root)
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception.__cause__, interruption)
            self.assertEqual(
                caught.exception.failure.code,
                "runtime-lease-allocation-pending",
            )
            recovery = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, execution._RuntimeAllocationRecovery)
            )
            try:
                self.assertTrue(recovery.retained)
                self.assertEqual(recovery.entry_state, "present-untransferred")
                os.fstat(recovery.parent_fd)
                os.fstat(recovery.container_fd)
                assert recovery.directory_fd is not None
                os.fstat(recovery.directory_fd)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if evidence.stage == "runtime-lease-allocation-pending"
                )
                self.assertEqual(evidence.parent_fd, recovery.container_fd)
                self.assertEqual(evidence.directory_fd, recovery.directory_fd)
                self.assertEqual(
                    evidence.protected_property,
                    "object-identity-and-access-policy",
                )
                self.assertTrue(recovery.root.is_dir())
            finally:
                recovery.close_descriptors_for_recovery()

    def test_runtime_child_rollback_failure_returns_recovery_custody(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            real_validate = execution.validate_private_directory_fd

            def fail_child_validation(
                _descriptor: int,
                path: pathlib.Path,
            ) -> object:
                if path == lease.root / "retained":
                    raise OSError("injected child validation failure")
                return real_validate(
                    _descriptor,
                    path,
                )

            with (
                patch.object(
                    execution,
                    "validate_private_directory_fd",
                    side_effect=fail_child_validation,
                ),
                patch.object(
                    execution,
                    "quarantine_and_remove_empty_root",
                    side_effect=OSError("injected child rollback failure"),
                ),
                self.assertRaises(execution.CodexExecutableRetentionRequired) as caught,
            ):
                lease.make_directory("retained")

            recovery = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, execution._RuntimeChildRecovery)
            )
            try:
                self.assertTrue(lease.retained)
                self.assertTrue((lease.root / "retained").is_dir())
                assert recovery.directory_fd is not None
                os.fstat(recovery.directory_fd)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if evidence.stage == "runtime-child-creation"
                )
                self.assertEqual(evidence.directory_fd, recovery.directory_fd)
            finally:
                recovery.close_descriptors_for_recovery()
                lease.close_descriptors_for_recovery()

    def test_runtime_container_rmdir_aba_preserves_public_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            runtime_root = pathlib.Path(raw_root) / "review-runtime"
            lease = execution._allocate_runtime_lease(runtime_root)
            real_rmdir = os.rmdir
            quarantine_rmdirs = 0

            def inject_on_container_quarantine(
                name: bytes,
                *,
                dir_fd: int,
            ) -> None:
                nonlocal quarantine_rmdirs
                if name.startswith(b".targeted-cleanup-quarantine-"):
                    quarantine_rmdirs += 1
                    if quarantine_rmdirs == 2:
                        runtime_root.mkdir(mode=0o700)
                        (runtime_root / "replacement.txt").write_text(
                            "replacement evidence",
                            encoding="ascii",
                        )
                real_rmdir(name, dir_fd=dir_fd)

            with (
                patch.object(
                    execution.os,
                    "rmdir",
                    side_effect=inject_on_container_quarantine,
                ),
                self.assertRaisesRegex(
                    execution.CodexExecutableRetentionRequired,
                    "runtime cleanup could not prove",
                ) as caught,
            ):
                lease.cleanup()

            self.assertTrue(lease.retained)
            self.assertEqual(
                (runtime_root / "replacement.txt").read_text(encoding="ascii"),
                "replacement evidence",
            )
            quarantine_evidence = tuple(
                evidence
                for evidence in caught.exception.recovery_evidence
                if isinstance(evidence, QuarantinedRootRecoveryEvidence)
            )
            self.assertEqual(len(quarantine_evidence), 1)
            self.assertEqual(quarantine_evidence[0].stage, "quarantine-removal")
            self.assertEqual(
                quarantine_evidence[0].original_name,
                os.fsencode(runtime_root.name),
            )
            self.assertEqual(
                quarantine_evidence[0].parent_fd,
                lease.container_parent_fd,
            )
            self.assertEqual(quarantine_evidence[0].root_fd, lease.container_fd)
            lease.close_descriptors_for_recovery()

    def test_fresh_auth_does_not_launch_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            auth_home = root / "home" / ".codex"
            auth_home.mkdir(parents=True, mode=0o700)
            os.chmod(auth_home, 0o700)
            auth_path = auth_home / "auth.json"
            lifecycle = _Lifecycle()
            lease = _Lease(root / "run")
            state = ProcessCustodyState(
                leader_reaped=True,
                process_group_empty=True,
                pipes_closed=True,
                exit_code=0,
            )
            with (
                patch.object(execution, "_allocate_runtime_lease", return_value=lease),
                patch.object(
                    execution, "load_external_auth", return_value=object()
                ) as load,
                patch.object(
                    execution, "revalidate_external_auth_source"
                ) as revalidate,
                patch.object(execution, "_run_auth_refresh") as refresh,
                patch.object(
                    execution,
                    "_run_review",
                    return_value=(
                        _process(),
                        state,
                        {"launch": True, "serialization": True},
                    ),
                ),
            ):
                result = execution.run_authenticated_review(
                    codex_executable=root / "codex",
                    aggregate_schema_path=root / "schema.json",
                    runtime_root=root / "runtime",
                    repo=root / "repo",
                    helper_root=root / "helper",
                    retention_root=root / "retention",
                    checkout_root=root / "checkout",
                    prompt=b"review",
                    requested_model="gpt-5.6-sol",
                    requested_reasoning_effort="xhigh",
                    lifecycle=lifecycle,
                    auth_path=auth_path,
                )
            self.assertEqual(load.call_count, 1)
            self.assertIs(
                load.call_args.kwargs["filesystem_metadata_verifier"],
                execution.verify_macos_filesystem_metadata,
            )
            revalidate.assert_called_once_with(
                auth_path,
                load.return_value,
                filesystem_metadata_verifier=execution.verify_macos_filesystem_metadata,
            )
            refresh.assert_not_called()
            self.assertEqual(result.auth_refresh, {"status": "not-required"})
            self.assertTrue(lease.cleaned)

    def test_codex_preflight_retention_failure_preserves_runtime_lease(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            auth_home = root / "home" / ".codex"
            auth_home.mkdir(parents=True, mode=0o700)
            auth_path = auth_home / "auth.json"
            lease = _Lease(root / "run")
            failure = execution.CodexExecutableRetentionRequired(
                "synthetic retained preflight evidence",
                code="synthetic-retention",
            )
            failure.retain_resource(lease)
            with (
                patch.object(execution, "_allocate_runtime_lease", return_value=lease),
                patch.object(execution, "load_external_auth", return_value=object()),
                patch.object(execution, "revalidate_external_auth_source"),
                patch.object(execution, "_run_review", side_effect=failure),
            ):
                with self.assertRaisesRegex(
                    execution.CodexExecutableRetentionRequired,
                    "synthetic retained preflight evidence",
                ):
                    execution.run_authenticated_review(
                        codex_executable=root / "codex",
                        aggregate_schema_path=root / "schema.json",
                        runtime_root=root / "runtime",
                        repo=root / "repo",
                        helper_root=root / "helper",
                        retention_root=root / "retention",
                        checkout_root=root / "checkout",
                        prompt=b"review",
                        requested_model="gpt-5.6-sol",
                        requested_reasoning_effort="xhigh",
                        lifecycle=_Lifecycle(),
                        auth_path=auth_path,
                    )

            self.assertTrue(lease.retained)
            self.assertTrue(lease.cleaned)
            self.assertEqual(
                sum(resource is lease for resource in failure.retained_resources),
                1,
            )

    def test_refreshed_auth_uses_the_filesystem_verifier_before_review(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            auth_home = root / "home" / ".codex"
            auth_home.mkdir(parents=True, mode=0o700)
            auth_path = auth_home / "auth.json"
            lifecycle = _Lifecycle()
            lease = _Lease(root / "run")
            state = ProcessCustodyState(
                leader_reaped=True,
                process_group_empty=True,
                pipes_closed=True,
                exit_code=0,
            )
            closure = ManagedAuthRefreshClosureReceipt(
                pid=424242,
                process_group_id=424242,
                session_id=424242,
                profile_sha256="a" * 64,
                exit_code=0,
                leader_reaped=True,
                process_group_empty=True,
                stdio_closed=True,
            )
            refresh_result = ManagedAuthRefreshResult(
                refresh_completed=True,
                managed_auth_verified=True,
                codex_home_verified=True,
                requires_openai_auth=False,
                process_closure=closure,
            )
            refreshed_auth = object()
            with (
                patch.object(execution, "_allocate_runtime_lease", return_value=lease),
                patch.object(
                    execution,
                    "load_external_auth",
                    side_effect=(
                        AuthCarrierRefreshRequired("synthetic refresh"),
                        refreshed_auth,
                    ),
                ) as load,
                patch.object(
                    execution, "revalidate_external_auth_source"
                ) as revalidate,
                patch.object(
                    execution,
                    "_run_auth_refresh",
                    return_value=refresh_result,
                ),
                patch.object(
                    execution,
                    "_run_review",
                    return_value=(
                        _process(),
                        state,
                        {"launch": True, "serialization": True},
                    ),
                ),
            ):
                execution.run_authenticated_review(
                    codex_executable=root / "codex",
                    aggregate_schema_path=root / "schema.json",
                    runtime_root=root / "runtime",
                    repo=root / "repo",
                    helper_root=root / "helper",
                    retention_root=root / "retention",
                    checkout_root=root / "checkout",
                    prompt=b"review",
                    requested_model="gpt-5.6-sol",
                    requested_reasoning_effort="xhigh",
                    lifecycle=lifecycle,
                    auth_path=auth_path,
                )

            self.assertEqual(load.call_count, 2)
            for call in load.call_args_list:
                self.assertIs(
                    call.kwargs["filesystem_metadata_verifier"],
                    execution.verify_macos_filesystem_metadata,
                )
            revalidate.assert_called_once_with(
                auth_path,
                refreshed_auth,
                filesystem_metadata_verifier=execution.verify_macos_filesystem_metadata,
            )

    def test_refresh_preparation_outer_drop_cleans_never_launched_custody(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex"
            snapshot.write_bytes(b"fixture")
            snapshot.chmod(0o500)
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                checkpoints = 0

                def require_outer() -> None:
                    nonlocal checkpoints
                    checkpoints += 1
                    if checkpoints == 2:
                        raise RuntimeError("synthetic outer EOF during preparation")

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ) as authenticate,
                    patch.object(execution, "_prepare_custodied_launch") as prepare,
                    self.assertRaisesRegex(RuntimeError, "synthetic outer EOF"),
                ):
                    execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=None,
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=lease,
                        lifecycle=lifecycle,
                        liveness_checkpoint=require_outer,
                    )

                schema_work_root = authenticate.call_args.kwargs["schema_work_root"]
                self.assertEqual(
                    schema_work_root,
                    lease.root / "auth-refresh-schema-work",
                )
                self.assertEqual(schema_work_root.stat().st_mode & 0o777, 0o700)
                self.assertIsNone(
                    authenticate.call_args.kwargs["aggregate_schema_path"]
                )
                prepare.assert_not_called()
                self.assertEqual(lifecycle.events, [])
                self.assertEqual(custody.events, ["quiescent", "cleanup"])
            finally:
                os.close(fd)

    def test_auth_refresh_preserves_unproven_closure_when_finalization_also_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex"
            snapshot.write_bytes(b"fixture")
            snapshot.chmod(0o500)
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="b" * 64,
                    profile_sha256="a" * 64,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                closure_error = UnprovenDirectHelperClosure(
                    "synthetic auth-refresh closure gap"
                )
                settlement_error = RuntimeError(
                    "synthetic outer auth-refresh settlement failure"
                )

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "refresh_managed_auth",
                        side_effect=closure_error,
                    ) as refresh,
                    patch.object(
                        execution,
                        "_settle_launched_process",
                        side_effect=settlement_error,
                    ) as settle,
                    self.assertRaises(UnprovenDirectHelperClosure) as caught,
                ):
                    execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=lease,
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertIsInstance(
                    caught.exception,
                    execution.AuthenticatedReviewClosureUnproven,
                )
                self.assertIs(
                    getattr(caught.exception, "source_closure_error"),
                    closure_error,
                )
                self.assertEqual(
                    getattr(caught.exception, "finalization_errors"),
                    (settlement_error,),
                )
                self.assertTrue(
                    any(
                        "synthetic outer auth-refresh settlement failure" in note
                        for note in getattr(caught.exception, "__notes__", ())
                    )
                )
                refresh.assert_called_once()
                settle.assert_called_once()
                self.assertTrue(lease.retained)
                self.assertIn(lease, caught.exception.retained_resources)
                self.assertIn(custody, caught.exception.retained_resources)
                os.fstat(custody.executable_fd)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if isinstance(
                        evidence,
                        execution.AuthenticatedReviewClosureRecoveryEvidence,
                    )
                )
                self.assertEqual(
                    evidence.protected_property,
                    "resource-ownership-and-closure-publication",
                )
                self.assertTrue(evidence.executable_custody_retained)
                self.assertTrue(evidence.writable_root_descriptors_retained)
                self.assertFalse(evidence.closure_publication_proven)
                self.assertEqual(custody.events, [])
                self.assertEqual(
                    lifecycle.events,
                    [("begin", "auth-refresh")],
                )
            finally:
                os.close(fd)

    def test_refresh_capability_binds_snapshot_profile_and_parent_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                prepared = Mock()
                target = Mock()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=prepared,
                    target=target,
                    handoff_token="b" * 64,
                    profile_sha256="a" * 64,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                environment = execution._isolated_environment(
                    codex_home=root,
                    temp_dir=root,
                )
                capability = execution._RefreshLaunchCapability(
                    launch=launch,
                    lifecycle=lifecycle,
                    expected_cwd=root,
                    expected_environment=environment,
                )
                process = _launched()
                request = ManagedAuthRefreshLaunchRequest(
                    arguments=execution._APP_SERVER_ARGUMENTS,
                    cwd=root,
                    environment=environment,
                    stdin_fd=0,
                    stdout_fd=1,
                    stderr_fd=2,
                    deadline_monotonic=time.monotonic() + 10,
                    expected_snapshot=capability.authenticated_snapshot,
                    expected_profile_sha256=capability.profile_sha256,
                )
                with patch.object(
                    execution,
                    "launch_no_child_process_with_result_publisher",
                    side_effect=_published_launch(process),
                ) as launcher:
                    receipt = capability.launch(request)
                self.assertEqual(receipt.snapshot, capability.authenticated_snapshot)
                self.assertEqual(receipt.profile_sha256, capability.profile_sha256)
                self.assertEqual(custody.events, ["parent"])
                self.assertEqual(
                    lifecycle.events, [("launched", "auth-refresh", process.pid)]
                )
                argv = launcher.call_args.args[2]
                self.assertEqual(argv[0], str(snapshot))
                self.assertEqual(argv[1:], execution._APP_SERVER_ARGUMENTS)
            finally:
                os.close(fd)

    def test_refresh_result_owner_retries_partial_process_state_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                process = _launched()
                capability = execution._RefreshLaunchCapability(
                    launch=execution._PreparedCustodiedLaunch(
                        custody=custody,
                        prepared=Mock(),
                        target=Mock(),
                        handoff_token="b" * 64,
                        profile_sha256=process.profile_sha256,
                        writable_roots=execution._HeldWritableRoots((), ()),
                    ),
                    lifecycle=_Lifecycle(),
                    expected_cwd=root,
                    expected_environment={},
                )
                capability.process_state.leader_reaped = True
                capability.process_state.process_group_empty = True
                capability.process_state.pipes_closed = True
                capability.process_state.exit_code = 99
                target_offset = _call_followup_offset(
                    execution._RefreshLaunchCapability.publish,
                    called_name="_record_launch",
                    following_opname="POP_TOP",
                )
                interruption = KeyboardInterrupt(
                    "injected managed-auth result owner partial publication"
                )
                injected = False

                def interrupt_partial_publication(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._RefreshLaunchCapability.publish.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_partial_publication

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_partial_publication)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        capability.publish(process)
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(caught.exception, interruption)
                self.assertTrue(injected)
                self.assertIs(capability.launched_process, process)
                self.assertFalse(capability.owns(process))
                capability.publish(process)
                self.assertTrue(capability.owns(process))
                self.assertEqual(capability.process_state.process_id, process.pid)
                self.assertEqual(
                    capability.process_state.process_group_id,
                    process.pgid,
                )
                self.assertEqual(
                    capability.process_state.profile_sha256,
                    process.profile_sha256,
                )
                self.assertFalse(capability.process_state.leader_reaped)
                self.assertFalse(capability.process_state.process_group_empty)
                self.assertFalse(capability.process_state.pipes_closed)
                self.assertIsNone(capability.process_state.exit_code)
            finally:
                os.close(fd)

    def test_refresh_launch_call_to_store_interrupt_keeps_typed_process_custody(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="b" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                environment = execution._isolated_environment(
                    codex_home=root,
                    temp_dir=root,
                )
                capability = execution._RefreshLaunchCapability(
                    launch=launch,
                    lifecycle=lifecycle,
                    expected_cwd=root,
                    expected_environment=environment,
                )
                request = ManagedAuthRefreshLaunchRequest(
                    arguments=execution._APP_SERVER_ARGUMENTS,
                    cwd=root,
                    environment=environment,
                    stdin_fd=0,
                    stdout_fd=1,
                    stderr_fd=2,
                    deadline_monotonic=time.monotonic() + 10,
                    expected_snapshot=capability.authenticated_snapshot,
                    expected_profile_sha256=capability.profile_sha256,
                )
                target_offset = _call_followup_offset(
                    execution._RefreshLaunchCapability.launch,
                    called_name="launch_no_child_process_with_result_publisher",
                    following_opname="STORE_FAST",
                    following_argval="launched",
                )
                interruption = KeyboardInterrupt(
                    "injected auth-refresh launch CALL-to-STORE interrupt"
                )
                injected = False

                def interrupt_result_store(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._RefreshLaunchCapability.launch.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_result_store

                def settle(
                    state: ProcessCustodyState,
                    launched: LaunchedNoChildProcess | None,
                    *,
                    pipes_closed: bool,
                ) -> None:
                    self.assertIs(launched, process)
                    state.exit_code = 130
                    state.leader_reaped = True
                    state.process_group_empty = True
                    state.pipes_closed = pipes_closed

                previous_trace = sys.gettrace()
                try:
                    with (
                        patch.object(
                            execution,
                            "launch_no_child_process_with_result_publisher",
                            side_effect=_published_launch(process),
                        ),
                        patch.object(
                            execution,
                            "_settle_launched_process",
                            side_effect=settle,
                        ) as settle_process,
                    ):
                        sys.settrace(interrupt_result_store)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            capability.launch(request)
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertIs(capability.launched_process, process)
                self.assertEqual(capability.process_state.process_id, process.pid)
                self.assertTrue(capability.process_state.leader_reaped)
                self.assertTrue(capability.process_state.process_group_empty)
                self.assertFalse(capability.process_state.pipes_closed)
                settle_process.assert_called_once()
                self.assertEqual(lifecycle.events, [])
            finally:
                os.close(fd)

    def test_successful_refresh_persists_exact_closure_before_finalization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="b" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                closure = ManagedAuthRefreshClosureReceipt(
                    pid=process.pid,
                    process_group_id=process.pgid,
                    session_id=process.session_id,
                    profile_sha256=process.profile_sha256,
                    exit_code=0,
                    leader_reaped=True,
                    process_group_empty=True,
                    stdio_closed=True,
                )

                def refresh(**kwargs: object) -> ManagedAuthRefreshResult:
                    capability = kwargs["launch_capability"]
                    request = ManagedAuthRefreshLaunchRequest(
                        arguments=execution._APP_SERVER_ARGUMENTS,
                        cwd=kwargs["neutral_cwd"],
                        environment=kwargs["environment"],
                        stdin_fd=0,
                        stdout_fd=1,
                        stderr_fd=2,
                        deadline_monotonic=time.monotonic() + 10,
                        expected_snapshot=kwargs["expected_snapshot"],
                        expected_profile_sha256=kwargs["expected_profile_sha256"],
                    )
                    capability.launch(request)
                    capability.record_closure(closure)
                    return ManagedAuthRefreshResult(
                        refresh_completed=True,
                        managed_auth_verified=True,
                        codex_home_verified=True,
                        requires_openai_auth=False,
                        process_closure=closure,
                    )

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "launch_no_child_process_with_result_publisher",
                        side_effect=_published_launch(process),
                    ),
                    patch.object(
                        execution, "refresh_managed_auth", side_effect=refresh
                    ),
                ):
                    result = execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=_Lease(root / "run"),
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertEqual(result.process_closure, closure)
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "auth-refresh"),
                        ("launched", "auth-refresh", process.pid),
                        ("closed", "auth-refresh", 0),
                    ],
                )
            finally:
                os.close(fd)

    def test_refresh_lifecycle_return_interrupt_still_closes_and_propagates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="c" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                target_offset = _call_followup_offset(
                    execution._LifecycleLaunchPublication.publish,
                    called_name="launched",
                    following_opname="POP_TOP",
                )
                interruption = KeyboardInterrupt(
                    "injected auth-refresh lifecycle return interrupt"
                )
                injected = False

                def interrupt_lifecycle_return(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._LifecycleLaunchPublication.publish.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_lifecycle_return

                def refresh(**kwargs: object) -> ManagedAuthRefreshResult:
                    capability = kwargs["launch_capability"]
                    return capability.launch(
                        ManagedAuthRefreshLaunchRequest(
                            arguments=execution._APP_SERVER_ARGUMENTS,
                            cwd=kwargs["neutral_cwd"],
                            environment=kwargs["environment"],
                            stdin_fd=0,
                            stdout_fd=1,
                            stderr_fd=2,
                            deadline_monotonic=time.monotonic() + 10,
                            expected_snapshot=kwargs["expected_snapshot"],
                            expected_profile_sha256=kwargs["expected_profile_sha256"],
                        )
                    )

                def settle(
                    state: ProcessCustodyState,
                    launched: LaunchedNoChildProcess | None,
                    *,
                    pipes_closed: bool,
                ) -> None:
                    self.assertIs(launched, process)
                    state.exit_code = 130
                    state.leader_reaped = True
                    state.process_group_empty = True
                    state.pipes_closed = pipes_closed

                previous_trace = sys.gettrace()
                try:
                    with (
                        patch.object(
                            execution,
                            "authenticate_codex_executable",
                            return_value=custody,
                        ),
                        patch.object(
                            execution,
                            "_prepare_custodied_launch",
                            return_value=launch,
                        ),
                        patch.object(
                            execution,
                            "launch_no_child_process_with_result_publisher",
                            side_effect=_published_launch(process),
                        ),
                        patch.object(
                            execution,
                            "refresh_managed_auth",
                            side_effect=refresh,
                        ),
                        patch.object(
                            execution,
                            "_settle_launched_process",
                            side_effect=settle,
                        ) as settle_process,
                    ):
                        sys.settrace(interrupt_lifecycle_return)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            execution._run_auth_refresh(
                                codex_executable=snapshot,
                                aggregate_schema_path=root / "schema.json",
                                exclusions=Mock(),
                                auth_path=root / "home" / ".codex" / "auth.json",
                                lease=lease,
                                lifecycle=lifecycle,
                                liveness_checkpoint=lambda: None,
                            )
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(caught.exception, interruption)
                self.assertTrue(injected)
                self.assertEqual(
                    [
                        call.kwargs["pipes_closed"]
                        for call in settle_process.call_args_list
                    ],
                    [False, True],
                )
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "auth-refresh"),
                        ("launched", "auth-refresh", process.pid),
                        ("closed", "auth-refresh", 130),
                    ],
                )
                self.assertEqual(custody.events, ["quiescent", "cleanup"])
            finally:
                os.close(fd)

    def test_refresh_post_launch_revalidation_failure_records_known_closure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(
                    fd,
                    snapshot,
                    fail_parent_revalidation=True,
                )
                lifecycle = _Lifecycle()
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="c" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )

                def refresh(**kwargs: object) -> ManagedAuthRefreshResult:
                    capability = kwargs["launch_capability"]
                    return capability.launch(
                        ManagedAuthRefreshLaunchRequest(
                            arguments=execution._APP_SERVER_ARGUMENTS,
                            cwd=kwargs["neutral_cwd"],
                            environment=kwargs["environment"],
                            stdin_fd=0,
                            stdout_fd=1,
                            stderr_fd=2,
                            deadline_monotonic=time.monotonic() + 10,
                            expected_snapshot=kwargs["expected_snapshot"],
                            expected_profile_sha256=kwargs["expected_profile_sha256"],
                        )
                    )

                def settle(
                    state: ProcessCustodyState,
                    launched: LaunchedNoChildProcess | None,
                    *,
                    pipes_closed: bool,
                ) -> None:
                    self.assertEqual(launched, process)
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    state.exit_code = 23
                    state.leader_reaped = True
                    state.process_group_empty = True
                    state.pipes_closed = pipes_closed
                    if not pipes_closed:
                        raise RuntimeError("synthetic closed launch failure")

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "launch_no_child_process_with_result_publisher",
                        side_effect=_published_launch(process),
                    ),
                    patch.object(
                        execution, "refresh_managed_auth", side_effect=refresh
                    ),
                    patch.object(
                        execution,
                        "_settle_launched_process",
                        side_effect=settle,
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=_Lease(root / "run"),
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "auth-refresh"),
                        ("launched", "auth-refresh", process.pid),
                        ("closed", "auth-refresh", 23),
                    ],
                )
            finally:
                os.close(fd)

    def test_refresh_capability_preserves_unproven_closure_when_settlement_also_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="c" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                closure_error = UnprovenDirectHelperClosure(
                    "synthetic capability closure gap"
                )
                settlement_error = RuntimeError(
                    "synthetic capability settlement failure"
                )

                def refresh(**kwargs: object) -> ManagedAuthRefreshResult:
                    capability = kwargs["launch_capability"]
                    return capability.launch(
                        ManagedAuthRefreshLaunchRequest(
                            arguments=execution._APP_SERVER_ARGUMENTS,
                            cwd=kwargs["neutral_cwd"],
                            environment=kwargs["environment"],
                            stdin_fd=0,
                            stdout_fd=1,
                            stderr_fd=2,
                            deadline_monotonic=time.monotonic() + 10,
                            expected_snapshot=kwargs["expected_snapshot"],
                            expected_profile_sha256=kwargs["expected_profile_sha256"],
                        )
                    )

                def settle(
                    state: ProcessCustodyState,
                    launched: LaunchedNoChildProcess | None,
                    *,
                    pipes_closed: bool,
                ) -> None:
                    self.assertEqual(launched, process)
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    state.exit_code = 23
                    state.leader_reaped = True
                    state.process_group_empty = True
                    state.pipes_closed = pipes_closed
                    if not pipes_closed:
                        raise settlement_error

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "launch_no_child_process_with_result_publisher",
                        side_effect=_published_launch(process),
                    ),
                    patch.object(
                        execution, "refresh_managed_auth", side_effect=refresh
                    ),
                    patch.object(
                        execution,
                        "_settle_launched_process",
                        side_effect=settle,
                    ) as settle_process,
                    patch.object(
                        custody,
                        "parent_revalidate_after_exec_handoff",
                        side_effect=closure_error,
                    ) as parent_revalidate,
                    self.assertRaises(UnprovenDirectHelperClosure) as caught,
                ):
                    execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=lease,
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertIsInstance(
                    caught.exception,
                    execution.AuthenticatedReviewClosureUnproven,
                )
                self.assertIs(
                    getattr(caught.exception, "source_closure_error"),
                    closure_error,
                )
                self.assertEqual(
                    getattr(caught.exception, "finalization_errors"),
                    (settlement_error,),
                )
                self.assertTrue(
                    any(
                        "synthetic capability settlement failure" in note
                        for note in getattr(caught.exception, "__notes__", ())
                    )
                )
                parent_revalidate.assert_called_once_with(
                    launch.target,
                    process_id=process.pid,
                )
                self.assertEqual(
                    [
                        call.kwargs["pipes_closed"]
                        for call in settle_process.call_args_list
                    ],
                    [False, True],
                )
                self.assertTrue(lease.retained)
                self.assertIn(lease, caught.exception.retained_resources)
                self.assertIn(custody, caught.exception.retained_resources)
                os.fstat(custody.executable_fd)
                self.assertEqual(custody.events, [])
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "auth-refresh"),
                        ("launched", "auth-refresh", process.pid),
                    ],
                )
            finally:
                os.close(fd)

    def test_review_post_launch_revalidation_failure_records_known_closure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(
                    fd,
                    snapshot,
                    fail_parent_revalidation=True,
                )
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="d" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )

                def run_process(**kwargs: object) -> AppServerProcessResult:
                    state = kwargs["process_state"]
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    try:
                        kwargs["on_launch"](process)
                    finally:
                        state.exit_code = 29
                        state.leader_reaped = True
                        state.process_group_empty = True
                        state.pipes_closed = True
                    raise AssertionError("post-launch revalidation should fail")

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ) as authenticate,
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "run_bounded_appserver_process",
                        side_effect=run_process,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "synthetic post-launch revalidation failure",
                    ),
                ):
                    execution._run_review(
                        codex_executable=snapshot,
                        aggregate_schema_path=None,
                        exclusions=Mock(),
                        auth_path=root / "auth.json",
                        auth=Mock(),
                        lease=lease,
                        prompt=b"review",
                        requested_model="gpt-5.6-sol",
                        requested_reasoning_effort="xhigh",
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                schema_work_root = authenticate.call_args.kwargs["schema_work_root"]
                self.assertEqual(schema_work_root, lease.root / "review-schema-work")
                self.assertEqual(schema_work_root.stat().st_mode & 0o777, 0o700)
                self.assertIsNone(
                    authenticate.call_args.kwargs["aggregate_schema_path"]
                )
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "reviewer"),
                        ("launched", "reviewer", process.pid),
                        ("closed", "reviewer", 29),
                    ],
                )
            finally:
                os.close(fd)

    def test_review_lifecycle_return_interrupt_still_closes_and_propagates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="d" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                target_offset = _call_followup_offset(
                    execution._LifecycleLaunchPublication.publish,
                    called_name="launched",
                    following_opname="POP_TOP",
                )
                interruption = KeyboardInterrupt(
                    "injected reviewer lifecycle return interrupt"
                )
                injected = False

                def interrupt_lifecycle_return(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._LifecycleLaunchPublication.publish.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_lifecycle_return

                def run_process(**kwargs: object) -> AppServerProcessResult:
                    state = kwargs["process_state"]
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    try:
                        kwargs["on_launch"](process)
                    finally:
                        state.exit_code = 130
                        state.leader_reaped = True
                        state.process_group_empty = True
                        state.pipes_closed = True
                    raise AssertionError("lifecycle interruption should propagate")

                previous_trace = sys.gettrace()
                try:
                    with (
                        patch.object(
                            execution,
                            "authenticate_codex_executable",
                            return_value=custody,
                        ),
                        patch.object(
                            execution,
                            "_prepare_custodied_launch",
                            return_value=launch,
                        ),
                        patch.object(
                            execution,
                            "run_bounded_appserver_process",
                            side_effect=run_process,
                        ),
                    ):
                        sys.settrace(interrupt_lifecycle_return)
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            execution._run_review(
                                codex_executable=snapshot,
                                aggregate_schema_path=None,
                                exclusions=Mock(),
                                auth_path=root / "auth.json",
                                auth=Mock(),
                                lease=lease,
                                prompt=b"review",
                                requested_model="gpt-5.6-sol",
                                requested_reasoning_effort="xhigh",
                                lifecycle=lifecycle,
                                liveness_checkpoint=lambda: None,
                            )
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(caught.exception, interruption)
                self.assertTrue(injected)
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "reviewer"),
                        ("launched", "reviewer", process.pid),
                        ("closed", "reviewer", 130),
                    ],
                )
                self.assertEqual(custody.events, ["quiescent", "cleanup"])
            finally:
                os.close(fd)

    def test_review_preserves_unproven_closure_when_settlement_also_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="d" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )
                closure_error = UnprovenDirectHelperClosure(
                    "synthetic direct-helper closure gap"
                )
                settlement_error = RuntimeError("synthetic settlement failure")

                def run_process(**kwargs: object) -> AppServerProcessResult:
                    state = kwargs["process_state"]
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    kwargs["on_launch"](process)
                    raise closure_error

                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "run_bounded_appserver_process",
                        side_effect=run_process,
                    ),
                    patch.object(
                        execution,
                        "_settle_launched_process",
                        side_effect=settlement_error,
                    ),
                    patch.object(execution, "revalidate_external_auth_source"),
                    self.assertRaises(UnprovenDirectHelperClosure) as caught,
                ):
                    execution._run_review(
                        codex_executable=snapshot,
                        aggregate_schema_path=None,
                        exclusions=Mock(),
                        auth_path=root / "auth.json",
                        auth=Mock(),
                        lease=lease,
                        prompt=b"review",
                        requested_model="gpt-5.6-sol",
                        requested_reasoning_effort="xhigh",
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertIsInstance(
                    caught.exception,
                    execution.AuthenticatedReviewClosureUnproven,
                )
                self.assertIs(
                    getattr(caught.exception, "source_closure_error"),
                    closure_error,
                )
                self.assertEqual(
                    getattr(caught.exception, "finalization_errors"),
                    (settlement_error,),
                )
                self.assertTrue(
                    any(
                        "synthetic settlement failure" in note
                        for note in getattr(caught.exception, "__notes__", ())
                    )
                )
                self.assertTrue(lease.retained)
                self.assertIn(lease, caught.exception.retained_resources)
                self.assertIn(custody, caught.exception.retained_resources)
                os.fstat(custody.executable_fd)
                self.assertEqual(custody.events, ["parent"])
                self.assertEqual(
                    lifecycle.events,
                    [
                        ("begin", "reviewer"),
                        ("launched", "reviewer", process.pid),
                    ],
                )
            finally:
                os.close(fd)

    def test_review_revalidates_auth_metadata_at_both_send_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            try:
                custody = _Custody(fd, snapshot)
                lifecycle = _Lifecycle()
                lease = _Lease(root / "run")
                process = _launched()
                launch = execution._PreparedCustodiedLaunch(
                    custody=custody,
                    prepared=Mock(),
                    target=Mock(),
                    handoff_token="d" * 64,
                    profile_sha256=process.profile_sha256,
                    writable_roots=execution._HeldWritableRoots((), ()),
                )

                def run_process(**kwargs: object) -> AppServerProcessResult:
                    state = kwargs["process_state"]
                    state.process_id = process.pid
                    state.process_group_id = process.pgid
                    state.profile_sha256 = process.profile_sha256
                    kwargs["on_launch"](process)
                    kwargs["before_external_auth_send"]()
                    state.exit_code = 0
                    state.leader_reaped = True
                    state.process_group_empty = True
                    state.pipes_closed = True
                    return _process()

                auth_path = root / "home" / ".codex" / "auth.json"
                auth = Mock()
                with (
                    patch.object(
                        execution,
                        "authenticate_codex_executable",
                        return_value=custody,
                    ),
                    patch.object(
                        execution,
                        "_prepare_custodied_launch",
                        return_value=launch,
                    ),
                    patch.object(
                        execution,
                        "run_bounded_appserver_process",
                        side_effect=run_process,
                    ),
                    patch.object(
                        execution, "revalidate_external_auth_source"
                    ) as revalidate,
                ):
                    _, _, auth_checks = execution._run_review(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=auth_path,
                        auth=auth,
                        lease=lease,
                        prompt=b"review",
                        requested_model="gpt-5.6-sol",
                        requested_reasoning_effort="xhigh",
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
                    )

                self.assertEqual(
                    auth_checks,
                    {"launch": True, "serialization": True},
                )
                self.assertEqual(revalidate.call_count, 2)
                for call in revalidate.call_args_list:
                    self.assertEqual(call.args, (auth_path, auth))
                    self.assertIs(
                        call.kwargs["filesystem_metadata_verifier"],
                        execution.verify_macos_filesystem_metadata,
                    )
            finally:
                os.close(fd)

    def _assert_exact_unproven_closure_retention(
        self,
        *,
        retained: object,
        custody: _Custody,
        lease: _Lease,
        source: UnprovenDirectHelperClosure,
        interruption: BaseException,
        writable_roots: object | None = None,
        prior_publication_errors: tuple[BaseException, ...] = (),
    ) -> None:
        self.assertIsInstance(
            retained,
            execution.AuthenticatedReviewClosureUnproven,
        )
        typed_retained = retained
        self.assertIs(typed_retained.source_closure_error, source)
        self.assertEqual(
            typed_retained.retention_publication_errors,
            (*prior_publication_errors, interruption),
        )
        self.assertEqual(
            sum(resource is custody for resource in typed_retained.retained_resources),
            1,
        )
        self.assertEqual(
            sum(resource is lease for resource in typed_retained.retained_resources),
            1,
        )
        self.assertEqual(
            sum(
                resource is writable_roots
                for resource in typed_retained.retained_resources
            ),
            int(writable_roots is not None),
        )
        closure_evidence = tuple(
            evidence
            for evidence in typed_retained.recovery_evidence
            if isinstance(
                evidence,
                execution.AuthenticatedReviewClosureRecoveryEvidence,
            )
        )
        self.assertEqual(closure_evidence, (typed_retained.evidence,))
        self.assertTrue(typed_retained.evidence.runtime_lease_retained)
        self.assertTrue(typed_retained.evidence.executable_custody_retained)
        self.assertEqual(
            typed_retained.evidence.writable_root_descriptors_retained,
            writable_roots is not None,
        )
        self.assertFalse(typed_retained.evidence.closure_publication_proven)
        self.assertEqual(
            typed_retained.evidence.protected_property,
            "resource-ownership-and-closure-publication",
        )
        os.fstat(custody.executable_fd)
        lease.cleanup()
        self.assertTrue(lease.cleaned)
        self.assertFalse(lease.deleted)

    def test_unproven_closure_final_delivery_interrupts_return_same_typed_owner(
        self,
    ) -> None:
        target_windows = (
            (
                "finish-publication-call-store",
                _call_followup_offset(
                    execution._retained_unproven_closure,
                    called_name="finish_publication",
                    following_opname="STORE_FAST",
                    following_argval="retained",
                ),
            ),
            (
                "annotation-call-followup",
                _call_followup_offset(
                    execution._retained_unproven_closure,
                    called_name="_annotate_retained_unproven_closure",
                    following_opname="POP_TOP",
                ),
            ),
        )

        for window, target_offset in target_windows:
            with self.subTest(window=window), tempfile.TemporaryDirectory() as raw_root:
                snapshot = pathlib.Path(raw_root) / "codex.snapshot"
                snapshot.write_bytes(b"snapshot")
                descriptor = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
                custody = _Custody(descriptor, snapshot)
                lease = _Lease(pathlib.Path(raw_root) / "runtime")
                state = ProcessCustodyState(process_id=424242)
                source = UnprovenDirectHelperClosure("synthetic closure gap")
                owner = execution._AuthenticatedReviewClosureRetentionOwner(
                    custody=custody,
                    lease=lease,
                    source_error=source,
                )
                prepublished = owner.ensure_error()
                interruption = KeyboardInterrupt(f"injected closure {window} interrupt")
                injected = False

                def interrupt_delivery(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._retained_unproven_closure.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_delivery

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_delivery)
                    retained = execution._retained_unproven_closure(
                        stage="reviewer",
                        custody=custody,
                        lease=lease,
                        state=state,
                        source_error=source,
                        result_owner=owner,
                    )
                finally:
                    sys.settrace(previous_trace)

                try:
                    self.assertTrue(injected)
                    self.assertIs(retained, prepublished)
                    self._assert_exact_unproven_closure_retention(
                        retained=retained,
                        custody=custody,
                        lease=lease,
                        source=source,
                        interruption=interruption,
                    )
                finally:
                    os.close(descriptor)

    def test_unproven_closure_annotation_interrupts_are_idempotent(
        self,
    ) -> None:
        setattr_offsets = _call_followup_offsets(
            execution._annotate_retained_unproven_closure,
            called_name="setattr",
            following_opname="POP_TOP",
        )
        note_offsets = _call_followup_offsets(
            execution._annotate_retained_unproven_closure,
            called_name="_add_note_once",
            following_opname="POP_TOP",
        )
        self.assertEqual(len(setattr_offsets), 3)
        self.assertEqual(len(note_offsets), 3)
        target_windows = tuple(
            (f"{annotation}-setattr", setattr_offsets[index], index)
            for index, annotation in enumerate(("source", "finalization", "diagnostic"))
        ) + tuple(
            (f"{annotation}-note", note_offsets[index], index)
            for index, annotation in enumerate(("source", "finalization", "diagnostic"))
        )

        for window, target_offset, annotation_index in target_windows:
            with self.subTest(window=window), tempfile.TemporaryDirectory() as raw_root:
                snapshot = pathlib.Path(raw_root) / "codex.snapshot"
                snapshot.write_bytes(b"snapshot")
                descriptor = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
                custody = _Custody(descriptor, snapshot)
                lease = _Lease(pathlib.Path(raw_root) / "runtime")
                state = ProcessCustodyState(process_id=424243)
                source = UnprovenDirectHelperClosure("synthetic closure gap")
                owner = execution._AuthenticatedReviewClosureRetentionOwner(
                    custody=custody,
                    lease=lease,
                    source_error=source,
                )
                prepublished = owner.ensure_error()
                finalization_error = RuntimeError("synthetic finalization gap")
                finalization_errors = (
                    (finalization_error,) if annotation_index >= 1 else ()
                )
                prior_publication_errors: tuple[BaseException, ...] = ()
                if annotation_index == 2:
                    prior_error = RuntimeError("synthetic prior publication gap")
                    owner.record_publication_error(prior_error)
                    prior_publication_errors = (prior_error,)
                interruption = KeyboardInterrupt(f"injected closure {window} interrupt")
                injected = False

                def interrupt_annotation(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is execution._annotate_retained_unproven_closure.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_annotation

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_annotation)
                    retained = execution._retained_unproven_closure(
                        stage="auth-refresh",
                        custody=custody,
                        lease=lease,
                        state=state,
                        source_error=source,
                        finalization_errors=finalization_errors,
                        result_owner=owner,
                    )
                finally:
                    sys.settrace(previous_trace)

                try:
                    self.assertTrue(injected)
                    self.assertIs(retained, prepublished)
                    self._assert_exact_unproven_closure_retention(
                        retained=retained,
                        custody=custody,
                        lease=lease,
                        source=source,
                        interruption=interruption,
                        prior_publication_errors=prior_publication_errors,
                    )
                    notes = getattr(retained, "__notes__", ())
                    self.assertEqual(len(notes), len(set(notes)))
                    if finalization_errors:
                        self.assertEqual(
                            retained.finalization_errors,
                            finalization_errors,
                        )
                finally:
                    os.close(descriptor)

    def test_unproven_closure_lease_retain_interrupt_returns_same_typed_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            snapshot = pathlib.Path(raw_root) / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            descriptor = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            custody = _Custody(descriptor, snapshot)
            lease = _Lease(pathlib.Path(raw_root) / "runtime")
            state = ProcessCustodyState(process_id=424244)
            source = UnprovenDirectHelperClosure("synthetic closure gap")
            owner = execution._AuthenticatedReviewClosureRetentionOwner(
                custody=custody,
                lease=lease,
                source_error=source,
            )
            prepublished = owner.ensure_error()
            interruption = KeyboardInterrupt(
                "injected closure lease retain internal interrupt"
            )
            original_retain = lease.retain
            retain_calls = 0

            def interrupt_first_retain() -> None:
                nonlocal retain_calls
                retain_calls += 1
                if retain_calls == 1:
                    raise interruption
                original_retain()

            lease.retain = interrupt_first_retain
            retained = execution._retained_unproven_closure(
                stage="auth-refresh",
                custody=custody,
                lease=lease,
                state=state,
                source_error=source,
                result_owner=owner,
            )

            try:
                self.assertEqual(retain_calls, 2)
                self.assertIs(retained, prepublished)
                self._assert_exact_unproven_closure_retention(
                    retained=retained,
                    custody=custody,
                    lease=lease,
                    source=source,
                    interruption=interruption,
                )
            finally:
                os.close(descriptor)

    def test_unproven_closure_caller_delivery_interrupt_raises_same_typed_owner(
        self,
    ) -> None:
        instructions = tuple(
            dis.get_instructions(execution._raise_retained_unproven_closure)
        )
        retained_instructions = tuple(
            dis.get_instructions(execution._retained_unproven_closure)
        )
        target_windows = (
            (
                "outer-prepublication",
                execution._raise_retained_unproven_closure.__code__,
                _call_followup_offset(
                    execution._raise_retained_unproven_closure,
                    called_name="ensure_error",
                    following_opname="POP_TOP",
                ),
            ),
            (
                "retained-call-store",
                execution._raise_retained_unproven_closure.__code__,
                _call_followup_offset(
                    execution._raise_retained_unproven_closure,
                    called_name="_retained_unproven_closure",
                    following_opname="STORE_FAST",
                    following_argval="retained",
                ),
            ),
            (
                "typed-raise-delivery",
                execution._raise_retained_unproven_closure.__code__,
                tuple(
                    instruction.offset
                    for instruction in instructions
                    if instruction.opname == "RAISE_VARARGS"
                )[1],
            ),
            (
                "callee-return-delivery",
                execution._retained_unproven_closure.__code__,
                next(
                    instruction.offset
                    for instruction in retained_instructions
                    if instruction.opname == "RETURN_VALUE"
                ),
            ),
        )

        for window, target_code, target_offset in target_windows:
            with self.subTest(window=window), tempfile.TemporaryDirectory() as raw_root:
                snapshot = pathlib.Path(raw_root) / "codex.snapshot"
                snapshot.write_bytes(b"snapshot")
                descriptor = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
                custody = _Custody(descriptor, snapshot)
                lease = _Lease(pathlib.Path(raw_root) / "runtime")
                state = ProcessCustodyState(process_id=424245)
                source = UnprovenDirectHelperClosure("synthetic closure gap")
                interruption = KeyboardInterrupt(
                    f"injected closure caller {window} interrupt"
                )
                injected = False
                prepublished: object | None = None

                def interrupt_caller_delivery(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected, prepublished
                    if getattr(frame, "f_code", None) is target_code:
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            prepublished = frame.f_locals["owner"].retained_error
                            raise interruption
                    return interrupt_caller_delivery

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_caller_delivery)
                    with self.assertRaises(
                        execution.AuthenticatedReviewClosureUnproven
                    ) as caught:
                        execution._raise_retained_unproven_closure(
                            stage="reviewer",
                            custody=custody,
                            lease=lease,
                            state=state,
                            source_error=source,
                        )
                finally:
                    sys.settrace(previous_trace)

                try:
                    self.assertTrue(injected)
                    self.assertIs(caught.exception, prepublished)
                    self._assert_exact_unproven_closure_retention(
                        retained=caught.exception,
                        custody=custody,
                        lease=lease,
                        source=source,
                        interruption=interruption,
                    )
                finally:
                    os.close(descriptor)

    def test_unproven_closure_owner_store_interrupt_retains_all_custody(
        self,
    ) -> None:
        target_offset = _call_followup_offset(
            execution._raise_retained_unproven_closure,
            called_name="_AuthenticatedReviewClosureRetentionOwner",
            following_opname="STORE_FAST",
            following_argval="owner",
        )
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            snapshot = root / "codex.snapshot"
            snapshot.write_bytes(b"snapshot")
            executable_fd = os.open(snapshot, os.O_RDONLY | os.O_CLOEXEC)
            writable_root_fd = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            custody = _Custody(executable_fd, snapshot)
            writable_roots = execution._HeldWritableRoots(
                (),
                (writable_root_fd,),
            )
            lease = _Lease(root / "runtime")
            state = ProcessCustodyState(process_id=424246)
            source = UnprovenDirectHelperClosure("synthetic closure gap")
            interruption = KeyboardInterrupt(
                "injected closure retention-owner store interrupt"
            )
            injected = False
            published_owner: (
                execution._AuthenticatedReviewClosureRetentionOwner | None
            ) = None

            def interrupt_owner_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected, published_owner
                if (
                    getattr(frame, "f_code", None)
                    is execution._raise_retained_unproven_closure.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        result_owner = frame.f_locals["owner_result"]
                        published_owner = result_owner.owner
                        raise interruption
                return interrupt_owner_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_owner_store)
                with self.assertRaises(
                    execution.AuthenticatedReviewClosureUnproven
                ) as caught:
                    execution._raise_retained_unproven_closure(
                        stage="reviewer",
                        custody=custody,
                        lease=lease,
                        state=state,
                        source_error=source,
                        writable_roots=writable_roots,
                    )
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIsNotNone(published_owner)
                assert published_owner is not None
                self.assertIs(caught.exception, published_owner.retained_error)
                self._assert_exact_unproven_closure_retention(
                    retained=caught.exception,
                    custody=custody,
                    lease=lease,
                    source=source,
                    interruption=interruption,
                    writable_roots=writable_roots,
                )
                os.fstat(writable_root_fd)
            finally:
                writable_roots.close()
                os.close(executable_fd)

    def test_real_launcher_publication_interrupt_has_one_settlement_owner(
        self,
    ) -> None:
        executable_path = pathlib.Path("/bin/sleep").resolve()
        metadata = os.stat(executable_path, follow_symlinks=False)
        executable = no_child_profile.ExecutableIdentity(
            path=str(executable_path),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
            sha256="a" * 64,
        )
        prepared = no_child_profile.PreparedNoChildProfile(
            executable=executable,
            expected_sha256=executable.sha256,
            seatbelt_profile="(version 1)\n",
            evidence=Mock(),
        )
        publish_discard_offset = _call_followup_offset(
            no_child_profile.launch_prepared_no_child_process,
            called_name="publish",
            following_opname="POP_TOP",
        )
        target_offset = _instruction_after_offset(
            no_child_profile.launch_prepared_no_child_process,
            publish_discard_offset,
        )
        interruption = KeyboardInterrupt(
            "injected real launcher post-publication interrupt"
        )
        injected = False
        published: LaunchedNoChildProcess | None = None
        publication_calls = 0
        state = ProcessCustodyState()
        devnull = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        original_internal_settle = no_child_profile._terminate_and_reap

        def publish(launched: object) -> None:
            nonlocal published, publication_calls
            publication_calls += 1
            typed = launched
            self.assertIsInstance(typed, LaunchedNoChildProcess)
            if published is not None:
                self.assertIs(published, typed)
            published = typed
            execution._record_launch(state, typed)

        def owns(launched: object) -> bool:
            return (
                published is launched
                and published is not None
                and state.process_id == published.pid
                and state.process_group_id == published.pgid
                and state.profile_sha256 == published.profile_sha256
            )

        def interrupt_launcher_return(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if (
                getattr(frame, "f_code", None)
                is no_child_profile.launch_prepared_no_child_process.__code__
            ):
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_launcher_return

        previous_trace = sys.gettrace()
        try:
            with (
                patch.object(no_child_profile, "require_compatible"),
                patch.object(no_child_profile, "_require_live_runtime"),
                patch.object(no_child_profile, "_revalidate_prepared_profile"),
                patch.object(no_child_profile, "prove_exec_budget"),
                patch.object(
                    no_child_profile,
                    "_launch_child",
                    new=_exec_sleep_test_child,
                ),
                patch.object(
                    no_child_profile,
                    "_terminate_and_reap",
                    wraps=original_internal_settle,
                ) as internal_settle,
            ):
                sys.settrace(interrupt_launcher_return)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    codex_executable.launch_no_child_process_with_result_publisher(
                        no_child_profile.launch_prepared_no_child_process,
                        prepared,
                        (str(executable_path), "30"),
                        result_owner=SimpleNamespace(
                            publish=publish,
                            owns=owns,
                        ),
                        cwd="/",
                        environment={},
                        stdin_fd=devnull,
                        stdout_fd=devnull,
                        stderr_fd=devnull,
                    )
            self.assertIs(caught.exception, interruption)
            self.assertTrue(injected)
            self.assertEqual(publication_calls, 1)
            internal_settle.assert_not_called()
            self.assertIsNotNone(published)
            assert published is not None
            os.close(devnull)
            closed_devnull = devnull
            devnull = -1
            with patch.object(
                execution,
                "_terminate_and_reap",
                wraps=execution._terminate_and_reap,
            ) as caller_settle:
                execution._settle_launched_process(
                    state,
                    published,
                    pipes_closed=True,
                )
            caller_settle.assert_called_once_with(published)
            self.assertTrue(state.leader_reaped)
            self.assertTrue(state.process_group_empty)
            self.assertTrue(state.pipes_closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(published.pid, os.WNOHANG)
            with self.assertRaises(OSError) as closed_fd:
                os.fstat(closed_devnull)
            self.assertEqual(closed_fd.exception.errno, errno.EBADF)
        finally:
            sys.settrace(previous_trace)
            if devnull >= 0:
                os.close(devnull)
            if published is not None and not state.leader_reaped:
                try:
                    os.kill(published.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(published.pid, 0)
                except ChildProcessError:
                    pass

    def test_lifecycle_closes_after_proven_review_settlement(self) -> None:
        lifecycle = _Lifecycle()
        process = _launched()
        lifecycle.begin("reviewer")
        lifecycle.launched("reviewer", process)
        state = ProcessCustodyState(
            process_id=process.pid,
            process_group_id=process.pgid,
            leader_reaped=True,
            process_group_empty=True,
            pipes_closed=True,
            exit_code=17,
        )
        custody = Mock()
        lease = _Lease(pathlib.Path("/unused"))
        execution._finalize_custodied_stage(
            stage="reviewer",
            custody=custody,
            writable_roots=None,
            handoff_token="c" * 64,
            state=state,
            launched=process,
            lifecycle=lifecycle,
            lifecycle_launched=True,
            completed=False,
            lease=lease,
        )
        self.assertEqual(
            lifecycle.events,
            [
                ("begin", "reviewer"),
                ("launched", "reviewer", process.pid),
                ("closed", "reviewer", 17),
            ],
        )
        custody.confirm_process_quiescence.assert_called_once()
        custody.cleanup.assert_called_once()

    def test_finalizer_preserves_snapshot_retention_type_and_runtime_lease(
        self,
    ) -> None:
        process = _launched()
        state = ProcessCustodyState(
            process_id=process.pid,
            process_group_id=process.pgid,
            leader_reaped=True,
            process_group_empty=True,
            pipes_closed=True,
            exit_code=17,
        )
        custody = Mock()
        retention = execution.CodexExecutableRetentionRequired(
            "synthetic snapshot retention",
            code="synthetic-snapshot-retention",
        )
        custody.cleanup.side_effect = retention
        lease = _Lease(pathlib.Path("/unused"))

        with self.assertRaises(execution.CodexExecutableRetentionRequired) as caught:
            execution._finalize_custodied_stage(
                stage="reviewer",
                custody=custody,
                writable_roots=None,
                handoff_token="c" * 64,
                state=state,
                launched=process,
                lifecycle=_Lifecycle(),
                lifecycle_launched=False,
                completed=False,
                lease=lease,
            )

        self.assertIs(caught.exception, retention)
        self.assertTrue(lease.retained)
        self.assertIn(lease, retention.retained_resources)

    def test_review_error_does_not_claim_unproven_closure(self) -> None:
        lifecycle = _Lifecycle()
        process = _launched()
        lifecycle.begin("reviewer")
        lifecycle.launched("reviewer", process)
        lease = _Lease(pathlib.Path("/unused"))
        custody = Mock()
        with (
            patch.object(
                execution,
                "_settle_launched_process",
                side_effect=RuntimeError("not settled"),
            ),
            self.assertRaises(execution.AuthenticatedReviewClosureUnproven) as caught,
        ):
            execution._finalize_custodied_stage(
                stage="reviewer",
                custody=custody,
                writable_roots=None,
                handoff_token="d" * 64,
                state=ProcessCustodyState(process_id=process.pid),
                launched=process,
                lifecycle=lifecycle,
                lifecycle_launched=True,
                completed=False,
                lease=lease,
            )
        self.assertFalse(any(event[0] == "closed" for event in lifecycle.events))
        self.assertTrue(lease.retained)
        self.assertIn(lease, caught.exception.retained_resources)
        self.assertIn(custody, caught.exception.retained_resources)

    def test_lifecycle_close_failure_retains_custody_and_writable_roots(
        self,
    ) -> None:
        failures = (
            RuntimeError("synthetic lifecycle publication failure"),
            KeyboardInterrupt("synthetic lifecycle publication interrupt"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                process = _launched()
                lifecycle = Mock()
                lifecycle.closed.side_effect = failure
                custody = Mock()
                lease = _Lease(pathlib.Path("/unused"))
                state = ProcessCustodyState(
                    process_id=process.pid,
                    process_group_id=process.pgid,
                    leader_reaped=True,
                    process_group_empty=True,
                    pipes_closed=True,
                    exit_code=17,
                )
                with tempfile.TemporaryDirectory() as raw_root:
                    writable_root_fd = os.open(
                        raw_root,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                    )
                    writable_roots = execution._HeldWritableRoots(
                        (),
                        (writable_root_fd,),
                    )
                    try:
                        with self.assertRaises(
                            execution.AuthenticatedReviewClosureUnproven
                        ) as caught:
                            execution._finalize_custodied_stage(
                                stage="reviewer",
                                custody=custody,
                                writable_roots=writable_roots,
                                handoff_token="e" * 64,
                                state=state,
                                launched=process,
                                lifecycle=lifecycle,
                                lifecycle_launched=True,
                                completed=False,
                                lease=lease,
                            )

                        self.assertEqual(
                            caught.exception.finalization_errors,
                            (failure,),
                        )
                        self.assertIn(
                            custody,
                            caught.exception.retained_resources,
                        )
                        self.assertIn(
                            lease,
                            caught.exception.retained_resources,
                        )
                        self.assertIn(
                            writable_roots,
                            caught.exception.retained_resources,
                        )
                        self.assertEqual(
                            caught.exception.evidence.protected_property,
                            "resource-ownership-and-closure-publication",
                        )
                        self.assertFalse(
                            caught.exception.evidence.closure_publication_proven
                        )
                        self.assertTrue(
                            caught.exception.evidence.writable_root_descriptors_retained
                        )
                        self.assertIn(
                            "lifecycle closure publication was not proved",
                            caught.exception.evidence.reason,
                        )
                        lifecycle.closed.assert_called_once_with(
                            "reviewer",
                            exit_code=17,
                        )
                        custody.confirm_process_quiescence.assert_not_called()
                        custody.cleanup.assert_not_called()
                        os.fstat(writable_root_fd)
                        lease.cleanup()
                        self.assertFalse(lease.deleted)
                    finally:
                        writable_roots.close()

    def test_unproven_lifecycle_helper_skips_custody_cleanup(self) -> None:
        process = _launched()
        lifecycle = Mock()
        lifecycle.closed.side_effect = UnprovenDirectHelperClosure(
            "synthetic direct-helper closure gap"
        )
        custody = Mock()
        writable_roots = Mock()
        lease = _Lease(pathlib.Path("/unused"))
        state = ProcessCustodyState(
            process_id=process.pid,
            process_group_id=process.pgid,
            leader_reaped=True,
            process_group_empty=True,
            pipes_closed=True,
            exit_code=17,
        )

        with self.assertRaises(execution.AuthenticatedReviewClosureUnproven) as caught:
            execution._finalize_custodied_stage(
                stage="reviewer",
                custody=custody,
                writable_roots=writable_roots,
                handoff_token="e" * 64,
                state=state,
                launched=process,
                lifecycle=lifecycle,
                lifecycle_launched=True,
                completed=False,
                lease=lease,
            )

        self.assertTrue(lease.retained)
        self.assertIn(lease, caught.exception.retained_resources)
        self.assertIn(custody, caught.exception.retained_resources)
        self.assertIn(writable_roots, caught.exception.retained_resources)
        self.assertTrue(caught.exception.evidence.writable_root_descriptors_retained)
        self.assertFalse(caught.exception.evidence.closure_publication_proven)
        writable_roots.close.assert_not_called()
        custody.confirm_process_quiescence.assert_not_called()
        custody.cleanup.assert_not_called()

    def test_settlement_does_not_signal_a_reaped_leader_process_group(self) -> None:
        process = _launched()
        state = ProcessCustodyState(
            leader_reaped=True,
            pipes_closed=True,
            exit_code=0,
        )
        with patch.object(execution.os, "killpg") as kill_group:
            execution._settle_launched_process(
                state,
                process,
                pipes_closed=True,
            )
        kill_group.assert_not_called()
        self.assertTrue(state.process_group_empty)

    def test_settlement_rejects_a_child_reaped_by_another_owner(self) -> None:
        process = _launched()
        state = ProcessCustodyState(pipes_closed=True)
        with (
            patch.object(execution, "_child_terminal_status", return_value="reaped"),
            self.assertRaisesRegex(RuntimeError, "reaped by another owner"),
        ):
            execution._settle_launched_process(
                state,
                process,
                pipes_closed=True,
            )
        self.assertFalse(state.process_group_empty)

    def test_retained_evidence_redacts_paths_and_raw_prompt(self) -> None:
        checkout = pathlib.Path("/private/checkout-secret")
        auth = pathlib.Path("/Users/reviewer/.codex/auth.json")
        raw_prompt = "RAW-PROMPT-SECRET"
        process = _process(f"{checkout}/file.py {auth} {raw_prompt}")
        retained = execution._sanitize_process_result(
            process,
            sensitive_paths=(checkout, auth),
            sensitive_text=raw_prompt,
        )
        encoded = json.dumps(asdict(retained), sort_keys=True)
        self.assertNotIn(str(checkout), encoded)
        self.assertNotIn(str(auth), encoded)
        self.assertNotIn(raw_prompt, encoded)
        self.assertNotIn("thread_path", retained.session.attestation)
        self.assertNotIn("runtime_workspace_roots", retained.session.attestation)


if __name__ == "__main__":
    unittest.main()
