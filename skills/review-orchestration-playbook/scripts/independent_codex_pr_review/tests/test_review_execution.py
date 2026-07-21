from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
import unittest
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import Mock, patch

from review_supervisor.appserver_protocol import (
    AppServerSessionResult,
)
from review_supervisor.auth_refresh import (
    ManagedAuthRefreshClosureReceipt,
    ManagedAuthRefreshLaunchRequest,
    ManagedAuthRefreshResult,
)
from review_supervisor.direct_gate import AppServerProcessResult, ProcessCustodyState
from review_supervisor.no_child_profile import LaunchedNoChildProcess
from review_supervisor import review_execution as execution


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

    def retain(self) -> None:
        self.retained = True

    def make_directory(self, name: str) -> pathlib.Path:
        path = self.root / name
        path.mkdir(parents=True, mode=0o700)
        return path

    def cleanup(self) -> None:
        self.cleaned = True


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
            revalidate.assert_called_once()
            refresh.assert_not_called()
            self.assertEqual(result.auth_refresh, {"status": "not-required"})
            self.assertTrue(lease.cleaned)

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
                    ),
                    patch.object(execution, "_prepare_custodied_launch") as prepare,
                    self.assertRaisesRegex(RuntimeError, "synthetic outer EOF"),
                ):
                    execution._run_auth_refresh(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "home" / ".codex" / "auth.json",
                        lease=_Lease(root / "run"),
                        lifecycle=lifecycle,
                        liveness_checkpoint=require_outer,
                    )

                prepare.assert_not_called()
                self.assertEqual(lifecycle.events, [])
                self.assertEqual(custody.events, ["quiescent", "cleanup"])
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
                    "launch_prepared_no_child_process",
                    return_value=process,
                ) as launcher:
                    receipt = capability.launch(request)
                self.assertEqual(receipt.snapshot, capability.authenticated_snapshot)
                self.assertEqual(receipt.profile_sha256, capability.profile_sha256)
                self.assertEqual(custody.events, ["parent"])
                self.assertEqual(
                    lifecycle.events, [("launched", "auth-refresh", process.pid)]
                )
                argv = launcher.call_args.args[1]
                self.assertEqual(argv[0], str(snapshot))
                self.assertEqual(argv[1:], execution._APP_SERVER_ARGUMENTS)
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
                        "launch_prepared_no_child_process",
                        return_value=process,
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
                        "launch_prepared_no_child_process",
                        return_value=process,
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
                    self.assertRaisesRegex(
                        RuntimeError,
                        "synthetic post-launch revalidation failure",
                    ),
                ):
                    execution._run_review(
                        codex_executable=snapshot,
                        aggregate_schema_path=root / "schema.json",
                        exclusions=Mock(),
                        auth_path=root / "auth.json",
                        auth=Mock(),
                        lease=_Lease(root / "run"),
                        prompt=b"review",
                        requested_model="gpt-5.6-sol",
                        requested_reasoning_effort="xhigh",
                        lifecycle=lifecycle,
                        liveness_checkpoint=lambda: None,
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

    def test_review_error_does_not_claim_unproven_closure(self) -> None:
        lifecycle = _Lifecycle()
        process = _launched()
        lifecycle.begin("reviewer")
        lifecycle.launched("reviewer", process)
        lease = _Lease(pathlib.Path("/unused"))
        with (
            patch.object(
                execution,
                "_settle_launched_process",
                side_effect=RuntimeError("not settled"),
            ),
            self.assertRaisesRegex(RuntimeError, "finalization was inconclusive"),
        ):
            execution._finalize_custodied_stage(
                stage="reviewer",
                custody=Mock(),
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
