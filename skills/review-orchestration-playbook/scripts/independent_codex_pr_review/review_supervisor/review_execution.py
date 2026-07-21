from __future__ import annotations

import fcntl
import hashlib
import os
import pathlib
import pwd
import secrets
import shutil
import signal
import stat
import sys
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Protocol

from .appserver_protocol import (
    APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
    AppServerSessionConfig,
    AppServerSessionResult,
)
from .auth_carrier import (
    AuthCarrierRefreshRequired,
    ExternalAuthEvidence,
    load_external_auth,
    revalidate_external_auth_source,
)
from .auth_refresh import (
    ManagedAuthRefreshClosureReceipt,
    ManagedAuthRefreshLaunchCapability,
    ManagedAuthRefreshLaunchRequest,
    ManagedAuthRefreshProcess,
    ManagedAuthRefreshResult,
    ManagedAuthSnapshotEvidence,
    ManagedAuthSnapshotIdentity,
    refresh_managed_auth,
)
from .codex_executable import (
    CodexExecutableCustody,
    ExecutableExclusionRoots,
    SnapshotExecTarget,
    SnapshotProtectionEvidence,
    authenticate_codex_executable,
    verify_macos_filesystem_metadata,
)
from .direct_gate import (
    AppServerProcessResult,
    BoundProtectionVerifier,
    ProcessCustodyState,
    _quiescence_evidence,
    _verify_quiescence,
    _verify_snapshot_mutation_denials,
    run_bounded_appserver_process,
)
from .no_child_profile import (
    LaunchedNoChildProcess,
    PreparedNoChildProfile,
    WritableRootAttestation,
    attest_writable_root,
    launch_prepared_no_child_process,
    prepare_custodied_snapshot_no_child_profile,
)


_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_APP_SERVER_ARGUMENTS = (
    "app-server",
    "--session-source",
    "exec",
    "--strict-config",
    *APP_SERVER_NO_EXECUTION_CONFIG_ARGS,
    "--stdio",
)
_PROCESS_CLEANUP_SECONDS = 5.0
_PROCESS_TERM_GRACE_SECONDS = 0.25


class ProcessLifecycle(Protocol):
    def begin(self, stage: str) -> None: ...

    def launched(self, stage: str, process: LaunchedNoChildProcess) -> None: ...

    def closed(self, stage: str, exit_code: int) -> None: ...


@dataclass(frozen=True, slots=True)
class AuthenticatedReviewResult:
    process: AppServerProcessResult
    auth: dict[str, Any]
    auth_refresh: dict[str, Any]
    observed_runtime: dict[str, Any]


@dataclass(slots=True)
class _RuntimeLease:
    container: pathlib.Path
    container_fd: int
    container_identity: tuple[int, int, int, int, int]
    root: pathlib.Path
    root_fd: int
    identity: tuple[int, int, int, int, int]
    retained: bool = False

    def make_directory(self, name: str) -> pathlib.Path:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError("runtime child name is invalid")
        path = self.root / name
        os.mkdir(path, 0o700)
        _require_owner_only_directory(path, label="runtime child")
        _require_empty_directory(path, label="runtime child")
        return path

    def retain(self) -> None:
        self.retained = True

    def cleanup(self) -> None:
        try:
            if self.retained:
                return
            descriptor = os.fstat(self.root_fd)
            current = os.lstat(self.root)
            container_descriptor = os.fstat(self.container_fd)
            container_current = os.lstat(self.container)
            if (
                _directory_identity(descriptor) != self.identity
                or _directory_identity(current) != self.identity
                or _directory_identity(container_descriptor) != self.container_identity
                or _directory_identity(container_current) != self.container_identity
            ):
                self.retained = True
                raise RuntimeError(
                    "fresh runtime identity changed; suspicious content was retained"
                )
            shutil.rmtree(self.root)
            _require_empty_directory(self.container, label="runtime root")
            os.rmdir(self.container)
        except BaseException:
            self.retained = True
            raise
        finally:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            try:
                os.close(self.container_fd)
            except OSError:
                pass


@dataclass(slots=True)
class _HeldWritableRoots:
    attestations: tuple[WritableRootAttestation, ...]
    descriptors: tuple[int, ...]

    def close(self) -> None:
        for descriptor in self.descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(slots=True)
class _PreparedCustodiedLaunch:
    custody: CodexExecutableCustody
    prepared: PreparedNoChildProfile
    target: SnapshotExecTarget
    handoff_token: str
    profile_sha256: str
    writable_roots: _HeldWritableRoots


class _RefreshLaunchCapability(ManagedAuthRefreshLaunchCapability):
    def __init__(
        self,
        *,
        launch: _PreparedCustodiedLaunch,
        lifecycle: ProcessLifecycle,
        expected_cwd: pathlib.Path,
        expected_environment: dict[str, str],
    ) -> None:
        descriptor = os.fstat(launch.custody.executable_fd)
        self._authenticated_snapshot = ManagedAuthSnapshotEvidence(
            sha256=launch.custody.evidence.sha256,
            identity=ManagedAuthSnapshotIdentity.from_stat(descriptor),
        )
        self._launch = launch
        self._lifecycle = lifecycle
        self._expected_cwd = expected_cwd
        self._expected_environment = dict(expected_environment)
        self.process_state = ProcessCustodyState()
        self.launched_process: LaunchedNoChildProcess | None = None
        self.lifecycle_launched = False
        self.closure_receipt: ManagedAuthRefreshClosureReceipt | None = None
        self._consumed = False

    @property
    def authenticated_snapshot(self) -> ManagedAuthSnapshotEvidence:
        return self._authenticated_snapshot

    @property
    def profile_sha256(self) -> str:
        return self._launch.profile_sha256

    def launch(
        self,
        request: ManagedAuthRefreshLaunchRequest,
    ) -> ManagedAuthRefreshProcess:
        if self._consumed:
            raise RuntimeError("managed-auth launch capability is one-shot")
        self._consumed = True
        if (
            request.expected_snapshot != self.authenticated_snapshot
            or request.expected_profile_sha256 != self.profile_sha256
            or request.arguments != _APP_SERVER_ARGUMENTS
            or request.cwd != self._expected_cwd
            or dict(request.environment) != self._expected_environment
            or time.monotonic() >= request.deadline_monotonic
        ):
            raise RuntimeError("managed-auth launch request is not capability-bound")

        launched: LaunchedNoChildProcess | None = None
        try:
            launched = launch_prepared_no_child_process(
                self._launch.prepared,
                (str(self._launch.custody.snapshot_path), *request.arguments),
                cwd=request.cwd,
                environment=request.environment,
                stdin_fd=request.stdin_fd,
                stdout_fd=request.stdout_fd,
                stderr_fd=request.stderr_fd,
            )
            self.launched_process = launched
            _record_launch(self.process_state, launched)
            self._lifecycle.launched("auth-refresh", launched)
            self.lifecycle_launched = True
            self._launch.custody.parent_revalidate_after_exec_handoff(
                self._launch.target,
                process_id=launched.pid,
            )
            if time.monotonic() >= request.deadline_monotonic:
                raise TimeoutError("managed-auth secure launch exceeded its deadline")
            return ManagedAuthRefreshProcess(
                pid=launched.pid,
                process_group_id=launched.pgid,
                session_id=launched.session_id,
                snapshot=self.authenticated_snapshot,
                profile_sha256=launched.profile_sha256,
            )
        except BaseException:
            if launched is not None:
                _settle_launched_process(
                    self.process_state,
                    launched,
                    pipes_closed=False,
                )
            raise

    def record_closure(
        self,
        receipt: ManagedAuthRefreshClosureReceipt,
    ) -> None:
        launched = self.launched_process
        if (
            launched is None
            or receipt.pid != launched.pid
            or receipt.process_group_id != launched.pgid
            or receipt.session_id != launched.session_id
            or receipt.profile_sha256 != launched.profile_sha256
            or type(receipt.exit_code) is not int
            or receipt.leader_reaped is not True
            or receipt.process_group_empty is not True
            or receipt.stdio_closed is not True
        ):
            raise RuntimeError("managed-auth closure receipt is not launch-bound")
        if self.closure_receipt is not None and self.closure_receipt != receipt:
            raise RuntimeError("managed-auth closure receipt changed")
        self.closure_receipt = receipt
        self.process_state.exit_code = receipt.exit_code
        self.process_state.leader_reaped = receipt.leader_reaped
        self.process_state.process_group_empty = receipt.process_group_empty
        self.process_state.pipes_closed = receipt.stdio_closed


def run_authenticated_review(
    *,
    codex_executable: pathlib.Path,
    runtime_root: pathlib.Path,
    repo: pathlib.Path,
    helper_root: pathlib.Path,
    retention_root: pathlib.Path,
    checkout_root: pathlib.Path,
    prompt: bytes,
    requested_model: str,
    requested_reasoning_effort: str,
    lifecycle: ProcessLifecycle,
    aggregate_schema_path: pathlib.Path | None = None,
    auth_path: pathlib.Path | None = None,
    liveness_checkpoint: Callable[[], None] = lambda: None,
) -> AuthenticatedReviewResult:
    _require_python_313()
    input_paths = {
        "codex_executable": codex_executable,
        "runtime_root": runtime_root,
        "repo": repo,
        "helper_root": helper_root,
        "retention_root": retention_root,
        "checkout_root": checkout_root,
    }
    if aggregate_schema_path is not None:
        input_paths["aggregate_schema_path"] = aggregate_schema_path
    paths = _validated_inputs(**input_paths)
    if not isinstance(prompt, bytes):
        raise TypeError("review prompt must be bytes")
    if not prompt:
        raise ValueError("review prompt must not be empty")
    if not isinstance(requested_model, str) or not requested_model:
        raise ValueError("requested model is invalid")
    if (
        not isinstance(requested_reasoning_effort, str)
        or not requested_reasoning_effort
    ):
        raise ValueError("requested reasoning effort is invalid")
    _validate_lifecycle(lifecycle)
    liveness_checkpoint()

    selected_auth_path = _validated_auth_path(
        _default_auth_path() if auth_path is None else auth_path
    )
    lease = _allocate_runtime_lease(paths["runtime_root"])
    refresh_evidence: dict[str, Any] = {"status": "not-required"}
    try:
        try:
            auth = load_external_auth(
                selected_auth_path,
                filesystem_metadata_verifier=verify_macos_filesystem_metadata,
            )
        except AuthCarrierRefreshRequired:
            refresh = _run_auth_refresh(
                codex_executable=paths["codex_executable"],
                aggregate_schema_path=paths.get("aggregate_schema_path"),
                exclusions=_exclusion_roots(paths),
                auth_path=selected_auth_path,
                lease=lease,
                lifecycle=lifecycle,
                liveness_checkpoint=liveness_checkpoint,
            )
            refresh_evidence = {
                "status": "completed",
                "managed_auth_verified": refresh.managed_auth_verified,
                "codex_home_verified": refresh.codex_home_verified,
                "requires_openai_auth": refresh.requires_openai_auth,
                "process_closure": _refresh_closure_evidence(refresh.process_closure),
            }
            auth = load_external_auth(
                selected_auth_path,
                filesystem_metadata_verifier=verify_macos_filesystem_metadata,
            )
        revalidate_external_auth_source(
            selected_auth_path,
            auth,
            filesystem_metadata_verifier=verify_macos_filesystem_metadata,
        )
        liveness_checkpoint()

        process, state, auth_checks = _run_review(
            codex_executable=paths["codex_executable"],
            aggregate_schema_path=paths.get("aggregate_schema_path"),
            exclusions=_exclusion_roots(paths),
            auth_path=selected_auth_path,
            auth=auth,
            lease=lease,
            prompt=prompt,
            requested_model=requested_model,
            requested_reasoning_effort=requested_reasoning_effort,
            lifecycle=lifecycle,
            liveness_checkpoint=liveness_checkpoint,
        )
        retained_process = _sanitize_process_result(
            process,
            sensitive_paths=(
                *paths.values(),
                selected_auth_path,
                selected_auth_path.parent,
                lease.root,
            ),
            sensitive_text=_decoded_prompt(prompt),
        )
        observed_runtime = _observed_runtime(
            retained_process,
            state=state,
        )
        return AuthenticatedReviewResult(
            process=retained_process,
            auth={
                "auth_mode": "external-chatgpt",
                "carrier_generation_verified": True,
                "source_revalidated_before_launch": auth_checks["launch"],
                "source_revalidated_before_login_serialization": auth_checks[
                    "serialization"
                ],
            },
            auth_refresh=refresh_evidence,
            observed_runtime=observed_runtime,
        )
    finally:
        lease.cleanup()


def _run_auth_refresh(
    *,
    codex_executable: pathlib.Path,
    aggregate_schema_path: pathlib.Path | None,
    exclusions: ExecutableExclusionRoots,
    auth_path: pathlib.Path,
    lease: _RuntimeLease,
    lifecycle: ProcessLifecycle,
    liveness_checkpoint: Callable[[], None],
) -> ManagedAuthRefreshResult:
    snapshot_parent = lease.make_directory("auth-refresh-snapshots")
    neutral_cwd = lease.make_directory("auth-refresh-cwd")
    temp_dir = lease.make_directory("auth-refresh-tmp")
    auth_home = auth_path.parent
    environment = _refresh_environment(
        auth_home=auth_home,
        account_home=auth_home.parent,
        temp_dir=temp_dir,
    )
    verifier = BoundProtectionVerifier()
    custody: CodexExecutableCustody | None = None
    launch: _PreparedCustodiedLaunch | None = None
    capability: _RefreshLaunchCapability | None = None
    completed = False
    schema_work_root = (
        lease.make_directory("auth-refresh-schema-work")
        if aggregate_schema_path is None
        else None
    )
    try:
        liveness_checkpoint()
        custody = authenticate_codex_executable(
            codex_executable,
            snapshot_parent=snapshot_parent,
            exclusion_roots=exclusions,
            aggregate_schema_path=aggregate_schema_path,
            schema_work_root=schema_work_root,
            snapshot_protection_verifier=verifier,
            quiescence_verifier=_verify_quiescence,
        )
        liveness_checkpoint()
        launch = _prepare_custodied_launch(
            custody=custody,
            verifier=verifier,
            writable_paths=(auth_home, temp_dir),
            liveness_checkpoint=liveness_checkpoint,
        )
        liveness_checkpoint()
        capability = _RefreshLaunchCapability(
            launch=launch,
            lifecycle=lifecycle,
            expected_cwd=neutral_cwd,
            expected_environment=environment,
        )
        lifecycle.begin("auth-refresh")
        liveness_checkpoint()
        result = refresh_managed_auth(
            launch_capability=capability,
            expected_snapshot=capability.authenticated_snapshot,
            expected_profile_sha256=capability.profile_sha256,
            neutral_cwd=neutral_cwd,
            environment=environment,
            expected_codex_home=auth_home,
            liveness_checkpoint=liveness_checkpoint,
        )
        liveness_checkpoint()
        if (
            not isinstance(result, ManagedAuthRefreshResult)
            or not result.refresh_completed
            or not result.managed_auth_verified
            or not result.codex_home_verified
            or result.process_closure is None
            or capability.closure_receipt != result.process_closure
            or result.process_closure.exit_code != 0
        ):
            raise RuntimeError("managed-auth refresh returned incomplete evidence")
        completed = True
        return result
    finally:
        if capability is not None:
            capability.process_state.pipes_closed = True
        state = (
            capability.process_state
            if capability is not None
            else ProcessCustodyState()
        )
        if capability is None:
            state.pipes_closed = True
        launched = capability.launched_process if capability is not None else None
        lifecycle_launched = (
            capability.lifecycle_launched if capability is not None else False
        )
        _finalize_custodied_stage(
            stage="auth-refresh",
            custody=custody,
            writable_roots=launch.writable_roots if launch is not None else None,
            handoff_token=launch.handoff_token if launch is not None else None,
            state=state,
            launched=launched,
            lifecycle=lifecycle,
            lifecycle_launched=lifecycle_launched,
            completed=completed,
            lease=lease,
        )


def _run_review(
    *,
    codex_executable: pathlib.Path,
    aggregate_schema_path: pathlib.Path | None,
    exclusions: ExecutableExclusionRoots,
    auth_path: pathlib.Path,
    auth: ExternalAuthEvidence,
    lease: _RuntimeLease,
    prompt: bytes,
    requested_model: str,
    requested_reasoning_effort: str,
    lifecycle: ProcessLifecycle,
    liveness_checkpoint: Callable[[], None],
) -> tuple[AppServerProcessResult, ProcessCustodyState, dict[str, bool]]:
    snapshot_parent = lease.make_directory("review-snapshots")
    codex_home = lease.make_directory("review-home")
    neutral_cwd = lease.make_directory("review-cwd")
    temp_dir = lease.make_directory("review-tmp")
    environment = _isolated_environment(codex_home=codex_home, temp_dir=temp_dir)
    verifier = BoundProtectionVerifier()
    custody: CodexExecutableCustody | None = None
    launch: _PreparedCustodiedLaunch | None = None
    launched: LaunchedNoChildProcess | None = None
    state = ProcessCustodyState()
    lifecycle_launched = False
    completed = False
    result: AppServerProcessResult | None = None
    process_boundary_entered = False
    auth_checks = {"launch": False, "serialization": False}
    schema_work_root = (
        lease.make_directory("review-schema-work")
        if aggregate_schema_path is None
        else None
    )
    try:
        liveness_checkpoint()
        custody = authenticate_codex_executable(
            codex_executable,
            snapshot_parent=snapshot_parent,
            exclusion_roots=exclusions,
            aggregate_schema_path=aggregate_schema_path,
            schema_work_root=schema_work_root,
            snapshot_protection_verifier=verifier,
            quiescence_verifier=_verify_quiescence,
        )
        liveness_checkpoint()
        launch = _prepare_custodied_launch(
            custody=custody,
            verifier=verifier,
            writable_paths=(codex_home, temp_dir),
            liveness_checkpoint=liveness_checkpoint,
        )
        liveness_checkpoint()
        config = AppServerSessionConfig(
            neutral_cwd=str(neutral_cwd),
            expected_codex_home=str(codex_home),
            expected_model=requested_model,
            expected_reasoning_effort=requested_reasoning_effort,
            external_auth=auth.auth,
        )

        def on_launch(process: LaunchedNoChildProcess) -> None:
            nonlocal launched, lifecycle_launched
            launched = process
            lifecycle.launched("reviewer", process)
            lifecycle_launched = True
            launch.custody.parent_revalidate_after_exec_handoff(
                launch.target,
                process_id=process.pid,
            )
            revalidate_external_auth_source(
                auth_path,
                auth,
                filesystem_metadata_verifier=verify_macos_filesystem_metadata,
            )
            auth_checks["launch"] = True

        def before_external_auth_send() -> None:
            revalidate_external_auth_source(
                auth_path,
                auth,
                filesystem_metadata_verifier=verify_macos_filesystem_metadata,
            )
            auth_checks["serialization"] = True

        lifecycle.begin("reviewer")
        process_boundary_entered = True
        result = run_bounded_appserver_process(
            prepared=launch.prepared,
            argv=(str(custody.snapshot_path), *_APP_SERVER_ARGUMENTS),
            cwd=neutral_cwd,
            environment=environment,
            prompt=prompt,
            config=config,
            process_state=state,
            on_launch=on_launch,
            before_external_auth_send=before_external_auth_send,
            liveness_checkpoint=liveness_checkpoint,
        )
        if not all(auth_checks.values()):
            raise RuntimeError(
                "external auth was not revalidated at both serialization boundaries"
            )
        completed = True
        return result, state, auth_checks
    finally:
        if not process_boundary_entered:
            state.pipes_closed = True
        _finalize_custodied_stage(
            stage="reviewer",
            custody=custody,
            writable_roots=launch.writable_roots if launch is not None else None,
            handoff_token=launch.handoff_token if launch is not None else None,
            state=state,
            launched=launched,
            lifecycle=lifecycle,
            lifecycle_launched=lifecycle_launched,
            completed=completed,
            lease=lease,
        )


def _prepare_custodied_launch(
    *,
    custody: CodexExecutableCustody,
    verifier: BoundProtectionVerifier,
    writable_paths: tuple[pathlib.Path, pathlib.Path],
    liveness_checkpoint: Callable[[], None],
) -> _PreparedCustodiedLaunch:
    liveness_checkpoint()
    attestation = custody.attest_owner_snapshot_launch()
    liveness_checkpoint()
    writable_roots = _attest_writable_roots(writable_paths)
    try:
        liveness_checkpoint()
        prepared = prepare_custodied_snapshot_no_child_profile(
            attestation,
            writable_roots=writable_roots.attestations,
        )
        liveness_checkpoint()
        profile_sha256 = hashlib.sha256(
            prepared.seatbelt_profile.encode("utf-8", "strict")
        ).hexdigest()
        verifier.bind(
            policy_sha256=custody.seatbelt_policy.sha256,
            profile_sha256=profile_sha256,
        )
        _verify_snapshot_mutation_denials(
            policy=custody.seatbelt_policy,
            snapshot_path=custody.snapshot_path,
        )
        liveness_checkpoint()
        handoff = custody.pre_fork_revalidate()
        liveness_checkpoint()
        target = custody.child_revalidate_immediately_before_exec(
            handoff,
            protection=SnapshotProtectionEvidence(
                snapshot_directory=custody.seatbelt_policy.snapshot_directory,
                snapshot_policy_sha256=custody.seatbelt_policy.sha256,
                effective_profile_sha256=profile_sha256,
                kernel="macos-seatbelt",
                no_child_profile_verified=True,
                applied_before_snapshot_exec=True,
                denied_operations=custody.seatbelt_policy.required_denials,
                self_mutation_probe_denied=True,
            ),
        )
        liveness_checkpoint()
        return _PreparedCustodiedLaunch(
            custody=custody,
            prepared=prepared,
            target=target,
            handoff_token=handoff.token,
            profile_sha256=profile_sha256,
            writable_roots=writable_roots,
        )
    except BaseException:
        writable_roots.close()
        raise


def _finalize_custodied_stage(
    *,
    stage: str,
    custody: CodexExecutableCustody | None,
    writable_roots: _HeldWritableRoots | None,
    handoff_token: str | None,
    state: ProcessCustodyState,
    launched: LaunchedNoChildProcess | None,
    lifecycle: ProcessLifecycle,
    lifecycle_launched: bool,
    completed: bool,
    lease: _RuntimeLease,
) -> None:
    errors: list[BaseException] = []
    try:
        _settle_launched_process(
            state,
            launched,
            pipes_closed=state.pipes_closed,
        )
    except BaseException as error:
        lease.retain()
        errors.append(error)

    closure_proven = _closure_proven(state)
    if lifecycle_launched and closure_proven and state.exit_code is not None:
        try:
            lifecycle.closed(stage, exit_code=state.exit_code)
        except BaseException as error:
            errors.append(error)

    if custody is not None:
        if closure_proven:
            try:
                quiescence = _quiescence_evidence(
                    handoff_token=handoff_token,
                    state=state,
                    reason=(
                        "bounded-appserver-session-complete"
                        if completed
                        else "bounded-appserver-session-aborted"
                    ),
                )
                custody.confirm_process_quiescence(quiescence)
                custody.cleanup()
            except BaseException as error:
                lease.retain()
                errors.append(error)
        else:
            lease.retain()
            errors.append(
                RuntimeError("process closure is inconclusive; runtime was retained")
            )
    if writable_roots is not None:
        writable_roots.close()
    if errors:
        raise RuntimeError(
            "custodied process finalization was inconclusive"
        ) from errors[0]


def _settle_launched_process(
    state: ProcessCustodyState,
    launched: LaunchedNoChildProcess | None,
    *,
    pipes_closed: bool,
) -> None:
    state.pipes_closed = pipes_closed
    if launched is None:
        if state.process_id is None:
            state.leader_reaped = True
            state.process_group_empty = True
        if not _closure_proven(state):
            raise RuntimeError("never-launched process boundary is not closed")
        return

    _record_launch(state, launched)
    if not state.leader_reaped:
        status = _child_terminal_status(launched.pid)
        if status == "reaped":
            raise RuntimeError("launched process was reaped by another owner")
        elif status is None:
            state.exit_code = _terminate_and_reap(launched)
            state.leader_reaped = True
        else:
            state.exit_code = _reap_child(launched.pid)
            state.leader_reaped = True
    if state.exit_code is None:
        raise RuntimeError("reaped process has no owner-observed exit status")
    # The authenticated Seatbelt profile prevents descendants. Once the
    # custodian reaps the anchored leader, its process group is therefore empty;
    # probing or signaling the old PGID would race PID/PGID reuse.
    state.process_group_empty = True
    if not _closure_proven(state):
        raise RuntimeError("launched process boundary is not proven closed")


def _terminate_and_reap(process: LaunchedNoChildProcess) -> int:
    try:
        if (
            os.getpgid(process.pid) != process.pgid
            or os.getsid(process.pid) != process.session_id
        ):
            raise RuntimeError(
                "launched process identity no longer matches its receipt"
            )
    except ProcessLookupError:
        status = _child_terminal_status(process.pid)
        if status == "reaped":
            raise RuntimeError("launched process was reaped without an exit status")

    deadline = time.monotonic() + _PROCESS_CLEANUP_SECONDS
    try:
        os.killpg(process.pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    grace = min(deadline, time.monotonic() + _PROCESS_TERM_GRACE_SECONDS)
    while time.monotonic() < grace:
        status = _child_terminal_status(process.pid)
        if status is not None:
            break
        time.sleep(0.01)
    if _child_terminal_status(process.pid) is None:
        try:
            os.killpg(process.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    while time.monotonic() < deadline:
        status = _child_terminal_status(process.pid)
        if status == "reaped":
            raise RuntimeError("launched process was reaped by another owner")
        if status is not None:
            return _reap_child(process.pid)
        time.sleep(0.01)
    raise RuntimeError("launched process could not be terminated within its bound")


def _child_terminal_status(pid: int) -> int | str | None:
    try:
        value = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return "reaped"
    if value is None:
        return None
    if value.si_code == os.CLD_EXITED:
        return value.si_status
    return 128 + value.si_status


def _reap_child(pid: int) -> int:
    waited, raw_status = os.waitpid(pid, 0)
    if waited != pid:
        raise RuntimeError("launched process returned an unexpected wait result")
    return os.waitstatus_to_exitcode(raw_status)


def _closure_proven(state: ProcessCustodyState) -> bool:
    return bool(
        state.leader_reaped and state.process_group_empty and state.pipes_closed
    )


def _record_launch(
    state: ProcessCustodyState,
    launched: LaunchedNoChildProcess,
) -> None:
    if state.process_id is not None and state.process_id != launched.pid:
        raise RuntimeError("process custody state was rebound to another leader")
    state.process_id = launched.pid
    state.process_group_id = launched.pgid
    state.profile_sha256 = launched.profile_sha256


def _attest_writable_roots(
    paths: tuple[pathlib.Path, pathlib.Path],
) -> _HeldWritableRoots:
    descriptors: list[int] = []
    attestations: list[WritableRootAttestation] = []
    try:
        for path in paths:
            _require_owner_only_directory(path, label="writable runtime root")
            descriptor = _open_read_only_directory(path)
            descriptors.append(descriptor)
            attestations.append(attest_writable_root(path, directory_fd=descriptor))
        return _HeldWritableRoots(tuple(attestations), tuple(descriptors))
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _open_read_only_directory(path: pathlib.Path) -> int:
    required = ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise RuntimeError("directory capability flags are unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.set_inheritable(descriptor, False)
        observed = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if observed & os.O_ACCMODE != os.O_RDONLY or os.get_inheritable(descriptor):
            raise RuntimeError(
                "writable-root descriptor is not read-only close-on-exec"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validated_inputs(**values: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        label: _canonical_absolute_path(path, label=label.replace("_", " "))
        for label, path in values.items()
    }


def _exclusion_roots(paths: dict[str, pathlib.Path]) -> ExecutableExclusionRoots:
    return ExecutableExclusionRoots(
        repo=paths["repo"],
        helper=paths["helper_root"],
        runtime=paths["runtime_root"],
        retention=paths["retention_root"],
        checkout=paths["checkout_root"],
    )


def _validated_auth_path(path: pathlib.Path) -> pathlib.Path:
    value = _canonical_absolute_path(path, label="auth path")
    if value.name != "auth.json" or value.parent.name != ".codex":
        raise ValueError("auth path must identify a normal .codex/auth.json carrier")
    _require_owner_only_directory(value.parent, label="normal Codex home")
    return value


def _default_auth_path() -> pathlib.Path:
    try:
        home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("current account home cannot be determined") from None
    return _canonical_absolute_path(home, label="account home") / ".codex" / "auth.json"


def _canonical_absolute_path(path: pathlib.Path, *, label: str) -> pathlib.Path:
    if not isinstance(path, pathlib.Path):
        raise TypeError(f"{label} must be pathlib.Path")
    raw = os.fspath(path)
    if (
        not raw.startswith("/")
        or raw.startswith("//")
        or "\x00" in raw
        or raw != os.path.normpath(raw)
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ValueError(f"{label} must be a canonical absolute path")
    return path


def _require_owner_only_directory(path: pathlib.Path, *, label: str) -> None:
    value = _canonical_absolute_path(path, label=label)
    metadata = os.lstat(value)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError(f"{label} must be an exact owner-only directory")


def _require_empty_directory(path: pathlib.Path, *, label: str) -> None:
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise ValueError(f"{label} must be empty")


def _ensure_runtime_root(path: pathlib.Path) -> None:
    value = _canonical_absolute_path(path, label="runtime root")
    value.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_owner_only_directory(value, label="runtime root")


def _allocate_runtime_lease(runtime_root: pathlib.Path) -> _RuntimeLease:
    _ensure_runtime_root(runtime_root)
    _require_empty_directory(runtime_root, label="runtime root")
    container_descriptor = _open_read_only_directory(runtime_root)
    try:
        for _ in range(64):
            root = runtime_root / f"authenticated-review-{secrets.token_hex(16)}"
            try:
                os.mkdir(root, 0o700)
            except FileExistsError:
                continue
            _require_owner_only_directory(root, label="fresh runtime")
            _require_empty_directory(root, label="fresh runtime")
            descriptor = _open_read_only_directory(root)
            return _RuntimeLease(
                container=runtime_root,
                container_fd=container_descriptor,
                container_identity=_directory_identity(os.fstat(container_descriptor)),
                root=root,
                root_fd=descriptor,
                identity=_directory_identity(os.fstat(descriptor)),
            )
    except BaseException:
        os.close(container_descriptor)
        raise
    os.close(container_descriptor)
    raise FileExistsError("cannot allocate a fresh authenticated-review runtime")


def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _refresh_environment(
    *,
    auth_home: pathlib.Path,
    account_home: pathlib.Path,
    temp_dir: pathlib.Path,
) -> dict[str, str]:
    return {
        "CODEX_HOME": str(auth_home),
        "HOME": str(account_home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": _SAFE_PATH,
        "TMPDIR": str(temp_dir) + "/",
    }


def _isolated_environment(
    *,
    codex_home: pathlib.Path,
    temp_dir: pathlib.Path,
) -> dict[str, str]:
    return {
        "CODEX_HOME": str(codex_home),
        "HOME": str(codex_home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": _SAFE_PATH,
        "TMPDIR": str(temp_dir) + "/",
    }


def _sanitize_process_result(
    process: AppServerProcessResult,
    *,
    sensitive_paths: tuple[pathlib.Path, ...],
    sensitive_text: str | None,
) -> AppServerProcessResult:
    attestation = process.session.attestation
    sandbox = attestation.get("sandbox")
    safe_sandbox = (
        {
            "type": sandbox.get("type"),
            "network_access": sandbox.get("networkAccess"),
        }
        if isinstance(sandbox, dict)
        else {}
    )
    runtime_roots = attestation.get("runtime_workspace_roots")
    safe_attestation = {
        "approval_policy": attestation.get("approval_policy"),
        "approvals_reviewer": attestation.get("approvals_reviewer"),
        "cli_version": attestation.get("cli_version"),
        "ephemeral": attestation.get("ephemeral"),
        "external_auth": attestation.get("external_auth"),
        "instruction_source_count": (
            len(attestation.get("instruction_sources", ()))
            if isinstance(attestation.get("instruction_sources"), list)
            else 0
        ),
        "model": attestation.get("model"),
        "model_attempt": attestation.get("model_attempt"),
        "model_provider": attestation.get("model_provider"),
        "reasoning_effort": attestation.get("reasoning_effort"),
        "remote_control": attestation.get("remote_control"),
        "runtime_workspace_root_count": (
            len(runtime_roots) if isinstance(runtime_roots, list) else 0
        ),
        "sandbox": safe_sandbox,
        "session_source": attestation.get("session_source"),
        "thread_path_recorded": attestation.get("thread_path") is not None,
    }
    final_text = process.session.final_text
    for path in sorted(
        {str(path) for path in sensitive_paths},
        key=len,
        reverse=True,
    ):
        final_text = final_text.replace(path, "<redacted-path>")
    if sensitive_text:
        final_text = final_text.replace(sensitive_text, "<redacted-prompt>")
    session = AppServerSessionResult(
        review_status=process.session.review_status,
        final_text=final_text,
        attestation=safe_attestation,
        streamed_message_bytes=process.session.streamed_message_bytes,
    )
    return replace(process, session=session)


def _refresh_closure_evidence(
    receipt: ManagedAuthRefreshClosureReceipt | None,
) -> dict[str, Any]:
    if receipt is None:
        raise RuntimeError("managed-auth refresh has no closure receipt")
    return {
        "pid": receipt.pid,
        "process_group_id": receipt.process_group_id,
        "session_id": receipt.session_id,
        "profile_sha256": receipt.profile_sha256,
        "exit_code": receipt.exit_code,
        "leader_reaped": receipt.leader_reaped,
        "process_group_empty": receipt.process_group_empty,
        "stdio_closed": receipt.stdio_closed,
    }


def _observed_runtime(
    process: AppServerProcessResult,
    *,
    state: ProcessCustodyState,
) -> dict[str, Any]:
    protocol = process.session.attestation
    return {
        "process": {
            "elapsed_seconds": round(process.elapsed_seconds, 3),
            "exit_code": process.exit_code,
            "stderr_bytes": process.stderr_bytes,
            "stdout_bytes": process.stdout_bytes,
            "streamed_message_bytes": process.session.streamed_message_bytes,
        },
        "protocol": {
            "external_auth": protocol.get("external_auth"),
            "ephemeral": protocol.get("ephemeral"),
            "remote_control": protocol.get("remote_control"),
            "runtime_workspace_root_count": protocol.get(
                "runtime_workspace_root_count"
            ),
            "session_source": protocol.get("session_source"),
        },
        "model": {
            "model": protocol.get("model"),
            "model_attempt": protocol.get("model_attempt"),
            "model_provider": protocol.get("model_provider"),
            "reasoning_effort": protocol.get("reasoning_effort"),
        },
        "containment": {
            "leader_reaped": state.leader_reaped,
            "process_group_empty": state.process_group_empty,
            "stdio_handles_closed": state.pipes_closed,
            "snapshot_mutation_denials_verified": True,
            "snapshot_profile_bound": True,
            "writable_root_count": 2,
        },
    }


def _validate_lifecycle(lifecycle: ProcessLifecycle) -> None:
    if any(
        not callable(getattr(lifecycle, name, None))
        for name in ("begin", "launched", "closed")
    ):
        raise TypeError("process lifecycle does not implement the required protocol")


def _decoded_prompt(prompt: bytes) -> str | None:
    try:
        value = prompt.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    return value or None


def _require_python_313() -> None:
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("authenticated review execution requires Python 3.13")


__all__ = [
    "AuthenticatedReviewResult",
    "ProcessLifecycle",
    "run_authenticated_review",
]
