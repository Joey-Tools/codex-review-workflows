from __future__ import annotations

import fcntl
import hashlib
import os
import pathlib
import pwd
import secrets
import signal
import sys
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Protocol, cast

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
    CodexExecutableRetentionRequired,
    ExecutableExclusionRoots,
    SnapshotExecTarget,
    SnapshotProtectionEvidence,
    authenticate_codex_executable,
    launch_no_child_process_with_result_publisher,
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
from .errors import UnprovenDirectHelperClosure
from .models import Identity
from .no_child_profile import (
    LaunchedNoChildProcess,
    PreparedNoChildProfile,
    WritableRootAttestation,
    attest_writable_root,
    launch_prepared_no_child_process,
    prepare_custodied_snapshot_no_child_profile,
)
from .secureio import (
    directory_identities_match,
    identity_from_stat,
    open_absolute_directory_chain,
    validate_private_directory_fd,
)
from .recovery_cleanup import (
    CustodiedDeletionResultOwner,
    CustodiedManifestResultOwner,
    QuarantinedRootRecoveryEvidence,
    RootSpec,
    build_custodied_manifest,
    delete_custodied_roots,
    quarantine_and_remove_empty_root,
    quarantined_root_recovery_evidence,
    remove_published_manifest,
)


_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_RUNTIME_LEASE_PREFIX = "authenticated-review-"
_RUNTIME_LEASE_TOKEN_BYTES = 16
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
_RUNTIME_CLEANUP_SECONDS = 30.0
_RUNTIME_CLEANUP_ENTRY_CAP = 100_000
_RUNTIME_CLEANUP_MANIFEST_BYTES = 16 * 1024 * 1024


class ProcessLifecycle(Protocol):
    def begin(self, stage: str) -> None: ...

    def launched(self, stage: str, process: LaunchedNoChildProcess) -> None: ...

    def closed(self, stage: str, exit_code: int) -> None: ...


@dataclass(slots=True)
class _LifecycleLaunchPublication:
    lifecycle: ProcessLifecycle
    stage: str
    process: LaunchedNoChildProcess | None = None

    def publish(self, process: LaunchedNoChildProcess) -> None:
        if self.process is process:
            return
        if self.process is not None:
            raise ValueError("lifecycle launch publication was rebound")
        # Publish the close obligation before the durable lifecycle call. If the
        # call returns and delivery is interrupted, the finalizer must still close
        # that exact process. A failure before durable publication is conservative:
        # closed() will fail rather than silently leaving a possible launch open.
        self.process = process
        self.lifecycle.launched(self.stage, process)

    @property
    def close_required(self) -> bool:
        return self.process is not None


@dataclass(frozen=True, slots=True)
class AuthenticatedReviewResult:
    process: AppServerProcessResult
    auth: dict[str, Any]
    auth_refresh: dict[str, Any]
    observed_runtime: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _RuntimeRecoveryEvidence:
    stage: str
    parent_path: str
    entry_name: str
    parent_fd: int
    directory_fd: int | None
    parent_identity: Identity
    directory_identity: Identity | None
    reason: str
    protected_property: str = "object-identity-and-access-policy"


@dataclass(frozen=True, slots=True)
class AuthenticatedReviewClosureRecoveryEvidence:
    stage: str
    protected_property: str
    process_id: int | None
    process_group_id: int | None
    profile_sha256: str | None
    leader_reaped: bool
    process_group_empty: bool
    pipes_closed: bool
    executable_custody_retained: bool
    runtime_lease_retained: bool
    writable_root_descriptors_retained: bool
    closure_publication_proven: bool
    reason: str


class AuthenticatedReviewClosureUnproven(
    CodexExecutableRetentionRequired,
    UnprovenDirectHelperClosure,
):
    def __init__(
        self,
        message: str,
        *,
        evidence: AuthenticatedReviewClosureRecoveryEvidence | None,
        result_owner: _AuthenticatedReviewClosureRetentionOwner | None = None,
    ) -> None:
        self.evidence = evidence
        super().__init__(
            message,
            code="authenticated-review-process-closure-unproven",
        )
        if result_owner is not None:
            result_owner.publish_error(self)


@dataclass(slots=True)
class _AuthenticatedReviewClosureRetentionResultOwner:
    owner: _AuthenticatedReviewClosureRetentionOwner | None = None

    def publish(self, owner: _AuthenticatedReviewClosureRetentionOwner) -> None:
        if self.owner is not None and self.owner is not owner:
            raise ValueError("closure retention owner was published more than once")
        self.owner = owner


@dataclass(slots=True)
class _AuthenticatedReviewClosureRetentionOwner:
    custody: CodexExecutableCustody | None
    lease: _RuntimeLease
    source_error: UnprovenDirectHelperClosure | None
    writable_roots: _HeldWritableRoots | None = None
    retained_error: AuthenticatedReviewClosureUnproven | None = None
    lease_retained: bool = False
    evidence: AuthenticatedReviewClosureRecoveryEvidence | None = None
    evidence_attached: bool = False
    publication_errors: list[BaseException] = field(default_factory=list)
    result_owner: _AuthenticatedReviewClosureRetentionResultOwner | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.result_owner is not None:
            self.result_owner.publish(self)

    def matches(
        self,
        *,
        custody: CodexExecutableCustody | None,
        lease: _RuntimeLease,
        source_error: UnprovenDirectHelperClosure | None,
        writable_roots: _HeldWritableRoots | None,
    ) -> bool:
        return (
            self.custody is custody
            and self.lease is lease
            and self.source_error is source_error
            and self.writable_roots is writable_roots
        )

    def record_publication_error(self, error: BaseException) -> None:
        if not any(existing is error for existing in self.publication_errors):
            self.publication_errors.append(error)

    def _exact_resources(self) -> list[object]:
        resources: list[object] = []
        if isinstance(self.source_error, CodexExecutableRetentionRequired):
            resources.extend(self.source_error.retained_resources)
        for resource in (self.custody, self.writable_roots, self.lease):
            if resource is not None and not any(
                existing is resource for existing in resources
            ):
                resources.append(resource)
        return resources

    def publish_error(self, error: AuthenticatedReviewClosureUnproven) -> None:
        if self.retained_error is not None and self.retained_error is not error:
            raise ValueError("closure retention error was published more than once")
        error.retained_resources = self._exact_resources()
        self.retained_error = error

    def ensure_error(self) -> AuthenticatedReviewClosureUnproven:
        if self.retained_error is None:
            AuthenticatedReviewClosureUnproven(
                "authenticated review closure publication is unproven; resource "
                "custody and runtime recovery state were retained",
                evidence=None,
                result_owner=self,
            )
        retained = self.retained_error
        if retained is None:
            raise RuntimeError("closure retention error publication was incomplete")
        return retained

    def publish_evidence(
        self,
        evidence: AuthenticatedReviewClosureRecoveryEvidence,
    ) -> None:
        self.evidence = evidence
        if self.retained_error is not None:
            self.retained_error.evidence = evidence

    def finish_publication(self) -> AuthenticatedReviewClosureUnproven:
        retained = self.retained_error
        if retained is None:
            raise RuntimeError("closure retention error was not published")
        retained.retained_resources = self._exact_resources()
        evidence_records = (
            list(self.source_error.recovery_evidence)
            if isinstance(self.source_error, CodexExecutableRetentionRequired)
            else []
        )
        if self.evidence is not None and self.evidence not in evidence_records:
            evidence_records.append(self.evidence)
        retained.recovery_evidence = evidence_records
        retained.evidence = self.evidence
        return retained


@dataclass(slots=True)
class _RuntimeChildRecovery:
    parent_fd: int
    directory_fd: int | None
    path: pathlib.Path

    def close_descriptors_for_recovery(self) -> None:
        if self.directory_fd is not None:
            try:
                os.close(self.directory_fd)
            except OSError:
                pass


@dataclass(slots=True)
class _RuntimeAllocationRecovery:
    parent_fd: int
    container_fd: int
    directory_fd: int | None
    container: pathlib.Path
    root: pathlib.Path
    parent_identity: Identity
    container_identity: Identity
    directory_identity: Identity | None = None
    entry_state: str = "mkdir-pending"
    retained: bool = False

    def close_descriptors_for_recovery(self) -> None:
        descriptors = (
            self.directory_fd,
            self.container_fd,
            self.parent_fd,
        )
        closed: set[int] = set()
        for descriptor in descriptors:
            if descriptor is None:
                continue
            if descriptor in closed:
                continue
            closed.add(descriptor)
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pending_runtime_allocation_retention(
    pending: _RuntimeAllocationRecovery,
    *,
    trigger: BaseException,
) -> CodexExecutableRetentionRequired | None:
    raw_name = os.fsencode(pending.root.name)
    observation_error: BaseException | None = None
    try:
        path_identity = identity_from_stat(
            os.stat(
                raw_name,
                dir_fd=pending.container_fd,
                follow_symlinks=False,
            )
        )
    except FileNotFoundError:
        return None
    except BaseException as error:
        path_identity = None
        observation_error = error
    if path_identity is not None:
        try:
            pending.directory_fd = os.open(
                raw_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=pending.container_fd,
            )
            descriptor_identity = validate_private_directory_fd(
                pending.directory_fd,
                pending.root,
            )
            current_identity = identity_from_stat(
                os.stat(
                    raw_name,
                    dir_fd=pending.container_fd,
                    follow_symlinks=False,
                )
            )
            if not directory_identities_match(
                path_identity,
                descriptor_identity,
            ) or not directory_identities_match(
                descriptor_identity,
                current_identity,
            ):
                raise RuntimeError(
                    "pending runtime allocation identity changed during recovery"
                )
            pending.directory_identity = descriptor_identity
            pending.entry_state = "present-untransferred"
        except BaseException as error:
            observation_error = error
            pending.entry_state = "presence-observed-custody-incomplete"

    pending.retained = True
    reason = f"trigger={type(trigger).__name__}: {trigger}"
    if observation_error is not None:
        reason += (
            f"; observation={type(observation_error).__name__}: {observation_error}"
        )
    retained = CodexExecutableRetentionRequired(
        "runtime lease mkdir result was interrupted before allocation ownership "
        "could transfer; pending allocation custody was retained",
        code="runtime-lease-allocation-pending",
    )
    retained.retain_resource(pending)
    retained.retain_recovery_evidence(
        _RuntimeRecoveryEvidence(
            stage="runtime-lease-allocation-pending",
            parent_path=str(pending.container),
            entry_name=pending.root.name,
            parent_fd=pending.container_fd,
            directory_fd=pending.directory_fd,
            parent_identity=pending.container_identity,
            directory_identity=pending.directory_identity,
            reason=reason,
        )
    )
    return retained


@dataclass(slots=True)
class _RuntimeLease:
    container_parent_fd: int
    container_parent_identity: Identity
    container: pathlib.Path
    container_fd: int
    container_identity: Identity
    root: pathlib.Path
    root_fd: int
    identity: Identity
    retained: bool = False

    def close_descriptors_for_recovery(self) -> None:
        for descriptor in (
            self.root_fd,
            self.container_fd,
            self.container_parent_fd,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def make_directory(self, name: str) -> pathlib.Path:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError("runtime child name is invalid")
        path = self.root / name
        raw_name = os.fsencode(name)
        child_fd: int | None = None
        creation_identity: Identity | None = None
        created = False
        try:
            os.mkdir(raw_name, 0o700, dir_fd=self.root_fd)
            created = True
            creation_identity = identity_from_stat(
                os.stat(raw_name, dir_fd=self.root_fd, follow_symlinks=False)
            )
            os.fsync(self.root_fd)
            child_fd = os.open(
                raw_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self.root_fd,
            )
            descriptor_identity = validate_private_directory_fd(child_fd, path)
            path_identity = identity_from_stat(
                os.stat(raw_name, dir_fd=self.root_fd, follow_symlinks=False)
            )
            if not directory_identities_match(
                descriptor_identity,
                creation_identity,
            ) or not directory_identities_match(
                path_identity,
                descriptor_identity,
            ):
                raise RuntimeError("runtime child identity changed during creation")
            _require_empty_directory_fd(child_fd, label="runtime child")
            return path
        except BaseException as error:
            if not created:
                raise
            rollback_fd = child_fd
            try:
                if creation_identity is None:
                    raise RuntimeError("runtime child creation identity is unavailable")
                if rollback_fd is None:
                    rollback_fd = os.open(
                        raw_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=self.root_fd,
                    )
                quarantine_and_remove_empty_root(
                    RootSpec(
                        label="authenticated-review-runtime-child",
                        parent_fd=self.root_fd,
                        parent_identity=self.identity,
                        name=raw_name,
                        expected_identity=creation_identity,
                        private_metadata=True,
                    ),
                    rollback_fd,
                    deadline=time.monotonic() + _RUNTIME_CLEANUP_SECONDS,
                )
            except BaseException as rollback_error:
                self.retained = True
                recovery = _RuntimeChildRecovery(
                    parent_fd=self.root_fd,
                    directory_fd=rollback_fd,
                    path=path,
                )
                rollback_fd = None
                retained = CodexExecutableRetentionRequired(
                    "runtime child creation failed and descriptor-bound rollback "
                    "could not be proved; the runtime lease and child custody were "
                    "retained",
                    code="runtime-child-creation-retained",
                )
                retained.retain_resource(self)
                retained.retain_resource(recovery)
                retained.retain_recovery_evidence(
                    _RuntimeRecoveryEvidence(
                        stage="runtime-child-creation",
                        parent_path=str(self.root),
                        entry_name=name,
                        parent_fd=self.root_fd,
                        directory_fd=recovery.directory_fd,
                        parent_identity=self.identity,
                        directory_identity=creation_identity,
                        reason=(
                            f"trigger={type(error).__name__}: {error}; "
                            f"rollback={type(rollback_error).__name__}: "
                            f"{rollback_error}"
                        ),
                    )
                )
                _retain_quarantined_root_recovery_evidence(
                    retained,
                    rollback_error,
                )
                raise retained from rollback_error
            finally:
                if rollback_fd is not None:
                    os.close(rollback_fd)
                child_fd = None
            raise
        finally:
            if child_fd is not None:
                os.close(child_fd)

    def retain(self) -> None:
        self.retained = True

    def cleanup(self) -> None:
        manifest = None
        manifest_owner = CustodiedManifestResultOwner()
        deletion_owner = CustodiedDeletionResultOwner()
        retained = CodexExecutableRetentionRequired(
            "runtime cleanup could not prove descriptor-bound deletion; "
            "the runtime lease and recovery custody were retained",
            code="runtime-cleanup-retained",
        )
        try:
            if self.retained:
                return
            descriptor = identity_from_stat(os.fstat(self.root_fd))
            current = identity_from_stat(
                os.stat(
                    os.fsencode(self.root.name),
                    dir_fd=self.container_fd,
                    follow_symlinks=False,
                )
            )
            container_descriptor = validate_private_directory_fd(
                self.container_fd,
                self.container,
            )
            container_current = identity_from_stat(
                os.stat(
                    os.fsencode(self.container.name),
                    dir_fd=self.container_parent_fd,
                    follow_symlinks=False,
                )
            )
            parent_descriptor = identity_from_stat(os.fstat(self.container_parent_fd))
            if (
                not directory_identities_match(descriptor, self.identity)
                or not directory_identities_match(current, self.identity)
                or not directory_identities_match(
                    container_descriptor,
                    self.container_identity,
                )
                or not directory_identities_match(
                    container_current,
                    self.container_identity,
                )
                or not directory_identities_match(
                    parent_descriptor,
                    self.container_parent_identity,
                )
            ):
                self.retained = True
                raise RuntimeError(
                    "fresh runtime identity changed; suspicious content was retained"
                )
            manifest_path = self.container / (
                f".{self.root.name}.cleanup-{secrets.token_hex(16)}.manifest"
            )
            deadline = time.monotonic() + _RUNTIME_CLEANUP_SECONDS
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label="authenticated-review-runtime",
                        parent_fd=self.container_fd,
                        parent_identity=self.container_identity,
                        name=os.fsencode(self.root.name),
                        expected_identity=self.identity,
                        private_metadata=True,
                    ),
                ),
                manifest_path=manifest_path,
                entry_cap=_RUNTIME_CLEANUP_ENTRY_CAP,
                payload_cap=_RUNTIME_CLEANUP_MANIFEST_BYTES,
                deadline=deadline,
                result_owner=manifest_owner,
            )
            manifest_owner.transfer(manifest)
            deletion_proof = delete_custodied_roots(
                manifest,
                deadline=deadline,
                result_owner=deletion_owner,
            )
            deletion_owner.transfer(deletion_proof)
            manifest.close()
            manifest_seal = manifest.seal
            manifest = None
            remove_published_manifest(manifest_seal)
            _require_empty_directory_fd(self.container_fd, label="runtime root")
            parent_descriptor = identity_from_stat(os.fstat(self.container_parent_fd))
            container_descriptor = validate_private_directory_fd(
                self.container_fd,
                self.container,
            )
            container_current = identity_from_stat(
                os.stat(
                    os.fsencode(self.container.name),
                    dir_fd=self.container_parent_fd,
                    follow_symlinks=False,
                )
            )
            if (
                not directory_identities_match(
                    parent_descriptor,
                    self.container_parent_identity,
                )
                or not directory_identities_match(
                    container_descriptor,
                    self.container_identity,
                )
                or not directory_identities_match(
                    container_current,
                    self.container_identity,
                )
            ):
                raise RuntimeError(
                    "runtime container identity changed before removal; "
                    "suspicious content was retained"
                )
            quarantine_and_remove_empty_root(
                RootSpec(
                    label="authenticated-review-runtime-container",
                    parent_fd=self.container_parent_fd,
                    parent_identity=self.container_parent_identity,
                    name=os.fsencode(self.container.name),
                    expected_identity=self.container_identity,
                    private_metadata=True,
                ),
                self.container_fd,
                deadline=deadline,
            )
        except BaseException as error:
            self.retained = True
            setattr(retained, "source_cleanup_error", error)
            retained.retain_resource(self)
            retained.retain_recovery_evidence(
                _RuntimeRecoveryEvidence(
                    stage="runtime-lease-cleanup",
                    parent_path=str(self.container),
                    entry_name=self.root.name,
                    parent_fd=self.container_fd,
                    directory_fd=self.root_fd,
                    parent_identity=self.container_identity,
                    directory_identity=self.identity,
                    reason=f"{type(error).__name__}: {error}",
                )
            )
            close_evidence = getattr(
                error,
                "custodied_manifest_close_evidence",
                None,
            )
            if (
                close_evidence is not None
                and close_evidence not in retained.recovery_evidence
            ):
                retained.retain_recovery_evidence(close_evidence)
            source_deletion_owner = getattr(
                error,
                "custodied_deletion_result_owner",
                None,
            )
            if source_deletion_owner is not None:
                if source_deletion_owner is not deletion_owner:
                    retained.add_note(
                        "runtime cleanup received a deletion result owner that "
                        "did not match the transaction owner"
                    )
                else:
                    setattr(
                        retained,
                        "custodied_deletion_result_owner",
                        deletion_owner,
                    )
            if deletion_owner.proof is not None:
                completed_proof = deletion_owner.finish()
                setattr(
                    retained,
                    "custodied_deletion_result_owner",
                    deletion_owner,
                )
                setattr(retained, "completed_deletion_proof", completed_proof)
            elif deletion_owner.root_outcomes:
                setattr(
                    retained,
                    "custodied_deletion_result_owner",
                    deletion_owner,
                )
                setattr(
                    retained,
                    "completed_root_deletion_proofs",
                    tuple(
                        outcome.proof
                        for outcome in deletion_owner.root_outcomes
                        if outcome.state == "complete" and outcome.proof is not None
                    ),
                )
            _retain_quarantined_root_recovery_evidence(
                retained,
                error,
            )
            retained_manifest = manifest_owner.manifest
            if retained_manifest is not None and (
                manifest is not None
                or retained_manifest.root_fds
                or retained_manifest.close_evidence
            ):
                try:
                    manifest_owner.retain(retained)
                    manifest = None
                except BaseException as publication_error:
                    if not manifest_owner.retained:
                        manifest_owner.retain(retained)
                    manifest_owner.finish_retention()
                    manifest = None
                    setattr(
                        retained,
                        "retention_publication_errors",
                        (publication_error,),
                    )
                    retained.add_note(
                        "runtime manifest retention publication recovered after "
                        "interruption: "
                        f"{type(publication_error).__name__}: {publication_error}"
                    )
            raise retained from error
        finally:
            if manifest is not None and not manifest_owner.preserves(manifest):
                manifest.close()
            if not self.retained:
                self.close_descriptors_for_recovery()


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


def _raise_finalization_errors(
    errors: list[BaseException],
    *,
    lease: _RuntimeLease,
) -> None:
    evidence = tuple(errors)
    for error in errors:
        if isinstance(error, CodexExecutableRetentionRequired):
            if not any(resource is lease for resource in error.retained_resources):
                error.retain_resource(lease)
            setattr(error, "finalization_errors", evidence)
            raise error
    failure = RuntimeError("custodied process finalization was inconclusive")
    setattr(failure, "finalization_errors", evidence)
    raise failure from errors[0]


def _retain_quarantined_root_recovery_evidence(
    retained: CodexExecutableRetentionRequired,
    error: BaseException,
) -> tuple[QuarantinedRootRecoveryEvidence, ...]:
    evidence_records = quarantined_root_recovery_evidence(error)
    for evidence in evidence_records:
        if evidence not in retained.recovery_evidence:
            retained.retain_recovery_evidence(evidence)
    return evidence_records


def _attach_finalization_errors(
    primary: UnprovenDirectHelperClosure,
    finalization_error: BaseException,
) -> None:
    evidence = getattr(finalization_error, "finalization_errors", None)
    if not isinstance(evidence, tuple) or not all(
        isinstance(error, BaseException) for error in evidence
    ):
        evidence = (finalization_error,)
    existing = getattr(primary, "finalization_errors", ())
    if not isinstance(existing, tuple) or not all(
        isinstance(error, BaseException) for error in existing
    ):
        existing = ()
    combined = (*existing, *evidence)
    setattr(primary, "finalization_errors", combined)
    summary = "; ".join(f"{type(error).__name__}: {error}" for error in evidence)
    primary.add_note(f"custodied process finalization evidence: {summary}")


def _prepare_retained_unproven_closure_publication(
    *,
    owner: _AuthenticatedReviewClosureRetentionOwner,
    stage: str,
    state: ProcessCustodyState,
    finalization_errors: tuple[BaseException, ...],
) -> tuple[BaseException, ...]:
    owner.ensure_error()
    owner.lease.retain()
    owner.lease_retained = True

    source_finalization_errors = (
        getattr(owner.source_error, "finalization_errors", ())
        if owner.source_error is not None
        else ()
    )
    if not isinstance(source_finalization_errors, tuple) or not all(
        isinstance(error, BaseException) for error in source_finalization_errors
    ):
        source_finalization_errors = ()
    combined_errors: list[BaseException] = []
    for error in (*source_finalization_errors, *finalization_errors):
        if not any(existing is error for existing in combined_errors):
            combined_errors.append(error)
    combined_finalization_errors = tuple(combined_errors)
    reason_parts = [
        (
            f"source={type(owner.source_error).__name__}: {owner.source_error}"
            if owner.source_error is not None
            else (
                "source=lifecycle closure publication was not proved"
                if _closure_proven(state)
                else "source=local process settlement did not prove closure"
            )
        )
    ]
    reason_parts.extend(
        f"finalization={type(error).__name__}: {error}"
        for error in combined_finalization_errors
    )
    owner.publish_evidence(
        AuthenticatedReviewClosureRecoveryEvidence(
            stage=stage,
            protected_property="resource-ownership-and-closure-publication",
            process_id=state.process_id,
            process_group_id=state.process_group_id,
            profile_sha256=state.profile_sha256,
            leader_reaped=state.leader_reaped,
            process_group_empty=state.process_group_empty,
            pipes_closed=state.pipes_closed,
            executable_custody_retained=owner.custody is not None,
            runtime_lease_retained=owner.lease_retained,
            writable_root_descriptors_retained=owner.writable_roots is not None,
            closure_publication_proven=False,
            reason="; ".join(reason_parts),
        )
    )
    owner.evidence_attached = True
    return combined_finalization_errors


def _add_note_once(error: BaseException, note: str) -> None:
    notes = getattr(error, "__notes__", ())
    if not isinstance(notes, list) or note not in notes:
        error.add_note(note)


def _annotate_retained_unproven_closure(
    *,
    owner: _AuthenticatedReviewClosureRetentionOwner,
    retained: AuthenticatedReviewClosureUnproven,
    combined_finalization_errors: tuple[BaseException, ...],
) -> None:
    source_error = owner.source_error
    if source_error is not None:
        setattr(retained, "source_closure_error", source_error)
        _add_note_once(
            retained,
            "source unproven-closure evidence: "
            f"{type(source_error).__name__}: {source_error}",
        )
    if combined_finalization_errors:
        setattr(retained, "finalization_errors", combined_finalization_errors)
        _add_note_once(
            retained,
            "custodied process finalization evidence: "
            + "; ".join(
                f"{type(error).__name__}: {error}"
                for error in combined_finalization_errors
            ),
        )
    if owner.publication_errors:
        publication_errors = tuple(owner.publication_errors)
        setattr(retained, "retention_publication_errors", publication_errors)
        _add_note_once(
            retained,
            "closure retention publication recovered after interruption: "
            + "; ".join(
                f"{type(error).__name__}: {error}" for error in publication_errors
            ),
        )


def _retained_unproven_closure(
    *,
    stage: str,
    custody: CodexExecutableCustody | None,
    lease: _RuntimeLease,
    state: ProcessCustodyState,
    source_error: UnprovenDirectHelperClosure | None,
    writable_roots: _HeldWritableRoots | None = None,
    finalization_errors: tuple[BaseException, ...] = (),
    result_owner: _AuthenticatedReviewClosureRetentionOwner | None = None,
) -> AuthenticatedReviewClosureUnproven:
    owner = result_owner or _AuthenticatedReviewClosureRetentionOwner(
        custody=custody,
        lease=lease,
        source_error=source_error,
        writable_roots=writable_roots,
    )
    if not owner.matches(
        custody=custody,
        lease=lease,
        source_error=source_error,
        writable_roots=writable_roots,
    ):
        raise ValueError("closure retention result owner was rebound")
    try:
        combined_finalization_errors = _prepare_retained_unproven_closure_publication(
            owner=owner,
            stage=stage,
            state=state,
            finalization_errors=finalization_errors,
        )
        retained = owner.finish_publication()
        _annotate_retained_unproven_closure(
            owner=owner,
            retained=retained,
            combined_finalization_errors=combined_finalization_errors,
        )
        return retained
    except BaseException as error:
        owner.record_publication_error(error)
        combined_finalization_errors = _prepare_retained_unproven_closure_publication(
            owner=owner,
            stage=stage,
            state=state,
            finalization_errors=finalization_errors,
        )
        retained = owner.finish_publication()
        _annotate_retained_unproven_closure(
            owner=owner,
            retained=retained,
            combined_finalization_errors=combined_finalization_errors,
        )
        return retained


def _raise_retained_unproven_closure(
    *,
    stage: str,
    custody: CodexExecutableCustody | None,
    lease: _RuntimeLease,
    state: ProcessCustodyState,
    source_error: UnprovenDirectHelperClosure | None,
    writable_roots: _HeldWritableRoots | None = None,
    finalization_errors: tuple[BaseException, ...] = (),
) -> None:
    construction_errors: list[BaseException] = []
    owner_result: _AuthenticatedReviewClosureRetentionResultOwner | None = None
    try:
        owner_result = _AuthenticatedReviewClosureRetentionResultOwner()
    except BaseException as error:
        construction_errors.append(error)
        owner_result = _AuthenticatedReviewClosureRetentionResultOwner()

    owner: _AuthenticatedReviewClosureRetentionOwner | None = None
    try:
        owner = _AuthenticatedReviewClosureRetentionOwner(
            custody=custody,
            lease=lease,
            source_error=source_error,
            writable_roots=writable_roots,
            publication_errors=construction_errors,
            result_owner=owner_result,
        )
    except BaseException as error:
        construction_errors.append(error)
        owner = owner_result.owner
        if owner is None:
            owner = _AuthenticatedReviewClosureRetentionOwner(
                custody=custody,
                lease=lease,
                source_error=source_error,
                writable_roots=writable_roots,
                publication_errors=construction_errors,
                result_owner=owner_result,
            )

    try:
        owner.ensure_error()
        retained = _retained_unproven_closure(
            stage=stage,
            custody=custody,
            lease=lease,
            state=state,
            source_error=source_error,
            writable_roots=writable_roots,
            finalization_errors=finalization_errors,
            result_owner=owner,
        )
        if retained is source_error:
            raise retained
        raise retained from source_error
    except AuthenticatedReviewClosureUnproven as error:
        if error is owner.retained_error:
            raise
        publication_error: BaseException = error
    except BaseException as error:
        publication_error = error

    owner.record_publication_error(publication_error)
    retained = _retained_unproven_closure(
        stage=stage,
        custody=custody,
        lease=lease,
        state=state,
        source_error=source_error,
        writable_roots=writable_roots,
        finalization_errors=finalization_errors,
        result_owner=owner,
    )
    if retained is source_error:
        raise retained
    raise retained from source_error


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
        self._lifecycle_publication = _LifecycleLaunchPublication(
            lifecycle=lifecycle,
            stage="auth-refresh",
        )
        self._expected_cwd = expected_cwd
        self._expected_environment = dict(expected_environment)
        self.process_state = ProcessCustodyState()
        self.launched_process: LaunchedNoChildProcess | None = None
        self.closure_receipt: ManagedAuthRefreshClosureReceipt | None = None
        self._consumed = False

    @property
    def authenticated_snapshot(self) -> ManagedAuthSnapshotEvidence:
        return self._authenticated_snapshot

    @property
    def profile_sha256(self) -> str:
        return self._launch.profile_sha256

    @property
    def lifecycle_launched(self) -> bool:
        return self._lifecycle_publication.close_required

    def publish(self, launched: object) -> None:
        if self.launched_process is not None and self.launched_process is launched:
            published = self.launched_process
        elif self.launched_process is not None:
            raise RuntimeError("managed-auth launch custody was published twice")
        else:
            published = cast(LaunchedNoChildProcess, launched)
            self.launched_process = published
        _record_launch(self.process_state, published)
        self.process_state.leader_reaped = False
        self.process_state.process_group_empty = False
        self.process_state.pipes_closed = False
        self.process_state.exit_code = None

    def owns(self, launched: object) -> bool:
        published = self.launched_process
        return (
            published is launched
            and published is not None
            and self.process_state.process_id == published.pid
            and self.process_state.process_group_id == published.pgid
            and self.process_state.profile_sha256 == published.profile_sha256
            and not self.process_state.leader_reaped
            and not self.process_state.process_group_empty
            and not self.process_state.pipes_closed
            and self.process_state.exit_code is None
        )

    def _publish_launched(self, launched: object) -> None:
        self.publish(launched)

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
            launched = launch_no_child_process_with_result_publisher(
                launch_prepared_no_child_process,
                self._launch.prepared,
                (str(self._launch.custody.snapshot_path), *request.arguments),
                result_owner=self,
                cwd=request.cwd,
                environment=request.environment,
                stdin_fd=request.stdin_fd,
                stdout_fd=request.stdout_fd,
                stderr_fd=request.stderr_fd,
            )
            if not self.owns(launched):
                raise RuntimeError(
                    "managed-auth launch custody transfer is inconsistent"
                )
            self._lifecycle_publication.publish(launched)
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
        except BaseException as error:
            owned_launch = self.launched_process
            if owned_launch is not None:
                try:
                    _settle_launched_process(
                        self.process_state,
                        owned_launch,
                        pipes_closed=False,
                    )
                except BaseException as finalization_error:
                    if not isinstance(error, UnprovenDirectHelperClosure):
                        raise
                    _attach_finalization_errors(error, finalization_error)
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
    except CodexExecutableRetentionRequired as error:
        lease.retain()
        if not any(resource is lease for resource in error.retained_resources):
            error.retain_resource(lease)
        raise
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
    direct_helper_closure_error: UnprovenDirectHelperClosure | None = None
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
    except UnprovenDirectHelperClosure as error:
        direct_helper_closure_error = error
        raise
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
        try:
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
                direct_helper_closure_error=direct_helper_closure_error,
            )
        except BaseException as finalization_error:
            if direct_helper_closure_error is None:
                raise
            if isinstance(finalization_error, CodexExecutableRetentionRequired):
                raise
            _attach_finalization_errors(
                direct_helper_closure_error,
                finalization_error,
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
    lifecycle_publication = _LifecycleLaunchPublication(
        lifecycle=lifecycle,
        stage="reviewer",
    )
    completed = False
    result: AppServerProcessResult | None = None
    process_boundary_entered = False
    direct_helper_closure_error: UnprovenDirectHelperClosure | None = None
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
            nonlocal launched
            launched = process
            lifecycle_publication.publish(process)
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
    except UnprovenDirectHelperClosure as error:
        direct_helper_closure_error = error
        raise
    finally:
        if not process_boundary_entered:
            state.pipes_closed = True
        try:
            _finalize_custodied_stage(
                stage="reviewer",
                custody=custody,
                writable_roots=launch.writable_roots if launch is not None else None,
                handoff_token=launch.handoff_token if launch is not None else None,
                state=state,
                launched=launched,
                lifecycle=lifecycle,
                lifecycle_launched=lifecycle_publication.close_required,
                completed=completed,
                lease=lease,
                direct_helper_closure_error=direct_helper_closure_error,
            )
        except BaseException as finalization_error:
            if direct_helper_closure_error is None:
                raise
            if isinstance(finalization_error, CodexExecutableRetentionRequired):
                raise
            # The pending typed closure remains primary after this finally block.
            _attach_finalization_errors(
                direct_helper_closure_error,
                finalization_error,
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
    direct_helper_closure_error: UnprovenDirectHelperClosure | None = None,
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
    if direct_helper_closure_error is not None or (
        custody is not None and not closure_proven
    ):
        _raise_retained_unproven_closure(
            stage=stage,
            custody=custody,
            lease=lease,
            state=state,
            source_error=direct_helper_closure_error,
            writable_roots=writable_roots,
            finalization_errors=tuple(errors),
        )
    if lifecycle_launched and closure_proven and state.exit_code is not None:
        try:
            lifecycle.closed(stage, exit_code=state.exit_code)
        except BaseException as error:
            source_error = (
                error if isinstance(error, UnprovenDirectHelperClosure) else None
            )
            finalization_errors = (
                tuple(errors) if source_error is not None else (*errors, error)
            )
            _raise_retained_unproven_closure(
                stage=stage,
                custody=custody,
                lease=lease,
                state=state,
                source_error=source_error,
                writable_roots=writable_roots,
                finalization_errors=finalization_errors,
            )

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
        _raise_finalization_errors(errors, lease=lease)


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
    try:
        fd, _ = open_absolute_directory_chain(value, private_leaf=True)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} must be an exact owner-only directory") from error
    os.close(fd)


def _require_empty_directory(path: pathlib.Path, *, label: str) -> None:
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise ValueError(f"{label} must be empty")


def _require_empty_directory_fd(directory_fd: int, *, label: str) -> None:
    with os.scandir(directory_fd) as entries:
        if next(entries, None) is not None:
            raise ValueError(f"{label} must be empty")


def _ensure_runtime_root(path: pathlib.Path) -> None:
    value = _canonical_absolute_path(path, label="runtime root")
    fd, _ = open_absolute_directory_chain(
        value,
        create=True,
        private_leaf=True,
    )
    os.close(fd)


def _allocate_runtime_lease(runtime_root: pathlib.Path) -> _RuntimeLease:
    _ensure_runtime_root(runtime_root)
    parent_descriptor, parent_identity = open_absolute_directory_chain(
        runtime_root.parent
    )
    container_descriptor: int | None = None
    try:
        container_descriptor = os.open(
            os.fsencode(runtime_root.name),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        container_identity = validate_private_directory_fd(
            container_descriptor,
            runtime_root,
        )
        container_path_identity = identity_from_stat(
            os.stat(
                os.fsencode(runtime_root.name),
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        if not directory_identities_match(
            container_identity,
            container_path_identity,
        ):
            raise OSError("runtime root identity changed while opening")
        _require_empty_directory_fd(container_descriptor, label="runtime root")
        for _ in range(64):
            root = runtime_root / (
                f"{_RUNTIME_LEASE_PREFIX}"
                f"{secrets.token_hex(_RUNTIME_LEASE_TOKEN_BYTES)}"
            )
            raw_name = os.fsencode(root.name)
            descriptor: int | None = None
            creation_identity: Identity | None = None
            pending = _RuntimeAllocationRecovery(
                parent_fd=parent_descriptor,
                container_fd=container_descriptor,
                directory_fd=None,
                container=runtime_root,
                root=root,
                parent_identity=parent_identity,
                container_identity=container_identity,
            )
            try:
                try:
                    os.mkdir(raw_name, 0o700, dir_fd=container_descriptor)
                except FileExistsError:
                    continue
                # Keep the syscall return and the first durable ownership
                # marker inside one exception region. An asynchronous
                # interruption may arrive after mkdir succeeds but before the
                # next Python assignment executes.
                pending.entry_state = "mkdir-returned"
            except BaseException as error:
                retained = _pending_runtime_allocation_retention(
                    pending,
                    trigger=error,
                )
                if retained is not None:
                    parent_descriptor = -1
                    container_descriptor = None
                    raise retained from error
                raise
            try:
                creation_identity = identity_from_stat(
                    os.stat(
                        raw_name,
                        dir_fd=container_descriptor,
                        follow_symlinks=False,
                    )
                )
                pending.directory_identity = creation_identity
                os.fsync(container_descriptor)
                descriptor = os.open(
                    raw_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=container_descriptor,
                )
                pending.directory_fd = descriptor
                descriptor_identity = validate_private_directory_fd(
                    descriptor,
                    root,
                )
                path_identity = identity_from_stat(
                    os.stat(
                        raw_name,
                        dir_fd=container_descriptor,
                        follow_symlinks=False,
                    )
                )
                if not directory_identities_match(
                    descriptor_identity,
                    creation_identity,
                ) or not directory_identities_match(
                    path_identity,
                    descriptor_identity,
                ):
                    raise RuntimeError(
                        "fresh runtime identity changed during allocation"
                    )
                _require_empty_directory_fd(descriptor, label="fresh runtime")
                return _RuntimeLease(
                    container_parent_fd=parent_descriptor,
                    container_parent_identity=parent_identity,
                    container=runtime_root,
                    container_fd=container_descriptor,
                    container_identity=container_identity,
                    root=root,
                    root_fd=descriptor,
                    identity=descriptor_identity,
                )
            except BaseException as error:
                rollback_fd = descriptor
                try:
                    if creation_identity is None:
                        raise RuntimeError(
                            "fresh runtime creation identity is unavailable"
                        )
                    if rollback_fd is None:
                        rollback_fd = os.open(
                            raw_name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=container_descriptor,
                        )
                        pending.directory_fd = rollback_fd
                    quarantine_and_remove_empty_root(
                        RootSpec(
                            label="authenticated-review-runtime-allocation",
                            parent_fd=container_descriptor,
                            parent_identity=container_identity,
                            name=raw_name,
                            expected_identity=creation_identity,
                            private_metadata=True,
                        ),
                        rollback_fd,
                        deadline=time.monotonic() + _RUNTIME_CLEANUP_SECONDS,
                    )
                except BaseException as rollback_error:
                    recovery = pending
                    recovery.directory_fd = rollback_fd
                    recovery.directory_identity = creation_identity
                    recovery.entry_state = "rollback-unproven"
                    recovery.retained = True
                    parent_descriptor = -1
                    container_descriptor = None
                    descriptor = None
                    rollback_fd = None
                    retained = CodexExecutableRetentionRequired(
                        "runtime lease allocation failed and descriptor-bound "
                        "rollback could not be proved; allocation custody and "
                        "recovery evidence were retained",
                        code="runtime-lease-allocation-retained",
                    )
                    retained.retain_resource(recovery)
                    retained.retain_recovery_evidence(
                        _RuntimeRecoveryEvidence(
                            stage="runtime-lease-allocation",
                            parent_path=str(runtime_root),
                            entry_name=root.name,
                            parent_fd=recovery.container_fd,
                            directory_fd=recovery.directory_fd,
                            parent_identity=container_identity,
                            directory_identity=creation_identity,
                            reason=(
                                f"trigger={type(error).__name__}: {error}; "
                                f"rollback={type(rollback_error).__name__}: "
                                f"{rollback_error}"
                            ),
                        )
                    )
                    _retain_quarantined_root_recovery_evidence(
                        retained,
                        rollback_error,
                    )
                    raise retained from rollback_error
                finally:
                    if rollback_fd is not None:
                        os.close(rollback_fd)
                    descriptor = None
                raise
    except BaseException:
        if container_descriptor is not None:
            os.close(container_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise
    assert container_descriptor is not None
    os.close(container_descriptor)
    os.close(parent_descriptor)
    raise FileExistsError("cannot allocate a fresh authenticated-review runtime")


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


def projected_isolated_review_environment(
    runtime_root: pathlib.Path,
) -> dict[str, str]:
    projected_lease = runtime_root / (
        f"{_RUNTIME_LEASE_PREFIX}{'0' * (_RUNTIME_LEASE_TOKEN_BYTES * 2)}"
    )
    return _isolated_environment(
        codex_home=projected_lease / "review-home",
        temp_dir=projected_lease / "review-tmp",
    )


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
