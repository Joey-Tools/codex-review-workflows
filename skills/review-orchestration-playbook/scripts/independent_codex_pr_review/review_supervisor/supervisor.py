from __future__ import annotations

import math
import os
import pathlib
import re
import shutil
import signal
import socket
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from .constants import (
    CHECKOUT_SECONDS,
    FINAL_MESSAGE_BYTES,
    HANDOFF_SECONDS,
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    LOG_AGGREGATE_BYTES,
    MAX_EVIDENCE_PRIMARY_BYTES,
    PROCESS_ENVELOPE_BYTES,
    NAMED_LANE_ELIGIBLE,
    RELEASED_TTL_SECONDS,
    REVIEWER_LAUNCH_SECONDS,
    REVIEWER_RUNTIME_SECONDS,
    UNSUPPORTED_CLAUSES,
)
from .appserver_runtime import (
    PrelaunchInputSizeError,
    build_primary_preflight_appserver_input,
)
from .custody import (
    CustodyHandles,
    acquire_source_custody,
    authenticate_helper_state,
    helper_custody_evidence_matches,
)
from .errors import (
    SupervisorError,
    UnprovenDirectHelperClosure,
    blocked,
    inconclusive,
)
from .evidence import (
    EvidenceBundleSizeError,
    EvidenceError,
    build_primary_evidence_bundle,
)
from .gitraw import (
    GitProcessClosureUnproven,
    authenticated_range_manifests,
    inspect_repository,
    manifest_digest,
    retry_git_process_closure,
)
from .ledger import (
    AttemptLease,
    RetentionLease,
    acquire_retention_lease,
    calculate_admission,
    create_reserved_attempt,
    open_attempt_lease,
    read_bound_attempt_state,
    reconcile_ledger,
    remove_bound_attempt_directory,
)
from .models import HelperCustody, Identity
from .process import (
    ForkExecResultOwner,
    ForkedProcessClosureUnproven,
    ForkedProcessOwnershipUnproven,
    SpawnedProcess,
    anchored_group_members,
    await_exec,
    fork_exec,
    process_start_identity,
    reap,
    require_authenticated_no_child_process_profile,
    signal_anchored_group,
    wait_terminal,
)
from .prompt import (
    prove_exec_budget,
    prompt_evidence,
    render_prompt,
    reviewer_argv,
    validate_canonical_pr_url,
    validate_final_message,
)
from .recovery_cleanup import (
    CustodiedDeletionResultOwner,
    RootSpec,
    build_custodied_manifest,
    delete_custodied_roots,
    remove_published_manifest,
)
from .review_execution import projected_isolated_review_environment
from .runtime import (
    _CHECKOUT_CLOSURE_RECEIPT_MAX_BYTES,
    _CHECKOUT_CLOSURE_RECEIPT_NAME,
    _authenticate_attempt_transfer,
    _build_checkout_closure_receipt,
    _cleanup_worktree,
    _compact_terminal,
    _kill_direct,
    _persist_attempt_git_closure_receipt,
    _read_checkout_closure_receipt,
    _settle_process,
    _validate_terminal_lifecycle,
    build_unsettled_checkout_summary,
    build_final_authorization_rewrite,
    commit_via_helper,
    complete_final_authorization_rewrite,
    direct_process_closure_failure,
    latch_direct_process_closure_unproven,
    latch_direct_process_ownership_unproven,
    publish_prompt_via_helper,
    require_direct_process_closure_proven,
    validate_checkout_closure_receipt,
    validate_final_authorization_rewrite,
)
from .secureio import (
    allocated_bytes_fd,
    boot_identifier,
    canonical_json,
    directory_identities_match,
    ensure_no_path_value,
    identity_from_stat,
    identities_match,
    measure_filesystem_fd,
    open_regular_at,
    publish_bytes,
    read_fd_exact,
    require_private_directory,
    sha256_bytes,
    validate_private_directory_fd,
)
from .signal_relay import checkpoint_bound_signal_interrupt
from .wire import receive_record, send_blob, send_record, socket_pair


ATTEMPT_NAME_PATTERN = re.compile(r"attempt-([0-9]+-[0-9a-f]{32})\Z")
PROCESS_LOG_PATTERN = re.compile(r"codex\.(?:stdout|stderr)\.[0-9]+\.gz\Z")
RECOVERY_TEMP_PATTERN = re.compile(
    r"(?:\.state\.json|\.final\.txt)\.tmp-[0-9]+-[0-9a-f]{16}\Z"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
HANDOFF_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
RUNTIME_CLEANUP_MANIFEST = "runtime-cleanup.manifest"
RUNTIME_CLEANUP_ENTRY_CAP = 10_000
RUNTIME_CLEANUP_PAYLOAD_CAP = 2 * 1024 * 1024
IDENTITY_KEYS = frozenset({"device", "inode", "mode", "link_count", "uid", "size"})
FINAL_AUTHORIZATION_KEYS = frozenset(
    {
        "predecessor_generation",
        "predecessor_sha256",
        "supervisor",
        "supervisor_exit_code",
        "handoff_token_sha256",
        "final_seal",
        "binding_sha256",
    }
)
UNSETTLED_CHECKOUT_SUMMARY_KEYS = frozenset(
    {
        "review_contract",
        "named_lane_eligible",
        "overall_status",
        "review_status",
        "launch_status",
        "failure_stage",
        "failure_code",
        "message",
        "attempt_dir",
        "closure_receipt_status",
        "closure_receipt",
        "unsupported_clauses",
    }
)
ATTEMPT_TERMINAL_RECORD_KEYS = frozenset({"type", "token", "summary"})


@dataclass(frozen=True)
class PreparedRun:
    helper: Any
    repository: Any
    base_manifest: Any
    head_manifest: Any
    admission: Any
    attempt_id: str
    worktree_path: pathlib.Path
    attempt_dir: pathlib.Path
    final_fifo: pathlib.Path
    prompt: bytes
    prompt_evidence: dict[str, int | str]
    codex_executable: str
    exec_budget: dict[str, int]


def _resolve_codex(value: str | None) -> str:
    candidate = value or shutil.which("codex")
    if candidate is None:
        raise blocked(
            "Codex executable is unavailable in the trusted reviewer environment",
            stage="runtime-selection",
            code="codex-unavailable",
        )
    path = pathlib.Path(candidate)
    if not path.is_absolute():
        located = shutil.which(candidate)
        if located is None:
            raise blocked(
                "Codex executable cannot be resolved to an absolute path",
                stage="runtime-selection",
                code="codex-unavailable",
            )
        path = pathlib.Path(located)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise blocked(
            "Codex executable cannot be opened as a stable regular file",
            stage="runtime-selection",
            code="codex-unavailable",
        ) from error
    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise blocked(
            "Codex executable is not an executable regular file",
            stage="runtime-selection",
            code="codex-unavailable",
        )
    if not os.access(path, os.X_OK):
        raise blocked(
            "Codex executable is not executable by the current user",
            stage="runtime-selection",
            code="codex-unavailable",
        )
    return str(path)


def _require_primary_evidence_budget(diff_length: int) -> None:
    if not 1 <= diff_length <= MAX_EVIDENCE_PRIMARY_BYTES:
        raise blocked(
            "Primary diff does not fit the independent reviewer evidence budget",
            stage="evidence-admission",
            code="primary-evidence-size-invalid",
        )


def _read_authenticated_primary_evidence(
    helper: HelperCustody,
    *,
    repo: pathlib.Path,
) -> bytes:
    _require_primary_evidence_budget(helper.diff_length)
    handles: CustodyHandles | None = None
    try:
        handles = acquire_source_custody(
            expected=helper,
            repo=repo,
            deadline=time.monotonic() + HANDOFF_SECONDS,
        )
        content = read_fd_exact(
            handles.source_fd,
            max_bytes=MAX_EVIDENCE_PRIMARY_BYTES,
            expected_size=helper.diff_length,
        )
        if identity_from_stat(os.fstat(handles.source_fd)) != helper.source_identity:
            raise ValueError("primary diff identity changed while it was read")
        if sha256_bytes(content) != helper.diff_sha256:
            raise ValueError("primary diff digest changed after authentication")
        return content
    except SupervisorError:
        raise
    except (OSError, ValueError) as error:
        raise blocked(
            "Primary diff cannot be reauthenticated for evidence admission",
            stage="evidence-admission",
            code="primary-evidence-invalid",
        ) from error
    finally:
        if handles is not None:
            handles.close()


def _require_primary_serialized_evidence_budget(
    content: bytes,
    *,
    expected_sha256: str,
) -> None:
    try:
        build_primary_evidence_bundle(
            content,
            expected_sha256=expected_sha256,
        )
    except EvidenceBundleSizeError as error:
        raise blocked(
            "Primary diff does not fit the serialized reviewer evidence budget",
            stage="evidence-admission",
            code="primary-evidence-size-invalid",
        ) from error
    except EvidenceError as error:
        raise blocked(
            "Primary diff is not valid serialized reviewer evidence",
            stage="evidence-admission",
            code="primary-evidence-invalid",
        ) from error


def _require_primary_appserver_admission(
    content: bytes,
    *,
    expected_sha256: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    forbidden_paths: tuple[pathlib.Path, ...],
) -> None:
    try:
        build_primary_preflight_appserver_input(
            content,
            expected_sha256=expected_sha256,
            pr_url=pr_url,
            base_sha=base_sha,
            head_sha=head_sha,
            forbidden_paths=forbidden_paths,
        )
    except PrelaunchInputSizeError as error:
        raise blocked(
            "Primary diff does not fit the final app-server turn/start budget",
            stage="evidence-admission",
            code="primary-evidence-size-invalid",
        ) from error
    except (EvidenceError, ValueError) as error:
        raise blocked(
            "Primary diff is not valid final app-server evidence",
            stage="evidence-admission",
            code="primary-evidence-invalid",
        ) from error


def prepare_run(
    *,
    helper_state: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    pr_url: str,
    retention_root: pathlib.Path,
    checkout_parent: pathlib.Path,
    git_executable: str,
    codex_executable: str | None,
    snapshot: Any,
    lease: RetentionLease,
) -> PreparedRun:
    pr_url = validate_canonical_pr_url(pr_url)
    helper = authenticate_helper_state(
        state_dir=helper_state,
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    primary_evidence = _read_authenticated_primary_evidence(helper, repo=repo)
    _require_primary_serialized_evidence_budget(
        primary_evidence,
        expected_sha256=helper.diff_sha256,
    )
    attempt_id = f"{int(time.time())}-{uuid.uuid4().hex}"
    worktree_path = checkout_parent / f"review-{attempt_id}"
    attempt_dir = retention_root / f"attempt-{attempt_id}"
    final_fifo = attempt_dir / "final.fifo"
    _require_primary_appserver_admission(
        primary_evidence,
        expected_sha256=helper.diff_sha256,
        pr_url=pr_url,
        base_sha=base_sha,
        head_sha=head_sha,
        forbidden_paths=(worktree_path,),
    )
    repository = inspect_repository(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        git_executable=git_executable,
        temporary_control_parent=retention_root,
    )
    base_manifest, head_manifest = authenticated_range_manifests(repository)
    admission = calculate_admission(
        snapshot=snapshot,
        retention_root=retention_root,
        lease=lease,
        checkout_parent=checkout_parent,
        common_git_dir=repository.common_git_dir,
        git_admin_parent=retention_root,
        manifest=head_manifest,
        diff_length=helper.diff_length,
    )
    prompt = render_prompt(
        repo=worktree_path,
        pr_url=pr_url,
        base_sha=base_sha,
        head_sha=head_sha,
        diff_length=helper.diff_length,
        diff_sha256=helper.diff_sha256,
    )
    evidence = prompt_evidence(prompt)
    codex = _resolve_codex(codex_executable)
    argv = reviewer_argv(
        codex_executable=codex,
        worktree=worktree_path,
        final_fifo=final_fifo,
        prompt=prompt,
    )
    ensure_no_path_value(os.environ.values(), pathlib.Path(helper.workspace_root))
    reviewer_environment = projected_isolated_review_environment(
        attempt_dir / "review-runtime"
    )
    exec_budget = prove_exec_budget(argv, environment=reviewer_environment)
    return PreparedRun(
        helper=helper,
        repository=repository,
        base_manifest=base_manifest,
        head_manifest=head_manifest,
        admission=admission,
        attempt_id=attempt_id,
        worktree_path=worktree_path,
        attempt_dir=attempt_dir,
        final_fifo=final_fifo,
        prompt=prompt,
        prompt_evidence=evidence,
        codex_executable=codex,
        exec_budget=exec_budget,
    )


def _prepare_with_reclamation(
    *,
    entrypoint: pathlib.Path,
    lease: RetentionLease,
    helper_state: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    pr_url: str,
    retention_root: pathlib.Path,
    checkout_parent: pathlib.Path,
    git_executable: str,
    codex_executable: str | None,
) -> PreparedRun:
    reconcile_ledger(retention_root, lease=lease)
    _reclaim_released_attempts(
        entrypoint=entrypoint,
        root=retention_root,
        lease=lease,
        trigger="ttl",
        released_before=time.time() - RELEASED_TTL_SECONDS,
    )
    while True:
        snapshot = reconcile_ledger(retention_root, lease=lease)
        try:
            return prepare_run(
                helper_state=helper_state,
                repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                pr_url=pr_url,
                retention_root=retention_root,
                checkout_parent=checkout_parent,
                git_executable=git_executable,
                codex_executable=codex_executable,
                snapshot=snapshot,
                lease=lease,
            )
        except SupervisorError as error:
            if error.failure.code not in {
                "blocked-retention",
                "blocked-worktree-capacity",
            }:
                raise
            if (
                snapshot.retained_worktree_attempt is not None
                or error.failure.message.startswith("checkout accounting cap")
            ):
                raise
            reclaimed = _reclaim_released_attempts(
                entrypoint=entrypoint,
                root=retention_root,
                lease=lease,
                trigger="admission-pressure",
                limit=1,
            )
            if not reclaimed:
                raise


def preflight(
    *,
    entrypoint: pathlib.Path,
    helper_state: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    pr_url: str,
    retention_root: pathlib.Path,
    checkout_parent: pathlib.Path,
    git_executable: str,
    codex_executable: str | None,
) -> dict[str, Any]:
    pr_url = validate_canonical_pr_url(pr_url)
    require_private_directory(retention_root, create=True)
    require_private_directory(checkout_parent, create=True)
    with acquire_retention_lease(
        retention_root, deadline=time.monotonic() + 30
    ) as lease:
        prepared = _prepare_with_reclamation(
            entrypoint=entrypoint,
            lease=lease,
            helper_state=helper_state,
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            pr_url=pr_url,
            retention_root=retention_root,
            checkout_parent=checkout_parent,
            git_executable=git_executable,
            codex_executable=codex_executable,
        )
        return {
            "status": "ready",
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "review_status": "not-run",
            "created_attempt": False,
            "repo": str(prepared.repository.repo),
            "review_range": prepared.helper.review_range,
            "helper_state": str(helper_state),
            "diff_length": prepared.helper.diff_length,
            "diff_sha256": prepared.helper.diff_sha256,
            "entry_count": prepared.head_manifest.entry_count,
            "base_manifest_sha256": manifest_digest(prepared.base_manifest),
            "head_manifest_sha256": manifest_digest(prepared.head_manifest),
            "admission": prepared.admission.to_json(),
            "prompt": prepared.prompt_evidence,
            "exec_budget": prepared.exec_budget,
            "unsupported_clauses": list(UNSUPPORTED_CLAUSES),
        }


def _spawn_attempt_supervisor(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    control_child: socket.socket,
    token: str,
    result_owner: ForkExecResultOwner,
) -> SpawnedProcess:
    require_direct_process_closure_proven()
    devnull = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        argv = (
            sys.executable,
            "-B",
            str(entrypoint),
            "_attempt-supervisor",
            "--entrypoint",
            str(entrypoint),
            "--attempt-dir",
            str(attempt.path),
            "--control-fd",
            "3",
            "--lease-fd",
            "4",
            "--root-fd",
            "5",
            "--attempt-fd",
            "6",
            "--handoff-token",
            token,
        )
        try:
            return fork_exec(
                argv,
                cwd=attempt.path,
                stdin_fd=devnull,
                stdout_fd=devnull,
                stderr_fd=devnull,
                pass_fds=(
                    control_child.fileno(),
                    attempt.retention.fd,
                    attempt.retention.root_fd,
                    attempt.fd,
                ),
                own_process_group=True,
                result_owner=result_owner,
            )
        except ForkedProcessClosureUnproven as error:
            failure = latch_direct_process_closure_unproven(error.process)
            raise failure from error
        except ForkedProcessOwnershipUnproven as error:
            failure = latch_direct_process_ownership_unproven(error)
            raise failure from error
    finally:
        os.close(devnull)


def _terminate_incomplete_handoff_once(
    process: SpawnedProcess,
    *,
    deadline: float,
) -> int:
    signal_anchored_group(process, signal.SIGTERM)
    time.sleep(0.05)
    signal_anchored_group(process, signal.SIGKILL)
    wait_terminal(process.pid, deadline=deadline)
    while True:
        members = anchored_group_members(process, deadline=deadline)
        if not any(pid != process.pid for pid in members):
            break
        signal_anchored_group(process, signal.SIGKILL)
        if time.monotonic() >= deadline:
            raise TimeoutError("incomplete-handoff process group survived cleanup")
        time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    return reap(process.pid, deadline=deadline)


def _terminate_incomplete_handoff(process: SpawnedProcess) -> int:
    cleanup_error: BaseException | None = None
    cleanup_control_flow: BaseException | None = None
    for cleanup_seconds in (2.0, 5.0):
        try:
            exit_code = _terminate_incomplete_handoff_once(
                process,
                deadline=time.monotonic() + cleanup_seconds,
            )
        except BaseException as error:
            cleanup_error = error
            if not isinstance(error, Exception):
                cleanup_control_flow = error
            continue
        if cleanup_control_flow is not None:
            raise cleanup_control_flow
        return exit_code
    assert cleanup_error is not None
    failure = latch_direct_process_closure_unproven(process)
    raise failure from cleanup_error


def _retain_attempt_supervisor_closure(
    process: SpawnedProcess,
    *,
    attempt_dir: pathlib.Path,
    token: str,
    trigger: BaseException,
) -> tuple[UnprovenDirectHelperClosure, dict[str, Any]]:
    failure = latch_direct_process_closure_unproven(process)
    retained_process = getattr(failure, "process", None)
    if retained_process is not process:
        raise RuntimeError("attempt supervisor closure latch retained another process")
    if not process.start_identity:
        raise RuntimeError("attempt supervisor has no authenticated start identity")
    receipt = {
        "version": 1,
        "kind": "attempt-supervisor-closure-unproven",
        "attempt_dir": str(attempt_dir),
        "handoff_token_sha256": sha256_bytes(token.encode("ascii")),
        "process": {
            "pid": process.pid,
            "pgid": process.pgid,
            "start_identity": process.start_identity,
        },
        "trigger": type(trigger).__name__,
    }
    receipt_payload = canonical_json(receipt)
    return failure, {
        "status": "retained-in-process",
        "receipt_path": None,
        "receipt_sha256": sha256_bytes(receipt_payload),
        "receipt": receipt,
    }


def _merge_process_closure_recovery(
    current: dict[str, Any] | None,
    added: dict[str, Any],
) -> dict[str, Any]:
    if current is None:
        return added
    return {
        "status": "multiple-unproven-processes",
        "recoveries": [current, added],
    }


def _settle_owned_attempt_supervisor_after_failure(
    process: SpawnedProcess,
    *,
    attempt_dir: pathlib.Path,
    token: str,
) -> tuple[UnprovenDirectHelperClosure, dict[str, Any]] | None:
    try:
        wait_terminal(process.pid, deadline=time.monotonic() + 30)
        reap(process.pid)
    except BaseException as closure_error:
        # Only the attempt supervisor may terminate its child PGID after handoff.
        # Retain its authenticated handle when liveness-driven settlement exceeds
        # this bounded outer wait.
        return _retain_attempt_supervisor_closure(
            process,
            attempt_dir=attempt_dir,
            token=token,
            trigger=closure_error,
        )
    return None


def _acquire_source_custody_via_helper(
    *,
    entrypoint: pathlib.Path,
    prepared: PreparedRun,
    deadline: float,
) -> CustodyHandles:
    require_direct_process_closure_proven()
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    process_owner = ForkExecResultOwner()
    received_fds: tuple[int, ...] = ()
    devnull = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        argv = (
            sys.executable,
            "-B",
            str(entrypoint),
            "_custody-helper",
            "--control-fd",
            "3",
            "--state-dir",
            prepared.helper.state_dir,
            "--repo",
            str(prepared.repository.repo),
            "--base",
            prepared.helper.base_sha,
            "--head",
            prepared.helper.head_sha,
            "--token",
            token,
        )
        try:
            with process_owner:
                process = fork_exec(
                    argv,
                    cwd=prepared.attempt_dir,
                    stdin_fd=devnull,
                    stdout_fd=devnull,
                    stderr_fd=devnull,
                    pass_fds=(child.fileno(),),
                    own_process_group=False,
                    result_owner=process_owner,
                )
                process_owner.transfer(process)
        except ForkedProcessClosureUnproven as error:
            failure = latch_direct_process_closure_unproven(error.process)
            raise failure from error
        except ForkedProcessOwnershipUnproven as error:
            failure = latch_direct_process_ownership_unproven(error)
            raise failure from error
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "custody-helper-ready" or ready.get("token") != token:
            raise ValueError("custody helper ready record is invalid")
        send_record(
            parent,
            {
                "type": "acquire-source-custody",
                "token": token,
                "expected": prepared.helper.to_json(),
            },
            deadline=deadline,
        )
        result, received_fds = receive_record(
            parent,
            deadline=deadline,
            expected_fds=2,
        )
        if (
            result.get("type") != "source-custody-result"
            or result.get("token") != token
            or result.get("ok") is not True
            or not helper_custody_evidence_matches(
                result.get("evidence"),
                prepared.helper,
            )
        ):
            raise ValueError(
                f"custody helper failed: {result.get('error', 'invalid result')}"
            )
        cleanup_lock_fd, source_fd = received_fds
        if (
            identity_from_stat(os.fstat(cleanup_lock_fd))
            != prepared.helper.cleanup_lock_identity
        ):
            raise ValueError("custody helper returned the wrong cleanup-lock identity")
        if identity_from_stat(os.fstat(source_fd)) != prepared.helper.source_identity:
            raise ValueError("custody helper returned the wrong source identity")
        send_record(
            parent,
            {"type": "source-custody-received", "token": token},
            deadline=deadline,
        )
        wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid)
        process = None
        if exit_code != 0:
            raise ValueError("custody helper exited nonzero after descriptor transfer")
        received_fds = ()
        return CustodyHandles(
            cleanup_lock_fd=cleanup_lock_fd,
            source_fd=source_fd,
            evidence=prepared.helper,
        )
    finally:
        os.close(devnull)
        parent.close()
        child.close()
        for fd in received_fds:
            os.close(fd)
        if process is not None:
            _kill_direct(process)


def _prequiescence_abort(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    message: str,
) -> None:
    require_direct_process_closure_proven()
    try:
        state, _, digest = read_bound_attempt_state(attempt)
        state, digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=digest,
            updates={
                "phase": "prelaunch-aborted",
                "handoff": "aborted",
                "process_owner": "outer",
                "launch_status": "prelaunch-aborted",
                "review_status": "not-run",
                "closure": "proven-by-owner",
                "failure_stage": "handoff",
                "failure": {
                    "status": "inconclusive",
                    "code": "handoff-incomplete",
                    "message": message,
                },
                "cleanup_status": "cleanup-pending",
            },
            deadline=time.monotonic() + 30,
        )
        prompt_path = pathlib.Path(state["prompt_path"])
        if prompt_path != attempt.path / "prompt.txt":
            raise ValueError("prompt path differs from the attempt binding")
        attempt.revalidate(state)
        try:
            fd, identity = open_regular_at(
                attempt.fd,
                b"prompt.txt",
                expected_uid=os.getuid(),
                private_metadata=True,
            )
            os.close(fd)
            if state.get("prompt_identity") and identity != Identity(
                **state["prompt_identity"]
            ):
                raise ValueError("prompt identity changed before pre-handoff cleanup")
            os.unlink(b"prompt.txt", dir_fd=attempt.fd)
            os.fsync(attempt.fd)
        except FileNotFoundError:
            pass
        attempt.revalidate(state)
        state, digest = _cleanup_worktree(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=digest,
        )
        _settle_process(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=digest,
        )
    except (GitProcessClosureUnproven, UnprovenDirectHelperClosure):
        raise
    except BaseException:
        return


def _process_charge_fields(
    attempt: AttemptLease,
    charge: int,
) -> dict[str, Any]:
    if type(charge) is not int or not 0 <= charge <= PROCESS_ENVELOPE_BYTES:
        raise ValueError("retained process charge is outside its envelope")
    attempt.revalidate()
    identity = measure_filesystem_fd(attempt.fd).identity
    attempt.revalidate()
    return {
        "retained_process_bytes": charge,
        "process_physical_remaining_by_fs": {identity: charge} if charge else {},
    }


def _process_accounting_is_exact(
    attempt: AttemptLease,
    state: dict[str, Any],
) -> bool:
    try:
        attempt.revalidate(state)
        measured = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
        attempt.revalidate(state)
        expected = _process_charge_fields(attempt, measured)
    except (OSError, ValueError):
        return False
    return bool(
        state.get("retained_process_bytes") == measured
        and state.get("process_physical_remaining_by_fs")
        == expected["process_physical_remaining_by_fs"]
    )


def _commit_conservative_process_rewrite(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
    updates: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if state.get("process_settlement") != "exact":
        raise ValueError("only exact process state can be rewritten conservatively")
    return commit_via_helper(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
        updates={
            **updates,
            **_process_charge_fields(attempt, PROCESS_ENVELOPE_BYTES),
        },
        deadline=time.monotonic() + 30,
    )


def _settle_rewritten_process_charge(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
) -> tuple[dict[str, Any], str]:
    if state.get("process_settlement") != "exact":
        raise ValueError("rewritten process state is not exactly settleable")
    for _ in range(8):
        attempt.revalidate(state)
        measured = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
        attempt.revalidate(state)
        expected = _process_charge_fields(attempt, measured)
        if (
            state.get("retained_process_bytes") == measured
            and state.get("process_physical_remaining_by_fs")
            == expected["process_physical_remaining_by_fs"]
        ):
            return state, state_digest
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            updates=expected,
            deadline=time.monotonic() + 30,
        )
    raise ValueError("rewritten process allocation accounting did not converge")


def _begin_final_authorization_rewrite(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
    operation: str,
    updates: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    existing = state.get("final_authorization_rewrite")
    if existing is not None:
        existing = validate_final_authorization_rewrite(state)
        if existing["status"] != "complete":
            raise ValueError("final authorization rewrite is already pending")
    rewrite = build_final_authorization_rewrite(
        attempt=attempt,
        state=state,
        state_digest=state_digest,
        operation=operation,
    )
    return _commit_conservative_process_rewrite(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
        updates={**updates, "final_authorization_rewrite": rewrite},
    )


def _complete_unauthed_final_authorization_rewrite(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
) -> tuple[dict[str, Any], str]:
    rewrite = validate_final_authorization_rewrite(state)
    if rewrite["authorization_required"]:
        raise ValueError("authorized rewrite requires final authorization publication")
    completed = complete_final_authorization_rewrite(rewrite)
    if rewrite != completed:
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            updates={"final_authorization_rewrite": completed},
            deadline=time.monotonic() + 30,
        )
    return _settle_rewritten_process_charge(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
    )


def _require_reviewer_closure_evidence(state: dict[str, Any]) -> None:
    if state.get("launch_status") != "completed":
        raise ValueError("reviewer launch was not durably completed")
    if (
        state.get("handoff") != "complete"
        or state.get("process_owner") != "attempt-supervisor"
        or state.get("closure") != "proven-by-owner"
    ):
        raise ValueError("reviewer handoff or closure is not exact")
    leader = state.get("leader")
    if (
        not isinstance(leader, dict)
        or set(leader) != {"pid", "pgid", "start_identity"}
        or type(leader.get("pid")) is not int
        or leader["pid"] <= 1
        or leader.get("pgid") != leader["pid"]
        or not isinstance(leader.get("start_identity"), str)
        or not leader["start_identity"]
    ):
        raise ValueError("reviewer leader binding is malformed")
    try:
        require_authenticated_no_child_process_profile(state)
    except ChildProcessError as error:
        raise ValueError("reviewer no-child profile binding is malformed") from error
    runtime_binding = state.get("runtime_process_binding")
    if (
        not isinstance(runtime_binding, dict)
        or set(runtime_binding) != {"session_id", "profile_sha256"}
        or runtime_binding.get("session_id") != leader["pid"]
        or not isinstance(runtime_binding.get("profile_sha256"), str)
        or SHA256_PATTERN.fullmatch(runtime_binding["profile_sha256"]) is None
    ):
        raise ValueError("reviewer runtime binding is malformed")
    process_history = state.get("process_history")
    leader_exit = state.get("leader_exit")
    if (
        not isinstance(process_history, list)
        or len(process_history) not in {1, 2}
        or not isinstance(process_history[-1], dict)
        or set(process_history[-1])
        != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
        or process_history[-1].get("stage") != "reviewer"
        or process_history[-1].get("leader") != leader
        or process_history[-1].get("runtime_binding") != runtime_binding
        or type(leader_exit) is not int
        or process_history[-1].get("exit_code") != leader_exit
        or process_history[-1].get("closure") != "proven-by-owner"
    ):
        raise ValueError("reviewer closure history is malformed")
    if len(process_history) == 2:
        refresh = process_history[0]
        if (
            not isinstance(refresh, dict)
            or set(refresh)
            != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
            or refresh.get("stage") != "auth-refresh"
            or refresh.get("exit_code") != 0
            or refresh.get("closure") != "proven-by-owner"
        ):
            raise ValueError("auth-refresh closure history is malformed")


def _terminal_handoff_token(
    state: dict[str, Any],
    supervisor_binding: dict[str, Any],
    supervisor_exit_code: int,
) -> str:
    if state.get("phase") != "reviewed" or state.get("launch_status") != "completed":
        raise ValueError("terminal review was not durably completed")
    _require_reviewer_closure_evidence(state)
    if (
        state.get("handoff") != "complete"
        or state.get("process_owner") != "attempt-supervisor"
    ):
        raise ValueError("terminal review has no complete supervisor handoff")
    if state.get("supervisor") != supervisor_binding:
        raise ValueError("terminal review supervisor binding changed")
    if (
        state.get("closure") != "proven-by-owner"
        or state.get("abandonment") is not False
    ):
        raise ValueError("terminal review closure is not exact")
    if type(supervisor_exit_code) is not int or supervisor_exit_code != 0:
        raise ValueError("attempt supervisor did not exit zero")
    if state.get("review_status") not in {"clean", "findings"}:
        raise ValueError("attempt supervisor produced no review result")
    if (
        state.get("process_settlement") != "exact"
        or state.get("checkout_settlement") != "exact"
        or state.get("worktree_status") != "removed"
        or state.get("source_custody_released") is not True
        or state.get("admission_status") != "completed"
        or state.get("reservation_status") != "settled"
    ):
        raise ValueError("terminal review ledgers or custody are incomplete")
    leader = state.get("leader")
    if (
        not isinstance(leader, dict)
        or set(leader) != {"pid", "pgid", "start_identity"}
        or type(leader.get("pid")) is not int
        or leader["pid"] <= 1
        or leader.get("pgid") != leader["pid"]
        or not isinstance(leader.get("start_identity"), str)
        or not leader["start_identity"]
    ):
        raise ValueError("terminal reviewer leader binding is malformed")
    try:
        require_authenticated_no_child_process_profile(state)
    except ChildProcessError as error:
        raise ValueError(
            "terminal reviewer no-child profile binding is malformed"
        ) from error
    runtime_binding = state.get("runtime_process_binding")
    if (
        not isinstance(runtime_binding, dict)
        or set(runtime_binding) != {"session_id", "profile_sha256"}
        or runtime_binding.get("session_id") != leader["pid"]
        or not isinstance(runtime_binding.get("profile_sha256"), str)
        or SHA256_PATTERN.fullmatch(runtime_binding["profile_sha256"]) is None
    ):
        raise ValueError("terminal reviewer runtime binding is malformed")
    process_history = state.get("process_history")
    if (
        not isinstance(process_history, list)
        or len(process_history) not in {1, 2}
        or not isinstance(process_history[-1], dict)
        or set(process_history[-1])
        != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
        or process_history[-1].get("stage") != "reviewer"
        or process_history[-1].get("leader") != leader
        or process_history[-1].get("runtime_binding") != runtime_binding
        or process_history[-1].get("exit_code") != 0
        or process_history[-1].get("closure") != "proven-by-owner"
        or state.get("leader_exit") != 0
    ):
        raise ValueError("terminal reviewer closure history is malformed")
    if len(process_history) == 2:
        refresh = process_history[0]
        if (
            not isinstance(refresh, dict)
            or set(refresh)
            != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
            or refresh.get("stage") != "auth-refresh"
            or refresh.get("exit_code") != 0
            or refresh.get("closure") != "proven-by-owner"
        ):
            raise ValueError("terminal auth-refresh closure history is malformed")
    if state.get("terminal_commit_authorized") is not True:
        raise ValueError("terminal review was not authorized")
    seal = state.get("final_seal")
    terminal_authorization = state.get("terminal_authorization")
    authorized_at = (
        terminal_authorization.get("authorized_at")
        if isinstance(terminal_authorization, dict)
        else None
    )
    if (
        not isinstance(seal, dict)
        or set(seal) != {"path", "identity", "length", "sha256"}
        or not isinstance(seal.get("identity"), dict)
        or set(seal["identity"]) != IDENTITY_KEYS
        or type(seal.get("length")) is not int
        or not 1 <= seal["length"] <= FINAL_MESSAGE_BYTES
        or not isinstance(seal.get("sha256"), str)
        or SHA256_PATTERN.fullmatch(seal["sha256"]) is None
        or not isinstance(terminal_authorization, dict)
        or set(terminal_authorization) != {"leader_exit", "final_seal", "authorized_at"}
        or type(terminal_authorization.get("leader_exit")) is not int
        or terminal_authorization["leader_exit"] != 0
        or terminal_authorization.get("final_seal") != seal
        or type(authorized_at) not in {int, float}
        or not math.isfinite(authorized_at)
    ):
        raise ValueError(
            "terminal authorization is not bound to a zero-exit final seal"
        )
    handoff_token = state.get("handoff_token")
    if (
        not isinstance(handoff_token, str)
        or HANDOFF_TOKEN_PATTERN.fullmatch(handoff_token) is None
    ):
        raise ValueError("terminal handoff token is malformed")
    return handoff_token


def _final_authorization_record(
    *,
    state: dict[str, Any],
    state_digest: str,
    supervisor_binding: dict[str, Any],
    supervisor_exit_code: int,
    handoff_token: str,
) -> dict[str, Any]:
    generation = state.get("record_generation")
    if type(generation) is not int or generation < 1:
        raise ValueError("terminal predecessor generation is malformed")
    if SHA256_PATTERN.fullmatch(state_digest) is None:
        raise ValueError("terminal predecessor digest is malformed")
    payload = {
        "predecessor_generation": generation,
        "predecessor_sha256": state_digest,
        "supervisor": supervisor_binding,
        "supervisor_exit_code": supervisor_exit_code,
        "handoff_token_sha256": sha256_bytes(handoff_token.encode("ascii")),
        "final_seal": state["final_seal"],
    }
    return {
        **payload,
        "binding_sha256": sha256_bytes(canonical_json(payload)),
    }


def _publish_final_authorization(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
    supervisor_binding: dict[str, Any],
    supervisor_exit_code: int,
) -> tuple[dict[str, Any], str]:
    handoff_token = _terminal_handoff_token(
        state, supervisor_binding, supervisor_exit_code
    )
    for _ in range(8):
        attempt.revalidate(state)
        measured = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
        attempt.revalidate(state)
        authorization = _final_authorization_record(
            state=state,
            state_digest=state_digest,
            supervisor_binding=supervisor_binding,
            supervisor_exit_code=supervisor_exit_code,
            handoff_token=handoff_token,
        )
        rewrite = state.get("final_authorization_rewrite")
        rewrite_updates = (
            {
                "final_authorization_rewrite": complete_final_authorization_rewrite(
                    validate_final_authorization_rewrite(state)
                )
            }
            if rewrite is not None
            else {}
        )
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            updates={
                "supervisor_exit_code": supervisor_exit_code,
                "final_authorization": authorization,
                **rewrite_updates,
                **_process_charge_fields(attempt, measured),
            },
            deadline=time.monotonic() + 30,
            request_type="final-authorization-commit",
        )
        attempt.revalidate(state)
        readback_charge = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
        attempt.revalidate(state)
        if readback_charge == state.get("retained_process_bytes"):
            return state, state_digest
    raise ValueError("final authorization allocation accounting did not converge")


def _publish_retained_git_closure_recovery(
    *,
    recovery_root: pathlib.Path,
    revalidate_owner: Callable[[], None],
    error: GitProcessClosureUnproven,
    token: str,
) -> dict[str, Any]:
    try:
        receipt = _build_checkout_closure_receipt(
            error,
            attempt_dir=recovery_root,
            token=token,
            owner_pid=os.getpid(),
            owner_start_identity=process_start_identity(os.getpid()),
        )
        retained_paths = receipt["retained_cleanup_paths"]
        receipt_path = (
            pathlib.Path(retained_paths[0]) / "closure-recovery.json"
            if retained_paths
            else None
        )
        receipt_payload = canonical_json(receipt)
        receipt_status = "publication-failed"
        if receipt_path is not None:
            try:
                revalidate_owner()
                publish_bytes(receipt_path, receipt_payload)
                revalidate_owner()
                receipt_status = "published"
            except BaseException:
                receipt_status = "publication-failed"
        return {
            "status": receipt_status,
            "receipt_path": str(receipt_path) if receipt_path is not None else None,
            "receipt_sha256": sha256_bytes(receipt_payload),
            "receipt": receipt,
        }
    except BaseException:
        return {
            "status": "receipt-preparation-failed",
            "receipt_path": None,
            "receipt_sha256": None,
            "receipt": None,
        }
    finally:
        error.finish_signal_deferral(deliver=False)


def _publish_attempt_git_closure_recovery(
    *,
    attempt: AttemptLease,
    error: GitProcessClosureUnproven,
    token: str,
) -> dict[str, Any]:
    try:
        state, _, _ = read_bound_attempt_state(attempt)
        durable_token = state.get("handoff_token")
        if (
            state.get("handoff") != "complete"
            or state.get("process_owner") != "attempt-supervisor"
            or not isinstance(durable_token, str)
            or HANDOFF_TOKEN_PATTERN.fullmatch(durable_token) is None
            or token != durable_token
        ):
            raise ValueError(
                "attempt Git closure receipt has no durable ownership binding"
            )
        owner_start_identity = process_start_identity(os.getpid())
        receipt = _build_checkout_closure_receipt(
            error,
            attempt_dir=attempt.path,
            token=token,
            owner_pid=os.getpid(),
            owner_start_identity=owner_start_identity,
        )
        receipt_payload = canonical_json(receipt)
        receipt_path = attempt.path / "checkout-closure-recovery.json"
        receipt_status = "publication-failed"
        try:
            persisted = _persist_attempt_git_closure_receipt(
                attempt=attempt,
                state=state,
                error=error,
                token=token,
                owner_start_identity=owner_start_identity,
            )
            if persisted != receipt:
                raise ValueError(
                    "attempt Git closure receipt changed during publication"
                )
            receipt_status = "published"
        except BaseException:
            receipt_status = "publication-failed"
        return {
            "status": receipt_status,
            "receipt_path": str(receipt_path),
            "receipt_sha256": sha256_bytes(receipt_payload),
            "receipt": receipt,
        }
    except BaseException:
        return {
            "status": "receipt-preparation-failed",
            "receipt_path": None,
            "receipt_sha256": None,
            "receipt": None,
        }
    finally:
        error.finish_signal_deferral(deliver=False)


def _select_reaped_attempt_terminal(
    *,
    exit_code: int,
    terminal: dict[str, Any] | None,
    terminal_receive_error: Exception | None,
    completion_attempt: AttemptLease,
    attempt_dir: pathlib.Path,
    token: str,
) -> dict[str, Any]:
    if exit_code == 2:
        return _derive_unsettled_checkout_summary(
            completion_attempt,
            attempt_dir=attempt_dir,
            token=token,
        )
    if exit_code not in {0, 1}:
        raise ValueError("nonzero attempt supervisor summary is not authenticated")
    if terminal_receive_error is not None:
        raise terminal_receive_error
    if (
        terminal is None
        or set(terminal) != ATTEMPT_TERMINAL_RECORD_KEYS
        or terminal.get("type") != "attempt-terminal"
        or terminal.get("token") != token
    ):
        raise ValueError("attempt supervisor terminal record is invalid")
    summary = terminal.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("attempt terminal summary is malformed")
    return summary


def run(
    *,
    entrypoint: pathlib.Path,
    helper_state: pathlib.Path,
    repo: pathlib.Path,
    base_sha: str,
    head_sha: str,
    pr_url: str,
    retention_root: pathlib.Path,
    checkout_parent: pathlib.Path,
    git_executable: str,
    codex_executable: str | None,
) -> tuple[int, dict[str, Any]]:
    pr_url = validate_canonical_pr_url(pr_url)
    require_private_directory(retention_root, create=True)
    require_private_directory(checkout_parent, create=True)
    lease = acquire_retention_lease(retention_root, deadline=time.monotonic() + 30)
    attempt_dir: pathlib.Path | None = None
    attempt: AttemptLease | None = None
    supervisor: SpawnedProcess | None = None
    supervisor_owner = ForkExecResultOwner()
    supervisor_binding: dict[str, Any] | None = None
    parent, child = socket_pair()
    custody = None
    ownership_complete = False
    incomplete_handoff_writers_stopped = True
    preflight_closure_token = os.urandom(32).hex()
    process_closure_recovery: dict[str, Any] | None = None
    git_signal_checkpoint_required = False
    try:
        prepared = _prepare_with_reclamation(
            entrypoint=entrypoint,
            lease=lease,
            helper_state=helper_state,
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            pr_url=pr_url,
            retention_root=retention_root,
            checkout_parent=checkout_parent,
            git_executable=git_executable,
            codex_executable=codex_executable,
        )
        attempt_dir, state, state_digest = create_reserved_attempt(
            lease=lease,
            checkout_parent=checkout_parent,
            prompt=prepared.prompt,
            prompt_sha256=prepared.prompt_evidence["sha256"],
            custody=prepared.helper,
            admission=prepared.admission,
            base_manifest_sha256=manifest_digest(prepared.base_manifest),
            head_manifest_sha256=manifest_digest(prepared.head_manifest),
            repo=prepared.repository.repo,
            common_git_dir=prepared.repository.common_git_dir,
            pr_url=pr_url,
            git_executable=prepared.repository.git_executable,
            codex_executable=prepared.codex_executable,
            exec_budget=prepared.exec_budget,
            attempt_id=prepared.attempt_id,
        )
        attempt = open_attempt_lease(lease, attempt_dir)
        disk_state, _, disk_digest = read_bound_attempt_state(attempt)
        if disk_state != state or disk_digest != state_digest:
            raise ValueError("reserved attempt binding readback failed")
        state, state_digest = publish_prompt_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            prompt=prepared.prompt,
            deadline=time.monotonic() + 30,
        )
        handoff_deadline = time.monotonic() + HANDOFF_SECONDS
        token = os.urandom(32).hex()
        with supervisor_owner:
            supervisor = _spawn_attempt_supervisor(
                entrypoint=entrypoint,
                attempt=attempt,
                control_child=child,
                token=token,
                result_owner=supervisor_owner,
            )
            supervisor_owner.transfer(supervisor)
        incomplete_handoff_writers_stopped = False
        child.close()
        await_exec(supervisor, deadline=handoff_deadline)
        _authenticate_attempt_transfer(
            control=parent,
            process=supervisor,
            attempt=attempt,
            token=token,
            ready_type="attempt-supervisor-ready",
            deadline=handoff_deadline,
            ready_extra={"start_identity": supervisor.start_identity},
        )
        supervisor_binding = {
            "pid": supervisor.pid,
            "start_identity": supervisor.start_identity,
        }
        custody = _acquire_source_custody_via_helper(
            entrypoint=entrypoint,
            prepared=prepared,
            deadline=handoff_deadline,
        )
        send_record(
            parent,
            {
                "type": "source-custody",
                "token": token,
                "helper_custody": prepared.helper.to_json(),
            },
            deadline=handoff_deadline,
            fds=(custody.cleanup_lock_fd, custody.source_fd),
        )
        custody_accepted, _ = receive_record(parent, deadline=handoff_deadline)
        if custody_accepted != {"type": "source-custody-accepted", "token": token}:
            raise ValueError("attempt supervisor did not accept source custody")
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            updates={
                "handoff": "pending",
                "handoff_token": token,
                "supervisor": {
                    "pid": supervisor.pid,
                    "start_identity": supervisor.start_identity,
                },
                "source_custody_transferred": True,
            },
            deadline=handoff_deadline,
        )
        send_record(
            parent, {"type": "prompt-offer", "token": token}, deadline=handoff_deadline
        )
        send_blob(parent, token, prepared.prompt, deadline=handoff_deadline)
        accepted, _ = receive_record(parent, deadline=handoff_deadline)
        if (
            accepted.get("type") != "handoff-accepted"
            or accepted.get("state_sha256") is None
        ):
            raise ValueError("attempt supervisor handoff acceptance is invalid")
        disk_state, _, disk_digest = read_bound_attempt_state(attempt)
        if (
            disk_digest != accepted["state_sha256"]
            or disk_state.get("handoff") != "accepted"
        ):
            raise ValueError("durable handoff acceptance readback failed")
        send_record(
            parent, {"type": "handoff-start", "token": token}, deadline=handoff_deadline
        )
        complete, _ = receive_record(parent, deadline=handoff_deadline)
        if complete.get("type") != "handoff-complete" or complete.get("token") != token:
            raise ValueError("attempt supervisor ownership completion is invalid")
        disk_state, _, disk_digest = read_bound_attempt_state(attempt)
        if (
            disk_digest != complete.get("state_sha256")
            or disk_state.get("handoff") != "complete"
            or disk_state.get("process_owner") != "attempt-supervisor"
        ):
            raise ValueError("durable ownership-completion readback failed")
        ownership_complete = True
        send_record(
            parent,
            {
                "type": "handoff-complete-ack",
                "token": token,
                "state_sha256": disk_digest,
            },
            deadline=handoff_deadline,
        )
        custody.close()
        custody = None
        attempt.close()
        attempt = None
        lease.close()

        terminal_deadline = (
            time.monotonic()
            + CHECKOUT_SECONDS
            + REVIEWER_LAUNCH_SECONDS
            + REVIEWER_RUNTIME_SECONDS
            + 10 * 60
        )
        terminal: dict[str, Any] | None = None
        terminal_receive_error: Exception | None = None
        try:
            terminal, _ = receive_record(parent, deadline=terminal_deadline)
        except Exception as error:
            terminal_receive_error = error
        wait_terminal(supervisor.pid, deadline=time.monotonic() + 30)
        exit_code = reap(supervisor.pid)
        supervisor = None
        if exit_code in {0, 1}:
            if supervisor_binding is None:
                raise ValueError("completed supervisor has no authenticated binding")
            with acquire_retention_lease(
                retention_root, deadline=time.monotonic() + 30
            ) as completion_lease:
                with open_attempt_lease(
                    completion_lease, attempt_dir
                ) as completion_attempt:
                    summary = _select_reaped_attempt_terminal(
                        exit_code=exit_code,
                        terminal=terminal,
                        terminal_receive_error=terminal_receive_error,
                        completion_attempt=completion_attempt,
                        attempt_dir=attempt_dir,
                        token=token,
                    )
                    completed_state, _, completed_digest = read_bound_attempt_state(
                        completion_attempt
                    )
                    if _compact_terminal(completed_state) != summary:
                        raise ValueError(
                            "attempt terminal summary differs from durable terminal state"
                        )
                    if exit_code == 0:
                        completed_state, completed_digest = (
                            _publish_final_authorization(
                                entrypoint=entrypoint,
                                attempt=completion_attempt,
                                state=completed_state,
                                state_digest=completed_digest,
                                supervisor_binding=supervisor_binding,
                                supervisor_exit_code=exit_code,
                            )
                        )
                        if not _has_exact_final_authorization(
                            completion_attempt,
                            completed_state,
                        ):
                            raise ValueError(
                                "published final authorization is not exact"
                            )
                        summary = _compact_terminal(
                            completed_state,
                            final_authorization_exact=True,
                        )
        elif exit_code == 2:
            with acquire_retention_lease(
                retention_root, deadline=time.monotonic() + 30
            ) as completion_lease:
                with open_attempt_lease(
                    completion_lease, attempt_dir
                ) as completion_attempt:
                    summary = _select_reaped_attempt_terminal(
                        exit_code=exit_code,
                        terminal=terminal,
                        terminal_receive_error=terminal_receive_error,
                        completion_attempt=completion_attempt,
                        attempt_dir=attempt_dir,
                        token=token,
                    )
        else:
            raise ValueError("nonzero attempt supervisor summary is not authenticated")
        return exit_code, summary
    except BaseException as caught_error:
        failure_error = caught_error
        if isinstance(caught_error, GitProcessClosureUnproven):
            if retry_git_process_closure(caught_error):
                caught_error.finish_signal_deferral(deliver=False)
                git_signal_checkpoint_required = True
                failure_error = caught_error.__cause__ or caught_error
            else:
                process_closure_recovery = _publish_retained_git_closure_recovery(
                    recovery_root=retention_root,
                    revalidate_owner=lease.revalidate_root,
                    error=caught_error,
                    token=preflight_closure_token,
                )
                git_signal_checkpoint_required = True
        outer_cleanup_error: BaseException | None = None
        if custody is not None:
            try:
                custody.close()
            except BaseException as cleanup_error:
                outer_cleanup_error = cleanup_error
            finally:
                custody = None
        try:
            parent.close()
        except BaseException as cleanup_error:
            if outer_cleanup_error is None:
                outer_cleanup_error = cleanup_error
        if supervisor is not None:
            if ownership_complete:
                if attempt_dir is None:
                    raise ValueError(
                        "owned attempt supervisor has no durable attempt directory"
                    )
                settlement = _settle_owned_attempt_supervisor_after_failure(
                    supervisor,
                    attempt_dir=attempt_dir,
                    token=token,
                )
                if settlement is None:
                    supervisor = None
                else:
                    failure_error, direct_recovery = settlement
                    process_closure_recovery = _merge_process_closure_recovery(
                        process_closure_recovery,
                        direct_recovery,
                    )
                    incomplete_handoff_writers_stopped = False
            else:
                try:
                    _terminate_incomplete_handoff(supervisor)
                    incomplete_handoff_writers_stopped = True
                except UnprovenDirectHelperClosure as closure_error:
                    failure_error = closure_error
                    incomplete_handoff_writers_stopped = False
                except BaseException:
                    incomplete_handoff_writers_stopped = False
                else:
                    supervisor = None
        if git_signal_checkpoint_required:
            checkpoint_bound_signal_interrupt(force=True)
            git_signal_checkpoint_required = False
        if outer_cleanup_error is not None:
            raise outer_cleanup_error
        if (
            attempt_dir is not None
            and not ownership_complete
            and incomplete_handoff_writers_stopped
            and attempt is not None
            and lease.fd >= 0
            and not isinstance(
                failure_error,
                (GitProcessClosureUnproven, UnprovenDirectHelperClosure),
            )
            and direct_process_closure_failure() is None
        ):
            try:
                _prequiescence_abort(
                    entrypoint=entrypoint,
                    attempt=attempt,
                    message=(f"{type(failure_error).__name__}: {failure_error}"),
                )
            except GitProcessClosureUnproven as closure_error:
                failure_error = closure_error
                incomplete_handoff_writers_stopped = False
                process_closure_recovery = _publish_attempt_git_closure_recovery(
                    attempt=attempt,
                    error=closure_error,
                    token=preflight_closure_token,
                )
                checkpoint_bound_signal_interrupt(force=True)
            except UnprovenDirectHelperClosure as closure_error:
                failure_error = closure_error
                incomplete_handoff_writers_stopped = False
        failure = (
            failure_error.failure
            if isinstance(failure_error, SupervisorError)
            else None
        )
        return 2, {
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "overall_status": failure.status if failure else "inconclusive",
            "review_status": failure.review_status if failure else "not-run",
            "failure_stage": failure.stage if failure else "outer-supervisor",
            "failure_code": failure.code if failure else "outer-supervisor-failed",
            "message": failure.message
            if failure
            else f"{type(failure_error).__name__}: {failure_error}",
            "attempt_dir": str(attempt_dir) if attempt_dir else None,
            "process_closure_recovery": process_closure_recovery,
            "unsupported_clauses": list(UNSUPPORTED_CLAUSES),
        }
    finally:
        parent.close()
        child.close()
        if custody is not None:
            custody.close()
        if attempt is not None:
            attempt.close()
        lease.close()


def _normalize_absolute(path: pathlib.Path) -> pathlib.Path:
    normalized = pathlib.Path(os.path.abspath(os.fspath(path)))
    if not normalized.is_absolute():
        raise ValueError("path did not normalize to an absolute path")
    return normalized


def _validate_unsettled_checkout_summary(
    summary: dict[str, Any],
    *,
    attempt_dir: pathlib.Path,
    token: str,
) -> None:
    if set(summary) != UNSETTLED_CHECKOUT_SUMMARY_KEYS:
        raise ValueError("unsettled checkout terminal summary is malformed")
    receipt = summary.get("closure_receipt")
    normalized_receipt = validate_checkout_closure_receipt(
        receipt,
        attempt_dir=attempt_dir,
        token=token,
    )
    if summary != build_unsettled_checkout_summary(
        attempt_dir=attempt_dir,
        receipt=normalized_receipt,
    ):
        raise ValueError("unsettled checkout terminal summary is not canonical")


def _derive_unsettled_checkout_summary(
    attempt: AttemptLease,
    *,
    attempt_dir: pathlib.Path,
    token: str,
) -> dict[str, Any]:
    state, _, _ = read_bound_attempt_state(attempt)
    if (
        state.get("handoff") != "complete"
        or state.get("process_owner") != "attempt-supervisor"
        or state.get("handoff_token") != token
        or state.get("terminal_at") is not None
    ):
        raise ValueError("unsettled checkout has no eligible durable state")
    recovered = _read_checkout_closure_receipt(
        attempt,
        token=token,
    )
    if recovered is None:
        raise ValueError("unsettled checkout has no durable closure receipt")
    receipt, _ = recovered
    summary = build_unsettled_checkout_summary(
        attempt_dir=attempt_dir,
        receipt=receipt,
    )
    _validate_unsettled_checkout_summary(
        summary,
        attempt_dir=attempt_dir,
        token=token,
    )
    return summary


def _normalize_attempt_directory(
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    root = _normalize_absolute(retention_root)
    attempt = _normalize_absolute(attempt_dir)
    match = ATTEMPT_NAME_PATTERN.fullmatch(attempt.name)
    if attempt.parent != root or match is None:
        raise ValueError(
            "attempt directory is not an exact child of the retention root"
        )
    return root, attempt


def _open_validated_attempt(
    lease: RetentionLease,
    attempt_dir: pathlib.Path,
) -> AttemptLease:
    root, attempt_path = _normalize_attempt_directory(lease.root, attempt_dir)
    if root != lease.root:
        raise ValueError("retention lease does not bind the attempt root")
    attempt = open_attempt_lease(lease, attempt_path)
    try:
        state, _, _ = read_bound_attempt_state(attempt)
        match = ATTEMPT_NAME_PATTERN.fullmatch(attempt_path.name)
        assert match is not None
        if state.get("attempt_id") != match.group(1):
            raise ValueError("attempt directory name does not match durable state")
        return attempt
    except BaseException:
        attempt.close()
        raise


def _list_attempt_directories(lease: RetentionLease) -> tuple[pathlib.Path, ...]:
    lease.revalidate_root()
    scan_fd = os.dup(lease.root_fd)
    try:
        names = tuple(os.fsencode(value) for value in os.listdir(scan_fd))
        if len(names) > 10_001:
            raise ValueError("retention root contains too many entries")
        attempts: list[pathlib.Path] = []
        for name in names:
            if name == b"retention.lock":
                continue
            text = os.fsdecode(name)
            metadata = os.stat(name, dir_fd=lease.root_fd, follow_symlinks=False)
            if ATTEMPT_NAME_PATTERN.fullmatch(text) is None or not stat.S_ISDIR(
                metadata.st_mode
            ):
                raise ValueError("retention root contains an unrecognized entry")
            if (
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError("retained attempt has unsafe ownership or mode")
            attempts.append(lease.root / text)
            lease.revalidate_root()
        return tuple(sorted(attempts))
    finally:
        os.close(scan_fd)
        lease.revalidate_root()


def _owner_liveness(state: dict[str, Any], current_boot: str) -> dict[str, Any]:
    same_boot = state.get("boot_id") == current_boot
    supervisor = state.get("supervisor")
    if not same_boot or not isinstance(supervisor, dict):
        return {"same_boot": same_boot, "supervisor_identity": "not-applicable"}
    pid = supervisor.get("pid")
    expected = supervisor.get("start_identity")
    if type(pid) is not int or pid <= 1 or not isinstance(expected, str):
        return {"same_boot": True, "supervisor_identity": "invalid"}
    try:
        actual = process_start_identity(pid)
    except (OSError, ValueError, ProcessLookupError):
        return {"same_boot": True, "supervisor_identity": "absent-or-unverifiable"}
    return {
        "same_boot": True,
        "supervisor_identity": "matching-live" if actual == expected else "mismatch",
    }


def status(
    *,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    root = _normalize_absolute(retention_root)
    current_boot = boot_identifier()
    attempts: list[dict[str, Any]] = []
    with acquire_retention_lease(root, deadline=time.monotonic() + 30) as lease:
        paths = (
            (_normalize_attempt_directory(root, attempt_dir)[1],)
            if attempt_dir is not None
            else _list_attempt_directories(lease)
        )
        for path in paths:
            with _open_validated_attempt(lease, path) as attempt:
                state, raw, digest = read_bound_attempt_state(attempt)
                final_authorization_exact = _has_exact_final_authorization(
                    attempt, state
                )
                attempts.append(
                    {
                        **_compact_terminal(
                            state,
                            final_authorization_exact=final_authorization_exact,
                        ),
                        "phase": state.get("phase"),
                        "handoff": state.get("handoff"),
                        "closure": state.get("closure"),
                        "process_settlement": state.get("process_settlement"),
                        "checkout_settlement": state.get("checkout_settlement"),
                        "retention_state": state.get("retention_state"),
                        "record_generation": state.get("record_generation"),
                        "state_length": len(raw),
                        "state_sha256": digest,
                        "owner": _owner_liveness(state, current_boot),
                    }
                )
    return {
        "status": "ok",
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "retention_root": str(root),
        "attempt_count": len(attempts),
        "attempts": attempts,
    }


def _validate_final_authorization(
    attempt: AttemptLease,
    state: dict[str, Any],
) -> dict[str, Any]:
    attempt.revalidate(state)
    _validate_terminal_lifecycle(attempt.path, state)
    supervisor_binding = state.get("supervisor")
    if (
        not isinstance(supervisor_binding, dict)
        or set(supervisor_binding) != {"pid", "start_identity"}
        or type(supervisor_binding.get("pid")) is not int
        or supervisor_binding["pid"] <= 1
        or not isinstance(supervisor_binding.get("start_identity"), str)
        or not supervisor_binding["start_identity"]
    ):
        raise ValueError("attempt supervisor binding is malformed")
    supervisor_exit_code = state.get("supervisor_exit_code")
    handoff_token = _terminal_handoff_token(
        state, supervisor_binding, supervisor_exit_code
    )
    authorization = state.get("final_authorization")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != FINAL_AUTHORIZATION_KEYS
    ):
        raise ValueError("final authorization record is malformed")
    generation = state.get("record_generation")
    predecessor_generation = authorization.get("predecessor_generation")
    predecessor_sha256 = authorization.get("predecessor_sha256")
    if (
        type(generation) is not int
        or type(predecessor_generation) is not int
        or predecessor_generation != generation - 1
        or not isinstance(predecessor_sha256, str)
        or SHA256_PATTERN.fullmatch(predecessor_sha256) is None
        or state.get("previous_record_sha256") != predecessor_sha256
    ):
        raise ValueError("final authorization is not bound to the direct predecessor")
    if (
        authorization.get("supervisor") != supervisor_binding
        or type(authorization.get("supervisor_exit_code")) is not int
        or authorization["supervisor_exit_code"] != supervisor_exit_code
        or authorization.get("handoff_token_sha256")
        != sha256_bytes(handoff_token.encode("ascii"))
        or authorization.get("final_seal") != state.get("final_seal")
    ):
        raise ValueError("final authorization binding differs from terminal state")
    payload = {
        key: value for key, value in authorization.items() if key != "binding_sha256"
    }
    if authorization.get("binding_sha256") != sha256_bytes(canonical_json(payload)):
        raise ValueError("final authorization binding digest is invalid")
    measured = allocated_bytes_fd(attempt.fd, entry_cap=1_000)
    attempt.revalidate(state)
    expected_charge = _process_charge_fields(attempt, measured)
    if (
        state.get("retained_process_bytes") != measured
        or state.get("process_physical_remaining_by_fs")
        != expected_charge["process_physical_remaining_by_fs"]
    ):
        raise ValueError("final attempt allocation is not exactly settled")
    rewrite = state.get("final_authorization_rewrite")
    if rewrite is not None:
        validated_rewrite = validate_final_authorization_rewrite(state)
        if validated_rewrite.get("status") != "complete":
            raise ValueError("final authorization rewrite remains pending")
    return state["final_seal"]


def _has_exact_final_authorization(
    attempt: AttemptLease,
    state: dict[str, Any],
) -> bool:
    try:
        _validate_final_authorization(attempt, state)
    except Exception:
        return False
    return True


def final_result(
    *,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> dict[str, Any]:
    root, attempt_path = _normalize_attempt_directory(retention_root, attempt_dir)
    with acquire_retention_lease(root, deadline=time.monotonic() + 30) as lease:
        with _open_validated_attempt(lease, attempt_path) as attempt:
            state, _, state_digest = read_bound_attempt_state(attempt)
            if (
                state.get("process_settlement") != "exact"
                or state.get("review_status") not in {"clean", "findings"}
                or state.get("terminal_commit_authorized") is not True
            ):
                raise blocked(
                    "attempt has no exactly settled authorized review artifact",
                    stage="output",
                    code="final-evidence-unavailable",
                )
            try:
                seal = _validate_final_authorization(attempt, state)
            except (OSError, TypeError, ValueError) as error:
                raise inconclusive(
                    f"durable final authorization is invalid: {error}",
                    stage="output",
                    code="final-authorization-invalid",
                ) from error
            if not isinstance(seal, dict) or not isinstance(seal.get("identity"), dict):
                raise inconclusive(
                    "durable final seal is malformed",
                    stage="output",
                    code="final-seal-invalid",
                )
            final_path = pathlib.Path(seal.get("path", ""))
            if final_path != attempt.path / "final.txt":
                raise inconclusive(
                    "durable final seal path escaped the attempt directory",
                    stage="output",
                    code="final-seal-invalid",
                )
            attempt.revalidate(state)
            fd, identity = open_regular_at(
                attempt.fd,
                b"final.txt",
                expected_uid=os.getuid(),
                private_metadata=True,
            )
            try:
                expected_identity = Identity(**seal["identity"])
                if identity != expected_identity or seal.get("length") != identity.size:
                    raise ValueError(
                        "final artifact identity or length differs from its seal"
                    )
                content = read_fd_exact(
                    fd,
                    max_bytes=FINAL_MESSAGE_BYTES,
                    expected_size=identity.size,
                )
            finally:
                os.close(fd)
            attempt.revalidate(state)
    digest = sha256_bytes(content)
    if seal.get("sha256") != digest:
        raise inconclusive(
            "final artifact digest differs from its durable seal",
            stage="output",
            code="final-seal-invalid",
        )
    review_status, message = validate_final_message(content)
    if review_status != state["review_status"]:
        raise inconclusive(
            "final artifact classification differs from durable state",
            stage="output",
            code="final-classification-invalid",
        )
    return {
        "status": "ok",
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "attempt_id": state["attempt_id"],
        "review_status": review_status,
        "review_range": state.get("review_range"),
        "final_message": message,
        "final_seal": seal,
        "state_sha256": state_digest,
    }


def _validate_process_inventory(
    attempt: AttemptLease,
    state: dict[str, Any],
    *,
    allow_fifo: bool,
    allow_checkout_closure_recovery: bool = False,
) -> dict[str, Any]:
    attempt.revalidate(state)
    directory_fd = os.dup(attempt.fd)
    identity = identity_from_stat(os.fstat(directory_fd))
    try:
        if identity.uid != os.getuid() or stat.S_IMODE(identity.mode) != 0o700:
            raise ValueError("attempt inventory root identity is unsafe")
        names = tuple(os.fsencode(value) for value in os.listdir(directory_fd))
        if len(names) > 1_000:
            raise ValueError("attempt inventory exceeds its entry cap")
        log_bytes = 0
        temporary_names: list[str] = []
        observed: list[str] = []
        runtime_identity: dict[str, Any] | None = None
        runtime_allocated_bytes = 0
        closure_recovery: dict[str, Any] | None = None
        closure_recovery_roots: dict[str, dict[str, Any]] = {}
        closure_receipt_name = os.fsdecode(_CHECKOUT_CLOSURE_RECEIPT_NAME)
        if _CHECKOUT_CLOSURE_RECEIPT_NAME in names:
            if not allow_checkout_closure_recovery:
                raise ValueError(
                    "checkout closure recovery receipt is not allowed in this phase"
                )
            handoff_token = state.get("handoff_token")
            if (
                state.get("handoff") != "complete"
                or state.get("process_owner") != "attempt-supervisor"
                or not isinstance(handoff_token, str)
                or HANDOFF_TOKEN_PATTERN.fullmatch(handoff_token) is None
            ):
                raise ValueError(
                    "checkout closure recovery receipt has no durable ownership token"
                )
            receipt_metadata = os.stat(
                _CHECKOUT_CLOSURE_RECEIPT_NAME,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            receipt_identity = identity_from_stat(receipt_metadata)
            if (
                not stat.S_ISREG(receipt_metadata.st_mode)
                or receipt_metadata.st_uid != os.getuid()
                or stat.S_IMODE(receipt_metadata.st_mode) != 0o600
                or receipt_metadata.st_nlink != 1
                or receipt_metadata.st_size > _CHECKOUT_CLOSURE_RECEIPT_MAX_BYTES
            ):
                raise ValueError("checkout closure recovery receipt is unsafe")
            recovered = _read_checkout_closure_receipt(
                attempt,
                token=handoff_token,
            )
            if recovered is None:
                raise ValueError("checkout closure recovery receipt disappeared")
            receipt, receipt_sha256 = recovered
            refreshed_identity = identity_from_stat(
                os.stat(
                    _CHECKOUT_CLOSURE_RECEIPT_NAME,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            )
            if not identities_match(
                receipt_identity,
                refreshed_identity,
            ):
                raise ValueError("checkout closure recovery receipt changed identity")
            retained_names = {
                pathlib.Path(path).name for path in receipt["retained_cleanup_paths"]
            }
            if len(retained_names) != len(receipt["retained_cleanup_paths"]):
                raise ValueError("checkout closure recovery roots are not unique")
            closure_recovery = {
                "receipt_sha256": receipt_sha256,
                "receipt_identity": receipt_identity.to_json(),
                "retained_names": sorted(retained_names),
            }
        for raw_name in names:
            name = os.fsdecode(raw_name)
            metadata = os.stat(raw_name, dir_fd=directory_fd, follow_symlinks=False)
            if metadata.st_uid != os.getuid():
                raise ValueError(f"attempt artifact has unexpected owner: {name}")
            observed.append(name)
            if (
                closure_recovery is not None
                and name in closure_recovery["retained_names"]
            ):
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ValueError(
                        "retained Git-control recovery root identity is unsafe"
                    )
                closure_recovery_roots[name] = {
                    "identity": identity_from_stat(metadata).to_json(),
                    "allocated_bytes": 0,
                }
                root_fd = os.open(
                    raw_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    refreshed = validate_private_directory_fd(
                        root_fd,
                        pathlib.Path(name),
                    )
                    expected = Identity(**closure_recovery_roots[name]["identity"])
                    if not directory_identities_match(refreshed, expected):
                        raise OSError(
                            "retained Git-control recovery root identity changed"
                        )
                    closure_recovery_roots[name]["allocated_bytes"] = (
                        allocated_bytes_fd(root_fd, entry_cap=1_000)
                    )
                finally:
                    os.close(root_fd)
                continue
            if name == "final.fifo":
                if not allow_fifo or not stat.S_ISFIFO(metadata.st_mode):
                    raise ValueError("unexpected or unsafe final FIFO")
                continue
            if name == "review-runtime":
                if (
                    runtime_identity is not None
                    or not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ValueError("retained review runtime identity is unsafe")
                runtime_identity = identity_from_stat(metadata).to_json()
                runtime_fd = os.open(
                    raw_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    if not directory_identities_match(
                        identity_from_stat(os.fstat(runtime_fd)),
                        identity_from_stat(metadata),
                    ):
                        raise OSError("retained review runtime identity changed")
                    runtime_allocated_bytes = allocated_bytes_fd(
                        runtime_fd,
                        entry_cap=RUNTIME_CLEANUP_ENTRY_CAP,
                    )
                finally:
                    os.close(runtime_fd)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(
                    f"attempt artifact is not a single-link regular file: {name}"
                )
            if name == closure_receipt_name:
                continue
            if name == "state.json":
                continue
            if RECOVERY_TEMP_PATTERN.fullmatch(name):
                temporary_names.append(name)
                continue
            if name == RUNTIME_CLEANUP_MANIFEST:
                if metadata.st_size > RUNTIME_CLEANUP_PAYLOAD_CAP:
                    raise ValueError("runtime cleanup manifest exceeds its bound")
                temporary_names.append(name)
                continue
            if name == "prompt.txt":
                if metadata.st_size > state.get("prompt_length", -1):
                    raise ValueError("retained prompt exceeds its reserved length")
                continue
            if name == "final.txt":
                if not 1 <= metadata.st_size <= FINAL_MESSAGE_BYTES:
                    raise ValueError("retained final artifact exceeds its bound")
                continue
            if PROCESS_LOG_PATTERN.fullmatch(name):
                log_bytes += metadata.st_size
                if log_bytes > LOG_AGGREGATE_BYTES:
                    raise ValueError(
                        "retained compressed logs exceed their aggregate cap"
                    )
                continue
            raise ValueError(
                f"attempt inventory contains an unrecognized artifact: {name}"
            )
        if "state.json" not in observed:
            raise ValueError("attempt inventory has no state record")
        if closure_recovery is not None:
            retained_names = set(closure_recovery["retained_names"])
            if not set(closure_recovery_roots) <= retained_names:
                raise ValueError("checkout closure recovery root inventory escaped")
            closure_recovery["retained_roots"] = closure_recovery_roots
            closure_recovery["absent_names"] = sorted(
                retained_names - set(closure_recovery_roots)
            )
        return {
            "entry_count": len(names),
            "allocated_bytes": allocated_bytes_fd(directory_fd, entry_cap=1_000),
            "compressed_log_bytes": log_bytes,
            "temporary_names": sorted(temporary_names),
            "runtime_identity": runtime_identity,
            "runtime_allocated_bytes": runtime_allocated_bytes,
            "checkout_closure_recovery": closure_recovery,
        }
    finally:
        os.close(directory_fd)
        attempt.revalidate(state)


def _remove_recovery_artifacts(
    attempt: AttemptLease,
    state: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    attempt.revalidate(state)
    directory_fd = os.dup(attempt.fd)
    prompt_result = "absent"
    removed_temporaries: list[str] = []
    runtime_cleanup: dict[str, Any] | None = None
    closure_cleanup: dict[str, Any] | None = None
    try:
        for name in inventory["temporary_names"]:
            raw_name = os.fsencode(name)
            metadata = os.stat(raw_name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("interrupted state temporary is unsafe")
            os.unlink(raw_name, dir_fd=directory_fd)
            removed_temporaries.append(name)
        prompt_path = pathlib.Path(state["prompt_path"])
        if prompt_path != attempt.path / "prompt.txt":
            raise ValueError("reserved prompt path escaped the attempt directory")
        try:
            metadata = os.stat(
                b"prompt.txt", dir_fd=directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            pass
        else:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("recoverable prompt artifact is unsafe")
            fd = os.open(
                b"prompt.txt",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                content = read_fd_exact(
                    fd,
                    max_bytes=state["prompt_length"],
                    expected_size=metadata.st_size,
                )
            finally:
                os.close(fd)
            prompt_result = (
                "exact"
                if len(content) == state["prompt_length"]
                and sha256_bytes(content) == state["prompt_sha256"]
                else "partial"
            )
            os.unlink(b"prompt.txt", dir_fd=directory_fd)
        os.fsync(directory_fd)
        runtime_identity = inventory.get("runtime_identity")
        if runtime_identity is not None:
            if not isinstance(runtime_identity, dict):
                raise ValueError("retained runtime inventory is malformed")
            parent_identity = identity_from_stat(os.fstat(directory_fd))
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label="retained-review-runtime",
                        parent_fd=directory_fd,
                        parent_identity=parent_identity,
                        name=b"review-runtime",
                        expected_identity=Identity(**runtime_identity),
                    ),
                ),
                manifest_path=attempt.path / RUNTIME_CLEANUP_MANIFEST,
                entry_cap=RUNTIME_CLEANUP_ENTRY_CAP,
                payload_cap=RUNTIME_CLEANUP_PAYLOAD_CAP,
                deadline=time.monotonic() + 30,
            )
            deleted = False
            deletion_owner = CustodiedDeletionResultOwner()
            try:
                runtime_cleanup = delete_custodied_roots(
                    manifest,
                    deadline=time.monotonic() + 30,
                    result_owner=deletion_owner,
                )
                deletion_owner.transfer(runtime_cleanup)
                deleted = True
            except BaseException as error:
                setattr(error, "custodied_deletion_result_owner", deletion_owner)
                raise
            finally:
                manifest.close()
                if deleted:
                    remove_published_manifest(manifest.seal)
            os.fsync(directory_fd)
        closure_recovery = inventory.get("checkout_closure_recovery")
        if closure_recovery is not None:
            if not isinstance(closure_recovery, dict):
                raise ValueError("checkout closure recovery inventory is malformed")
            retained_roots = closure_recovery.get("retained_roots")
            if not isinstance(retained_roots, dict):
                raise ValueError(
                    "checkout closure recovery root inventory is malformed"
                )
            retained_cleanup_batches: list[dict[str, Any]] = []
            if retained_roots:
                parent_identity = identity_from_stat(os.fstat(directory_fd))
                retained_items = sorted(retained_roots.items())
                cleanup_deadline = time.monotonic() + 30
                for offset in range(0, len(retained_items), 2):
                    batch = retained_items[offset : offset + 2]
                    manifest = build_custodied_manifest(
                        roots=tuple(
                            RootSpec(
                                label=f"retained-git-control:{name}",
                                parent_fd=directory_fd,
                                parent_identity=parent_identity,
                                name=os.fsencode(name),
                                expected_identity=Identity(**details["identity"]),
                                private_metadata=True,
                            )
                            for name, details in batch
                        ),
                        manifest_path=attempt.path / RUNTIME_CLEANUP_MANIFEST,
                        entry_cap=RUNTIME_CLEANUP_ENTRY_CAP,
                        payload_cap=RUNTIME_CLEANUP_PAYLOAD_CAP,
                        deadline=cleanup_deadline,
                    )
                    deleted = False
                    deletion_owner = CustodiedDeletionResultOwner()
                    try:
                        batch_cleanup = delete_custodied_roots(
                            manifest,
                            deadline=cleanup_deadline,
                            result_owner=deletion_owner,
                        )
                        deletion_owner.transfer(batch_cleanup)
                        deleted = True
                    except BaseException as error:
                        setattr(
                            error,
                            "custodied_deletion_result_owner",
                            deletion_owner,
                        )
                        raise
                    finally:
                        manifest.close()
                        if deleted:
                            remove_published_manifest(manifest.seal)
                    retained_cleanup_batches.append(batch_cleanup)
                    os.fsync(directory_fd)
            handoff_token = state.get("handoff_token")
            if not isinstance(handoff_token, str):
                raise ValueError(
                    "checkout closure recovery lost its durable ownership token"
                )
            recovered = _read_checkout_closure_receipt(
                attempt,
                token=handoff_token,
            )
            if recovered is None or recovered[1] != closure_recovery.get(
                "receipt_sha256"
            ):
                raise ValueError(
                    "checkout closure recovery receipt changed before cleanup"
                )
            retained_names = closure_recovery.get("retained_names")
            if not isinstance(retained_names, list):
                raise ValueError(
                    "checkout closure recovery retained-name inventory is malformed"
                )
            for name in retained_names:
                try:
                    os.stat(
                        os.fsencode(name),
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                raise ValueError(
                    "checkout closure recovery root remains before receipt cleanup"
                )
            expected_receipt_identity = Identity(**closure_recovery["receipt_identity"])
            current_receipt_identity = identity_from_stat(
                os.stat(
                    _CHECKOUT_CLOSURE_RECEIPT_NAME,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            )
            if not identities_match(
                expected_receipt_identity,
                current_receipt_identity,
            ):
                raise ValueError(
                    "checkout closure recovery receipt changed identity before cleanup"
                )
            os.unlink(_CHECKOUT_CLOSURE_RECEIPT_NAME, dir_fd=directory_fd)
            os.fsync(directory_fd)
            closure_cleanup = {
                "receipt": "removed",
                "retained_git_control_cleanup": {
                    "batch_count": len(retained_cleanup_batches),
                    "batches": retained_cleanup_batches,
                    "exact_names_absent": True,
                },
            }
    finally:
        os.close(directory_fd)
        attempt.revalidate(state)
    return {
        "prompt_reconciliation": prompt_result,
        "removed_state_temporaries": removed_temporaries,
        "retained_runtime_cleanup": runtime_cleanup,
        "checkout_closure_recovery_cleanup": closure_cleanup,
    }


def _remove_exact_settled_runtime(
    attempt: AttemptLease,
    state: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    attempt.revalidate(state)
    directory_fd = os.dup(attempt.fd)
    removed_temporaries: list[str] = []
    runtime_cleanup: dict[str, Any] | None = None
    try:
        for name in inventory["temporary_names"]:
            raw_name = os.fsencode(name)
            metadata = os.stat(raw_name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("exact-settled cleanup temporary is unsafe")
            os.unlink(raw_name, dir_fd=directory_fd)
            removed_temporaries.append(name)
        runtime_identity = inventory.get("runtime_identity")
        if runtime_identity is not None:
            if not isinstance(runtime_identity, dict):
                raise ValueError("exact-settled runtime identity is malformed")
            parent_identity = identity_from_stat(os.fstat(directory_fd))
            manifest = build_custodied_manifest(
                roots=(
                    RootSpec(
                        label="exact-settled-review-runtime",
                        parent_fd=directory_fd,
                        parent_identity=parent_identity,
                        name=b"review-runtime",
                        expected_identity=Identity(**runtime_identity),
                    ),
                ),
                manifest_path=attempt.path / RUNTIME_CLEANUP_MANIFEST,
                entry_cap=RUNTIME_CLEANUP_ENTRY_CAP,
                payload_cap=RUNTIME_CLEANUP_PAYLOAD_CAP,
                deadline=time.monotonic() + 30,
            )
            deleted = False
            deletion_owner = CustodiedDeletionResultOwner()
            try:
                runtime_cleanup = delete_custodied_roots(
                    manifest,
                    deadline=time.monotonic() + 30,
                    result_owner=deletion_owner,
                )
                deletion_owner.transfer(runtime_cleanup)
                deleted = True
            except BaseException as error:
                setattr(error, "custodied_deletion_result_owner", deletion_owner)
                raise
            finally:
                manifest.close()
                if deleted:
                    remove_published_manifest(manifest.seal)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
        attempt.revalidate(state)
    return {
        "removed_state_temporaries": removed_temporaries,
        "retained_runtime_cleanup": runtime_cleanup,
    }


def _recover_exact_settled_runtime(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
    inventory: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    rewrite = state.get("final_authorization_rewrite")
    if rewrite is None:
        state, state_digest = _begin_final_authorization_rewrite(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            operation="runtime-cleanup",
            updates={},
        )
        rewrite = validate_final_authorization_rewrite(state)
    else:
        rewrite = validate_final_authorization_rewrite(state)
        if rewrite["status"] == "complete":
            state, state_digest = _begin_final_authorization_rewrite(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=state_digest,
                operation="runtime-cleanup",
                updates={},
            )
            rewrite = validate_final_authorization_rewrite(state)
        elif rewrite["operation"] != "runtime-cleanup":
            raise ValueError("another process rewrite operation is outstanding")

    _remove_exact_settled_runtime(attempt, state, inventory)
    state, state_digest = _settle_rewritten_process_charge(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
    )
    if rewrite["authorization_required"]:
        state, state_digest = _publish_final_authorization(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            supervisor_binding=state.get("supervisor"),
            supervisor_exit_code=state.get("supervisor_exit_code"),
        )
        if not _has_exact_final_authorization(attempt, state):
            raise ValueError("runtime-cleanup final authorization is not exact")
    else:
        state, state_digest = _complete_unauthed_final_authorization_rewrite(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
        )
    return state, state_digest


def _finish_release_authorization_rewrite(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    state: dict[str, Any],
    state_digest: str,
) -> tuple[dict[str, Any], str, bool]:
    rewrite = validate_final_authorization_rewrite(state)
    if rewrite["operation"] != "release":
        raise ValueError("release recovery has another rewrite operation")
    state, state_digest = _settle_rewritten_process_charge(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
    )
    if rewrite["authorization_required"]:
        state, state_digest = _publish_final_authorization(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=state_digest,
            supervisor_binding=state.get("supervisor"),
            supervisor_exit_code=state.get("supervisor_exit_code"),
        )
        if not _has_exact_final_authorization(attempt, state):
            raise ValueError("released final authorization is not exact")
        return state, state_digest, True
    state, state_digest = _complete_unauthed_final_authorization_rewrite(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=state_digest,
    )
    if not _process_accounting_is_exact(attempt, state):
        raise ValueError("released process accounting is not exact")
    return state, state_digest, False


def recover(
    *,
    entrypoint: pathlib.Path,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> tuple[int, dict[str, Any]]:
    root, attempt_path = _normalize_attempt_directory(retention_root, attempt_dir)
    lease = acquire_retention_lease(root, deadline=time.monotonic() + 30)
    attempt: AttemptLease | None = None
    try:
        attempt = _open_validated_attempt(lease, attempt_path)
        state, _, digest = read_bound_attempt_state(attempt)
        settlements_exact = (
            state.get("process_settlement") == "exact"
            and state.get("checkout_settlement") == "exact"
        )
        process_accounting_exact = _process_accounting_is_exact(attempt, state)
        terminal_review = state.get("review_status") in {"clean", "findings"}
        final_authorization_exact = (
            _has_exact_final_authorization(attempt, state) if terminal_review else False
        )
        rewrite = state.get("final_authorization_rewrite")
        if rewrite is not None:
            try:
                rewrite = validate_final_authorization_rewrite(state)
            except ValueError as error:
                raise inconclusive(
                    f"durable process rewrite state is invalid: {error}",
                    stage="recovery",
                    code="recovery-rewrite-invalid",
                ) from error
        if (
            isinstance(rewrite, dict)
            and rewrite.get("operation") == "release"
            and (
                rewrite.get("status") != "complete"
                or not process_accounting_exact
                or (
                    rewrite.get("authorization_required")
                    and not final_authorization_exact
                )
            )
        ):
            try:
                state, digest, final_authorization_exact = (
                    _finish_release_authorization_rewrite(
                        entrypoint=entrypoint,
                        attempt=attempt,
                        state=state,
                        state_digest=digest,
                    )
                )
            except ValueError as error:
                raise inconclusive(
                    f"release authorization recovery is invalid: {error}",
                    stage="recovery",
                    code="recovery-release-rewrite-invalid",
                ) from error
            return 0, {
                "status": "recovered",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=final_authorization_exact,
                ),
                "state_sha256": digest,
            }
        exact_inventory: dict[str, Any] | None = None
        if settlements_exact and (
            process_accounting_exact
            or (
                isinstance(rewrite, dict)
                and rewrite.get("operation") == "runtime-cleanup"
            )
        ):
            exact_inventory = _validate_process_inventory(
                attempt,
                state,
                allow_fifo=False,
            )
        exact_cleanup_authorized = (
            not terminal_review
            or final_authorization_exact
            or (
                isinstance(rewrite, dict)
                and rewrite.get("operation") == "runtime-cleanup"
            )
        )
        exact_cleanup_needed = (
            exact_inventory is not None
            and exact_cleanup_authorized
            and (
                exact_inventory.get("runtime_identity") is not None
                or bool(exact_inventory.get("temporary_names"))
                or (
                    isinstance(rewrite, dict)
                    and rewrite.get("operation") == "runtime-cleanup"
                    and (
                        rewrite.get("status") != "complete"
                        or (
                            rewrite.get("authorization_required")
                            and not final_authorization_exact
                        )
                        or not process_accounting_exact
                    )
                )
            )
        )
        if exact_cleanup_needed:
            try:
                state, digest = _recover_exact_settled_runtime(
                    entrypoint=entrypoint,
                    attempt=attempt,
                    state=state,
                    state_digest=digest,
                    inventory=exact_inventory,
                )
            except ValueError as error:
                raise inconclusive(
                    f"exact-settled runtime cleanup is invalid: {error}",
                    stage="recovery",
                    code="recovery-runtime-cleanup-invalid",
                ) from error
            final_authorization_exact = (
                _has_exact_final_authorization(attempt, state)
                if terminal_review
                else False
            )
            return 0, {
                "status": "recovered",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=final_authorization_exact,
                ),
                "state_sha256": digest,
            }
        if (
            settlements_exact
            and process_accounting_exact
            and (not terminal_review or final_authorization_exact)
        ):
            return 0, {
                "status": "already-settled",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=final_authorization_exact,
                ),
            }
        recorded_boot = state.get("boot_id")
        current_boot = boot_identifier()
        if not isinstance(recorded_boot, str):
            raise inconclusive(
                "attempt has no authenticated recorded boot identity",
                stage="recovery",
                code="recovery-boot-identity-invalid",
            )
        if recorded_boot == current_boot:
            raise blocked(
                "same-boot successor recovery cannot prove closure of the original owner and children",
                stage="recovery",
                code="same-boot-owner-required",
            )
        phase = state.get("phase")
        post_review = phase in {
            "review-finished",
            "terminal-authorization-pending",
            "reviewed",
            "post-review-aborted",
        }
        if post_review:
            try:
                _require_reviewer_closure_evidence(state)
            except ValueError as error:
                raise inconclusive(
                    f"post-review recovery closure evidence is invalid: {error}",
                    stage="recovery",
                    code="recovery-reviewer-closure-invalid",
                ) from error
        inventory = _validate_process_inventory(
            attempt,
            state,
            allow_fifo=True,
            allow_checkout_closure_recovery=True,
        )
        process_was_exact = state.get("process_settlement") == "exact"
        if process_was_exact:
            state, digest = _commit_conservative_process_rewrite(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=digest,
                updates={},
            )
        reconciliation = _remove_recovery_artifacts(attempt, state, inventory)
        if phase in {"reserved", "worktree-adding", "validating", "prelaunch-aborted"}:
            recovered_phase = "prelaunch-aborted"
            launch_status = "prelaunch-aborted"
            review_status = "not-run"
        elif phase == "spawn-intent":
            recovered_phase = "spawn-intent"
            launch_status = "uncertain"
            review_status = "inconclusive"
        elif phase == "launched":
            recovered_phase = "launched"
            launch_status = "launched"
            review_status = "inconclusive"
        elif post_review:
            recovered_phase = "post-review-aborted"
            launch_status = "completed"
            review_status = "inconclusive"
        else:
            raise inconclusive(
                f"attempt phase is not recoverable: {phase!r}",
                stage="recovery",
                code="recovery-phase-invalid",
            )
        state, digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt=attempt,
            state=state,
            state_digest=digest,
            updates={
                "phase": recovered_phase,
                "launch_status": launch_status,
                "review_status": review_status,
                "closure": (
                    "proven-by-owner" if post_review else "proven-by-boot-change"
                ),
                "abandonment": True,
                "failure_stage": "boot-change-recovery",
                "failure": {
                    "status": "inconclusive"
                    if review_status == "inconclusive"
                    else "blocked",
                    "code": "owner-lost-across-boot-change",
                    "message": "Recorded owner and child processes cannot survive the authenticated boot change.",
                },
                "recovery": {
                    "recorded_boot_id": recorded_boot,
                    "current_boot_id": current_boot,
                    "supervisor_closure": "proven-by-boot-change",
                    "process_inventory": inventory,
                    **reconciliation,
                },
                "cleanup_status": (
                    state.get("cleanup_status")
                    if state.get("checkout_settlement") == "exact"
                    else "cleanup-pending"
                ),
                "admission_status": "completed",
                "terminal_at": time.time(),
            },
            deadline=time.monotonic() + 30,
        )
        if state.get("checkout_settlement") != "exact":
            try:
                state, digest = _cleanup_worktree(
                    entrypoint=entrypoint,
                    attempt=attempt,
                    state=state,
                    state_digest=digest,
                )
            except BaseException as cleanup_error:
                state, digest = commit_via_helper(
                    entrypoint=entrypoint,
                    attempt=attempt,
                    state=state,
                    state_digest=digest,
                    updates={
                        "worktree_status": "manual-recovery-required",
                        "cleanup_status": "cleanup-warning",
                        "failure_stage": "worktree-recovery",
                        "cleanup_error": (
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        ),
                    },
                    deadline=time.monotonic() + 30,
                )
        if state.get("process_settlement") != "exact":
            state, digest = _settle_process(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=digest,
            )
        else:
            state, digest = _settle_rewritten_process_charge(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=digest,
            )
        return (
            1 if state.get("worktree_status") == "manual-recovery-required" else 0,
            {
                "status": "recovered",
                "attempt": _compact_terminal(state),
                "state_sha256": digest,
            },
        )
    finally:
        if attempt is not None:
            attempt.close()
        lease.close()


def release(
    *,
    entrypoint: pathlib.Path,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
    reason: str,
) -> tuple[int, dict[str, Any]]:
    if reason not in {"resolved", "handoff-complete"}:
        raise ValueError("release reason must be resolved or handoff-complete")
    root, attempt_path = _normalize_attempt_directory(retention_root, attempt_dir)
    lease = acquire_retention_lease(root, deadline=time.monotonic() + 30)
    attempt: AttemptLease | None = None
    try:
        attempt = _open_validated_attempt(lease, attempt_path)
        state, _, digest = read_bound_attempt_state(attempt)
        final_authorization_exact = _has_exact_final_authorization(attempt, state)
        process_accounting_exact = _process_accounting_is_exact(attempt, state)
        rewrite = state.get("final_authorization_rewrite")
        if rewrite is not None:
            rewrite = validate_final_authorization_rewrite(state)
            if rewrite["operation"] != "release":
                if rewrite["status"] != "complete":
                    raise ValueError("another process rewrite operation is outstanding")
                rewrite = None
        retention_state = state.get("retention_state")
        if retention_state in {"released", "reclaiming", "reclaimed"}:
            if state.get("release_reason") != reason:
                raise ValueError("attempt was already released for a different reason")
        if retention_state in {"reclaiming", "reclaimed"}:
            return 0, {
                "status": f"already-{retention_state}",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=final_authorization_exact,
                ),
            }
        already_released = retention_state == "released"
        if (
            retention_state not in {"held", "released"}
            or state.get("process_settlement") != "exact"
        ):
            raise blocked(
                "only exactly settled held process evidence can be released",
                stage="retention",
                code="evidence-not-releasable",
            )
        if (
            already_released
            and rewrite is not None
            and rewrite["status"] == "complete"
            and (not rewrite["authorization_required"] or final_authorization_exact)
            and process_accounting_exact
        ):
            return 0, {
                "status": "already-released",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=final_authorization_exact,
                ),
                "state_sha256": digest,
            }
        if already_released and rewrite is None and final_authorization_exact:
            return 0, {
                "status": "already-released",
                "attempt": _compact_terminal(
                    state,
                    final_authorization_exact=True,
                ),
                "state_sha256": digest,
            }
        released_at = _released_at(state) if already_released else time.time()
        if rewrite is None:
            state, digest = _begin_final_authorization_rewrite(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=digest,
                operation="release",
                updates={
                    "retention_state": "released",
                    "released_at": released_at,
                    "release_reason": reason,
                },
            )
            rewrite = validate_final_authorization_rewrite(state)
        state, digest, final_authorization_exact = (
            _finish_release_authorization_rewrite(
                entrypoint=entrypoint,
                attempt=attempt,
                state=state,
                state_digest=digest,
            )
        )
        return 0, {
            "status": "already-released" if already_released else "released",
            "attempt": _compact_terminal(
                state,
                final_authorization_exact=final_authorization_exact,
            ),
            "state_sha256": digest,
        }
    finally:
        if attempt is not None:
            attempt.close()
        lease.close()


def _released_at(state: dict[str, Any]) -> float:
    value = state.get("released_at")
    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
        raise ValueError("released attempt timestamp is malformed")
    if state.get("release_reason") not in {"resolved", "handoff-complete"}:
        raise ValueError("released attempt reason is malformed")
    return float(value)


def _released_attempt_candidates(
    lease: RetentionLease,
    *,
    released_before: float | None,
) -> tuple[pathlib.Path, ...]:
    candidates: list[tuple[float, str, pathlib.Path]] = []
    for attempt_path in _list_attempt_directories(lease):
        with _open_validated_attempt(lease, attempt_path) as attempt:
            state, _, _ = read_bound_attempt_state(attempt)
            retention_state = state.get("retention_state")
            if retention_state not in {"released", "reclaiming", "reclaimed"}:
                continue
            released_at = _released_at(state)
            if (
                state.get("process_settlement") != "exact"
                or state.get("checkout_settlement") != "exact"
                or state.get("worktree_status") == "manual-recovery-required"
            ):
                if retention_state in {"reclaiming", "reclaimed"}:
                    raise ValueError(
                        "interrupted reclaim is no longer exactly eligible"
                    )
                continue
            if (
                retention_state == "released"
                and released_before is not None
                and released_at > released_before
            ):
                continue
            candidates.append((released_at, attempt.path.name, attempt.path))
    return tuple(value[2] for value in sorted(candidates))


def _remove_reclaim_artifacts(
    attempt: AttemptLease,
    state: dict[str, Any],
) -> None:
    attempt.revalidate(state)
    attempt_fd = os.dup(attempt.fd)
    try:
        names = tuple(os.fsencode(value) for value in os.listdir(attempt_fd))
        if len(names) > 1_000:
            raise ValueError("reclaiming attempt exceeds cleanup entry cap")
        if b"state.json" not in names:
            raise ValueError("reclaiming attempt lost its durable state")
        for name in sorted(value for value in names if value != b"state.json"):
            metadata = os.stat(name, dir_fd=attempt_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError(
                    "reclaiming attempt contains a non-regular or unsafe artifact"
                )
            os.unlink(name, dir_fd=attempt_fd)
        os.fsync(attempt_fd)
    finally:
        os.close(attempt_fd)
        attempt.revalidate(state)


def _remove_reclaimed_attempt(
    attempt: AttemptLease,
    state: dict[str, Any],
) -> None:
    attempt.revalidate(state)
    attempt_fd = os.dup(attempt.fd)
    try:
        names = tuple(os.fsencode(value) for value in os.listdir(attempt_fd))
        if names != (b"state.json",):
            raise ValueError(
                "reclaimed attempt contains artifacts beyond durable state"
            )
        metadata = os.stat(b"state.json", dir_fd=attempt_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ValueError("reclaimed attempt state is unsafe")
        os.unlink(b"state.json", dir_fd=attempt_fd)
        os.fsync(attempt_fd)
    finally:
        os.close(attempt_fd)
    attempt.revalidate()
    remove_bound_attempt_directory(attempt)


def _reclaim_attempt_locked(
    *,
    entrypoint: pathlib.Path,
    attempt: AttemptLease,
    trigger: str,
) -> dict[str, Any]:
    if trigger not in {"explicit", "ttl", "admission-pressure"}:
        raise ValueError("reclaim trigger is invalid")
    state, _, digest = read_bound_attempt_state(attempt)
    retention_state = state.get("retention_state")
    if retention_state not in {"released", "reclaiming", "reclaimed"}:
        raise blocked(
            "attempt evidence has not been explicitly released",
            stage="retention",
            code="release-required",
        )
    _released_at(state)
    rewrite = state.get("final_authorization_rewrite")
    if rewrite is not None:
        rewrite = validate_final_authorization_rewrite(state)
        if rewrite["status"] != "complete" or (
            rewrite["authorization_required"]
            and not _has_exact_final_authorization(attempt, state)
        ):
            raise blocked(
                "attempt release authorization rewrite is not complete",
                stage="retention",
                code="release-authorization-pending",
            )
        if (
            retention_state == "released"
            and not rewrite["authorization_required"]
            and not _process_accounting_is_exact(attempt, state)
        ):
            raise blocked(
                "attempt release accounting rewrite is not complete",
                stage="retention",
                code="release-accounting-pending",
            )
    if (
        state.get("process_settlement") != "exact"
        or state.get("checkout_settlement") != "exact"
    ):
        raise blocked(
            "attempt cannot be reclaimed before both ledgers settle exactly",
            stage="retention",
            code="settlement-required",
        )
    if state.get("worktree_status") == "manual-recovery-required":
        raise blocked(
            "manual worktree recovery remains outstanding",
            stage="retention",
            code="manual-worktree-recovery-required",
        )
    attempt_id = state["attempt_id"]
    if retention_state == "reclaimed":
        if (
            state.get("retained_process_bytes") != 0
            or state.get("process_physical_remaining_by_fs") != {}
        ):
            raise ValueError("reclaimed attempt retained a nonzero process charge")
        _remove_reclaimed_attempt(attempt, state)
        return {
            "attempt_id": attempt_id,
            "state_sha256_before_removal": digest,
        }

    _validate_process_inventory(attempt, state, allow_fifo=False)
    started_at = state.get("reclaim_started_at")
    if type(started_at) not in {int, float}:
        started_at = time.time()
    original_trigger = state.get("reclaim_trigger")
    state, digest = _commit_conservative_process_rewrite(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=digest,
        updates={
            "retention_state": "reclaiming",
            "reclaim_started_at": started_at,
            "reclaim_trigger": original_trigger or trigger,
        },
    )
    _validate_process_inventory(attempt, state, allow_fifo=False)
    _remove_reclaim_artifacts(attempt, state)
    state, digest = commit_via_helper(
        entrypoint=entrypoint,
        attempt=attempt,
        state=state,
        state_digest=digest,
        updates={
            "retention_state": "reclaimed",
            "reclaimed_at": time.time(),
            "retained_process_bytes": 0,
            "process_physical_remaining_by_fs": {},
        },
        deadline=time.monotonic() + 30,
    )
    _remove_reclaimed_attempt(attempt, state)
    return {
        "attempt_id": attempt_id,
        "state_sha256_before_removal": digest,
    }


def _reclaim_released_attempts(
    *,
    entrypoint: pathlib.Path,
    root: pathlib.Path,
    lease: RetentionLease,
    trigger: str,
    released_before: float | None = None,
    limit: int | None = None,
) -> tuple[str, ...]:
    if limit is not None and limit < 1:
        raise ValueError("reclaim limit must be positive")
    reclaimed: list[str] = []
    lease.revalidate_root()
    for attempt_path in _released_attempt_candidates(
        lease, released_before=released_before
    ):
        with _open_validated_attempt(lease, attempt_path) as attempt:
            result = _reclaim_attempt_locked(
                entrypoint=entrypoint,
                attempt=attempt,
                trigger=trigger,
            )
        reclaimed.append(result["attempt_id"])
        if limit is not None and len(reclaimed) >= limit:
            break
    return tuple(reclaimed)


def _remove_empty_attempt_residue(
    lease: RetentionLease,
    attempt_path: pathlib.Path,
) -> bool:
    lease.revalidate_root()
    attempt_fd: int | None = None
    try:
        try:
            attempt_fd = os.open(
                os.fsencode(attempt_path.name),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=lease.root_fd,
            )
        except FileNotFoundError:
            lease.revalidate_root()
            return True
        metadata = os.fstat(attempt_fd)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("empty cleanup residue has unsafe ownership or mode")
        if os.listdir(attempt_fd):
            return False
        residue = AttemptLease(
            retention=lease,
            path=attempt_path,
            fd=attempt_fd,
            identity=identity_from_stat(metadata),
        )
        remove_bound_attempt_directory(residue)
        residue.close()
        attempt_fd = None
        return True
    finally:
        if attempt_fd is not None:
            os.close(attempt_fd)


def cleanup(
    *,
    entrypoint: pathlib.Path,
    retention_root: pathlib.Path,
    attempt_dir: pathlib.Path,
) -> tuple[int, dict[str, Any]]:
    root, attempt_path = _normalize_attempt_directory(retention_root, attempt_dir)
    with acquire_retention_lease(root, deadline=time.monotonic() + 30) as lease:
        try:
            attempt = _open_validated_attempt(lease, attempt_path)
        except FileNotFoundError:
            if _remove_empty_attempt_residue(lease, attempt_path):
                return 0, {
                    "status": "already-reclaimed",
                    "attempt_id": ATTEMPT_NAME_PATTERN.fullmatch(
                        attempt_path.name
                    ).group(1),
                    "attempt_dir": str(attempt_path),
                }
            raise
        try:
            result = _reclaim_attempt_locked(
                entrypoint=entrypoint,
                attempt=attempt,
                trigger="explicit",
            )
        finally:
            attempt.close()
        return 0, {
            "status": "reclaimed",
            "attempt_id": result["attempt_id"],
            "attempt_dir": str(attempt_path),
            "state_sha256_before_removal": result["state_sha256_before_removal"],
        }
