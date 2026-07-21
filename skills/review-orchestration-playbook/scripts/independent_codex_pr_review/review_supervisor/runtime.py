from __future__ import annotations

import fcntl
import math
import os
import pathlib
import re
import selectors
import signal
import socket
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any

from .appserver_runtime import build_prelaunch_appserver_input
from .checkout import (
    RawMaterializer,
    probe_name_semantics,
    read_and_validate_symlink_graphs,
    validate_namespaces,
)
from .constants import (
    CHECKOUT_SECONDS,
    FINAL_MESSAGE_BYTES,
    HANDOFF_SECONDS,
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    PRIMARY_DIFF_RELATIVE_PATH,
    PROCESS_TERM_GRACE_SECONDS,
    READER_DRAIN_SECONDS,
    REVIEWER_LAUNCH_SECONDS,
    tool_root,
)
from .evidence import (
    AuthenticatedManifest,
    EvidenceError,
    ManifestEntry,
    manifest_sha256 as evidence_manifest_sha256,
)
from .errors import SupervisorError, inconclusive
from .gitraw import (
    WorktreeRegistration,
    add_detached_worktree,
    enumerate_registration,
    enumerate_tree,
    initialize_index,
    inspect_repository,
    manifest_digest,
    remove_both_present_worktree,
    verify_worktree_absent,
)
from .ledger import commit_state, read_attempt_state
from .models import HelperCustody, Identity
from .no_child_profile import LaunchedNoChildProcess
from .process import (
    SpawnedProcess,
    TerminationSchedule,
    await_exec,
    fork_exec,
    process_start_identity,
    reap,
    require_authenticated_no_child_process_profile,
    signal_anchored_group,
    terminate_direct_process,
    wait_terminal,
)
from .prompt import prompt_evidence
from .review_execution import AuthenticatedReviewResult, run_authenticated_review
from .recovery_cleanup import (
    CustodiedManifest,
    RootSpec,
    build_custodied_manifest,
    delete_custodied_roots,
    enumerate_registration_conflicts,
    remove_published_manifest,
    require_no_registration_conflicts,
)
from .secureio import (
    allocated_bytes,
    canonical_json,
    directory_identities_match,
    identity_from_stat,
    measure_filesystem,
    open_absolute_directory_chain,
    open_regular_nofollow,
    publish_bytes,
    read_fd_exact,
    sha256_bytes,
    fsync_directory,
    validate_private_directory_fd,
)
from .settlement_state import publish_exact_process_settlement
from .wire import (
    peer_is_open,
    receive_blob,
    receive_record,
    send_blob,
    send_record,
    socket_pair,
)


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_HANDOFF_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_KEYS = frozenset({"device", "inode", "mode", "link_count", "uid", "size"})
_FINAL_AUTHORIZATION_KEYS = frozenset(
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
_FINAL_AUTHORIZATION_REWRITE_KEYS = frozenset(
    {
        "version",
        "operation",
        "status",
        "source_generation",
        "source_sha256",
        "source_previous_record_sha256",
        "authorization_required",
        "source_final_authorization",
        "source_binding_sha256",
    }
)

_KNOWN_PHASES = frozenset(
    {
        "reserved",
        "worktree-adding",
        "validating",
        "spawn-intent",
        "launched",
        "review-finished",
        "terminal-authorization-pending",
        "reviewed",
        "prelaunch-aborted",
        "post-review-aborted",
    }
)


def _transition(
    predecessors: set[str] | frozenset[str],
    successor: str | None,
    keys: set[str] | frozenset[str],
) -> tuple[frozenset[str], str | None, frozenset[str]]:
    return frozenset(predecessors), successor, frozenset(keys)


_FAILURE_KEYS = frozenset(
    {
        "phase",
        "launch_status",
        "review_status",
        "closure",
        "abandonment",
        "failure_stage",
        "failure",
        "cleanup_status",
    }
)
_CLEANUP_PHASES = _KNOWN_PHASES
_ORDINARY_PHASE_TRANSITIONS = (
    _transition(
        {"reserved"},
        "reserved",
        {"handoff", "handoff_token", "supervisor", "source_custody_transferred"},
    ),
    _transition(
        {"reserved"},
        "reserved",
        {"handoff", "prompt_private_copy_verified"},
    ),
    _transition(
        {"reserved"},
        "reserved",
        {"handoff", "process_owner", "ownership_linearized_at"},
    ),
    _transition(
        {"reserved"},
        "worktree-adding",
        {"phase", "worktree_status"},
    ),
    _transition(
        {"worktree-adding"},
        "worktree-adding",
        {"registration", "worktree_status"},
    ),
    _transition(
        {"worktree-adding"},
        "worktree-adding",
        {"registration_initial_enumeration", "registration", "worktree_status"},
    ),
    _transition(
        {"worktree-adding"},
        "validating",
        {"phase", "name_semantics", "symlink_target_count"},
    ),
    _transition(
        {"validating"},
        "validating",
        {"checkout_evidence", "source_custody_released", "worktree_status"},
    ),
    _transition(
        {"validating"},
        "spawn-intent",
        {
            "phase",
            "runtime_stage",
            "launch_status",
            "leader",
            "runtime_process_binding",
            "no_child_process_profile",
            "leader_exit",
            "closure",
        },
    ),
    _transition(
        {"spawn-intent"},
        "launched",
        {
            "phase",
            "launch_status",
            "leader",
            "runtime_process_binding",
            "no_child_process_profile",
        },
    ),
    _transition(
        {"launched"},
        "validating",
        {"phase", "launch_status", "closure", "leader_exit", "process_history"},
    ),
    _transition(
        {"launched"},
        "review-finished",
        {"phase", "launch_status", "closure", "leader_exit", "process_history"},
    ),
    _transition(
        {"review-finished"},
        "terminal-authorization-pending",
        {"phase", "closure", "leader_exit", "observed_runtime"},
    ),
    _transition(
        {"terminal-authorization-pending"},
        "reviewed",
        {"phase", "launch_status", "review_status", "final_seal", "failure_stage"},
    ),
    _transition(
        {"reserved"},
        "prelaunch-aborted",
        {
            "phase",
            "handoff",
            "process_owner",
            "launch_status",
            "review_status",
            "closure",
            "failure_stage",
            "failure",
            "cleanup_status",
        },
    ),
    _transition(
        {"reserved", "worktree-adding", "validating", "spawn-intent"},
        "prelaunch-aborted",
        _FAILURE_KEYS,
    ),
    _transition(_KNOWN_PHASES, None, _FAILURE_KEYS),
    _transition(
        {"reserved", "worktree-adding", "validating", "spawn-intent"},
        "prelaunch-aborted",
        _FAILURE_KEYS | {"observed_runtime"},
    ),
    _transition(_KNOWN_PHASES, None, _FAILURE_KEYS | {"observed_runtime"}),
    _transition(
        _CLEANUP_PHASES,
        None,
        {
            "worktree_status",
            "checkout_settlement",
            "reservation_status",
            "cleanup_status",
            "cleanup_warning",
            "failure_stage",
            "cleanup_error",
            "cleanup_recovery_evidence",
            "unsupported_clauses",
        },
    ),
    _transition(
        _CLEANUP_PHASES,
        None,
        {
            "worktree_status",
            "retained_worktree",
            "checkout_cleanup_evidence",
            "checkout_settlement",
            "checkout_physical_remaining_by_fs",
            "unsupported_clauses",
        },
    ),
    _transition(
        _CLEANUP_PHASES,
        None,
        {
            "worktree_status",
            "retained_worktree",
            "checkout_settlement",
            "reservation_status",
            "cleanup_status",
            "cleanup_warning",
            "worktree_cleanup_intent",
            "targeted_cleanup",
            "unsupported_clauses",
        },
    ),
    _transition(
        _CLEANUP_PHASES,
        None,
        {"worktree_cleanup_intent", "targeted_cleanup", "checkout_cleanup_progress"},
    ),
    _transition(
        _CLEANUP_PHASES,
        None,
        {
            "worktree_status",
            "retained_worktree",
            "checkout_cleanup_evidence",
            "checkout_settlement",
            "checkout_physical_remaining_by_fs",
            "cleanup_status",
            "cleanup_warning",
            "worktree_cleanup_intent",
            "targeted_cleanup",
            "unsupported_clauses",
        },
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {"admission_status", "terminal_at", "failure_stage"},
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {"retained_process_bytes", "process_physical_remaining_by_fs"},
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {
            "retention_state",
            "released_at",
            "release_reason",
            "final_authorization_rewrite",
            "retained_process_bytes",
            "process_physical_remaining_by_fs",
        },
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {
            "final_authorization_rewrite",
            "retained_process_bytes",
            "process_physical_remaining_by_fs",
        },
    ),
    _transition(_KNOWN_PHASES, None, {"final_authorization_rewrite"}),
    _transition(
        _KNOWN_PHASES,
        None,
        {
            "retention_state",
            "reclaim_started_at",
            "reclaim_trigger",
            "retained_process_bytes",
            "process_physical_remaining_by_fs",
        },
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {
            "retention_state",
            "reclaimed_at",
            "retained_process_bytes",
            "process_physical_remaining_by_fs",
        },
    ),
    _transition(
        {"reserved", "worktree-adding", "validating", "prelaunch-aborted"},
        "prelaunch-aborted",
        {
            "phase",
            "launch_status",
            "review_status",
            "closure",
            "abandonment",
            "failure_stage",
            "failure",
            "recovery",
            "cleanup_status",
            "admission_status",
            "terminal_at",
        },
    ),
    _transition(
        {"spawn-intent"},
        "spawn-intent",
        {
            "phase",
            "launch_status",
            "review_status",
            "closure",
            "abandonment",
            "failure_stage",
            "failure",
            "recovery",
            "cleanup_status",
            "admission_status",
            "terminal_at",
        },
    ),
    _transition(
        {"launched"},
        "launched",
        {
            "phase",
            "launch_status",
            "review_status",
            "closure",
            "abandonment",
            "failure_stage",
            "failure",
            "recovery",
            "cleanup_status",
            "admission_status",
            "terminal_at",
        },
    ),
    _transition(
        {
            "review-finished",
            "terminal-authorization-pending",
            "reviewed",
            "post-review-aborted",
        },
        "post-review-aborted",
        {
            "phase",
            "launch_status",
            "review_status",
            "closure",
            "abandonment",
            "failure_stage",
            "failure",
            "recovery",
            "cleanup_status",
            "admission_status",
            "terminal_at",
        },
    ),
    _transition(
        _KNOWN_PHASES,
        None,
        {"worktree_status", "cleanup_status", "failure_stage", "cleanup_error"},
    ),
)


def _identity(value: dict[str, Any]) -> Identity:
    return Identity(
        device=value["device"],
        inode=value["inode"],
        mode=value["mode"],
        link_count=value["link_count"],
        uid=value["uid"],
        size=value["size"],
    )


def _custody(value: dict[str, Any]) -> HelperCustody:
    return HelperCustody(
        state_dir=value["state_dir"],
        state_identity=_identity(value["state_identity"]),
        workspace_root=value["workspace_root"],
        source_path=value["source_path"],
        source_identity=_identity(value["source_identity"]),
        cleanup_lock_path=value["cleanup_lock_path"],
        cleanup_lock_identity=_identity(value["cleanup_lock_identity"]),
        review_range=value["review_range"],
        base_sha=value["base_sha"],
        head_sha=value["head_sha"],
        diff_length=value["diff_length"],
        diff_sha256=value["diff_sha256"],
        preflight_sha256=value["preflight_sha256"],
        control_state_sha256=value["control_state_sha256"],
    )


@dataclass
class DurableProcessLifecycle:
    entrypoint: pathlib.Path
    attempt_dir: pathlib.Path
    lease_fd: int
    state: dict[str, Any]
    state_digest: str

    def begin(self, stage: str) -> None:
        self._validate_stage(stage)
        self._validate_begin_predecessor(stage)
        self.state, self.state_digest = commit_via_helper(
            entrypoint=self.entrypoint,
            attempt_dir=self.attempt_dir,
            lease_fd=self.lease_fd,
            state=self.state,
            state_digest=self.state_digest,
            updates={
                "phase": "spawn-intent",
                "runtime_stage": stage,
                "launch_status": "spawn-intent",
                "leader": None,
                "runtime_process_binding": None,
                "no_child_process_profile": None,
                "leader_exit": None,
                "closure": "unproven",
            },
            deadline=time.monotonic() + 30,
        )

    def launched(self, stage: str, process: LaunchedNoChildProcess) -> None:
        self._validate_stage(stage)
        if (
            self.state.get("phase") != "spawn-intent"
            or self.state.get("runtime_stage") != stage
        ):
            raise ValueError("durable process launch has no matching spawn intent")
        leader = {
            "pid": process.pid,
            "pgid": process.pgid,
            "start_identity": process.start_identity,
        }
        runtime_binding = {
            "session_id": process.session_id,
            "profile_sha256": process.profile_sha256,
        }
        self.state, self.state_digest = commit_via_helper(
            entrypoint=self.entrypoint,
            attempt_dir=self.attempt_dir,
            lease_fd=self.lease_fd,
            state=self.state,
            state_digest=self.state_digest,
            updates={
                "phase": "launched",
                "launch_status": "launched",
                "leader": leader,
                "runtime_process_binding": runtime_binding,
                "no_child_process_profile": {
                    "version": 1,
                    "authenticated": True,
                    "kernel_enforced": True,
                    "child_process_limit": 0,
                    "leader": leader,
                },
            },
            deadline=time.monotonic() + 30,
        )

    def closed(self, stage: str, *, exit_code: int) -> None:
        self._validate_stage(stage)
        if type(exit_code) is not int:
            raise ValueError("durable process exit status is invalid")
        if (
            self.state.get("phase") != "launched"
            or self.state.get("runtime_stage") != stage
        ):
            raise ValueError("durable process closure has no matching launch")
        leader = self.state.get("leader")
        if not isinstance(leader, dict):
            raise ValueError("durable process closure has no leader binding")
        runtime_binding = self.state.get("runtime_process_binding")
        if not isinstance(runtime_binding, dict):
            raise ValueError("durable process closure has no runtime binding")
        history = self.state.get("process_history", [])
        if not isinstance(history, list) or len(history) >= 2:
            raise ValueError(
                "durable process history is malformed or exceeds its bound"
            )
        history = [
            *history,
            {
                "stage": stage,
                "leader": dict(leader),
                "runtime_binding": dict(runtime_binding),
                "exit_code": exit_code,
                "closure": "proven-by-owner",
            },
        ]
        self.state, self.state_digest = commit_via_helper(
            entrypoint=self.entrypoint,
            attempt_dir=self.attempt_dir,
            lease_fd=self.lease_fd,
            state=self.state,
            state_digest=self.state_digest,
            updates={
                "phase": "validating" if stage == "auth-refresh" else "review-finished",
                "launch_status": "completed",
                "closure": "proven-by-owner",
                "leader_exit": exit_code,
                "process_history": history,
            },
            deadline=time.monotonic() + 30,
        )

    @staticmethod
    def _validate_stage(stage: str) -> None:
        if stage not in {"auth-refresh", "reviewer"}:
            raise ValueError("durable process stage is invalid")

    def _validate_begin_predecessor(self, stage: str) -> None:
        if self.state.get("phase") != "validating":
            raise ValueError("durable process spawn intent has an invalid phase")
        history = self.state.get("process_history")
        if not isinstance(history, list):
            raise ValueError("durable process history is malformed")
        if not history:
            expected = {
                "launch_status": "not-attempted",
                "runtime_stage": None,
                "leader": None,
                "runtime_process_binding": None,
                "no_child_process_profile": None,
                "leader_exit": None,
                "closure": "unproven",
            }
            if any(self.state.get(key) != value for key, value in expected.items()):
                raise ValueError("durable process initial predecessor is not pristine")
            return
        if stage != "reviewer" or len(history) != 1:
            raise ValueError("durable process stage history is out of sequence")
        previous = history[0]
        if (
            not isinstance(previous, dict)
            or set(previous)
            != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
            or previous.get("stage") != "auth-refresh"
            or previous.get("exit_code") != 0
            or previous.get("closure") != "proven-by-owner"
            or not isinstance(previous.get("leader"), dict)
            or not isinstance(previous.get("runtime_binding"), dict)
        ):
            raise ValueError("durable auth-refresh history is malformed")
        expected = {
            "launch_status": "completed",
            "runtime_stage": "auth-refresh",
            "leader": previous["leader"],
            "runtime_process_binding": previous["runtime_binding"],
            "leader_exit": 0,
            "closure": "proven-by-owner",
        }
        if any(self.state.get(key) != value for key, value in expected.items()):
            raise ValueError("durable auth-refresh predecessor changed")
        profile = self.state.get("no_child_process_profile")
        if (
            not isinstance(profile, dict)
            or set(profile)
            != {
                "version",
                "authenticated",
                "kernel_enforced",
                "child_process_limit",
                "leader",
            }
            or profile.get("version") != 1
            or profile.get("authenticated") is not True
            or profile.get("kernel_enforced") is not True
            or profile.get("child_process_limit") != 0
            or profile.get("leader") != previous["leader"]
        ):
            raise ValueError("durable auth-refresh profile is malformed")


def _registration(value: dict[str, Any]) -> WorktreeRegistration:
    return WorktreeRegistration(
        worktree=pathlib.Path(value["worktree"]),
        registration=pathlib.Path(value["registration"]),
        worktree_identity=_identity(value["worktree_identity"]),
        registration_identity=_identity(value["registration_identity"]),
        marker_identity=_identity(value["marker_identity"]),
        descendant_count=value["descendant_count"],
        descendant_path_bytes=value["descendant_path_bytes"],
    )


def _registration_json(value: WorktreeRegistration) -> dict[str, Any]:
    return {
        "worktree": str(value.worktree),
        "registration": str(value.registration),
        "worktree_identity": value.worktree_identity.to_json(),
        "registration_identity": value.registration_identity.to_json(),
        "marker_identity": value.marker_identity.to_json(),
        "descendant_count": value.descendant_count,
        "descendant_path_bytes": value.descendant_path_bytes,
    }


def _open_devnull() -> int:
    return os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)


def _kill_direct(process: SpawnedProcess) -> None:
    try:
        terminate_direct_process(
            process,
            grace_seconds=1.0,
            deadline=time.monotonic() + 2.0,
        )
    except (ChildProcessError, TimeoutError):
        pass


def _spawn_internal(
    *,
    entrypoint: pathlib.Path,
    mode: str,
    arguments: tuple[str, ...],
    cwd: pathlib.Path,
    pass_fds: tuple[int, ...],
    own_process_group: bool,
) -> SpawnedProcess:
    devnull = _open_devnull()
    try:
        argv = (sys.executable, str(entrypoint), mode, *arguments)
        return fork_exec(
            argv,
            cwd=cwd,
            stdin_fd=devnull,
            stdout_fd=devnull,
            stderr_fd=devnull,
            pass_fds=pass_fds,
            own_process_group=own_process_group,
        )
    finally:
        os.close(devnull)


def _validate_ordinary_phase_updates(
    *,
    attempt_dir: pathlib.Path,
    state: dict[str, Any],
    state_digest: str,
    updates: dict[str, Any],
) -> None:
    protected_authorization_fields = {
        "terminal_commit_authorized",
        "terminal_authorization",
        "terminal_authorization_proof",
        "final_authorization",
        "supervisor_exit_code",
    }
    if protected_authorization_fields.intersection(updates):
        raise ValueError("phase helper cannot mutate authorization-owned fields")
    predecessor = state.get("phase")
    successor = updates.get("phase", predecessor)
    update_keys = frozenset(updates)
    if (
        predecessor not in _KNOWN_PHASES
        or successor not in _KNOWN_PHASES
        or not any(
            predecessor in predecessors
            and (expected_successor is None or successor == expected_successor)
            and update_keys == expected_keys
            for predecessors, expected_successor, expected_keys in _ORDINARY_PHASE_TRANSITIONS
        )
    ):
        raise ValueError("phase helper transition shape is not allowlisted")
    if update_keys in {_FAILURE_KEYS, _FAILURE_KEYS | {"observed_runtime"}}:
        if updates.get("review_status") not in {"not-run", "inconclusive"}:
            raise ValueError("failure transition cannot publish a review result")
    if "supervisor" in updates or "handoff_token" in updates:
        supervisor = updates.get("supervisor")
        handoff_token = updates.get("handoff_token")
        if (
            state.get("supervisor") is not None
            or state.get("handoff") != "none"
            or state.get("process_owner") != "outer"
            or updates.get("handoff") != "pending"
            or not isinstance(supervisor, dict)
            or set(supervisor) != {"pid", "start_identity"}
            or type(supervisor.get("pid")) is not int
            or supervisor["pid"] <= 1
            or not isinstance(supervisor.get("start_identity"), str)
            or not supervisor["start_identity"]
            or not isinstance(handoff_token, str)
            or len(handoff_token) != 64
            or any(value not in "0123456789abcdef" for value in handoff_token)
        ):
            raise ValueError("supervisor handoff binding transition is invalid")
    if updates.get("review_status") in {"clean", "findings"} or "final_seal" in updates:
        authorization = state.get("terminal_authorization")
        proof = state.get("terminal_authorization_proof")
        final_seal = updates.get("final_seal")
        if (
            state.get("terminal_commit_authorized") is not True
            or not isinstance(authorization, dict)
            or not isinstance(proof, dict)
            or proof.get("predecessor_sha256") != state.get("previous_record_sha256")
            or proof.get("final_seal") != final_seal
            or proof.get("leader_exit") != authorization.get("leader_exit")
            or authorization.get("final_seal") != final_seal
            or proof.get("readback") != "exact-nofollow-under-publication-lease"
        ):
            raise ValueError("terminal commit is not bound to its authorization")
        expected_binding = sha256_bytes(
            canonical_json(
                {
                    "predecessor_sha256": proof["predecessor_sha256"],
                    "leader_exit": proof.get("leader_exit"),
                    "final_seal": final_seal,
                }
            )
        )
        if proof.get("binding_sha256") != expected_binding:
            raise ValueError("terminal authorization binding is invalid")
    rewrite = updates.get("final_authorization_rewrite")
    current_rewrite = state.get("final_authorization_rewrite")
    if rewrite is not None:
        if current_rewrite is None:
            operation = rewrite.get("operation") if isinstance(rewrite, dict) else None
            expected_rewrite = build_final_authorization_rewrite(
                attempt_dir=attempt_dir,
                state=state,
                state_digest=state_digest,
                operation=operation,
            )
            if rewrite != expected_rewrite:
                raise ValueError("final authorization rewrite intent is invalid")
        else:
            validated = validate_final_authorization_rewrite(state)
            if (
                validated["status"] == "complete"
                and isinstance(rewrite, dict)
                and rewrite.get("status") == "pending"
            ):
                operation = (
                    rewrite.get("operation") if isinstance(rewrite, dict) else None
                )
                expected_rewrite = build_final_authorization_rewrite(
                    attempt_dir=attempt_dir,
                    state=state,
                    state_digest=state_digest,
                    operation=operation,
                )
                if rewrite != expected_rewrite:
                    raise ValueError(
                        "chained final authorization rewrite intent is invalid"
                    )
            elif rewrite != complete_final_authorization_rewrite(validated):
                raise ValueError("final authorization rewrite completion is invalid")


def _validate_process_binding(
    leader: Any,
    runtime_binding: Any,
    *,
    label: str,
) -> None:
    if (
        not isinstance(leader, dict)
        or set(leader) != {"pid", "pgid", "start_identity"}
        or type(leader.get("pid")) is not int
        or leader["pid"] <= 1
        or leader.get("pgid") != leader["pid"]
        or not isinstance(leader.get("start_identity"), str)
        or not leader["start_identity"]
    ):
        raise ValueError(f"{label} leader binding is malformed")
    if (
        not isinstance(runtime_binding, dict)
        or set(runtime_binding) != {"session_id", "profile_sha256"}
        or runtime_binding.get("session_id") != leader["pid"]
        or not isinstance(runtime_binding.get("profile_sha256"), str)
        or _SHA256_PATTERN.fullmatch(runtime_binding["profile_sha256"]) is None
    ):
        raise ValueError(f"{label} runtime binding is malformed")


def _validate_observed_runtime(state: dict[str, Any]) -> None:
    observed = state.get("observed_runtime")
    expected_keys = {
        "process",
        "protocol",
        "model",
        "containment",
        "actual_invocation_enabled",
        "auth",
        "auth_refresh",
        "evidence_bundle_sha256",
        "model_input_length",
        "model_input_sha256",
        "requested_model",
        "requested_reasoning_effort",
        "transport",
    }
    if not isinstance(observed, dict) or set(observed) != expected_keys:
        raise ValueError("terminal observed runtime is malformed")
    process = observed.get("process")
    if (
        not isinstance(process, dict)
        or set(process)
        != {
            "elapsed_seconds",
            "exit_code",
            "stderr_bytes",
            "stdout_bytes",
            "streamed_message_bytes",
        }
        or type(process.get("exit_code")) is not int
        or process["exit_code"] != state.get("leader_exit")
        or type(process.get("elapsed_seconds")) not in {int, float}
        or not math.isfinite(process["elapsed_seconds"])
        or process["elapsed_seconds"] < 0
        or any(
            type(process.get(key)) is not int or process[key] < 0
            for key in ("stderr_bytes", "stdout_bytes", "streamed_message_bytes")
        )
    ):
        raise ValueError("terminal process runtime evidence is malformed")
    containment = observed.get("containment")
    if (
        not isinstance(containment, dict)
        or set(containment)
        != {
            "leader_reaped",
            "process_group_empty",
            "stdio_handles_closed",
            "snapshot_mutation_denials_verified",
            "snapshot_profile_bound",
            "writable_root_count",
        }
        or any(
            containment.get(key) is not True
            for key in (
                "leader_reaped",
                "process_group_empty",
                "stdio_handles_closed",
                "snapshot_mutation_denials_verified",
                "snapshot_profile_bound",
            )
        )
        or containment.get("writable_root_count") != 2
    ):
        raise ValueError("terminal containment evidence is malformed")
    protocol = observed.get("protocol")
    if (
        not isinstance(protocol, dict)
        or set(protocol)
        != {
            "external_auth",
            "ephemeral",
            "remote_control",
            "runtime_workspace_root_count",
            "session_source",
        }
        or protocol.get("external_auth") != "accepted"
        or protocol.get("ephemeral") is not True
        or protocol.get("remote_control") != "disabled-notification-observed"
        or protocol.get("runtime_workspace_root_count") != 0
        or protocol.get("session_source") != "exec"
    ):
        raise ValueError("terminal protocol runtime evidence is malformed")
    model = observed.get("model")
    if (
        not isinstance(model, dict)
        or set(model)
        != {"model", "model_attempt", "model_provider", "reasoning_effort"}
        or model.get("model") != state.get("requested_model")
        or model.get("reasoning_effort") != state.get("requested_reasoning_effort")
        or model.get("model_provider") != "openai"
        or not isinstance(model.get("model_attempt"), str)
        or not model["model_attempt"]
    ):
        raise ValueError("terminal model runtime evidence is malformed")
    auth = observed.get("auth")
    if (
        not isinstance(auth, dict)
        or set(auth)
        != {
            "auth_mode",
            "carrier_generation_verified",
            "source_revalidated_before_launch",
            "source_revalidated_before_login_serialization",
        }
        or auth.get("auth_mode") != "external-chatgpt"
        or any(
            auth.get(key) is not True
            for key in (
                "carrier_generation_verified",
                "source_revalidated_before_launch",
                "source_revalidated_before_login_serialization",
            )
        )
    ):
        raise ValueError("terminal auth runtime evidence is malformed")
    refresh = observed.get("auth_refresh")
    if not isinstance(refresh, dict) or refresh.get("status") not in {
        "not-required",
        "completed",
    }:
        raise ValueError("terminal auth-refresh evidence is malformed")
    if refresh["status"] == "not-required":
        if set(refresh) != {"status"}:
            raise ValueError("terminal auth-refresh evidence is malformed")
    else:
        expected_refresh_keys = {
            "status",
            "managed_auth_verified",
            "codex_home_verified",
            "requires_openai_auth",
            "process_closure",
        }
        if (
            set(refresh) != expected_refresh_keys
            or refresh.get("managed_auth_verified") is not True
            or refresh.get("codex_home_verified") is not True
            or type(refresh.get("requires_openai_auth")) is not bool
        ):
            raise ValueError("terminal auth-refresh evidence is malformed")
        refresh_closure = refresh.get("process_closure")
        if (
            not isinstance(refresh_closure, dict)
            or set(refresh_closure)
            != {
                "pid",
                "process_group_id",
                "session_id",
                "profile_sha256",
                "exit_code",
                "leader_reaped",
                "process_group_empty",
                "stdio_closed",
            }
            or type(refresh_closure.get("pid")) is not int
            or refresh_closure["pid"] <= 1
            or refresh_closure.get("process_group_id") != refresh_closure["pid"]
            or refresh_closure.get("session_id") != refresh_closure["pid"]
            or not isinstance(refresh_closure.get("profile_sha256"), str)
            or _SHA256_PATTERN.fullmatch(refresh_closure["profile_sha256"]) is None
            or refresh_closure.get("exit_code") != 0
            or any(
                refresh_closure.get(key) is not True
                for key in (
                    "leader_reaped",
                    "process_group_empty",
                    "stdio_closed",
                )
            )
        ):
            raise ValueError("terminal auth-refresh closure is malformed")
    if (
        observed.get("actual_invocation_enabled") is not True
        or observed.get("transport") != "app-server-stdio"
        or observed.get("requested_model") != state.get("requested_model")
        or observed.get("requested_reasoning_effort")
        != state.get("requested_reasoning_effort")
        or type(observed.get("model_input_length")) is not int
        or observed["model_input_length"] < 1
        or not isinstance(observed.get("model_input_sha256"), str)
        or _SHA256_PATTERN.fullmatch(observed["model_input_sha256"]) is None
        or not isinstance(observed.get("evidence_bundle_sha256"), str)
        or _SHA256_PATTERN.fullmatch(observed["evidence_bundle_sha256"]) is None
    ):
        raise ValueError("terminal runtime binding evidence is malformed")


def _validate_terminal_lifecycle(
    attempt_dir: pathlib.Path,
    state: dict[str, Any],
) -> str:
    if (
        state.get("phase") != "reviewed"
        or state.get("launch_status") != "completed"
        or state.get("review_status") not in {"clean", "findings"}
        or state.get("handoff") != "complete"
        or state.get("process_owner") != "attempt-supervisor"
        or state.get("closure") != "proven-by-owner"
        or state.get("abandonment") is not False
        or state.get("process_settlement") != "exact"
        or state.get("checkout_settlement") != "exact"
        or state.get("worktree_status") != "removed"
        or state.get("source_custody_transferred") is not True
        or state.get("source_custody_released") is not True
        or state.get("admission_status") != "completed"
        or state.get("reservation_status") != "settled"
        or state.get("leader_exit") != 0
        or not isinstance(state.get("boot_id"), str)
        or not state["boot_id"]
    ):
        raise ValueError("final authorization lifecycle predecessor is invalid")
    leader = state.get("leader")
    runtime_binding = state.get("runtime_process_binding")
    _validate_process_binding(leader, runtime_binding, label="terminal reviewer")
    try:
        require_authenticated_no_child_process_profile(state)
    except ChildProcessError as error:
        raise ValueError("terminal reviewer no-child profile is malformed") from error
    history = state.get("process_history")
    if not isinstance(history, list) or len(history) not in {1, 2}:
        raise ValueError("terminal process history is malformed")
    for index, entry in enumerate(history):
        expected_stage = "reviewer" if index == len(history) - 1 else "auth-refresh"
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {"stage", "leader", "runtime_binding", "exit_code", "closure"}
            or entry.get("stage") != expected_stage
            or entry.get("exit_code") != 0
            or entry.get("closure") != "proven-by-owner"
        ):
            raise ValueError("terminal process history entry is malformed")
        _validate_process_binding(
            entry.get("leader"),
            entry.get("runtime_binding"),
            label=expected_stage,
        )
    if (
        history[-1].get("leader") != leader
        or history[-1].get("runtime_binding") != runtime_binding
    ):
        raise ValueError("terminal reviewer history binding changed")
    seal = state.get("final_seal")
    if (
        not isinstance(seal, dict)
        or set(seal) != {"path", "identity", "length", "sha256"}
        or pathlib.Path(seal.get("path", "")) != attempt_dir / "final.txt"
        or not isinstance(seal.get("identity"), dict)
        or set(seal["identity"]) != _IDENTITY_KEYS
        or type(seal.get("length")) is not int
        or not 1 <= seal["length"] <= FINAL_MESSAGE_BYTES
        or not isinstance(seal.get("sha256"), str)
        or _SHA256_PATTERN.fullmatch(seal["sha256"]) is None
    ):
        raise ValueError("terminal final seal is malformed")
    authorization = state.get("terminal_authorization")
    proof = state.get("terminal_authorization_proof")
    authorized_at = (
        authorization.get("authorized_at") if isinstance(authorization, dict) else None
    )
    if (
        state.get("terminal_commit_authorized") is not True
        or not isinstance(authorization, dict)
        or set(authorization) != {"leader_exit", "final_seal", "authorized_at"}
        or authorization.get("leader_exit") != 0
        or authorization.get("final_seal") != seal
        or type(authorized_at) not in {int, float}
        or not math.isfinite(authorized_at)
        or not isinstance(proof, dict)
        or set(proof)
        != {
            "predecessor_sha256",
            "leader_exit",
            "final_seal",
            "binding_sha256",
            "readback",
        }
        or proof.get("leader_exit") != 0
        or proof.get("final_seal") != seal
        or not isinstance(proof.get("predecessor_sha256"), str)
        or _SHA256_PATTERN.fullmatch(proof["predecessor_sha256"]) is None
        or proof.get("readback") != "exact-nofollow-under-publication-lease"
    ):
        raise ValueError("terminal authorization evidence is malformed")
    expected_terminal_binding = sha256_bytes(
        canonical_json(
            {
                "predecessor_sha256": proof["predecessor_sha256"],
                "leader_exit": 0,
                "final_seal": seal,
            }
        )
    )
    if proof.get("binding_sha256") != expected_terminal_binding:
        raise ValueError("terminal authorization proof binding is invalid")
    handoff_token = state.get("handoff_token")
    if (
        not isinstance(handoff_token, str)
        or _HANDOFF_TOKEN_PATTERN.fullmatch(handoff_token) is None
    ):
        raise ValueError("terminal handoff token is malformed")
    _validate_observed_runtime(state)
    refresh_runtime = state["observed_runtime"]["auth_refresh"]
    if len(history) == 1:
        if refresh_runtime.get("status") != "not-required":
            raise ValueError("terminal auth-refresh history is missing")
    else:
        refresh_history = history[0]
        refresh_leader = refresh_history["leader"]
        refresh_binding = refresh_history["runtime_binding"]
        refresh_closure = refresh_runtime.get("process_closure")
        if (
            refresh_runtime.get("status") != "completed"
            or not isinstance(refresh_closure, dict)
            or refresh_closure.get("pid") != refresh_leader["pid"]
            or refresh_closure.get("process_group_id") != refresh_leader["pgid"]
            or refresh_closure.get("session_id") != refresh_binding["session_id"]
            or refresh_closure.get("profile_sha256")
            != refresh_binding["profile_sha256"]
            or refresh_closure.get("exit_code") != refresh_history["exit_code"]
        ):
            raise ValueError(
                "terminal auth-refresh closure does not match process history"
            )
    return handoff_token


def _validate_final_authorization_record(
    *,
    attempt_dir: pathlib.Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    handoff_token = _validate_terminal_lifecycle(attempt_dir, state)
    authorization = state.get("final_authorization")
    generation = state.get("record_generation")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != _FINAL_AUTHORIZATION_KEYS
        or type(generation) is not int
        or type(authorization.get("predecessor_generation")) is not int
        or authorization["predecessor_generation"] != generation - 1
        or authorization.get("predecessor_sha256")
        != state.get("previous_record_sha256")
        or authorization.get("supervisor") != state.get("supervisor")
        or authorization.get("supervisor_exit_code")
        != state.get("supervisor_exit_code")
        or authorization.get("handoff_token_sha256")
        != sha256_bytes(handoff_token.encode("ascii"))
        or authorization.get("final_seal") != state.get("final_seal")
    ):
        raise ValueError("existing final authorization binding is invalid")
    payload = {
        key: value for key, value in authorization.items() if key != "binding_sha256"
    }
    if authorization.get("binding_sha256") != sha256_bytes(canonical_json(payload)):
        raise ValueError("existing final authorization digest is invalid")
    measured = allocated_bytes(attempt_dir, entry_cap=1_000)
    filesystem_identity = measure_filesystem(attempt_dir).identity
    expected_physical = {filesystem_identity: measured} if measured else {}
    if (
        state.get("retained_process_bytes") != measured
        or state.get("process_physical_remaining_by_fs") != expected_physical
    ):
        raise ValueError("existing final authorization accounting is inexact")
    return authorization


def build_final_authorization_rewrite(
    *,
    attempt_dir: pathlib.Path,
    state: dict[str, Any],
    state_digest: str,
    operation: Any,
) -> dict[str, Any]:
    if operation not in {"release", "runtime-cleanup"}:
        raise ValueError("final authorization rewrite operation is invalid")
    if _SHA256_PATTERN.fullmatch(state_digest) is None:
        raise ValueError("final authorization rewrite source digest is invalid")
    generation = state.get("record_generation")
    previous = state.get("previous_record_sha256")
    if (
        type(generation) is not int
        or generation < 1
        or (previous is not None and _SHA256_PATTERN.fullmatch(previous) is None)
    ):
        raise ValueError("final authorization rewrite source is malformed")
    authorization_required = state.get("review_status") in {"clean", "findings"}
    source_authorization: dict[str, Any] | None = None
    if authorization_required:
        source_authorization = _validate_final_authorization_record(
            attempt_dir=attempt_dir,
            state=state,
        )
    elif state.get("final_authorization") is not None:
        raise ValueError("nonterminal rewrite retained unexpected final authorization")
    payload = {
        "version": 1,
        "operation": operation,
        "source_generation": generation,
        "source_sha256": state_digest,
        "source_previous_record_sha256": previous,
        "authorization_required": authorization_required,
        "source_final_authorization": source_authorization,
    }
    return {
        **payload,
        "status": "pending",
        "source_binding_sha256": sha256_bytes(canonical_json(payload)),
    }


def validate_final_authorization_rewrite(
    state: dict[str, Any],
) -> dict[str, Any]:
    rewrite = state.get("final_authorization_rewrite")
    if (
        not isinstance(rewrite, dict)
        or set(rewrite) != _FINAL_AUTHORIZATION_REWRITE_KEYS
        or rewrite.get("version") != 1
        or rewrite.get("operation") not in {"release", "runtime-cleanup"}
        or rewrite.get("status") not in {"pending", "complete"}
        or type(rewrite.get("source_generation")) is not int
        or rewrite["source_generation"] < 1
        or not isinstance(rewrite.get("source_sha256"), str)
        or _SHA256_PATTERN.fullmatch(rewrite["source_sha256"]) is None
        or (
            rewrite.get("source_previous_record_sha256") is not None
            and (
                not isinstance(rewrite["source_previous_record_sha256"], str)
                or _SHA256_PATTERN.fullmatch(rewrite["source_previous_record_sha256"])
                is None
            )
        )
        or type(rewrite.get("authorization_required")) is not bool
    ):
        raise ValueError("final authorization rewrite record is malformed")
    payload = {
        key: rewrite[key]
        for key in (
            "version",
            "operation",
            "source_generation",
            "source_sha256",
            "source_previous_record_sha256",
            "authorization_required",
            "source_final_authorization",
        )
    }
    if rewrite.get("source_binding_sha256") != sha256_bytes(canonical_json(payload)):
        raise ValueError("final authorization rewrite source binding is invalid")
    source_authorization = rewrite.get("source_final_authorization")
    if rewrite["authorization_required"]:
        if (
            not isinstance(source_authorization, dict)
            or set(source_authorization) != _FINAL_AUTHORIZATION_KEYS
            or source_authorization.get("predecessor_generation")
            != rewrite["source_generation"] - 1
            or source_authorization.get("predecessor_sha256")
            != rewrite["source_previous_record_sha256"]
            or source_authorization.get("supervisor") != state.get("supervisor")
            or source_authorization.get("supervisor_exit_code") != 0
            or source_authorization.get("final_seal") != state.get("final_seal")
        ):
            raise ValueError(
                "final authorization rewrite source authorization is invalid"
            )
        authorization_payload = {
            key: value
            for key, value in source_authorization.items()
            if key != "binding_sha256"
        }
        if source_authorization.get("binding_sha256") != sha256_bytes(
            canonical_json(authorization_payload)
        ):
            raise ValueError("final authorization rewrite source digest is invalid")
    elif source_authorization is not None:
        raise ValueError("unnecessary final authorization rewrite source is present")
    if rewrite["operation"] == "release" and (
        state.get("retention_state") != "released"
        or state.get("release_reason") not in {"resolved", "handoff-complete"}
    ):
        raise ValueError("release rewrite state is incomplete")
    generation = state.get("record_generation")
    if type(generation) is not int or generation <= rewrite["source_generation"]:
        raise ValueError("final authorization rewrite did not advance state")
    return rewrite


def complete_final_authorization_rewrite(
    rewrite: dict[str, Any],
) -> dict[str, Any]:
    if rewrite.get("status") not in {"pending", "complete"}:
        raise ValueError("final authorization rewrite completion source is invalid")
    return {**rewrite, "status": "complete"}


def _validate_final_authorization_updates(
    *,
    attempt_dir: pathlib.Path,
    state: dict[str, Any],
    state_digest: str,
    updates: dict[str, Any],
) -> None:
    expected_update_keys = {
        "supervisor_exit_code",
        "final_authorization",
        "retained_process_bytes",
        "process_physical_remaining_by_fs",
    }
    rewrite = state.get("final_authorization_rewrite")
    if rewrite is not None:
        expected_update_keys.add("final_authorization_rewrite")
    if set(updates) != expected_update_keys:
        raise ValueError("final authorization update shape is invalid")
    supervisor = state.get("supervisor")
    if (
        not isinstance(supervisor, dict)
        or set(supervisor) != {"pid", "start_identity"}
        or type(supervisor.get("pid")) is not int
        or supervisor["pid"] <= 1
        or not isinstance(supervisor.get("start_identity"), str)
        or not supervisor["start_identity"]
        or updates.get("supervisor_exit_code") != 0
    ):
        raise ValueError("final authorization predecessor is invalid")
    try:
        actual_start = process_start_identity(supervisor["pid"])
    except (OSError, ValueError):
        try:
            os.kill(supervisor["pid"], 0)
        except ProcessLookupError:
            actual_start = None
        else:
            raise ValueError("former attempt supervisor liveness is inconclusive")
    if actual_start == supervisor["start_identity"]:
        raise ValueError("attempt supervisor is still live")
    handoff_token = _validate_terminal_lifecycle(attempt_dir, state)
    if rewrite is not None:
        validated_rewrite = validate_final_authorization_rewrite(state)
        if updates.get(
            "final_authorization_rewrite"
        ) != complete_final_authorization_rewrite(validated_rewrite):
            raise ValueError("final authorization rewrite completion is invalid")
    generation = state.get("record_generation")
    final_seal = state.get("final_seal")
    if (
        type(generation) is not int
        or generation < 1
        or _SHA256_PATTERN.fullmatch(state_digest) is None
        or not isinstance(final_seal, dict)
    ):
        raise ValueError("final authorization binding input is malformed")
    payload = {
        "predecessor_generation": generation,
        "predecessor_sha256": state_digest,
        "supervisor": supervisor,
        "supervisor_exit_code": 0,
        "handoff_token_sha256": sha256_bytes(handoff_token.encode("ascii")),
        "final_seal": final_seal,
    }
    expected_authorization = {
        **payload,
        "binding_sha256": sha256_bytes(canonical_json(payload)),
    }
    if updates.get("final_authorization") != expected_authorization:
        raise ValueError("final authorization is not bound to its predecessor")
    charge = updates.get("retained_process_bytes")
    current_allocated = allocated_bytes(attempt_dir, entry_cap=1_000)
    if type(charge) is not int or charge != current_allocated:
        raise ValueError("final authorization process charge is invalid")
    filesystem_identity = measure_filesystem(attempt_dir).identity
    expected_physical = {filesystem_identity: charge} if charge else {}
    if updates.get("process_physical_remaining_by_fs") != expected_physical:
        raise ValueError("final authorization physical charge is invalid")


def phase_helper_main(
    *,
    attempt_dir: pathlib.Path,
    control_fd: int,
    lease_fd: int,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        send_record(
            control,
            {"type": "phase-helper-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        request, _ = receive_record(control, deadline=time.monotonic() + 30)
        request_type = request.get("type")
        if (
            request_type
            not in {
                "phase-commit",
                "process-settlement",
                "final-authorization-commit",
            }
            or request.get("token") != token
        ):
            raise ValueError("phase helper request is invalid")
        state, _, digest = read_attempt_state(attempt_dir)
        if digest != request.get("predecessor_sha256"):
            raise ValueError("phase helper predecessor digest mismatch")
        if request_type in {"phase-commit", "final-authorization-commit"}:
            updates = request.get("updates")
            if not isinstance(updates, dict):
                raise ValueError("phase helper updates are malformed")
            if request_type == "phase-commit":
                _validate_ordinary_phase_updates(
                    attempt_dir=attempt_dir,
                    state=state,
                    state_digest=digest,
                    updates=updates,
                )
            else:
                _validate_final_authorization_updates(
                    attempt_dir=attempt_dir,
                    state=state,
                    state_digest=digest,
                    updates=updates,
                )
            next_state, next_digest = commit_state(
                attempt_dir, state, digest, **updates
            )
        else:
            if state.get("closure") not in {
                "proven-by-owner",
                "proven-by-boot-change",
            }:
                raise ValueError("process settlement requires proven process closure")
            next_state, next_digest = publish_exact_process_settlement(
                attempt_dir,
                state,
                digest,
                deadline=time.monotonic() + 30,
            )
        send_record(
            control,
            {
                "type": (
                    "phase-commit-result"
                    if request_type in {"phase-commit", "final-authorization-commit"}
                    else "process-settlement-result"
                ),
                "token": token,
                "ok": True,
                "state": next_state,
                "state_sha256": next_digest,
            },
            deadline=time.monotonic() + 5,
        )
        return 0
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "phase-commit-result",
                    "token": token,
                    "ok": False,
                    "error": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        control.close()
        os.close(lease_fd)


def commit_via_helper(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
    updates: dict[str, Any],
    deadline: float,
    request_type: str = "phase-commit",
) -> tuple[dict[str, Any], str]:
    if request_type not in {"phase-commit", "final-authorization-commit"}:
        raise ValueError("phase helper commit type is invalid")
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    try:
        process = _spawn_internal(
            entrypoint=entrypoint,
            mode="_phase-helper",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--lease-fd",
                "4",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), lease_fd),
            own_process_group=False,
        )
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "phase-helper-ready" or ready.get("token") != token:
            raise ValueError("phase helper ready record is invalid")
        send_record(
            parent,
            {
                "type": request_type,
                "token": token,
                "predecessor_sha256": state_digest,
                "updates": updates,
            },
            deadline=deadline,
        )
        result, _ = receive_record(parent, deadline=deadline)
        terminal = wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid, deadline=deadline)
        process = None
        if (
            terminal.exit_code != 0
            or exit_code != 0
            or result.get("type") != "phase-commit-result"
            or result.get("token") != token
            or result.get("ok") is not True
        ):
            raise ValueError(
                f"phase helper failed: {result.get('error', 'unknown error')}"
            )
        next_state = result.get("state")
        next_digest = result.get("state_sha256")
        if not isinstance(next_state, dict) or not isinstance(next_digest, str):
            raise ValueError("phase helper result is malformed")
        disk_state, _, disk_digest = read_attempt_state(attempt_dir)
        if disk_state != next_state or disk_digest != next_digest:
            raise ValueError("phase helper result does not match durable state")
        return next_state, next_digest
    finally:
        parent.close()
        child.close()
        if process is not None:
            _kill_direct(process)


def settle_process_via_helper(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
    deadline: float,
) -> tuple[dict[str, Any], str]:
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    try:
        process = _spawn_internal(
            entrypoint=entrypoint,
            mode="_phase-helper",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--lease-fd",
                "4",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), lease_fd),
            own_process_group=False,
        )
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "phase-helper-ready" or ready.get("token") != token:
            raise ValueError("process settlement helper ready record is invalid")
        send_record(
            parent,
            {
                "type": "process-settlement",
                "token": token,
                "predecessor_sha256": state_digest,
            },
            deadline=deadline,
        )
        result, _ = receive_record(parent, deadline=deadline)
        wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid, deadline=deadline)
        process = None
        if (
            exit_code != 0
            or result.get("type") != "process-settlement-result"
            or result.get("token") != token
            or result.get("ok") is not True
        ):
            raise ValueError(
                f"process settlement helper failed: {result.get('error', 'unknown error')}"
            )
        next_state = result.get("state")
        next_digest = result.get("state_sha256")
        if not isinstance(next_state, dict) or not isinstance(next_digest, str):
            raise ValueError("process settlement helper result is malformed")
        disk_state, _, disk_digest = read_attempt_state(attempt_dir)
        if disk_state != next_state or disk_digest != next_digest:
            raise ValueError("process settlement helper result is not durable")
        return next_state, next_digest
    finally:
        parent.close()
        child.close()
        if process is not None:
            _kill_direct(process)


def prompt_helper_main(
    *,
    attempt_dir: pathlib.Path,
    control_fd: int,
    lease_fd: int,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        send_record(
            control,
            {"type": "prompt-helper-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        request, _ = receive_record(control, deadline=time.monotonic() + 30)
        if request.get("type") != "prompt-offer" or request.get("token") != token:
            raise ValueError("prompt helper offer is invalid")
        prompt = receive_blob(control, token, deadline=time.monotonic() + 30)
        evidence = prompt_evidence(prompt)
        state, _, digest = read_attempt_state(attempt_dir)
        if digest != request.get("predecessor_sha256"):
            raise ValueError("prompt helper predecessor digest mismatch")
        if evidence != {
            "length": state["prompt_length"],
            "sha256": state["prompt_sha256"],
        }:
            raise ValueError("prompt helper bytes do not match the reservation")
        prompt_path = pathlib.Path(state["prompt_path"])
        identity = publish_bytes(prompt_path, prompt)
        next_state, next_digest = commit_state(
            attempt_dir,
            state,
            digest,
            prompt_published=True,
            prompt_identity=identity.to_json(),
        )
        send_record(
            control,
            {
                "type": "prompt-result",
                "token": token,
                "ok": True,
                "state": next_state,
                "state_sha256": next_digest,
            },
            deadline=time.monotonic() + 5,
        )
        return 0
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "prompt-result",
                    "token": token,
                    "ok": False,
                    "error": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        control.close()
        os.close(lease_fd)


def publish_prompt_via_helper(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
    prompt: bytes,
    deadline: float,
) -> tuple[dict[str, Any], str]:
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    try:
        process = _spawn_internal(
            entrypoint=entrypoint,
            mode="_prompt-helper",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--lease-fd",
                "4",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), lease_fd),
            own_process_group=False,
        )
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "prompt-helper-ready" or ready.get("token") != token:
            raise ValueError("prompt helper ready record is invalid")
        send_record(
            parent,
            {
                "type": "prompt-offer",
                "token": token,
                "predecessor_sha256": state_digest,
            },
            deadline=deadline,
        )
        send_blob(parent, token, prompt, deadline=deadline)
        result, _ = receive_record(parent, deadline=deadline)
        wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid, deadline=deadline)
        process = None
        if exit_code != 0 or result.get("ok") is not True:
            raise ValueError(
                f"prompt helper failed: {result.get('error', 'unknown error')}"
            )
        next_state = result.get("state")
        next_digest = result.get("state_sha256")
        if not isinstance(next_state, dict) or not isinstance(next_digest, str):
            raise ValueError("prompt helper result is malformed")
        return next_state, next_digest
    finally:
        parent.close()
        child.close()
        if process is not None:
            _kill_direct(process)


def checkout_worker_main(
    *,
    attempt_dir: pathlib.Path,
    control_fd: int,
    source_fd: int,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    materializer: RawMaterializer | None = None
    try:
        state, _, _ = read_attempt_state(attempt_dir)
        custody = _custody(state["helper_custody"])
        if identity_from_stat(os.fstat(source_fd)) != custody.source_identity:
            raise ValueError("checkout worker source descriptor identity is invalid")
        deadline = time.monotonic() + CHECKOUT_SECONDS
        info = inspect_repository(
            repo=pathlib.Path(state["repo"]),
            base_sha=state["base_sha"],
            head_sha=state["head_sha"],
            git_executable=state["git_executable"],
        )
        base = enumerate_tree(info, info.base_sha)
        head = enumerate_tree(info, info.head_sha)
        if (
            manifest_digest(base) != state["base_manifest_sha256"]
            or manifest_digest(head) != state["head_manifest_sha256"]
            or head.entry_count != state["admission"]["entry_count"]
            or head.metadata_bytes != state["admission"]["tree_metadata_bytes"]
        ):
            raise ValueError("worker tree enumeration differs from reserved manifests")
        registration = add_detached_worktree(info, pathlib.Path(state["worktree_path"]))
        send_record(
            control,
            {
                "type": "worktree-created",
                "token": token,
                "registration": _registration_json(registration),
            },
            deadline=deadline,
        )
        release, _ = receive_record(control, deadline=deadline)
        if release != {"type": "continue-index", "token": token}:
            raise ValueError("checkout worker index release is invalid")
        initialize_index(info, registration)
        post_index_count, post_index_path_bytes = enumerate_registration(
            registration.registration
        )
        send_record(
            control,
            {
                "type": "index-initialized",
                "token": token,
                "registration_descendant_count": post_index_count,
                "registration_descendant_path_bytes": post_index_path_bytes,
            },
            deadline=deadline,
        )
        release, _ = receive_record(control, deadline=deadline)
        if release != {"type": "continue-phase0", "token": token}:
            raise ValueError("checkout worker phase-0 release is invalid")
        checkout_parent_fd, checkout_parent_identity = open_absolute_directory_chain(
            pathlib.Path(state["worktree_path"]).parent,
            private_leaf=True,
        )
        try:
            control_namespace, _ = _ensure_control_namespace(
                state,
                checkout_parent_fd=checkout_parent_fd,
                checkout_parent_identity=checkout_parent_identity,
            )
        finally:
            os.close(checkout_parent_fd)
        semantics = probe_name_semantics(control_namespace)
        base_entries, head_entries = validate_namespaces(
            base,
            head,
            semantics=semantics,
            checkout_root=registration.worktree,
        )
        graph = read_and_validate_symlink_graphs(
            info,
            base,
            head,
            base_entries=base_entries,
            head_entries=head_entries,
            semantics=semantics,
        )
        send_record(
            control,
            {
                "type": "phase0-complete",
                "token": token,
                "name_semantics": {
                    "case_insensitive": semantics.case_insensitive,
                    "normalization_insensitive": semantics.normalization_insensitive,
                    "name_max": semantics.name_max,
                    "path_max": semantics.path_max,
                },
                "symlink_target_count": len(graph.targets),
            },
            deadline=deadline,
        )
        release, _ = receive_record(control, deadline=deadline)
        if release != {"type": "continue-materialization", "token": token}:
            raise ValueError("checkout worker materialization release is invalid")
        materializer = RawMaterializer(
            info=info,
            registration=registration,
            base=base,
            head=head,
            semantics=semantics,
            graph=graph,
            source_fd=source_fd,
            custody=custody,
            deadline=deadline,
            checkout_root_bound=state["admission"]["checkout_root_bound"],
            git_admin_bound=state["admission"]["git_admin_bound"],
            view_path=attempt_dir / "sanitized-git-view",
        )
        materializer.phase1()
        evidence = materializer.materialize()
        send_record(
            control,
            {
                "type": "checkout-complete",
                "token": token,
                "evidence": evidence.to_json(),
            },
            deadline=deadline,
        )
        return 0
    except BaseException as error:
        failure = error.failure if isinstance(error, SupervisorError) else None
        try:
            send_record(
                control,
                {
                    "type": "checkout-failed",
                    "token": token,
                    "status": failure.status if failure else "inconclusive",
                    "stage": failure.stage if failure else "checkout",
                    "code": failure.code if failure else "checkout-worker-failed",
                    "error": failure.message
                    if failure
                    else f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        if materializer is not None:
            materializer.close()
        os.close(source_fd)
        control.close()


class OuterAbandoned(RuntimeError):
    pass


class PrelaunchWorkerClosureUnproven(RuntimeError):
    pass


def _require_outer_liveness(outer: socket.socket) -> None:
    if not peer_is_open(outer):
        raise OuterAbandoned("outer liveness peer closed")


def _verify_prompt_artifact(state: dict[str, Any], prompt: bytes) -> None:
    evidence = prompt_evidence(prompt)
    if evidence != {
        "length": state["prompt_length"],
        "sha256": state["prompt_sha256"],
    }:
        raise ValueError("supervisor-private prompt does not match durable state")
    path = pathlib.Path(state["prompt_path"])
    fd, identity = open_regular_nofollow(
        path,
        expected_uid=os.getuid(),
        private_metadata=True,
    )
    try:
        if identity != _identity(state["prompt_identity"]):
            raise ValueError("published prompt identity changed")
        actual = read_fd_exact(fd, max_bytes=len(prompt), expected_size=len(prompt))
        if actual != prompt:
            raise ValueError(
                "published prompt exact readback differs from handoff bytes"
            )
    finally:
        os.close(fd)


def prompt_verifier_main(
    *,
    attempt_dir: pathlib.Path,
    control_fd: int,
    lease_fd: int,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        send_record(
            control,
            {"type": "prompt-verifier-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        request, descriptors = receive_record(
            control,
            deadline=time.monotonic() + 30,
        )
        if descriptors:
            raise ValueError("prompt verifier request contained descriptors")
        if request.get("type") != "verify-prompt" or request.get("token") != token:
            raise ValueError("prompt verifier request is invalid")
        prompt = receive_blob(control, token, deadline=time.monotonic() + 30)
        state, _, digest = read_attempt_state(attempt_dir)
        if digest != request.get("predecessor_sha256"):
            raise ValueError("prompt verifier predecessor digest changed")
        _verify_prompt_artifact(state, prompt)
        send_record(
            control,
            {
                "type": "prompt-verifier-result",
                "token": token,
                "ok": True,
                "prompt": prompt_evidence(prompt),
            },
            deadline=time.monotonic() + 5,
        )
        return 0
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "prompt-verifier-result",
                    "token": token,
                    "ok": False,
                    "error": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        control.close()
        os.close(lease_fd)


def verify_prompt_via_helper(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state_digest: str,
    prompt: bytes,
    deadline: float,
) -> None:
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    try:
        process = _spawn_internal(
            entrypoint=entrypoint,
            mode="_prompt-verifier",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--lease-fd",
                "4",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), lease_fd),
            own_process_group=False,
        )
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "prompt-verifier-ready" or ready.get("token") != token:
            raise ValueError("prompt verifier ready record is invalid")
        send_record(
            parent,
            {
                "type": "verify-prompt",
                "token": token,
                "predecessor_sha256": state_digest,
            },
            deadline=deadline,
        )
        send_blob(parent, token, prompt, deadline=deadline)
        result, _ = receive_record(parent, deadline=deadline)
        wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid, deadline=deadline)
        process = None
        if (
            exit_code != 0
            or result.get("type") != "prompt-verifier-result"
            or result.get("token") != token
            or result.get("ok") is not True
            or result.get("prompt") != prompt_evidence(prompt)
        ):
            raise ValueError(
                f"prompt verifier failed: {result.get('error', 'invalid result')}"
            )
    finally:
        parent.close()
        child.close()
        if process is not None:
            _kill_direct(process)


def _wait_child_record(
    *,
    child: socket.socket,
    outer: socket.socket,
    deadline: float,
) -> dict[str, Any]:
    selector = selectors.DefaultSelector()
    try:
        selector.register(child, selectors.EVENT_READ, "child")
        selector.register(outer, selectors.EVENT_READ, "outer")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("supervised child control deadline expired")
            for key, _ in selector.select(min(remaining, 0.25)):
                if key.data == "outer":
                    if not peer_is_open(outer):
                        raise OuterAbandoned("outer liveness peer closed")
                    raise ValueError(
                        "outer peer sent an unexpected post-handoff record"
                    )
                record, fds = receive_record(child, deadline=deadline)
                if fds:
                    for fd in fds:
                        os.close(fd)
                    raise ValueError("child sent unexpected descriptors")
                return record
    finally:
        selector.close()


def _terminate_group(
    process: SpawnedProcess,
    schedule: TerminationSchedule | None = None,
) -> int:
    deadline = time.monotonic() + PROCESS_TERM_GRACE_SECONDS + READER_DRAIN_SECONDS
    term_sent_at = schedule.term_sent_at if schedule is not None else None
    kill_sent_at = schedule.kill_sent_at if schedule is not None else None
    if term_sent_at is None:
        signal_anchored_group(process, signal.SIGTERM)
        term_sent_at = time.monotonic()
    try:
        wait_terminal(
            process.pid,
            deadline=min(deadline, term_sent_at + PROCESS_TERM_GRACE_SECONDS),
        )
    except TimeoutError:
        if kill_sent_at is None:
            signal_anchored_group(process, signal.SIGKILL)
        wait_terminal(process.pid, deadline=deadline)
    return reap(process.pid, deadline=deadline)


def authorization_helper_main(
    *,
    attempt_dir: pathlib.Path,
    control_fd: int,
    lease_fd: int,
    outer_liveness_fd: int,
    token: str,
) -> int:
    control = socket.socket(fileno=control_fd)
    outer = socket.socket(fileno=outer_liveness_fd)
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        send_record(
            control,
            {"type": "authorization-ready", "token": token, "pid": os.getpid()},
            deadline=time.monotonic() + 5,
        )
        request, _ = receive_record(control, deadline=time.monotonic() + 30)
        if request.get("type") != "authorize-terminal" or request.get("token") != token:
            raise ValueError("terminal authorization request is invalid")
        if not peer_is_open(outer):
            send_record(
                control,
                {
                    "type": "authorization-result",
                    "token": token,
                    "ok": False,
                    "reason": "outer-eof",
                },
                deadline=time.monotonic() + 2,
            )
            return 2
        state, _, digest = read_attempt_state(attempt_dir)
        if digest != request.get("predecessor_sha256"):
            raise ValueError("terminal authorization predecessor changed")
        requested_seal = request.get("final_seal")
        leader_exit = request.get("leader_exit")
        if (
            not isinstance(requested_seal, dict)
            or type(leader_exit) is not int
            or leader_exit != 0
        ):
            raise ValueError("terminal authorization evidence is malformed")
        final_path = pathlib.Path(requested_seal.get("path", ""))
        if final_path != attempt_dir / "final.txt":
            raise ValueError("terminal authorization final path is invalid")
        _, verified_seal = _verify_final_seal(final_path, requested_seal)
        if verified_seal != requested_seal:
            raise ValueError("terminal authorization final seal changed on readback")
        rebound_state, _, rebound_digest = read_attempt_state(attempt_dir)
        if rebound_state != state or rebound_digest != digest:
            raise ValueError(
                "terminal authorization predecessor changed during readback"
            )
        _require_outer_liveness(outer)
        binding_sha256 = sha256_bytes(
            canonical_json(
                {
                    "predecessor_sha256": digest,
                    "leader_exit": leader_exit,
                    "final_seal": verified_seal,
                }
            )
        )
        authorized_at = time.time()
        next_state, next_digest = commit_state(
            attempt_dir,
            state,
            digest,
            terminal_commit_authorized=True,
            abandonment=False,
            terminal_authorization={
                "leader_exit": leader_exit,
                "final_seal": verified_seal,
                "authorized_at": authorized_at,
            },
            terminal_authorization_proof={
                "predecessor_sha256": digest,
                "leader_exit": leader_exit,
                "final_seal": verified_seal,
                "binding_sha256": binding_sha256,
                "readback": "exact-nofollow-under-publication-lease",
            },
        )
        _require_outer_liveness(outer)
        send_record(
            control,
            {
                "type": "authorization-result",
                "token": token,
                "ok": True,
                "state": next_state,
                "state_sha256": next_digest,
            },
            deadline=time.monotonic() + 5,
        )
        return 0
    except BaseException as error:
        try:
            send_record(
                control,
                {
                    "type": "authorization-result",
                    "token": token,
                    "ok": False,
                    "reason": f"{type(error).__name__}: {error}",
                },
                deadline=time.monotonic() + 1,
            )
        except BaseException:
            pass
        return 1
    finally:
        control.close()
        outer.close()
        os.close(lease_fd)


def authorize_terminal_via_helper(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    outer: socket.socket,
    state: dict[str, Any],
    state_digest: str,
    leader_exit: int,
    final_seal: dict[str, Any],
    deadline: float,
) -> tuple[dict[str, Any], str]:
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    process: SpawnedProcess | None = None
    try:
        process = _spawn_internal(
            entrypoint=entrypoint,
            mode="_authorization-helper",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--lease-fd",
                "4",
                "--outer-liveness-fd",
                "5",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), lease_fd, outer.fileno()),
            own_process_group=False,
        )
        child.close()
        await_exec(process, deadline=deadline)
        ready, _ = receive_record(parent, deadline=deadline)
        if ready.get("type") != "authorization-ready" or ready.get("token") != token:
            raise ValueError("terminal authorization helper ready record is invalid")
        send_record(
            parent,
            {
                "type": "authorize-terminal",
                "token": token,
                "predecessor_sha256": state_digest,
                "leader_exit": leader_exit,
                "final_seal": final_seal,
            },
            deadline=deadline,
        )
        result, _ = receive_record(parent, deadline=deadline)
        wait_terminal(process.pid, deadline=deadline)
        exit_code = reap(process.pid, deadline=deadline)
        process = None
        if exit_code != 0 or result.get("ok") is not True:
            raise OuterAbandoned(
                f"terminal authorization refused: {result.get('reason')}"
            )
        next_state = result.get("state")
        next_digest = result.get("state_sha256")
        if not isinstance(next_state, dict) or not isinstance(next_digest, str):
            raise ValueError("terminal authorization result is malformed")
        return next_state, next_digest
    finally:
        parent.close()
        child.close()
        if process is not None:
            _kill_direct(process)


def _verify_final_seal(
    path: pathlib.Path,
    reader_result: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    identity_value = reader_result.get("identity")
    if not isinstance(identity_value, dict):
        raise ValueError("reader seal does not contain an identity")
    expected = _identity(identity_value)
    fd, actual = open_regular_nofollow(
        path,
        expected_uid=os.getuid(),
        private_metadata=True,
    )
    try:
        if actual != expected:
            raise ValueError("final artifact identity differs from the reader seal")
        if not 1 <= actual.size <= FINAL_MESSAGE_BYTES:
            raise ValueError("final artifact length is outside the accepted range")
        content = read_fd_exact(
            fd, max_bytes=FINAL_MESSAGE_BYTES, expected_size=actual.size
        )
    finally:
        os.close(fd)
    digest = sha256_bytes(content)
    if (
        reader_result.get("length") != len(content)
        or reader_result.get("sha256") != digest
    ):
        raise ValueError("final artifact length/digest differs from the reader seal")
    return content, {
        "path": str(path),
        "identity": actual.to_json(),
        "length": len(content),
        "sha256": digest,
    }


def publish_terminal_review(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    outer: socket.socket,
    state: dict[str, Any],
    state_digest: str,
    review_status: str,
    final_text: str,
    leader_exit: int,
    observed_runtime: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if review_status not in {"clean", "findings"}:
        raise ValueError("terminal review classification is invalid")
    if type(leader_exit) is not int:
        raise ValueError("terminal reviewer exit status is invalid")
    final_bytes = final_text.encode("utf-8", "strict")
    if not 1 <= len(final_bytes) <= FINAL_MESSAGE_BYTES:
        raise ValueError("terminal review artifact exceeds its byte bound")
    final_path = attempt_dir / "final.txt"
    final_identity = publish_bytes(final_path, final_bytes, mode=0o600)
    final_seal = {
        "path": str(final_path),
        "identity": final_identity.to_json(),
        "length": len(final_bytes),
        "sha256": sha256_bytes(final_bytes),
    }
    state, state_digest = commit_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        updates={
            "phase": "terminal-authorization-pending",
            "closure": "proven-by-owner",
            "leader_exit": leader_exit,
            "observed_runtime": dict(observed_runtime),
        },
        deadline=time.monotonic() + 30,
    )
    state, state_digest = authorize_terminal_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        outer=outer,
        state=state,
        state_digest=state_digest,
        leader_exit=leader_exit,
        final_seal=final_seal,
        deadline=time.monotonic() + 30,
    )
    return commit_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        updates={
            "phase": "reviewed",
            "launch_status": "completed",
            "review_status": review_status,
            "final_seal": final_seal,
            "failure_stage": None,
        },
        deadline=time.monotonic() + 30,
    )


def _run_authenticated_review_boundary(
    **arguments: Any,
) -> tuple[AuthenticatedReviewResult | None, bool]:
    try:
        return run_authenticated_review(**arguments), False
    except BaseException:
        return None, True


def run_reviewer(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    outer: socket.socket,
    state: dict[str, Any],
    state_digest: str,
    prompt: bytes,
) -> tuple[dict[str, Any], str, str]:
    if not peer_is_open(outer):
        raise OuterAbandoned("outer liveness closed before prompt verification")
    launch_deadline = time.monotonic() + REVIEWER_LAUNCH_SECONDS
    verify_prompt_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state_digest=state_digest,
        prompt=prompt,
        deadline=launch_deadline,
    )
    if not peer_is_open(outer):
        raise OuterAbandoned("outer liveness closed during prompt verification")

    primary_entry = ManifestEntry(
        path=PRIMARY_DIFF_RELATIVE_PATH,
        kind="regular",
        size=state["diff_length"],
        sha256=state["diff_sha256"],
    )
    evidence_manifest_digest = evidence_manifest_sha256((primary_entry,))
    evidence_manifest = AuthenticatedManifest.authenticate(
        (primary_entry,),
        expected_sha256=evidence_manifest_digest,
    )
    worktree = pathlib.Path(state["worktree_path"])
    root_fd, root_identity = open_absolute_directory_chain(worktree)
    try:
        registration_value = state.get("registration")
        if not isinstance(registration_value, dict):
            raise EvidenceError("checkout registration is unavailable")
        registered_identity = _registration(registration_value).worktree_identity
        if not directory_identities_match(root_identity, registered_identity):
            raise EvidenceError("evidence root identity differs from registration")
        prepared_input = build_prelaunch_appserver_input(
            root_fd=root_fd,
            manifest=evidence_manifest,
            pr_url=state["pr_url"],
            base_sha=state["base_sha"],
            head_sha=state["head_sha"],
            forbidden_paths=(worktree,),
        )
    except ValueError as evidence_error:
        raise inconclusive(
            f"artifact-only app-server evidence is not trustworthy: {evidence_error}",
            stage="reviewer-evidence",
            code="appserver-evidence-inconclusive",
        ) from evidence_error
    finally:
        os.close(root_fd)

    lifecycle = DurableProcessLifecycle(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
    )
    result, execution_failed = _run_authenticated_review_boundary(
        codex_executable=pathlib.Path(state["codex_executable"]),
        runtime_root=attempt_dir / "review-runtime",
        repo=pathlib.Path(state["repo"]),
        helper_root=tool_root(),
        retention_root=attempt_dir.parent,
        checkout_root=worktree,
        prompt=prepared_input.prompt,
        requested_model=state["requested_model"],
        requested_reasoning_effort=state["requested_reasoning_effort"],
        lifecycle=lifecycle,
        liveness_checkpoint=lambda: _require_outer_liveness(outer),
    )
    if execution_failed and not peer_is_open(outer):
        raise OuterAbandoned("outer liveness closed during reviewer execution")
    if execution_failed or result is None:
        error = inconclusive(
            "authenticated app-server review failed at a closed runtime boundary",
            stage="reviewer-runtime",
            code="authenticated-appserver-failed",
        )
        error.observed_runtime = {
            "actual_invocation_enabled": True,
            "evidence_bundle_sha256": sha256_bytes(
                prepared_input.evidence_bundle.to_bytes()
            ),
            "model_input_length": len(prepared_input.prompt),
            "model_input_sha256": sha256_bytes(prepared_input.prompt),
            "requested_model": state.get("requested_model"),
            "requested_reasoning_effort": state.get("requested_reasoning_effort"),
            "transport": "app-server-stdio",
        }
        if lifecycle.state.get("phase") == "spawn-intent":
            error.reviewer_child_started = True
        raise error from None

    if not peer_is_open(outer):
        raise OuterAbandoned("outer liveness closed after reviewer completion")
    state = lifecycle.state
    state_digest = lifecycle.state_digest
    observed_runtime = {
        **result.observed_runtime,
        "actual_invocation_enabled": True,
        "auth": result.auth,
        "auth_refresh": result.auth_refresh,
        "evidence_bundle_sha256": sha256_bytes(
            prepared_input.evidence_bundle.to_bytes()
        ),
        "model_input_length": len(prepared_input.prompt),
        "model_input_sha256": sha256_bytes(prepared_input.prompt),
        "requested_model": state.get("requested_model"),
        "requested_reasoning_effort": state.get("requested_reasoning_effort"),
        "transport": "app-server-stdio",
    }
    state, state_digest = publish_terminal_review(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        outer=outer,
        state=state,
        state_digest=state_digest,
        review_status=result.process.session.review_status,
        final_text=result.process.session.final_text,
        leader_exit=result.process.exit_code,
        observed_runtime=observed_runtime,
    )
    return state, state_digest, result.process.session.final_text


def _run_checkout(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    outer: socket.socket,
    state: dict[str, Any],
    state_digest: str,
    source_fd: int,
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + CHECKOUT_SECONDS
    state, state_digest = commit_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        updates={"phase": "worktree-adding", "worktree_status": "adding"},
        deadline=deadline,
    )
    parent, child = socket_pair()
    token = os.urandom(32).hex()
    worker: SpawnedProcess | None = None
    try:
        worker = _spawn_internal(
            entrypoint=entrypoint,
            mode="_checkout-worker",
            arguments=(
                "--attempt-dir",
                str(attempt_dir),
                "--control-fd",
                "3",
                "--source-fd",
                "4",
                "--token",
                token,
            ),
            cwd=attempt_dir,
            pass_fds=(child.fileno(), source_fd),
            own_process_group=True,
        )
        child.close()
        await_exec(worker, deadline=deadline)
        created = _wait_child_record(child=parent, outer=outer, deadline=deadline)
        if created.get("type") == "checkout-failed":
            raise SupervisorError(
                created.get("error", "checkout worker failed"),
                status=created.get("status", "inconclusive"),
                stage=created.get("stage", "checkout"),
                code=created.get("code", "checkout-worker-failed"),
            )
        if created.get("type") != "worktree-created" or created.get("token") != token:
            raise ValueError("checkout worker registration record is invalid")
        registration_value = created.get("registration")
        if not isinstance(registration_value, dict):
            raise ValueError("checkout worker registration evidence is malformed")
        registration = _registration(registration_value)
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "registration": _registration_json(registration),
                "worktree_status": "active",
            },
            deadline=deadline,
        )
        send_record(
            parent, {"type": "continue-index", "token": token}, deadline=deadline
        )
        index_complete = _wait_child_record(
            child=parent, outer=outer, deadline=deadline
        )
        if index_complete.get("type") == "checkout-failed":
            raise SupervisorError(
                index_complete.get("error", "checkout worker failed"),
                status=index_complete.get("status", "inconclusive"),
                stage=index_complete.get("stage", "checkout"),
                code=index_complete.get("code", "checkout-worker-failed"),
            )
        if (
            index_complete.get("type") != "index-initialized"
            or index_complete.get("token") != token
        ):
            raise ValueError("checkout worker index record is invalid")
        post_index_count = index_complete.get("registration_descendant_count")
        post_index_path_bytes = index_complete.get("registration_descendant_path_bytes")
        if type(post_index_count) is not int or type(post_index_path_bytes) is not int:
            raise ValueError("checkout worker index enumeration is malformed")
        updated_registration = dict(registration_value)
        updated_registration["descendant_count"] = post_index_count
        updated_registration["descendant_path_bytes"] = post_index_path_bytes
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "registration_initial_enumeration": {
                    "descendant_count": registration.descendant_count,
                    "descendant_path_bytes": registration.descendant_path_bytes,
                },
                "registration": updated_registration,
                "worktree_status": "index-initialized",
            },
            deadline=deadline,
        )
        send_record(
            parent, {"type": "continue-phase0", "token": token}, deadline=deadline
        )
        phase0 = _wait_child_record(child=parent, outer=outer, deadline=deadline)
        if phase0.get("type") == "checkout-failed":
            raise SupervisorError(
                phase0.get("error", "checkout worker failed"),
                status=phase0.get("status", "inconclusive"),
                stage=phase0.get("stage", "checkout"),
                code=phase0.get("code", "checkout-worker-failed"),
            )
        if phase0.get("type") != "phase0-complete" or phase0.get("token") != token:
            raise ValueError("checkout worker phase-0 record is invalid")
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "phase": "validating",
                "name_semantics": phase0.get("name_semantics"),
                "symlink_target_count": phase0.get("symlink_target_count"),
            },
            deadline=deadline,
        )
        send_record(
            parent,
            {"type": "continue-materialization", "token": token},
            deadline=deadline,
        )
        complete = _wait_child_record(child=parent, outer=outer, deadline=deadline)
        if complete.get("type") == "checkout-failed":
            raise SupervisorError(
                complete.get("error", "checkout worker failed"),
                status=complete.get("status", "inconclusive"),
                stage=complete.get("stage", "checkout"),
                code=complete.get("code", "checkout-worker-failed"),
            )
        if (
            complete.get("type") != "checkout-complete"
            or complete.get("token") != token
        ):
            raise ValueError("checkout worker completion record is invalid")
        wait_terminal(worker.pid, deadline=deadline)
        exit_code = reap(worker.pid, deadline=deadline)
        worker = None
        if exit_code != 0:
            raise ValueError("checkout worker exited nonzero after completion")
        evidence = complete.get("evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("sealed_diff_sha256") != state["diff_sha256"]
        ):
            raise ValueError("checkout worker sealed-diff evidence is malformed")
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "checkout_evidence": evidence,
                "source_custody_released": True,
                "worktree_status": "validated",
            },
            deadline=deadline,
        )
        return state, state_digest
    except BaseException as error:
        if worker is not None:
            try:
                _terminate_group(worker)
            except BaseException as cleanup_error:
                raise PrelaunchWorkerClosureUnproven(
                    "checkout worker group closure is unproven"
                ) from cleanup_error
            worker = None
            raise PrelaunchWorkerClosureUnproven(
                "checkout worker descendants cannot be proven absent"
            ) from error
        raise
    finally:
        parent.close()
        child.close()


def _preserved_cleanup_status(state: dict[str, Any]) -> str:
    status = state.get("cleanup_status")
    if status in {"logs-truncated", "cleanup-warning"}:
        return status
    return "cleanup-warning"


def _implemented_unsupported_clauses(state: dict[str, Any]) -> list[Any]:
    clauses = state.get("unsupported_clauses", [])
    if not isinstance(clauses, list):
        return []
    return [
        clause
        for clause in clauses
        if not isinstance(clause, dict)
        or clause.get("clause") != "automatic-targeted-mixed-worktree-removal"
    ]


def _ensure_control_namespace(
    state: dict[str, Any],
    *,
    checkout_parent_fd: int,
    checkout_parent_identity: Identity,
) -> tuple[pathlib.Path, Identity]:
    path = pathlib.Path(state["control_namespace"])
    worktree = pathlib.Path(state["worktree_path"])
    if path.parent != worktree.parent:
        raise ValueError("control namespace escaped the checkout parent")
    name = os.fsencode(path.name)
    try:
        metadata = os.stat(name, dir_fd=checkout_parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        os.mkdir(name, 0o700, dir_fd=checkout_parent_fd)
        os.fsync(checkout_parent_fd)
        metadata = os.stat(name, dir_fd=checkout_parent_fd, follow_symlinks=False)
    if not directory_identities_match(
        identity_from_stat(os.fstat(checkout_parent_fd)), checkout_parent_identity
    ):
        raise ValueError("checkout parent changed while creating control namespace")
    identity = identity_from_stat(metadata)
    if (
        not stat.S_ISDIR(identity.mode)
        or identity.uid != os.getuid()
        or stat.S_IMODE(identity.mode) != 0o700
    ):
        raise ValueError("control namespace identity or mode is unsafe")
    namespace_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=checkout_parent_fd,
    )
    try:
        validate_private_directory_fd(namespace_fd, path)
        if not directory_identities_match(
            identity_from_stat(os.fstat(namespace_fd)), identity
        ):
            raise ValueError("control namespace changed while opening")
    finally:
        os.close(namespace_fd)
    return path, identity


def _cleanup_control_namespace(
    state: dict[str, Any],
    *,
    expected_identity: Identity | None = None,
) -> None:
    path = pathlib.Path(state["control_namespace"])
    parent_fd, _ = open_absolute_directory_chain(path.parent, private_leaf=True)
    directory_fd: int | None = None
    try:
        try:
            directory_fd = os.open(
                os.fsencode(path.name),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return
        identity = identity_from_stat(os.fstat(directory_fd))
        validate_private_directory_fd(directory_fd, path)
        if (
            identity.uid != os.getuid()
            or stat.S_IMODE(identity.mode) != 0o700
            or (
                expected_identity is not None
                and not directory_identities_match(identity, expected_identity)
            )
        ):
            raise ValueError("control namespace identity or mode changed")
        if os.listdir(directory_fd):
            raise ValueError("control namespace is not empty")
        os.fsync(directory_fd)
        os.close(directory_fd)
        directory_fd = None
        os.rmdir(os.fsencode(path.name), dir_fd=parent_fd)
        os.fsync(parent_fd)
        try:
            os.stat(
                os.fsencode(path.name),
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ValueError("control namespace remains present after removal")
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def _manual_worktree_recovery(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
    stage: str,
    error: BaseException | str,
    evidence: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    warning = state.get("cleanup_warning")
    if not isinstance(warning, dict):
        warning = {
            "kind": "destructive-worktree-cleanup",
            "non_ttl": True,
            "ttl_seconds": None,
            "expires_at": None,
            "fallback_overall_status": "blocked-worktree-capacity",
            "created_at": time.time(),
        }
    warning = {**warning, "outstanding": True, "manual_recovery": True}
    message = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
    return commit_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        updates={
            "worktree_status": "manual-recovery-required",
            "checkout_settlement": "outstanding",
            "reservation_status": "checkout-outstanding",
            "cleanup_status": _preserved_cleanup_status(state),
            "cleanup_warning": warning,
            "failure_stage": stage,
            "cleanup_error": message,
            "cleanup_recovery_evidence": evidence,
            "unsupported_clauses": _implemented_unsupported_clauses(state),
        },
        deadline=time.monotonic() + 30,
    )


def _cleanup_worktree(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
) -> tuple[dict[str, Any], str]:
    worktree = pathlib.Path(state["worktree_path"])
    registration_value = state.get("registration")
    checkout_parent_fd: int | None = None
    registration_parent_fd: int | None = None
    manifest: CustodiedManifest | None = None
    try:
        existing_intent = state.get("worktree_cleanup_intent")
        if isinstance(existing_intent, dict) and existing_intent.get("outstanding"):
            return _manual_worktree_recovery(
                entrypoint=entrypoint,
                attempt_dir=attempt_dir,
                lease_fd=lease_fd,
                state=state,
                state_digest=state_digest,
                stage="worktree-cleanup-custody-lost",
                error="durable cleanup intent outlived its continuously held descriptors",
                evidence={"worktree_cleanup_intent": existing_intent},
            )

        checkout_binding = state.get("checkout_parent_binding")
        common_binding = state.get("common_git_dir_binding")
        if not isinstance(checkout_binding, dict) or not isinstance(
            common_binding, dict
        ):
            raise ValueError("reservation has no authenticated parent bindings")
        if pathlib.Path(checkout_binding.get("path", "")) != worktree.parent:
            raise ValueError("worktree parent differs from the reservation")
        common_git_dir = pathlib.Path(common_binding.get("path", ""))
        checkout_parent_fd, checkout_parent_identity = open_absolute_directory_chain(
            worktree.parent,
            private_leaf=True,
        )
        common_fd, common_identity = open_absolute_directory_chain(common_git_dir)
        try:
            if not directory_identities_match(
                checkout_parent_identity,
                _identity(checkout_binding["identity"]),
            ) or not directory_identities_match(
                common_identity,
                _identity(common_binding["identity"]),
            ):
                raise ValueError("reserved parent directory identity changed")
        finally:
            os.close(common_fd)

        worktree_name = os.fsencode(worktree.name)
        try:
            worktree_identity = identity_from_stat(
                os.stat(
                    worktree_name,
                    dir_fd=checkout_parent_fd,
                    follow_symlinks=False,
                )
            )
            worktree_present = True
        except FileNotFoundError:
            worktree_identity = None
            worktree_present = False

        registration: WorktreeRegistration | None = None
        registration_identity: Identity | None = None
        registration_present = False
        registration_parent_identity: Identity | None = None
        if registration_value is not None:
            if not isinstance(registration_value, dict):
                raise ValueError("worktree registration record is malformed")
            registration = _registration(registration_value)
            if registration.worktree != worktree:
                raise ValueError("recorded worktree path changed")
            expected_registration_parent = common_git_dir / "worktrees"
            if registration.registration.parent != expected_registration_parent:
                raise ValueError("registration parent escaped the common Git directory")
            try:
                registration_parent_fd, registration_parent_identity = (
                    open_absolute_directory_chain(expected_registration_parent)
                )
            except FileNotFoundError:
                registration_parent_fd = None
            if registration_parent_fd is not None:
                try:
                    registration_identity = identity_from_stat(
                        os.stat(
                            os.fsencode(registration.registration.name),
                            dir_fd=registration_parent_fd,
                            follow_symlinks=False,
                        )
                    )
                    registration_present = True
                except FileNotFoundError:
                    pass

        registration_scan = enumerate_registration_conflicts(
            common_git_dir=common_git_dir,
            worktree=worktree,
        )
        if registration is None:
            try:
                require_no_registration_conflicts(registration_scan)
            except BaseException as error:
                return _manual_worktree_recovery(
                    entrypoint=entrypoint,
                    attempt_dir=attempt_dir,
                    lease_fd=lease_fd,
                    state=state,
                    state_digest=state_digest,
                    stage="worktree-registration-unknown",
                    error=error,
                    evidence={"registration_scan": registration_scan},
                )

        info = inspect_repository(
            repo=pathlib.Path(state["repo"]),
            base_sha=state["base_sha"],
            head_sha=state["head_sha"],
            git_executable=state["git_executable"],
        )

        if not worktree_present and not registration_present:
            require_no_registration_conflicts(registration_scan)
            _cleanup_control_namespace(state)
            return commit_via_helper(
                entrypoint=entrypoint,
                attempt_dir=attempt_dir,
                lease_fd=lease_fd,
                state=state,
                state_digest=state_digest,
                updates={
                    "worktree_status": "removed" if registration else "absent",
                    "retained_worktree": None,
                    "checkout_cleanup_evidence": {
                        "branch": "double-absence",
                        "registration_scan": registration_scan,
                        "exact_names_absent": True,
                    },
                    "checkout_settlement": "exact",
                    "checkout_physical_remaining_by_fs": {},
                    "unsupported_clauses": _implemented_unsupported_clauses(state),
                },
                deadline=time.monotonic() + 30,
            )

        allocated = 0
        if worktree_present:
            allocated += allocated_bytes(worktree)
        if registration_present:
            assert registration is not None
            allocated += allocated_bytes(registration.registration)

        if worktree_present:
            assert worktree_identity is not None
            if registration is not None and not directory_identities_match(
                worktree_identity, registration.worktree_identity
            ):
                raise ValueError("worktree root identity changed before cleanup")
            if not stat.S_ISDIR(worktree_identity.mode):
                raise ValueError("worktree cleanup entry is not a directory")
        if registration_present:
            assert registration is not None and registration_identity is not None
            if not directory_identities_match(
                registration_identity, registration.registration_identity
            ):
                raise ValueError(
                    "worktree registration identity changed before cleanup"
                )
            if not stat.S_ISDIR(registration_identity.mode):
                raise ValueError("registration cleanup entry is not a directory")

        parent_evidence = {
            "checkout_parent": {
                "path": str(worktree.parent),
                "identity": checkout_parent_identity.to_json(),
            },
            "registration_parent": (
                {
                    "path": str(registration.registration.parent),
                    "identity": registration_parent_identity.to_json(),
                }
                if registration is not None and registration_parent_identity is not None
                else {"present": False}
            ),
            "checkout_entry": {
                "present": worktree_present,
                "name": worktree.name,
                "identity": worktree_identity.to_json()
                if worktree_identity is not None
                else None,
            },
            "registration_entry": {
                "present": registration_present,
                "name": registration.registration.name
                if registration is not None
                else None,
                "identity": registration_identity.to_json()
                if registration_identity is not None
                else None,
            },
        }

        operation = (
            "both-present"
            if worktree_present and registration_present
            else "checkout-only"
            if worktree_present
            else "registration-only"
        )
        control_path, control_identity = _ensure_control_namespace(
            state,
            checkout_parent_fd=checkout_parent_fd,
            checkout_parent_identity=checkout_parent_identity,
        )
        manifest_seal: dict[str, Any] | None = None
        if operation != "both-present":
            roots: list[RootSpec] = []
            if worktree_present:
                assert worktree_identity is not None
                roots.append(
                    RootSpec(
                        label="checkout",
                        parent_fd=checkout_parent_fd,
                        parent_identity=checkout_parent_identity,
                        name=worktree_name,
                        expected_identity=worktree_identity,
                    )
                )
            if registration_present:
                assert (
                    registration is not None
                    and registration_parent_fd is not None
                    and registration_parent_identity is not None
                    and registration_identity is not None
                )
                roots.append(
                    RootSpec(
                        label="registration",
                        parent_fd=registration_parent_fd,
                        parent_identity=registration_parent_identity,
                        name=os.fsencode(registration.registration.name),
                        expected_identity=registration_identity,
                    )
                )
            admission = state.get("admission", {})
            entry_cap = (
                admission.get("targeted_manifest_entry_bound", 200_000)
                if isinstance(admission, dict)
                else 200_000
            )
            payload_cap = (
                admission.get("targeted_manifest_payload_bound", 256 * 1024 * 1024)
                if isinstance(admission, dict)
                else 256 * 1024 * 1024
            )
            if type(entry_cap) is not int or type(payload_cap) is not int:
                raise ValueError("targeted cleanup manifest bounds are malformed")
            manifest_path = pathlib.Path(
                state.get("targeted_manifest_published", control_path / "manifest.bin")
            )
            if manifest_path != control_path / "manifest.bin":
                raise ValueError("targeted cleanup manifest path escaped its namespace")
            manifest = build_custodied_manifest(
                roots=tuple(roots),
                manifest_path=manifest_path,
                entry_cap=entry_cap,
                payload_cap=payload_cap,
            )
            manifest_seal = manifest.seal

        cleanup_warning = {
            "kind": "destructive-worktree-cleanup",
            "non_ttl": True,
            "ttl_seconds": None,
            "expires_at": None,
            "fallback_overall_status": "blocked-worktree-capacity",
            "outstanding": True,
            "created_at": time.time(),
        }
        intent = {
            "version": 1,
            "operation": operation,
            "stage": "intent-persisted",
            "outstanding": True,
            "custody": "continuous-descriptor",
            "custody_owner": {
                "pid": os.getpid(),
                "start_identity": process_start_identity(os.getpid()),
            },
            "non_ttl": True,
            "fallback_overall_status": "blocked-worktree-capacity",
            "parent_evidence": parent_evidence,
            "control_namespace_identity": control_identity.to_json(),
            "manifest": manifest_seal,
        }
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "worktree_status": "retained-worktree",
                "retained_worktree": {
                    **(registration_value or {}),
                    "worktree": str(worktree),
                    "allocated_bytes": allocated,
                    "checkout_settlement": "outstanding",
                    "parent_evidence": parent_evidence,
                },
                "checkout_settlement": "outstanding",
                "reservation_status": "checkout-outstanding",
                "cleanup_status": _preserved_cleanup_status(state),
                "cleanup_warning": cleanup_warning,
                "worktree_cleanup_intent": intent,
                "targeted_cleanup": intent if manifest_seal is not None else None,
                "unsupported_clauses": _implemented_unsupported_clauses(state),
            },
            deadline=time.monotonic() + 30,
        )
        if operation == "both-present":
            assert registration is not None
            count, path_bytes = enumerate_registration(registration.registration)
            if (count, path_bytes) != (
                registration.descendant_count,
                registration.descendant_path_bytes,
            ):
                raise ValueError(
                    "worktree registration descendants changed before cleanup"
                )
            remove_both_present_worktree(info, registration)
            assert checkout_parent_fd is not None and registration_parent_fd is not None
            os.fsync(checkout_parent_fd)
            os.fsync(registration_parent_fd)
            if not directory_identities_match(
                identity_from_stat(os.fstat(checkout_parent_fd)),
                checkout_parent_identity,
            ) or not directory_identities_match(
                identity_from_stat(os.fstat(registration_parent_fd)),
                registration_parent_identity,
            ):
                raise ValueError("cleanup parent identity changed during Git removal")
            for parent_fd, name in (
                (checkout_parent_fd, os.fsencode(worktree.name)),
                (registration_parent_fd, os.fsencode(registration.registration.name)),
            ):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("Git removal left an exact cleanup name present")
            deletion_proof = {
                "branch": "both-present",
                "parent_fsync_complete": True,
                "exact_names_absent": True,
            }
        else:
            assert manifest is not None
            deletion_proof = {
                "branch": operation,
                **delete_custodied_roots(manifest),
            }

        progressed_intent = {
            **intent,
            "stage": "deletion-proven",
            "deletion_proof": deletion_proof,
        }
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "worktree_cleanup_intent": progressed_intent,
                "targeted_cleanup": (
                    progressed_intent if manifest_seal is not None else None
                ),
                "checkout_cleanup_progress": deletion_proof,
            },
            deadline=time.monotonic() + 30,
        )

        registration_scan = enumerate_registration_conflicts(
            common_git_dir=common_git_dir,
            worktree=worktree,
        )
        require_no_registration_conflicts(registration_scan)
        verify_worktree_absent(info, worktree)
        if manifest_seal is not None:
            remove_published_manifest(manifest_seal)
        _cleanup_control_namespace(state, expected_identity=control_identity)
        completed_warning = {
            **cleanup_warning,
            "outstanding": False,
            "resolved_at": time.time(),
        }
        completed_intent = {
            **progressed_intent,
            "stage": "complete",
            "outstanding": False,
            "registration_scan": registration_scan,
        }
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "worktree_status": "removed",
                "retained_worktree": None,
                "checkout_cleanup_evidence": {
                    "branch": operation,
                    "parent_evidence": parent_evidence,
                    "deletion_proof": deletion_proof,
                    "registration_scan": registration_scan,
                    "manifest": manifest_seal,
                    "exact_names_absent": True,
                },
                "checkout_settlement": "exact",
                "checkout_physical_remaining_by_fs": {},
                "cleanup_status": _preserved_cleanup_status(state),
                "cleanup_warning": completed_warning,
                "worktree_cleanup_intent": completed_intent,
                "targeted_cleanup": (
                    completed_intent if manifest_seal is not None else None
                ),
                "unsupported_clauses": _implemented_unsupported_clauses(state),
            },
            deadline=time.monotonic() + 30,
        )
        return state, state_digest
    except BaseException as error:
        disk_state, _, disk_digest = read_attempt_state(attempt_dir)
        return _manual_worktree_recovery(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=disk_state,
            state_digest=disk_digest,
            stage="worktree-cleanup",
            error=error,
        )
    finally:
        if manifest is not None:
            manifest.close()
        if registration_parent_fd is not None:
            os.close(registration_parent_fd)
        if checkout_parent_fd is not None:
            os.close(checkout_parent_fd)


def _remove_clean_logs(attempt_dir: pathlib.Path) -> None:
    directory_fd, _ = open_absolute_directory_chain(attempt_dir, private_leaf=True)
    try:
        for name in tuple(os.fsencode(value) for value in os.listdir(directory_fd)):
            if not (
                name.startswith(b"codex.stdout.") or name.startswith(b"codex.stderr.")
            ):
                continue
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError("diagnostic archive identity is unsafe")
            os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _settle_process(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
) -> tuple[dict[str, Any], str]:
    fifo_path = pathlib.Path(state["final_fifo_path"])
    try:
        fifo_stat = os.lstat(fifo_path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISFIFO(fifo_stat.st_mode) or fifo_stat.st_uid != os.getuid():
            raise ValueError("unsettled final transport path is unsafe")
        os.unlink(fifo_path)
        fsync_directory(fifo_path.parent)
    if state.get("review_status") == "clean" and state.get("cleanup_status") == "clean":
        _remove_clean_logs(attempt_dir)
    return settle_process_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        deadline=time.monotonic() + 30,
    )


def _record_failure(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    lease_fd: int,
    state: dict[str, Any],
    state_digest: str,
    error: BaseException,
    abandoned: bool,
) -> tuple[dict[str, Any], str]:
    failure = error.failure if isinstance(error, SupervisorError) else None
    current_phase = state.get("phase")
    if current_phase in {"reserved", "worktree-adding", "validating"}:
        phase = "prelaunch-aborted"
        if isinstance(error, PrelaunchWorkerClosureUnproven):
            launch_status = "uncertain"
            review_status = "inconclusive"
            closure = "unproven"
        else:
            launch_status = "prelaunch-aborted"
            review_status = "not-run"
            closure = "proven-by-owner"
    elif current_phase == "spawn-intent":
        if getattr(error, "reviewer_child_started", False):
            phase = "spawn-intent"
            launch_status = "uncertain"
            review_status = "inconclusive"
            closure = "unproven"
        else:
            phase = "prelaunch-aborted"
            launch_status = "prelaunch-aborted"
            review_status = "not-run"
            closure = "proven-by-owner"
    elif current_phase == "launched":
        phase = "launched"
        launch_status = "launched"
        review_status = "inconclusive"
        closure = "unproven"
    else:
        phase = current_phase
        launch_status = state.get("launch_status", "launched")
        review_status = "inconclusive"
        closure = (
            "proven-by-owner"
            if state.get("closure") == "proven-by-owner"
            else "unproven"
        )
    cleanup_status = (
        "logs-truncated"
        if getattr(error, "logs_truncated", False)
        else state.get("cleanup_status")
        if state.get("cleanup_status") in {"logs-truncated", "cleanup-warning"}
        else "cleanup-pending"
    )
    updates = {
        "phase": phase,
        "launch_status": launch_status,
        "review_status": review_status,
        "closure": closure,
        "abandonment": abandoned,
        "failure_stage": failure.stage if failure else "attempt-supervisor",
        "failure": {
            "status": failure.status if failure else "inconclusive",
            "code": failure.code if failure else "attempt-supervisor-failed",
            "message": failure.message
            if failure
            else f"{type(error).__name__}: {error}",
        },
        "cleanup_status": cleanup_status,
    }
    observed_runtime = getattr(error, "observed_runtime", None)
    if isinstance(observed_runtime, dict):
        updates["observed_runtime"] = dict(observed_runtime)
    return commit_via_helper(
        entrypoint=entrypoint,
        attempt_dir=attempt_dir,
        lease_fd=lease_fd,
        state=state,
        state_digest=state_digest,
        updates=updates,
        deadline=time.monotonic() + 30,
    )


def _compact_terminal(
    state: dict[str, Any],
    *,
    final_authorization_exact: bool = False,
) -> dict[str, Any]:
    cleanup_warning = state.get("cleanup_warning")
    cleanup_outstanding = isinstance(cleanup_warning, dict) and cleanup_warning.get(
        "outstanding"
    )
    if (
        state.get("worktree_status") == "manual-recovery-required"
        or state.get("checkout_settlement") != "exact"
        or cleanup_outstanding
    ):
        overall = "blocked-worktree-capacity"
    elif final_authorization_exact and state.get("review_status") in {
        "clean",
        "findings",
    }:
        overall = "completed"
    elif state.get("review_status") in {"clean", "findings"}:
        overall = "inconclusive"
    else:
        overall = state.get("failure", {}).get("status", "inconclusive")
    retained_worktree = state.get("retained_worktree")
    helper_custody = state.get("helper_custody")
    return {
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "attempt_id": state.get("attempt_id"),
        "overall_status": overall,
        "repo": state.get("repo"),
        "pr_url": state.get("pr_url"),
        "admission_status": state.get("admission_status"),
        "phase": state.get("phase"),
        "handoff": state.get("handoff"),
        "closure": state.get("closure"),
        "launch_status": state.get("launch_status"),
        "review_status": state.get("review_status"),
        "cleanup_status": state.get("cleanup_status"),
        "worktree_status": state.get("worktree_status"),
        "reservation_status": state.get("reservation_status"),
        "process_settlement": state.get("process_settlement"),
        "checkout_settlement": state.get("checkout_settlement"),
        "retention_state": state.get("retention_state"),
        "failure_stage": state.get("failure_stage"),
        "review_range": state.get("review_range"),
        "diff_length": state.get("diff_length"),
        "diff_sha256": state.get("diff_sha256"),
        "source_custody_released": state.get("source_custody_released", False),
        "helper_state": (
            helper_custody.get("state_dir")
            if isinstance(helper_custody, dict)
            else None
        ),
        "requested_model": state.get("requested_model"),
        "requested_reasoning_effort": state.get("requested_reasoning_effort"),
        "observed_runtime": state.get("observed_runtime"),
        "final_seal": state.get("final_seal"),
        "retained_process_bytes": state.get("retained_process_bytes"),
        "retained_worktree_path": (
            state.get("worktree_path") if isinstance(retained_worktree, dict) else None
        ),
        "retained_worktree_allocated_bytes": (
            retained_worktree.get("allocated_bytes")
            if isinstance(retained_worktree, dict)
            else None
        ),
        "attempt_dir": str(pathlib.Path(state["prompt_path"]).parent),
        "state_path": str(pathlib.Path(state["prompt_path"]).parent / "state.json"),
        "unsupported_clauses": state.get("unsupported_clauses", []),
        "cleanup_warning": cleanup_warning,
    }


def attempt_supervisor_main(
    *,
    entrypoint: pathlib.Path,
    attempt_dir: pathlib.Path,
    control_fd: int,
    lease_fd: int,
    handoff_token: str,
) -> int:
    outer = socket.socket(fileno=control_fd)
    source_fd: int | None = None
    cleanup_lock_fd: int | None = None
    prompt: bytes | None = None
    state: dict[str, Any] | None = None
    state_digest: str | None = None
    final_text: str | None = None
    abandoned = False
    try:
        handoff_deadline = time.monotonic() + HANDOFF_SECONDS
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state, _, state_digest = read_attempt_state(attempt_dir)
        send_record(
            outer,
            {
                "type": "attempt-supervisor-ready",
                "token": handoff_token,
                "pid": os.getpid(),
                "start_identity": process_start_identity(os.getpid()),
            },
            deadline=handoff_deadline,
        )
        custody_record, custody_fds = receive_record(
            outer,
            deadline=handoff_deadline,
            expected_fds=2,
        )
        if (
            custody_record.get("type") != "source-custody"
            or custody_record.get("token") != handoff_token
            or custody_record.get("helper_custody") != state["helper_custody"]
        ):
            raise ValueError("source custody handoff record is invalid")
        cleanup_lock_fd, source_fd = custody_fds
        custody = _custody(state["helper_custody"])
        if (
            identity_from_stat(os.fstat(cleanup_lock_fd))
            != custody.cleanup_lock_identity
        ):
            raise ValueError("received cleanup-lock descriptor identity is invalid")
        if identity_from_stat(os.fstat(source_fd)) != custody.source_identity:
            raise ValueError("received source descriptor identity is invalid")
        send_record(
            outer,
            {"type": "source-custody-accepted", "token": handoff_token},
            deadline=handoff_deadline,
        )

        offer, _ = receive_record(outer, deadline=handoff_deadline)
        if offer != {"type": "prompt-offer", "token": handoff_token}:
            raise ValueError("prompt handoff offer is invalid")
        prompt = receive_blob(outer, handoff_token, deadline=handoff_deadline)
        state, _, state_digest = read_attempt_state(attempt_dir)
        if (
            state.get("handoff") != "pending"
            or state.get("handoff_token") != handoff_token
            or state.get("supervisor", {}).get("pid") != os.getpid()
        ):
            raise ValueError("durable pending handoff state is invalid")
        _verify_prompt_artifact(state, prompt)
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={"handoff": "accepted", "prompt_private_copy_verified": True},
            deadline=handoff_deadline,
        )
        send_record(
            outer,
            {
                "type": "handoff-accepted",
                "token": handoff_token,
                "state_sha256": state_digest,
            },
            deadline=handoff_deadline,
        )
        start, _ = receive_record(outer, deadline=handoff_deadline)
        if start != {"type": "handoff-start", "token": handoff_token}:
            raise ValueError("handoff start acknowledgement is invalid")
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "handoff": "complete",
                "process_owner": "attempt-supervisor",
                "ownership_linearized_at": time.time(),
            },
            deadline=handoff_deadline,
        )
        send_record(
            outer,
            {
                "type": "handoff-complete",
                "token": handoff_token,
                "state_sha256": state_digest,
            },
            deadline=handoff_deadline,
        )
        acknowledgement, _ = receive_record(outer, deadline=handoff_deadline)
        if acknowledgement != {
            "type": "handoff-complete-ack",
            "token": handoff_token,
            "state_sha256": state_digest,
        }:
            raise OuterAbandoned(
                "outer did not acknowledge the exact ownership handoff"
            )

        try:
            state, state_digest = _run_checkout(
                entrypoint=entrypoint,
                attempt_dir=attempt_dir,
                lease_fd=lease_fd,
                outer=outer,
                state=state,
                state_digest=state_digest,
                source_fd=source_fd,
            )
            os.close(source_fd)
            source_fd = None
            os.close(cleanup_lock_fd)
            cleanup_lock_fd = None
            state, state_digest, final_text = run_reviewer(
                entrypoint=entrypoint,
                attempt_dir=attempt_dir,
                lease_fd=lease_fd,
                outer=outer,
                state=state,
                state_digest=state_digest,
                prompt=prompt,
            )
        except OuterAbandoned as error:
            abandoned = True
            raise error
        except BaseException:
            raise
    except BaseException as error:
        if isinstance(error, OuterAbandoned):
            abandoned = True
        if (
            state is not None
            and state_digest is not None
            and state.get("handoff") == "complete"
        ):
            try:
                state, _, state_digest = read_attempt_state(attempt_dir)
                state, state_digest = _record_failure(
                    entrypoint=entrypoint,
                    attempt_dir=attempt_dir,
                    lease_fd=lease_fd,
                    state=state,
                    state_digest=state_digest,
                    error=error,
                    abandoned=abandoned,
                )
            except BaseException:
                state = None
        else:
            outer.close()
            os.close(lease_fd)
            return 2
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if cleanup_lock_fd is not None:
            os.close(cleanup_lock_fd)

    if state is None or state_digest is None:
        outer.close()
        os.close(lease_fd)
        return 2
    try:
        state, state_digest = _cleanup_worktree(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
        )
        state, state_digest = commit_via_helper(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
            updates={
                "admission_status": (
                    "completed"
                    if state.get("checkout_settlement") == "exact"
                    else "blocked-worktree-capacity"
                ),
                "terminal_at": time.time(),
                "failure_stage": (
                    state.get("failure_stage")
                    if state.get("review_status") not in {"clean", "findings"}
                    else state.get("failure_stage")
                ),
            },
            deadline=time.monotonic() + 30,
        )
        state, state_digest = _settle_process(
            entrypoint=entrypoint,
            attempt_dir=attempt_dir,
            lease_fd=lease_fd,
            state=state,
            state_digest=state_digest,
        )
        summary = _compact_terminal(state)
        send_record(
            outer,
            {
                "type": "attempt-terminal",
                "token": handoff_token,
                "summary": summary,
            },
            deadline=time.monotonic() + 5,
        )
        return (
            0
            if state.get("review_status") in {"clean", "findings"}
            and state.get("worktree_status") != "manual-recovery-required"
            and state.get("checkout_settlement") == "exact"
            and not (
                isinstance(state.get("cleanup_warning"), dict)
                and state["cleanup_warning"].get("outstanding")
            )
            else 1
        )
    except BaseException:
        return 2
    finally:
        outer.close()
        os.close(lease_fd)
