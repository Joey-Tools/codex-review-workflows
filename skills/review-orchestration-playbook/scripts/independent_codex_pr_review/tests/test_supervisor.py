from __future__ import annotations

import os
import pathlib
import select
import signal
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    MAX_EVIDENCE_PRIMARY_BYTES,
    NAMED_LANE_ELIGIBLE,
    PROCESS_ENVELOPE_BYTES,
    RELEASED_TTL_SECONDS,
    SCHEMA_VERSION,
)
from review_supervisor.evidence import build_primary_evidence_bundle
from review_supervisor.errors import SupervisorError, blocked
from review_supervisor.gitraw import GitProcessClosureUnproven
from review_supervisor.ledger import (
    acquire_retention_lease,
    read_attempt_state,
    reconcile_ledger,
)
from review_supervisor.process import SpawnedProcess, await_exec, fork_exec
from review_supervisor.runtime import (
    DirectProcessClosureUnproven,
    _compact_terminal,
    _validate_terminal_lifecycle,
    direct_process_closure_failure,
)
from review_supervisor.secureio import (
    allocated_bytes,
    boot_identifier,
    canonical_json,
    fsync_directory,
    identity_from_stat,
    measure_filesystem,
    sha256_bytes,
)
from review_supervisor.supervisor import (
    _prepare_with_reclamation,
    _prequiescence_abort,
    _publish_final_authorization,
    _reclaim_released_attempts,
    _require_primary_evidence_budget,
    _require_primary_serialized_evidence_budget,
    _resolve_codex,
    _settle_rewritten_process_charge,
    _terminate_incomplete_handoff,
    cleanup,
    final_result,
    recover,
    release,
    status,
)

from tests.support import owned_temporary_directory


TOOL_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENTRYPOINT = TOOL_ROOT / "independent-codex-pr-review"


class ReviewContractEnvelopeTests(unittest.TestCase):
    def test_compact_terminal_is_always_named_lane_ineligible(self) -> None:
        cases = (
            ("clean", True),
            ("findings", True),
            ("inconclusive", False),
        )
        for review_status, authorized in cases:
            with self.subTest(review_status=review_status):
                summary = _compact_terminal(
                    {
                        "prompt_path": "/tmp/attempt/prompt.txt",
                        "review_contract": "forged",
                        "named_lane_eligible": True,
                        "review_status": review_status,
                        "checkout_settlement": "exact",
                        "worktree_status": "removed",
                        "failure": {"status": "inconclusive"},
                    },
                    final_authorization_exact=authorized,
                )
                self.assertEqual(
                    summary["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT
                )
                self.assertIs(summary["named_lane_eligible"], False)


class PreflightAdmissionTests(unittest.TestCase):
    def test_rejects_primary_diff_outside_final_evidence_budget(self) -> None:
        for length in (0, MAX_EVIDENCE_PRIMARY_BYTES + 1):
            with (
                self.subTest(length=length),
                self.assertRaises(SupervisorError) as caught,
            ):
                _require_primary_evidence_budget(length)

            self.assertEqual(caught.exception.failure.stage, "evidence-admission")
            self.assertEqual(
                caught.exception.failure.code,
                "primary-evidence-size-invalid",
            )

    def test_accepts_primary_diff_at_final_evidence_limit(self) -> None:
        _require_primary_evidence_budget(MAX_EVIDENCE_PRIMARY_BYTES)

    def test_rejects_primary_diff_after_json_escaping_expands_the_bundle(self) -> None:
        cases = (
            ("cjk", "界".encode() * (MAX_EVIDENCE_PRIMARY_BYTES // 3)),
            ("backslash", b"\\" * (3 * 1024 * 1024)),
        )
        for label, content in cases:
            with (
                self.subTest(label=label),
                self.assertRaises(SupervisorError) as caught,
            ):
                _require_primary_serialized_evidence_budget(
                    content,
                    expected_sha256=sha256_bytes(content),
                )

            self.assertEqual(caught.exception.failure.stage, "evidence-admission")
            self.assertEqual(
                caught.exception.failure.code,
                "primary-evidence-size-invalid",
            )

    def test_accepts_primary_diff_at_exact_serialized_bundle_limit(self) -> None:
        content = ("界\\" * 40).encode()
        bundle = build_primary_evidence_bundle(
            content,
            expected_sha256=sha256_bytes(content),
        )
        serialized_size = len(canonical_json(bundle.to_json()))

        with mock.patch(
            "review_supervisor.evidence.MAX_EVIDENCE_BUNDLE_BYTES",
            serialized_size,
        ):
            _require_primary_serialized_evidence_budget(
                content,
                expected_sha256=sha256_bytes(content),
            )
        with (
            mock.patch(
                "review_supervisor.evidence.MAX_EVIDENCE_BUNDLE_BYTES",
                serialized_size - 1,
            ),
            self.assertRaises(SupervisorError),
        ):
            _require_primary_serialized_evidence_budget(
                content,
                expected_sha256=sha256_bytes(content),
            )

    def test_rejects_invalid_primary_content_separately_from_bundle_size(self) -> None:
        with self.assertRaises(SupervisorError) as caught:
            _require_primary_serialized_evidence_budget(
                b"\xff",
                expected_sha256=sha256_bytes(b"\xff"),
            )

        self.assertEqual(caught.exception.failure.stage, "evidence-admission")
        self.assertEqual(
            caught.exception.failure.code,
            "primary-evidence-invalid",
        )

    def test_rejects_missing_and_nonexecutable_codex_paths(self) -> None:
        with owned_temporary_directory("codex-preflight-") as root:
            missing = root / "missing-codex"
            with self.assertRaises(SupervisorError) as missing_error:
                _resolve_codex(str(missing))
            self.assertEqual(
                missing_error.exception.failure.stage,
                "runtime-selection",
            )

            nonexecutable = root / "codex"
            nonexecutable.write_bytes(b"not executable\n")
            nonexecutable.chmod(0o600)
            with self.assertRaises(SupervisorError) as mode_error:
                _resolve_codex(str(nonexecutable))
            self.assertEqual(
                mode_error.exception.failure.code,
                "codex-unavailable",
            )


def _write_exact_state(attempt: pathlib.Path, state: dict[str, object]) -> None:
    state_path = attempt / "state.json"
    for _ in range(8):
        state_path.write_bytes(canonical_json(state))
        state_path.chmod(0o600)
        retained = allocated_bytes(attempt, entry_cap=1_000)
        physical = {measure_filesystem(attempt).identity: retained}
        if (
            state.get("retained_process_bytes") == retained
            and state.get("process_physical_remaining_by_fs") == physical
        ):
            return
        state["retained_process_bytes"] = retained
        state["process_physical_remaining_by_fs"] = physical
    raise AssertionError("test attempt allocation did not converge")


def _write_attempt(
    retention: pathlib.Path,
    *,
    suffix: str,
    retention_state: str,
    released_at: float | None,
    artifact: bool = True,
) -> pathlib.Path:
    attempt_id = f"1-{suffix}"
    attempt = retention / f"attempt-{attempt_id}"
    attempt.mkdir(mode=0o700)
    prompt = attempt / "prompt.txt"
    if artifact:
        prompt.write_bytes(b"retained prompt\n")
        prompt.chmod(0o600)
    state: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "attempt_id": attempt_id,
        "record_generation": 1,
        "previous_record_sha256": None,
        "boot_id": boot_identifier(),
        "phase": "prelaunch-aborted",
        "handoff": "aborted",
        "closure": "proven-by-owner",
        "process_settlement": "exact",
        "checkout_settlement": "exact",
        "checkout_physical_remaining_by_fs": {},
        "retention_state": retention_state,
        "prompt_path": str(prompt),
        "prompt_length": len(b"retained prompt\n"),
        "prompt_sha256": "0" * 64,
        "review_status": "not-run",
        "launch_status": "prelaunch-aborted",
        "cleanup_status": "clean",
        "worktree_status": "absent",
        "reservation_status": "settled",
        "admission_status": "completed",
        "failure_stage": None,
        "review_range": f"{'1' * 40}..{'2' * 40}",
        "requested_model": "gpt-5.6-sol",
        "requested_reasoning_effort": "xhigh",
        "observed_runtime": {},
        "final_seal": None,
        "final_fifo_path": str(attempt / "final.fifo"),
        "unsupported_clauses": [],
        "retained_process_bytes": 0,
        "process_physical_remaining_by_fs": {},
        "released_at": released_at,
        "release_reason": "resolved" if released_at is not None else None,
    }
    _write_exact_state(attempt, state)
    return attempt


def _terminal_observed_runtime() -> dict[str, object]:
    return {
        "process": {
            "elapsed_seconds": 1.0,
            "exit_code": 0,
            "stderr_bytes": 0,
            "stdout_bytes": 64,
            "streamed_message_bytes": 32,
        },
        "protocol": {
            "external_auth": "accepted",
            "ephemeral": True,
            "remote_control": "disabled-notification-observed",
            "runtime_workspace_root_count": 0,
            "session_source": "exec",
        },
        "model": {
            "model": "gpt-5.6-sol",
            "model_attempt": "primary",
            "model_provider": "openai",
            "reasoning_effort": "xhigh",
        },
        "containment": {
            "leader_reaped": True,
            "process_group_empty": True,
            "stdio_handles_closed": True,
            "snapshot_mutation_denials_verified": True,
            "snapshot_profile_bound": True,
            "writable_root_count": 2,
        },
        "actual_invocation_enabled": True,
        "auth": {
            "auth_mode": "external-chatgpt",
            "carrier_generation_verified": True,
            "source_revalidated_before_launch": True,
            "source_revalidated_before_login_serialization": True,
        },
        "auth_refresh": {"status": "not-required"},
        "evidence_bundle_sha256": "a" * 64,
        "model_input_length": 128,
        "model_input_sha256": "b" * 64,
        "requested_model": "gpt-5.6-sol",
        "requested_reasoning_effort": "xhigh",
        "transport": "app-server-stdio",
    }


def _write_authorized_attempt(
    retention: pathlib.Path,
    *,
    suffix: str,
) -> pathlib.Path:
    attempt = _write_attempt(
        retention,
        suffix=suffix,
        retention_state="held",
        released_at=None,
    )
    content = b"No findings.\n"
    final_path = attempt / "final.txt"
    final_path.write_bytes(content)
    final_path.chmod(0o600)
    seal = {
        "path": str(final_path),
        "identity": identity_from_stat(os.stat(final_path)).to_json(),
        "length": len(content),
        "sha256": sha256_bytes(content),
    }
    supervisor = {"pid": 987_654_321, "start_identity": "fixture-supervisor"}
    leader = {
        "pid": 5678,
        "pgid": 5678,
        "start_identity": "fixture-reviewer",
    }
    runtime_binding = {
        "session_id": leader["pid"],
        "profile_sha256": "8" * 64,
    }
    terminal_predecessor = "6" * 64
    terminal_proof_payload = {
        "predecessor_sha256": terminal_predecessor,
        "leader_exit": 0,
        "final_seal": seal,
    }
    state, _, _ = read_attempt_state(attempt)
    state.update(
        {
            "phase": "reviewed",
            "handoff": "complete",
            "handoff_token": "7" * 64,
            "process_owner": "attempt-supervisor",
            "supervisor": supervisor,
            "leader": leader,
            "runtime_process_binding": runtime_binding,
            "leader_exit": 0,
            "no_child_process_profile": {
                "version": 1,
                "authenticated": True,
                "kernel_enforced": True,
                "child_process_limit": 0,
                "leader": leader,
            },
            "process_history": [
                {
                    "stage": "reviewer",
                    "leader": leader,
                    "runtime_binding": runtime_binding,
                    "exit_code": 0,
                    "closure": "proven-by-owner",
                }
            ],
            "closure": "proven-by-owner",
            "abandonment": False,
            "launch_status": "completed",
            "review_status": "clean",
            "worktree_status": "removed",
            "source_custody_transferred": True,
            "source_custody_released": True,
            "terminal_commit_authorized": True,
            "terminal_authorization": {
                "leader_exit": 0,
                "final_seal": seal,
                "authorized_at": 1.0,
            },
            "terminal_authorization_proof": {
                **terminal_proof_payload,
                "binding_sha256": sha256_bytes(canonical_json(terminal_proof_payload)),
                "readback": "exact-nofollow-under-publication-lease",
            },
            "final_seal": seal,
            "observed_runtime": _terminal_observed_runtime(),
        }
    )
    _write_exact_state(attempt, state)
    state, _, digest = read_attempt_state(attempt)
    with acquire_retention_lease(retention, deadline=time.monotonic() + 5) as lease:
        _publish_final_authorization(
            entrypoint=ENTRYPOINT,
            attempt_dir=attempt,
            lease=lease,
            state=state,
            state_digest=digest,
            supervisor_binding=supervisor,
            supervisor_exit_code=0,
        )
    return attempt


class ReclaimCrashSafetyTests(unittest.TestCase):
    def _released_attempt(
        self, root: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path]:
        retention = root / "retention"
        retention.mkdir(mode=0o700)
        attempt = _write_attempt(
            retention,
            suffix="a" * 32,
            retention_state="released",
            released_at=1.0,
        )
        return retention, attempt

    def test_reclaiming_keeps_charge_when_deletion_never_starts(self) -> None:
        with owned_temporary_directory("reclaim-before-delete-") as root:
            retention, attempt = self._released_attempt(root)
            with mock.patch(
                "review_supervisor.supervisor._remove_reclaim_artifacts",
                side_effect=RuntimeError("kill point before deletion"),
            ):
                with self.assertRaisesRegex(RuntimeError, "kill point"):
                    cleanup(
                        entrypoint=ENTRYPOINT,
                        retention_root=retention,
                        attempt_dir=attempt,
                    )
            state, _, _ = read_attempt_state(attempt)
            self.assertEqual(state["retention_state"], "reclaiming")
            self.assertEqual(state["retained_process_bytes"], PROCESS_ENVELOPE_BYTES)
            self.assertTrue((attempt / "prompt.txt").is_file())
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.process_logical_bytes, PROCESS_ENVELOPE_BYTES)
            cleanup(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertFalse(attempt.exists())

    def test_partial_artifact_deletion_resumes_from_reclaiming(self) -> None:
        with owned_temporary_directory("reclaim-partial-delete-") as root:
            retention, attempt = self._released_attempt(root)

            def delete_one_then_stop(path: pathlib.Path) -> None:
                os.unlink(path / "prompt.txt")
                fsync_directory(path)
                raise RuntimeError("kill point after partial deletion")

            with mock.patch(
                "review_supervisor.supervisor._remove_reclaim_artifacts",
                side_effect=delete_one_then_stop,
            ):
                with self.assertRaisesRegex(RuntimeError, "partial deletion"):
                    cleanup(
                        entrypoint=ENTRYPOINT,
                        retention_root=retention,
                        attempt_dir=attempt,
                    )
            state, _, _ = read_attempt_state(attempt)
            self.assertEqual(state["retention_state"], "reclaiming")
            self.assertEqual(state["retained_process_bytes"], PROCESS_ENVELOPE_BYTES)
            self.assertFalse((attempt / "prompt.txt").exists())
            cleanup(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertFalse(attempt.exists())

    def test_zero_charge_tombstone_resumes_state_last_removal(self) -> None:
        with owned_temporary_directory("reclaim-zero-tombstone-") as root:
            retention, attempt = self._released_attempt(root)
            with mock.patch(
                "review_supervisor.supervisor._remove_reclaimed_attempt",
                side_effect=RuntimeError("kill point before state removal"),
            ):
                with self.assertRaisesRegex(RuntimeError, "before state"):
                    cleanup(
                        entrypoint=ENTRYPOINT,
                        retention_root=retention,
                        attempt_dir=attempt,
                    )
            state, _, _ = read_attempt_state(attempt)
            self.assertEqual(state["retention_state"], "reclaimed")
            self.assertEqual(state["retained_process_bytes"], 0)
            self.assertEqual(
                sorted(path.name for path in attempt.iterdir()), ["state.json"]
            )
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.process_logical_bytes, 0)
            cleanup(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertFalse(attempt.exists())

    def test_reconcile_rejects_zero_tombstone_with_an_artifact(self) -> None:
        with owned_temporary_directory("reclaim-invalid-zero-") as root:
            retention, attempt = self._released_attempt(root)
            with mock.patch(
                "review_supervisor.supervisor._remove_reclaimed_attempt",
                side_effect=RuntimeError("kill point before state removal"),
            ):
                with self.assertRaisesRegex(RuntimeError, "before state"):
                    cleanup(
                        entrypoint=ENTRYPOINT,
                        retention_root=retention,
                        attempt_dir=attempt,
                    )
            unexpected = attempt / "unexpected.txt"
            unexpected.write_bytes(b"unexpected\n")
            unexpected.chmod(0o600)
            with self.assertRaisesRegex(SupervisorError, "still contains artifacts"):
                reconcile_ledger(retention)

    def test_reconcile_removes_empty_state_last_crash_residue(self) -> None:
        with owned_temporary_directory("reclaim-empty-residue-") as root:
            retention, attempt = self._released_attempt(root)

            def remove_state_then_stop(
                unused_root: pathlib.Path, path: pathlib.Path
            ) -> None:
                os.unlink(path / "state.json")
                fsync_directory(path)
                raise RuntimeError("kill point after state removal")

            with mock.patch(
                "review_supervisor.supervisor._remove_reclaimed_attempt",
                side_effect=remove_state_then_stop,
            ):
                with self.assertRaisesRegex(RuntimeError, "after state"):
                    cleanup(
                        entrypoint=ENTRYPOINT,
                        retention_root=retention,
                        attempt_dir=attempt,
                    )
            self.assertTrue(attempt.is_dir())
            self.assertEqual(list(attempt.iterdir()), [])
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.attempt_count, 0)
            self.assertFalse(attempt.exists())


class FinalAuthorizationTests(unittest.TestCase):
    def test_publish_binds_the_direct_predecessor_and_exact_allocation(self) -> None:
        with owned_temporary_directory("final-publish-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="8" * 32,
                retention_state="held",
                released_at=None,
            )
            content = b"No findings.\n"
            final_path = attempt / "final.txt"
            final_path.write_bytes(content)
            final_path.chmod(0o600)
            state, _, _ = read_attempt_state(attempt)
            seal = {
                "path": str(final_path),
                "identity": identity_from_stat(os.stat(final_path)).to_json(),
                "length": len(content),
                "sha256": sha256_bytes(content),
            }
            supervisor = {"pid": 1234, "start_identity": "fixture-supervisor"}
            leader = {
                "pid": 5678,
                "pgid": 5678,
                "start_identity": "fixture-reviewer",
            }
            runtime_binding = {
                "session_id": leader["pid"],
                "profile_sha256": "8" * 64,
            }
            terminal_predecessor = "6" * 64
            terminal_proof_payload = {
                "predecessor_sha256": terminal_predecessor,
                "leader_exit": 0,
                "final_seal": seal,
            }
            state.update(
                {
                    "phase": "reviewed",
                    "handoff": "complete",
                    "handoff_token": "7" * 64,
                    "process_owner": "attempt-supervisor",
                    "supervisor": supervisor,
                    "leader": leader,
                    "runtime_process_binding": runtime_binding,
                    "leader_exit": 0,
                    "no_child_process_profile": {
                        "version": 1,
                        "authenticated": True,
                        "kernel_enforced": True,
                        "child_process_limit": 0,
                        "leader": leader,
                    },
                    "process_history": [
                        {
                            "stage": "reviewer",
                            "leader": leader,
                            "runtime_binding": runtime_binding,
                            "exit_code": 0,
                            "closure": "proven-by-owner",
                        }
                    ],
                    "closure": "proven-by-owner",
                    "abandonment": False,
                    "launch_status": "completed",
                    "review_status": "clean",
                    "worktree_status": "removed",
                    "source_custody_transferred": True,
                    "source_custody_released": True,
                    "terminal_commit_authorized": True,
                    "terminal_authorization": {
                        "leader_exit": 0,
                        "final_seal": seal,
                        "authorized_at": 1.0,
                    },
                    "terminal_authorization_proof": {
                        **terminal_proof_payload,
                        "binding_sha256": sha256_bytes(
                            canonical_json(terminal_proof_payload)
                        ),
                        "readback": "exact-nofollow-under-publication-lease",
                    },
                    "final_seal": seal,
                    "observed_runtime": _terminal_observed_runtime(),
                }
            )
            _write_exact_state(attempt, state)
            state, _, digest = read_attempt_state(attempt)
            pending = status(
                retention_root=retention,
                attempt_dir=attempt,
            )["attempts"][0]
            self.assertEqual(pending["overall_status"], "inconclusive")
            with acquire_retention_lease(
                retention, deadline=time.monotonic() + 5
            ) as lease:
                state, digest = _publish_final_authorization(
                    entrypoint=ENTRYPOINT,
                    attempt_dir=attempt,
                    lease=lease,
                    state=state,
                    state_digest=digest,
                    supervisor_binding=supervisor,
                    supervisor_exit_code=0,
                )
            authorization = state["final_authorization"]
            completed = status(
                retention_root=retention,
                attempt_dir=attempt,
            )["attempts"][0]
            self.assertEqual(completed["overall_status"], "completed")
            self.assertEqual(
                completed["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT
            )
            self.assertIs(completed["named_lane_eligible"], False)
            self.assertEqual(
                authorization["predecessor_generation"],
                state["record_generation"] - 1,
            )
            self.assertEqual(
                authorization["predecessor_sha256"],
                state["previous_record_sha256"],
            )
            self.assertEqual(
                state["retained_process_bytes"],
                allocated_bytes(attempt, entry_cap=1_000),
            )
            result = final_result(
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertEqual(
                result["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT
            )
            self.assertIs(result["named_lane_eligible"], False)
            self.assertEqual(result["final_message"], "No findings.")

    def test_terminal_auth_refresh_closure_must_match_process_history(self) -> None:
        with owned_temporary_directory("final-auth-refresh-binding-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_authorized_attempt(
                retention,
                suffix="9" * 32,
            )
            state, _, _ = read_attempt_state(attempt)
            refresh_leader = {
                "pid": 4567,
                "pgid": 4567,
                "start_identity": "fixture-auth-refresh",
            }
            refresh_binding = {
                "session_id": refresh_leader["pid"],
                "profile_sha256": "9" * 64,
            }
            state["process_history"].insert(
                0,
                {
                    "stage": "auth-refresh",
                    "leader": refresh_leader,
                    "runtime_binding": refresh_binding,
                    "exit_code": 0,
                    "closure": "proven-by-owner",
                },
            )
            state["observed_runtime"]["auth_refresh"] = {
                "status": "completed",
                "managed_auth_verified": True,
                "codex_home_verified": True,
                "requires_openai_auth": False,
                "process_closure": {
                    "pid": refresh_leader["pid"] + 1,
                    "process_group_id": refresh_leader["pid"] + 1,
                    "session_id": refresh_leader["pid"] + 1,
                    "profile_sha256": refresh_binding["profile_sha256"],
                    "exit_code": 0,
                    "leader_reaped": True,
                    "process_group_empty": True,
                    "stdio_closed": True,
                },
            }

            with self.assertRaisesRegex(ValueError, "does not match process history"):
                _validate_terminal_lifecycle(attempt, state)
            refresh_closure = state["observed_runtime"]["auth_refresh"][
                "process_closure"
            ]
            refresh_closure.update(
                {
                    "pid": refresh_leader["pid"],
                    "process_group_id": refresh_leader["pid"],
                    "session_id": refresh_leader["pid"],
                }
            )
            self.assertEqual(
                _validate_terminal_lifecycle(attempt, state),
                state["handoff_token"],
            )


class RecoverySettlementTests(unittest.TestCase):
    def test_released_attempt_chains_runtime_cleanup_reauthorization(self) -> None:
        with owned_temporary_directory("recover-released-runtime-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_authorized_attempt(
                retention,
                suffix="e" * 32,
            )
            release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            runtime = attempt / "review-runtime"
            runtime.mkdir(mode=0o700)
            retained = runtime / "authenticated-review-fixture"
            retained.mkdir(mode=0o700)
            artifact = retained / "ephemeral.txt"
            artifact.write_text("temporary review material")
            artifact.chmod(0o600)

            state, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                state, digest = _settle_rewritten_process_charge(
                    entrypoint=ENTRYPOINT,
                    attempt_dir=attempt,
                    lease_fd=lease.fd,
                    state=state,
                    state_digest=digest,
                )
                state, _ = _publish_final_authorization(
                    entrypoint=ENTRYPOINT,
                    attempt_dir=attempt,
                    lease=lease,
                    state=state,
                    state_digest=digest,
                    supervisor_binding=state["supervisor"],
                    supervisor_exit_code=state["supervisor_exit_code"],
                )

            exit_code, result = recover(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )

            self.assertEqual(exit_code, 0, result)
            self.assertEqual(result["status"], "recovered")
            self.assertFalse(runtime.exists())
            completed, _, _ = read_attempt_state(attempt)
            self.assertEqual(
                completed["final_authorization_rewrite"]["operation"],
                "runtime-cleanup",
            )
            self.assertEqual(
                completed["final_authorization_rewrite"]["status"],
                "complete",
            )
            self.assertEqual(
                final_result(
                    retention_root=retention,
                    attempt_dir=attempt,
                )["final_message"],
                "No findings.",
            )

    def test_exact_settled_retained_runtime_is_custodied_and_reaccounted(self) -> None:
        with owned_temporary_directory("recover-exact-runtime-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="5" * 32,
                retention_state="held",
                released_at=None,
            )
            runtime = attempt / "review-runtime"
            runtime.mkdir(mode=0o700)
            lease = runtime / "authenticated-review-fixture"
            lease.mkdir(mode=0o700)
            artifact = lease / "ephemeral.txt"
            artifact.write_text("temporary review material")
            artifact.chmod(0o600)
            state, _, _ = read_attempt_state(attempt)
            _write_exact_state(attempt, state)

            exit_code, result = recover(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )

            self.assertEqual(exit_code, 0, result)
            self.assertEqual(result["status"], "recovered")
            recovered, _, _ = read_attempt_state(attempt)
            rewrite = recovered["final_authorization_rewrite"]
            self.assertEqual(rewrite["operation"], "runtime-cleanup")
            self.assertEqual(rewrite["status"], "complete")
            self.assertFalse(rewrite["authorization_required"])
            self.assertFalse(runtime.exists())
            self.assertFalse((attempt / "runtime-cleanup.manifest").exists())
            retained = allocated_bytes(attempt, entry_cap=1_000)
            self.assertEqual(recovered["retained_process_bytes"], retained)
            self.assertEqual(recovered["process_settlement"], "exact")

            second_code, second = recover(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertEqual(second_code, 0)
            self.assertEqual(second["status"], "already-settled")

    def test_boot_change_recovers_unfinalized_review_and_retained_runtime(self) -> None:
        with owned_temporary_directory("recover-post-review-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="3" * 32,
                retention_state="held",
                released_at=None,
            )
            runtime = attempt / "review-runtime"
            runtime.mkdir(mode=0o700)
            lease = runtime / "authenticated-review-fixture"
            lease.mkdir(mode=0o700)
            secret = lease / "ephemeral.txt"
            secret.write_text("temporary review material")
            secret.chmod(0o600)
            state, _, _ = read_attempt_state(attempt)
            leader = {
                "pid": 4321,
                "pgid": 4321,
                "start_identity": "fixture-reviewer",
            }
            runtime_binding = {
                "session_id": leader["pid"],
                "profile_sha256": "9" * 64,
            }
            state.update(
                {
                    "boot_id": "previous-boot",
                    "phase": "reviewed",
                    "review_status": "clean",
                    "launch_status": "completed",
                    "handoff": "complete",
                    "process_owner": "attempt-supervisor",
                    "closure": "proven-by-owner",
                    "leader": leader,
                    "runtime_process_binding": runtime_binding,
                    "leader_exit": 0,
                    "no_child_process_profile": {
                        "version": 1,
                        "authenticated": True,
                        "kernel_enforced": True,
                        "child_process_limit": 0,
                        "leader": leader,
                    },
                    "process_history": [
                        {
                            "stage": "reviewer",
                            "leader": leader,
                            "runtime_binding": runtime_binding,
                            "exit_code": 0,
                            "closure": "proven-by-owner",
                        }
                    ],
                    "final_authorization": None,
                }
            )
            _write_exact_state(attempt, state)

            with mock.patch(
                "review_supervisor.supervisor.boot_identifier",
                return_value="current-boot",
            ):
                exit_code, result = recover(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(result["status"], "recovered")
            self.assertEqual(result["attempt"]["overall_status"], "inconclusive")
            recovered, _, _ = read_attempt_state(attempt)
            self.assertEqual(recovered["phase"], "post-review-aborted")
            self.assertEqual(recovered["review_status"], "inconclusive")
            self.assertEqual(recovered["closure"], "proven-by-owner")
            self.assertEqual(
                recovered["recovery"]["supervisor_closure"],
                "proven-by-boot-change",
            )
            retained = allocated_bytes(attempt, entry_cap=1_000)
            self.assertEqual(recovered["retained_process_bytes"], retained)
            snapshot = reconcile_ledger(retention)
            self.assertEqual(snapshot.process_logical_bytes, retained)
            self.assertFalse(runtime.exists())
            self.assertFalse((attempt / "runtime-cleanup.manifest").exists())
            release_code, _ = release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            self.assertEqual(release_code, 0)
            with self.assertRaises(SupervisorError):
                final_result(
                    retention_root=retention,
                    attempt_dir=attempt,
                )

    def test_boot_change_recovers_reaped_nonzero_review_before_settlement(self) -> None:
        with owned_temporary_directory("recover-nonzero-review-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="6" * 32,
                retention_state="held",
                released_at=None,
            )
            leader = {
                "pid": 4321,
                "pgid": 4321,
                "start_identity": "fixture-reviewer",
            }
            runtime_binding = {
                "session_id": leader["pid"],
                "profile_sha256": "9" * 64,
            }
            state, _, _ = read_attempt_state(attempt)
            state.update(
                {
                    "boot_id": "previous-boot",
                    "phase": "review-finished",
                    "review_status": "not-run",
                    "launch_status": "completed",
                    "handoff": "complete",
                    "process_owner": "attempt-supervisor",
                    "closure": "proven-by-owner",
                    "leader": leader,
                    "runtime_process_binding": runtime_binding,
                    "leader_exit": 17,
                    "no_child_process_profile": {
                        "version": 1,
                        "authenticated": True,
                        "kernel_enforced": True,
                        "child_process_limit": 0,
                        "leader": leader,
                    },
                    "process_history": [
                        {
                            "stage": "reviewer",
                            "leader": leader,
                            "runtime_binding": runtime_binding,
                            "exit_code": 17,
                            "closure": "proven-by-owner",
                        }
                    ],
                    "process_settlement": "outstanding",
                    "admission": {
                        "retention_fs": {
                            "identity": measure_filesystem(attempt).identity,
                        }
                    },
                    "final_authorization": None,
                }
            )
            _write_exact_state(attempt, state)

            with mock.patch(
                "review_supervisor.supervisor.boot_identifier",
                return_value="current-boot",
            ):
                exit_code, result = recover(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )

            self.assertEqual(exit_code, 0, result)
            recovered, _, _ = read_attempt_state(attempt)
            self.assertEqual(recovered["phase"], "post-review-aborted")
            self.assertEqual(recovered["review_status"], "inconclusive")
            self.assertEqual(recovered["leader_exit"], 17)
            self.assertEqual(recovered["process_settlement"], "exact")

    def test_post_review_recovery_rejects_invalid_history_without_mutation(
        self,
    ) -> None:
        with owned_temporary_directory("recover-invalid-history-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="2" * 32,
                retention_state="held",
                released_at=None,
            )
            state, _, _ = read_attempt_state(attempt)
            leader = {
                "pid": 4321,
                "pgid": 4321,
                "start_identity": "fixture-reviewer",
            }
            state.update(
                {
                    "boot_id": "previous-boot",
                    "phase": "reviewed",
                    "review_status": "clean",
                    "launch_status": "completed",
                    "handoff": "complete",
                    "process_owner": "attempt-supervisor",
                    "closure": "proven-by-owner",
                    "leader": leader,
                    "runtime_process_binding": {
                        "session_id": leader["pid"],
                        "profile_sha256": "9" * 64,
                    },
                    "leader_exit": 0,
                    "no_child_process_profile": {
                        "version": 1,
                        "authenticated": True,
                        "kernel_enforced": True,
                        "child_process_limit": 0,
                        "leader": leader,
                    },
                    "process_history": [],
                    "final_authorization": None,
                }
            )
            _write_exact_state(attempt, state)
            before_state = (attempt / "state.json").read_bytes()
            before_prompt = (attempt / "prompt.txt").read_bytes()

            with (
                mock.patch(
                    "review_supervisor.supervisor.boot_identifier",
                    return_value="current-boot",
                ),
                self.assertRaises(SupervisorError) as caught,
            ):
                recover(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )

            self.assertEqual(
                caught.exception.failure.code,
                "recovery-reviewer-closure-invalid",
            )
            self.assertEqual((attempt / "state.json").read_bytes(), before_state)
            self.assertEqual((attempt / "prompt.txt").read_bytes(), before_prompt)

    def test_exact_process_with_outstanding_checkout_fails_closed(self) -> None:
        with owned_temporary_directory("recover-checkout-outstanding-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="4" * 32,
                retention_state="held",
                released_at=None,
            )
            state, _, _ = read_attempt_state(attempt)
            state.update(
                {
                    "checkout_settlement": "outstanding",
                    "checkout_physical_remaining_by_fs": {"fixture": 1},
                    "reservation_status": "checkout-outstanding",
                }
            )
            _write_exact_state(attempt, state)
            before = (attempt / "state.json").read_bytes()

            with self.assertRaises(SupervisorError) as caught:
                recover(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )

            self.assertEqual(caught.exception.failure.status, "blocked")
            self.assertEqual(
                caught.exception.failure.code,
                "same-boot-owner-required",
            )
            self.assertEqual((attempt / "state.json").read_bytes(), before)


class ReleaseAuthorizationRecoveryTests(unittest.TestCase):
    def test_recover_finishes_pending_release_authorization(self) -> None:
        with owned_temporary_directory("recover-release-authorization-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_authorized_attempt(
                retention,
                suffix="d" * 32,
            )

            with (
                mock.patch(
                    "review_supervisor.supervisor._publish_final_authorization",
                    side_effect=RuntimeError("synthetic crash before reauthorization"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic crash"),
            ):
                release(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                    reason="resolved",
                )

            code, result = recover(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
            )
            self.assertEqual(code, 0, result)
            self.assertEqual(result["status"], "recovered")
            self.assertEqual(
                final_result(
                    retention_root=retention,
                    attempt_dir=attempt,
                )["final_message"],
                "No findings.",
            )

    def test_unauthed_release_retry_finishes_exact_accounting(self) -> None:
        with owned_temporary_directory("release-crash-unauthed-accounting-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="c" * 32,
                retention_state="held",
                released_at=None,
            )
            settle_calls = 0

            def crash_after_completion(**kwargs: object):
                nonlocal settle_calls
                settle_calls += 1
                if settle_calls == 2:
                    temporary = attempt / ".state.json.tmp-123-0123456789abcdef"
                    temporary.write_bytes(b"x" * 8192)
                    temporary.chmod(0o600)
                    raise RuntimeError("synthetic crash before final reaccounting")
                return _settle_rewritten_process_charge(**kwargs)

            with (
                mock.patch(
                    "review_supervisor.supervisor._settle_rewritten_process_charge",
                    side_effect=crash_after_completion,
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic crash"),
            ):
                release(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                    reason="resolved",
                )

            interrupted, _, _ = read_attempt_state(attempt)
            self.assertEqual(
                interrupted["final_authorization_rewrite"]["status"],
                "complete",
            )
            with self.assertRaises(SupervisorError) as caught:
                cleanup(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )
            self.assertEqual(
                caught.exception.failure.code,
                "release-accounting-pending",
            )

            code, result = release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            self.assertEqual(code, 0, result)
            completed, _, _ = read_attempt_state(attempt)
            measured = allocated_bytes(attempt, entry_cap=1_000)
            self.assertEqual(completed["retained_process_bytes"], measured)
            self.assertEqual(
                completed["process_physical_remaining_by_fs"],
                {measure_filesystem(attempt).identity: measured},
            )

    def test_release_retry_recovers_crash_before_reaccounting(self) -> None:
        with owned_temporary_directory("release-crash-reaccount-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_authorized_attempt(
                retention,
                suffix="a" * 32,
            )

            with (
                mock.patch(
                    "review_supervisor.supervisor._settle_rewritten_process_charge",
                    side_effect=RuntimeError("synthetic crash before reaccounting"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic crash"),
            ):
                release(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                    reason="resolved",
                )

            interrupted, _, _ = read_attempt_state(attempt)
            self.assertEqual(interrupted["retention_state"], "released")
            self.assertEqual(
                interrupted["final_authorization_rewrite"]["status"],
                "pending",
            )
            code, result = release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            self.assertEqual(code, 0, result)
            self.assertEqual(result["status"], "already-released")
            completed, _, _ = read_attempt_state(attempt)
            self.assertEqual(
                completed["final_authorization_rewrite"]["status"],
                "complete",
            )
            self.assertEqual(
                final_result(
                    retention_root=retention,
                    attempt_dir=attempt,
                )["final_message"],
                "No findings.",
            )

    def test_release_retry_recovers_crash_before_reauthorization(self) -> None:
        with owned_temporary_directory("release-crash-reauthorize-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_authorized_attempt(
                retention,
                suffix="b" * 32,
            )

            with (
                mock.patch(
                    "review_supervisor.supervisor._publish_final_authorization",
                    side_effect=RuntimeError("synthetic crash before reauthorization"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic crash"),
            ):
                release(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                    reason="resolved",
                )

            interrupted, _, _ = read_attempt_state(attempt)
            self.assertEqual(
                interrupted["final_authorization_rewrite"]["status"],
                "pending",
            )
            code, result = release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            self.assertEqual(code, 0, result)
            completed, _, _ = read_attempt_state(attempt)
            self.assertEqual(
                completed["final_authorization_rewrite"]["status"],
                "complete",
            )
            self.assertEqual(
                final_result(
                    retention_root=retention,
                    attempt_dir=attempt,
                )["final_message"],
                "No findings.",
            )


class ReclamationPolicyTests(unittest.TestCase):
    def test_explicit_cleanup_rejects_held_evidence_without_mutation(self) -> None:
        with owned_temporary_directory("cleanup-held-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="7" * 32,
                retention_state="held",
                released_at=None,
            )
            before = (attempt / "state.json").read_bytes()
            with self.assertRaises(SupervisorError) as caught:
                cleanup(
                    entrypoint=ENTRYPOINT,
                    retention_root=retention,
                    attempt_dir=attempt,
                )
            self.assertEqual(caught.exception.failure.code, "release-required")
            self.assertEqual((attempt / "state.json").read_bytes(), before)

    def test_ttl_and_pressure_reclaim_oldest_released_attempts_first(self) -> None:
        with owned_temporary_directory("reclaim-order-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            oldest = _write_attempt(
                retention,
                suffix="f" * 32,
                retention_state="released",
                released_at=100.0,
            )
            second = _write_attempt(
                retention,
                suffix="e" * 32,
                retention_state="released",
                released_at=200.0,
            )
            third = _write_attempt(
                retention,
                suffix="d" * 32,
                retention_state="released",
                released_at=300.0,
            )
            newest = _write_attempt(
                retention,
                suffix="c" * 32,
                retention_state="released",
                released_at=400.0,
            )
            with acquire_retention_lease(
                retention, deadline=time.monotonic() + 5
            ) as lease:
                ttl_reclaimed = _reclaim_released_attempts(
                    entrypoint=ENTRYPOINT,
                    root=retention,
                    lease=lease,
                    trigger="ttl",
                    released_before=250.0,
                )
                pressure_reclaimed = _reclaim_released_attempts(
                    entrypoint=ENTRYPOINT,
                    root=retention,
                    lease=lease,
                    trigger="admission-pressure",
                    limit=1,
                )
            self.assertEqual(
                ttl_reclaimed,
                (
                    oldest.name.removeprefix("attempt-"),
                    second.name.removeprefix("attempt-"),
                ),
            )
            self.assertEqual(pressure_reclaimed, (third.name.removeprefix("attempt-"),))
            self.assertFalse(oldest.exists())
            self.assertFalse(second.exists())
            self.assertFalse(third.exists())
            self.assertTrue(newest.exists())

    def test_prepare_reclaims_one_fresh_release_only_after_pressure(self) -> None:
        with owned_temporary_directory("reclaim-admission-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            checkout = root / "checkout"
            checkout.mkdir(mode=0o700)
            now = time.time()
            oldest = _write_attempt(
                retention,
                suffix="b" * 32,
                retention_state="released",
                released_at=now - RELEASED_TTL_SECONDS + 60,
            )
            newest = _write_attempt(
                retention,
                suffix="a" * 32,
                retention_state="released",
                released_at=now,
            )
            prepared = object()
            pressure = blocked(
                "retention pressure",
                stage="admission",
                code="blocked-retention",
            )
            with (
                acquire_retention_lease(
                    retention, deadline=time.monotonic() + 5
                ) as lease,
                mock.patch(
                    "review_supervisor.supervisor.prepare_run",
                    side_effect=(pressure, prepared),
                ) as prepare,
            ):
                result = _prepare_with_reclamation(
                    entrypoint=ENTRYPOINT,
                    lease=lease,
                    helper_state=root / "unused-helper",
                    repo=root / "unused-repo",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    pr_url="https://example.invalid/owner/repo/pull/1",
                    retention_root=retention,
                    checkout_parent=checkout,
                    git_executable="/usr/bin/git",
                    codex_executable="/usr/bin/false",
                )
            self.assertIs(result, prepared)
            self.assertEqual(prepare.call_count, 2)
            self.assertFalse(oldest.exists())
            self.assertTrue(newest.exists())

    def test_prepare_applies_the_seven_day_ttl_before_admission(self) -> None:
        with owned_temporary_directory("reclaim-seven-day-ttl-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            checkout = root / "checkout"
            checkout.mkdir(mode=0o700)
            now = time.time()
            expired = _write_attempt(
                retention,
                suffix="6" * 32,
                retention_state="released",
                released_at=now - RELEASED_TTL_SECONDS - 60,
            )
            fresh = _write_attempt(
                retention,
                suffix="5" * 32,
                retention_state="released",
                released_at=now - RELEASED_TTL_SECONDS + 60,
            )
            prepared = object()
            with (
                acquire_retention_lease(
                    retention, deadline=time.monotonic() + 5
                ) as lease,
                mock.patch(
                    "review_supervisor.supervisor.prepare_run", return_value=prepared
                ) as prepare,
            ):
                result = _prepare_with_reclamation(
                    entrypoint=ENTRYPOINT,
                    lease=lease,
                    helper_state=root / "unused-helper",
                    repo=root / "unused-repo",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    pr_url="https://example.invalid/owner/repo/pull/1",
                    retention_root=retention,
                    checkout_parent=checkout,
                    git_executable="/usr/bin/git",
                    codex_executable="/usr/bin/false",
                )
            self.assertIs(result, prepared)
            self.assertEqual(prepare.call_count, 1)
            self.assertFalse(expired.exists())
            self.assertTrue(fresh.exists())

    def test_release_remeasures_the_rewritten_state(self) -> None:
        with owned_temporary_directory("release-remeasure-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="9" * 32,
                retention_state="held",
                released_at=None,
            )
            code, result = release(
                entrypoint=ENTRYPOINT,
                retention_root=retention,
                attempt_dir=attempt,
                reason="resolved",
            )
            self.assertEqual(code, 0, result)
            state, _, _ = read_attempt_state(attempt)
            retained = allocated_bytes(attempt, entry_cap=1_000)
            self.assertEqual(state["retained_process_bytes"], retained)
            self.assertEqual(
                state["process_physical_remaining_by_fs"],
                {measure_filesystem(attempt).identity: retained},
            )


class IncompleteHandoffProcessTests(unittest.TestCase):
    def test_cleanup_failure_latches_the_incomplete_handoff_receipt(self) -> None:
        process = SpawnedProcess(
            pid=123,
            pgid=123,
            acknowledgement_fd=-1,
            passed_fd_numbers=(),
            start_identity="darwin-proc-start:123:456",
        )
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.supervisor._terminate_incomplete_handoff_once",
                side_effect=PermissionError("synthetic group cleanup failure"),
            ) as terminate,
        ):
            with self.assertRaises(DirectProcessClosureUnproven) as raised:
                _terminate_incomplete_handoff(process)
            self.assertIs(direct_process_closure_failure(), raised.exception)
        self.assertEqual(terminate.call_count, 2)
        self.assertIs(raised.exception.process, process)

    def test_prequiescence_abort_preserves_unproven_git_closure(self) -> None:
        process = SimpleNamespace(pid=124)
        failure = GitProcessClosureUnproven(
            process,
            None,
            TimeoutError("synthetic cleanup timeout"),
        )
        state = {"prompt_path": "/tmp/synthetic-prompt"}
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.supervisor.read_attempt_state",
                return_value=(state, b"state", "digest"),
            ),
            mock.patch(
                "review_supervisor.supervisor.commit_via_helper",
                return_value=(state, "next-digest"),
            ),
            mock.patch(
                "review_supervisor.supervisor.open_regular_nofollow",
                side_effect=FileNotFoundError,
            ),
            mock.patch(
                "review_supervisor.supervisor._cleanup_worktree",
                side_effect=failure,
            ),
            self.assertRaises(GitProcessClosureUnproven) as raised,
        ):
            _prequiescence_abort(
                entrypoint=ENTRYPOINT,
                attempt_dir=pathlib.Path("/tmp/synthetic-attempt"),
                lease=SimpleNamespace(fd=-1),
                message="synthetic handoff failure",
            )
        self.assertIs(raised.exception, failure)

    def test_termination_reaches_a_sigterm_ignoring_grandchild(self) -> None:
        script = """
import os
import signal
import time

child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(10)
os.write(3, f"{child}\\n".encode("ascii"))
os.close(3)
while True:
    time.sleep(10)
"""
        read_fd, write_fd = os.pipe()
        devnull = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        process = None
        try:
            process = fork_exec(
                (sys.executable, "-c", script),
                cwd=TOOL_ROOT,
                stdin_fd=devnull,
                stdout_fd=devnull,
                stderr_fd=devnull,
                pass_fds=(write_fd,),
                own_process_group=True,
            )
            os.close(write_fd)
            write_fd = -1
            await_exec(process, deadline=time.monotonic() + 5)
            ready, _, _ = select.select((read_fd,), (), (), 5)
            self.assertEqual(ready, [read_fd])
            grandchild_pid = int(os.read(read_fd, 64).strip())
            self.assertGreater(grandchild_pid, 1)
            exit_code = _terminate_incomplete_handoff(process)
            process = None
            self.assertIn(exit_code, {-signal.SIGTERM, -signal.SIGKILL})
            ready, _, _ = select.select((read_fd,), (), (), 5)
            self.assertEqual(ready, [read_fd])
            self.assertEqual(os.read(read_fd, 1), b"")
        finally:
            os.close(devnull)
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
            if process is not None:
                try:
                    os.killpg(process.pgid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    os.waitpid(process.pid, 0)
                except ChildProcessError:
                    pass


if __name__ == "__main__":
    unittest.main()
