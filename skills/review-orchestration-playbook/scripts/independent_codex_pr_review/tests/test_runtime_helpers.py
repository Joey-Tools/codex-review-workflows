from __future__ import annotations

import os
import pathlib
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from review_supervisor.constants import (
    APP_SERVER_CLI_VERSION,
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.errors import inconclusive
from review_supervisor.ledger import acquire_retention_lease, read_attempt_state
from review_supervisor.process import TerminationSchedule, process_start_identity
from review_supervisor.runtime import (
    DurableProcessLifecycle,
    OuterAbandoned,
    PrelaunchWorkerClosureUnproven,
    _record_failure,
    _run_authenticated_review_boundary,
    _validate_final_authorization_updates,
    authorize_terminal_via_helper,
    attempt_supervisor_main,
    commit_via_helper,
    publish_terminal_review,
    run_reviewer,
    settle_process_via_helper,
    verify_prompt_via_helper,
)
from review_supervisor.secureio import (
    canonical_json,
    identity_from_stat,
    publish_bytes,
    sha256_bytes,
)
from review_supervisor.wire import receive_record, send_blob, send_record, socket_pair

from tests.support import owned_temporary_directory


ENTRYPOINT = (
    pathlib.Path(__file__).resolve().parent.parent / "independent-codex-pr-review"
)


class RuntimeHelperTests(unittest.TestCase):
    def test_authenticated_review_boundary_drops_sensitive_traceback(self) -> None:
        marker = "sensitive-access-marker"

        def fail(**_arguments: object) -> None:
            auth = {"access_token": marker, "refresh_token": marker}
            raise RuntimeError(f"synthetic failure {len(auth)}")

        with mock.patch(
            "review_supervisor.runtime.run_authenticated_review",
            side_effect=fail,
        ):
            result, failed = _run_authenticated_review_boundary()

        self.assertIsNone(result)
        self.assertTrue(failed)

    def test_durable_process_lifecycle_records_intent_binding_and_closure(self) -> None:
        generations = iter(("intent", "launched", "closed"))

        def commit(**kwargs: object) -> tuple[dict[str, object], str]:
            state = dict(kwargs["state"])
            state.update(kwargs["updates"])
            return state, next(generations)

        lifecycle = DurableProcessLifecycle(
            entrypoint=ENTRYPOINT,
            attempt_dir=pathlib.Path("/attempt"),
            lease_fd=3,
            state={
                "phase": "validating",
                "launch_status": "not-attempted",
                "runtime_stage": None,
                "leader": None,
                "runtime_process_binding": None,
                "no_child_process_profile": None,
                "leader_exit": None,
                "closure": "unproven",
                "process_history": [],
            },
            state_digest="initial",
        )
        process = SimpleNamespace(
            pid=123,
            pgid=123,
            session_id=123,
            start_identity="darwin-proc-start:123",
            profile_sha256="a" * 64,
        )
        with mock.patch(
            "review_supervisor.runtime.commit_via_helper",
            side_effect=commit,
        ) as committed:
            lifecycle.begin("reviewer")
            lifecycle.launched("reviewer", process)
            lifecycle.closed("reviewer", exit_code=0)

        self.assertEqual(committed.call_count, 3)
        self.assertEqual(lifecycle.state_digest, "closed")
        self.assertEqual(lifecycle.state["phase"], "review-finished")
        self.assertEqual(lifecycle.state["closure"], "proven-by-owner")
        self.assertEqual(
            lifecycle.state["process_history"],
            [
                {
                    "stage": "reviewer",
                    "leader": lifecycle.state["leader"],
                    "runtime_binding": lifecycle.state["runtime_process_binding"],
                    "exit_code": 0,
                    "closure": "proven-by-owner",
                }
            ],
        )
        self.assertEqual(
            lifecycle.state["no_child_process_profile"]["leader"],
            lifecycle.state["leader"],
        )

    def test_durable_process_lifecycle_rejects_an_unclosed_predecessor(self) -> None:
        lifecycle = DurableProcessLifecycle(
            entrypoint=ENTRYPOINT,
            attempt_dir=pathlib.Path("/attempt"),
            lease_fd=3,
            state={
                "phase": "launched",
                "launch_status": "launched",
                "runtime_stage": "auth-refresh",
                "leader": {"pid": 123, "pgid": 123, "start_identity": "start"},
                "runtime_process_binding": {
                    "session_id": 123,
                    "profile_sha256": "a" * 64,
                },
                "no_child_process_profile": None,
                "leader_exit": None,
                "closure": "unproven",
                "process_history": [],
            },
            state_digest="initial",
        )
        with (
            mock.patch("review_supervisor.runtime.commit_via_helper") as commit,
            self.assertRaisesRegex(ValueError, "invalid phase"),
        ):
            lifecycle.begin("reviewer")
        commit.assert_not_called()

    def test_reviewer_stage_accepts_one_proven_auth_refresh(self) -> None:
        leader = {"pid": 123, "pgid": 123, "start_identity": "start"}
        runtime_binding = {
            "session_id": 123,
            "profile_sha256": "a" * 64,
        }
        lifecycle = DurableProcessLifecycle(
            entrypoint=ENTRYPOINT,
            attempt_dir=pathlib.Path("/attempt"),
            lease_fd=3,
            state={
                "phase": "validating",
                "launch_status": "completed",
                "runtime_stage": "auth-refresh",
                "leader": leader,
                "runtime_process_binding": runtime_binding,
                "no_child_process_profile": {
                    "version": 1,
                    "authenticated": True,
                    "kernel_enforced": True,
                    "child_process_limit": 0,
                    "leader": leader,
                },
                "leader_exit": 0,
                "closure": "proven-by-owner",
                "process_history": [
                    {
                        "stage": "auth-refresh",
                        "leader": leader,
                        "runtime_binding": runtime_binding,
                        "exit_code": 0,
                        "closure": "proven-by-owner",
                    }
                ],
            },
            state_digest="initial",
        )

        def commit(**kwargs: object) -> tuple[dict[str, object], str]:
            state = dict(kwargs["state"])
            state.update(kwargs["updates"])
            return state, "spawn-intent"

        with mock.patch(
            "review_supervisor.runtime.commit_via_helper",
            side_effect=commit,
        ):
            lifecycle.begin("reviewer")

        self.assertEqual(lifecycle.state["phase"], "spawn-intent")
        self.assertEqual(lifecycle.state["process_history"][0]["stage"], "auth-refresh")

    def test_publish_bytes_never_leaves_a_partial_destination(self) -> None:
        with owned_temporary_directory("atomic-artifact-") as root:
            destination = root / "final.txt"

            def fail_after_partial_write(fd: int, data: bytes) -> None:
                os.write(fd, data[:1])
                raise OSError("injected write failure")

            with mock.patch(
                "review_supervisor.secureio.write_all",
                side_effect=fail_after_partial_write,
            ):
                with self.assertRaisesRegex(OSError, "injected write failure"):
                    publish_bytes(destination, b"CLEAN\n")

            self.assertFalse(destination.exists())
            self.assertEqual(tuple(root.iterdir()), ())

    def test_terminal_review_is_authorized_before_classification_commit(self) -> None:
        with owned_temporary_directory("terminal-review-") as attempt:
            outer, peer = socket_pair()
            predecessor = {"phase": "launched"}
            authorization_pending = {
                "phase": "terminal-authorization-pending",
                "previous_record_sha256": "earlier",
            }
            authorized = {
                **authorization_pending,
                "terminal_commit_authorized": True,
            }
            completed = {
                **authorized,
                "phase": "reviewed",
                "review_status": "clean",
            }
            commits = mock.Mock(
                side_effect=(
                    (authorization_pending, "pending-digest"),
                    (completed, "completed-digest"),
                )
            )
            authorize = mock.Mock(return_value=(authorized, "authorized-digest"))
            try:
                with (
                    mock.patch(
                        "review_supervisor.runtime.commit_via_helper",
                        commits,
                    ),
                    mock.patch(
                        "review_supervisor.runtime.authorize_terminal_via_helper",
                        authorize,
                    ),
                ):
                    state, digest = publish_terminal_review(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=3,
                        outer=outer,
                        state=predecessor,
                        state_digest="predecessor-digest",
                        review_status="clean",
                        final_text="No findings.\n",
                        leader_exit=0,
                        observed_runtime={"transport": "app-server-stdio"},
                    )
            finally:
                outer.close()
                peer.close()

            self.assertEqual((state, digest), (completed, "completed-digest"))
            first_updates = commits.call_args_list[0].kwargs["updates"]
            self.assertNotIn("review_status", first_updates)
            self.assertNotIn("final_seal", first_updates)
            authorization_seal = authorize.call_args.kwargs["final_seal"]
            self.assertEqual((attempt / "final.txt").read_text(), "No findings.\n")
            self.assertEqual(
                authorization_seal["sha256"],
                sha256_bytes(b"No findings.\n"),
            )
            second_updates = commits.call_args_list[1].kwargs["updates"]
            self.assertEqual(second_updates["review_status"], "clean")
            self.assertEqual(second_updates["final_seal"], authorization_seal)

    def test_appserver_gate_evidence_is_retained_for_failure(self) -> None:
        observed = {
            "actual_invocation_enabled": False,
            "cli_version_expected": APP_SERVER_CLI_VERSION,
            "no_child_kernel_profile_verified": False,
            "requested_model": "gpt-5.6-sol",
            "requested_reasoning_effort": "xhigh",
            "supervisor_executable_authenticated": False,
            "transport": "app-server-stdio",
        }
        error = inconclusive(
            "app-server compatibility gate is closed",
            stage="reviewer-runtime",
            code="appserver-compatibility-gate-closed",
        )
        error.observed_runtime = observed
        error.logs_truncated = True
        state = {
            "phase": "launched",
            "launch_status": "launched",
            "cleanup_status": "clean",
        }
        with mock.patch(
            "review_supervisor.runtime.commit_via_helper",
            return_value=(state, "next-digest"),
        ) as commit:
            _record_failure(
                entrypoint=ENTRYPOINT,
                attempt_dir=pathlib.Path("/unused"),
                lease_fd=3,
                state=state,
                state_digest="previous-digest",
                error=error,
                abandoned=False,
            )
        updates = commit.call_args.kwargs["updates"]
        self.assertEqual(updates["observed_runtime"], observed)
        self.assertEqual(updates["cleanup_status"], "logs-truncated")
        self.assertEqual(updates["closure"], "unproven")

    def test_checkout_worker_uncertainty_never_claims_process_closure(self) -> None:
        state = {
            "phase": "validating",
            "launch_status": "not-attempted",
            "cleanup_status": "pending",
        }
        with mock.patch(
            "review_supervisor.runtime.commit_via_helper",
            return_value=(state, "next-digest"),
        ) as commit:
            _record_failure(
                entrypoint=ENTRYPOINT,
                attempt_dir=pathlib.Path("/unused"),
                lease_fd=3,
                state=state,
                state_digest="previous-digest",
                error=PrelaunchWorkerClosureUnproven("uncertain"),
                abandoned=False,
            )
        updates = commit.call_args.kwargs["updates"]
        self.assertEqual(updates["phase"], "prelaunch-aborted")
        self.assertEqual(updates["launch_status"], "uncertain")
        self.assertEqual(updates["review_status"], "inconclusive")
        self.assertEqual(updates["closure"], "unproven")

    def test_phase_helper_rejects_authorization_owned_fields(self) -> None:
        with owned_temporary_directory("phase-auth-fields-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = retention / f"attempt-1-{'a' * 32}"
            attempt.mkdir(mode=0o700)
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"1-{'a' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
                "phase": "validating",
            }
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                for field, value in {
                    "terminal_commit_authorized": True,
                    "terminal_authorization": {},
                    "terminal_authorization_proof": {},
                    "final_authorization": {},
                    "supervisor_exit_code": 0,
                }.items():
                    with (
                        self.subTest(field=field),
                        self.assertRaisesRegex(
                            ValueError,
                            "authorization-owned fields",
                        ),
                    ):
                        commit_via_helper(
                            entrypoint=ENTRYPOINT,
                            attempt_dir=attempt,
                            lease_fd=lease.fd,
                            state=state,
                            state_digest=digest,
                            updates={field: value},
                            deadline=time.monotonic() + 10,
                        )

    def test_phase_helper_rejects_boot_id_and_two_stage_phase_forgery(self) -> None:
        with owned_temporary_directory("phase-transition-forgery-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = retention / f"attempt-1-{'9' * 32}"
            attempt.mkdir(mode=0o700)
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"1-{'9' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
                "phase": "validating",
            }
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            forged_leader = {
                "pid": 424242,
                "pgid": 424242,
                "start_identity": "forged",
            }
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                with self.assertRaisesRegex(ValueError, "not allowlisted"):
                    commit_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        state=state,
                        state_digest=digest,
                        updates={"boot_id": "forged-boot"},
                        deadline=time.monotonic() + 10,
                    )
                state, digest = commit_via_helper(
                    entrypoint=ENTRYPOINT,
                    attempt_dir=attempt,
                    lease_fd=lease.fd,
                    state=state,
                    state_digest=digest,
                    updates={
                        "phase": "spawn-intent",
                        "runtime_stage": "reviewer",
                        "launch_status": "spawn-intent",
                        "leader": None,
                        "runtime_process_binding": None,
                        "no_child_process_profile": None,
                        "leader_exit": None,
                        "closure": "unproven",
                    },
                    deadline=time.monotonic() + 10,
                )
                forged_runtime = {
                    "session_id": forged_leader["pid"],
                    "profile_sha256": "a" * 64,
                }
                with self.assertRaisesRegex(ValueError, "not allowlisted"):
                    commit_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        state=state,
                        state_digest=digest,
                        updates={
                            "phase": "review-finished",
                            "launch_status": "completed",
                            "closure": "proven-by-owner",
                            "leader_exit": 0,
                            "process_history": [
                                {
                                    "stage": "reviewer",
                                    "leader": forged_leader,
                                    "runtime_binding": forged_runtime,
                                    "exit_code": 0,
                                    "closure": "proven-by-owner",
                                }
                            ],
                        },
                        deadline=time.monotonic() + 10,
                    )
            durable, _, durable_digest = read_attempt_state(attempt)
            self.assertEqual(durable, state)
            self.assertEqual(durable_digest, digest)
            self.assertEqual(durable["phase"], "spawn-intent")

    def test_process_settlement_requires_proven_closure(self) -> None:
        with owned_temporary_directory("phase-process-closure-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = retention / f"attempt-1-{'b' * 32}"
            attempt.mkdir(mode=0o700)
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"1-{'b' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
                "phase": "prelaunch-aborted",
                "closure": "unproven",
            }
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                with self.assertRaisesRegex(ValueError, "proven process closure"):
                    settle_process_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        state=state,
                        state_digest=digest,
                        deadline=time.monotonic() + 10,
                    )

    def test_final_authorization_commit_rejects_a_live_supervisor(self) -> None:
        with owned_temporary_directory("final-auth-live-supervisor-") as attempt:
            supervisor = {
                "pid": os.getpid(),
                "start_identity": process_start_identity(os.getpid()),
            }
            state = {
                "phase": "reviewed",
                "review_status": "clean",
                "handoff": "complete",
                "process_owner": "attempt-supervisor",
                "closure": "proven-by-owner",
                "process_settlement": "exact",
                "checkout_settlement": "exact",
                "terminal_commit_authorized": True,
                "leader_exit": 0,
                "supervisor": supervisor,
            }
            with self.assertRaisesRegex(ValueError, "still live"):
                _validate_final_authorization_updates(
                    attempt_dir=attempt,
                    state=state,
                    state_digest="a" * 64,
                    updates={
                        "supervisor_exit_code": 0,
                        "final_authorization": {},
                        "retained_process_bytes": 0,
                        "process_physical_remaining_by_fs": {},
                    },
                )

    def test_final_authorization_revalidates_complete_process_history(self) -> None:
        with owned_temporary_directory("final-auth-forged-history-") as attempt:
            leader = {
                "pid": 424242,
                "pgid": 424242,
                "start_identity": "forged-reviewer",
            }
            state = {
                "boot_id": "authenticated-boot",
                "phase": "reviewed",
                "review_status": "clean",
                "launch_status": "completed",
                "handoff": "complete",
                "handoff_token": "7" * 64,
                "process_owner": "attempt-supervisor",
                "closure": "proven-by-owner",
                "abandonment": False,
                "process_settlement": "exact",
                "checkout_settlement": "exact",
                "worktree_status": "removed",
                "source_custody_transferred": True,
                "source_custody_released": True,
                "admission_status": "completed",
                "reservation_status": "settled",
                "terminal_commit_authorized": True,
                "leader": leader,
                "runtime_process_binding": {
                    "session_id": leader["pid"],
                    "profile_sha256": "8" * 64,
                },
                "no_child_process_profile": {
                    "version": 1,
                    "authenticated": True,
                    "kernel_enforced": True,
                    "child_process_limit": 0,
                    "leader": leader,
                },
                "leader_exit": 0,
                "process_history": [],
                "supervisor": {
                    "pid": 999_999_999,
                    "start_identity": "former-supervisor",
                },
            }
            with self.assertRaisesRegex(ValueError, "process history"):
                _validate_final_authorization_updates(
                    attempt_dir=attempt,
                    state=state,
                    state_digest="a" * 64,
                    updates={
                        "supervisor_exit_code": 0,
                        "final_authorization": {},
                        "retained_process_bytes": 0,
                        "process_physical_remaining_by_fs": {},
                    },
                )

    def test_reviewer_builds_primary_evidence_executes_and_authorizes(self) -> None:
        with owned_temporary_directory("runtime-appserver-gate-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff = b"diff --git a/a.py b/a.py\n+fixed\n"
            (control / "review.diff").write_bytes(diff)
            identity = identity_from_stat(os.stat(root, follow_symlinks=False))
            state = {
                "base_sha": "1" * 40,
                "diff_length": len(diff),
                "diff_sha256": sha256_bytes(diff),
                "head_sha": "2" * 40,
                "pr_url": "https://github.example/owner/repo/pull/1",
                "repo": str(root),
                "codex_executable": "/authenticated/codex",
                "registration": {
                    "descendant_count": 1,
                    "descendant_path_bytes": 1,
                    "marker_identity": identity.to_json(),
                    "registration": str(root),
                    "registration_identity": identity.to_json(),
                    "worktree": str(root),
                    "worktree_identity": identity.to_json(),
                },
                "requested_model": "gpt-5.6-sol",
                "requested_reasoning_effort": "xhigh",
                "worktree_path": str(root),
            }
            execution_calls: list[dict[str, object]] = []

            def execute(**kwargs: object) -> SimpleNamespace:
                execution_calls.append(kwargs)
                lifecycle = kwargs["lifecycle"]
                lifecycle.state = {
                    **state,
                    "phase": "review-finished",
                    "closure": "proven-by-owner",
                    "leader_exit": 0,
                }
                lifecycle.state_digest = "review-finished-digest"
                return SimpleNamespace(
                    process=SimpleNamespace(
                        session=SimpleNamespace(
                            review_status="clean",
                            final_text="No findings.",
                        ),
                        exit_code=0,
                    ),
                    auth={"carrier_generation_verified": True},
                    auth_refresh={"status": "not-required"},
                    observed_runtime={"containment": {"closed": True}},
                )

            outer, peer = socket_pair()
            try:
                with (
                    mock.patch("review_supervisor.runtime.verify_prompt_via_helper"),
                    mock.patch(
                        "review_supervisor.runtime.run_authenticated_review",
                        side_effect=execute,
                    ),
                    mock.patch(
                        "review_supervisor.runtime.publish_terminal_review",
                        return_value=({"phase": "reviewed"}, "reviewed-digest"),
                    ) as publish,
                ):
                    completed, digest, final_text = run_reviewer(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=root,
                        lease_fd=3,
                        outer=outer,
                        state=state,
                        state_digest="digest",
                        prompt=b"control prompt",
                    )
            finally:
                outer.close()
                peer.close()
        self.assertEqual(
            (completed, digest, final_text),
            (
                {"phase": "reviewed"},
                "reviewed-digest",
                "No findings.",
            ),
        )
        self.assertEqual(len(execution_calls), 1)
        self.assertNotIn("aggregate_schema_path", execution_calls[0])
        model_prompt = execution_calls[0]["prompt"]
        self.assertIsInstance(model_prompt, bytes)
        self.assertGreater(len(model_prompt), len(diff))
        observed = publish.call_args.kwargs["observed_runtime"]
        self.assertEqual(observed["requested_model"], "gpt-5.6-sol")
        self.assertEqual(observed["transport"], "app-server-stdio")
        self.assertTrue(observed["actual_invocation_enabled"])

    def test_output_limit_termination_schedule_never_resets_grace(self) -> None:
        schedule = TerminationSchedule(grace_seconds=5.0, drain_seconds=2.0)

        self.assertTrue(schedule.request_term(now=100.0))
        self.assertFalse(schedule.request_term(now=104.0))
        self.assertEqual(schedule.grace_deadline, 105.0)
        self.assertFalse(schedule.request_kill_if_due(now=104.999))
        self.assertTrue(schedule.request_kill_if_due(now=105.0))
        self.assertFalse(schedule.request_kill_if_due(now=106.0))
        self.assertEqual(schedule.drain_deadline, 107.0)

    def test_process_start_identity_is_stable_without_ps(self) -> None:
        first = process_start_identity(os.getpid())
        second = process_start_identity(os.getpid())
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(("darwin-proc-start:", "linux-start-ticks:")))

    def test_prompt_verifier_uses_private_handoff_bytes_and_durable_identity(
        self,
    ) -> None:
        with owned_temporary_directory("prompt-verifier-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = retention / f"attempt-1-{'c' * 32}"
            attempt.mkdir(mode=0o700)
            prompt = b"bounded exact prompt\n"
            prompt_path = attempt / "prompt.txt"
            prompt_path.write_bytes(prompt)
            prompt_path.chmod(0o600)
            identity = identity_from_stat(os.stat(prompt_path, follow_symlinks=False))
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"1-{'c' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
                "prompt_path": str(prompt_path),
                "prompt_length": len(prompt),
                "prompt_sha256": sha256_bytes(prompt),
                "prompt_identity": identity.to_json(),
            }
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            _, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                verify_prompt_via_helper(
                    entrypoint=ENTRYPOINT,
                    attempt_dir=attempt,
                    lease_fd=lease.fd,
                    state_digest=digest,
                    prompt=prompt,
                    deadline=time.monotonic() + 10,
                )
                prompt_path.write_bytes(b"tampered exact prompt")
                with self.assertRaises(ValueError):
                    verify_prompt_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        state_digest=digest,
                        prompt=prompt,
                        deadline=time.monotonic() + 10,
                    )

    def test_terminal_authorizer_performs_its_own_exact_final_readback(self) -> None:
        with owned_temporary_directory("terminal-authorizer-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = retention / f"attempt-1-{'e' * 32}"
            attempt.mkdir(mode=0o700)
            final_path = attempt / "final.txt"
            final_content = b"CLEAN\n"
            final_path.write_bytes(final_content)
            final_path.chmod(0o600)
            final_identity = identity_from_stat(os.lstat(final_path))
            final_seal = {
                "path": str(final_path),
                "identity": final_identity.to_json(),
                "length": len(final_content),
                "sha256": sha256_bytes(final_content),
            }
            state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"1-{'e' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
            }
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            outer, peer = socket_pair()
            try:
                with acquire_retention_lease(
                    retention,
                    deadline=time.monotonic() + 5,
                ) as lease:
                    authorized, _ = authorize_terminal_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        outer=outer,
                        state=state,
                        state_digest=digest,
                        leader_exit=0,
                        final_seal=final_seal,
                        deadline=time.monotonic() + 10,
                    )
                authorization = authorized["terminal_authorization"]
                self.assertEqual(
                    set(authorization),
                    {"leader_exit", "final_seal", "authorized_at"},
                )
                self.assertEqual(authorization["final_seal"], final_seal)
                proof = authorized["terminal_authorization_proof"]
                self.assertEqual(proof["predecessor_sha256"], digest)
                self.assertEqual(proof["final_seal"], final_seal)
                self.assertEqual(
                    proof["readback"],
                    "exact-nofollow-under-publication-lease",
                )
            finally:
                outer.close()
                peer.close()

            tampered_attempt = retention / f"attempt-2-{'f' * 32}"
            tampered_attempt.mkdir(mode=0o700)
            tampered_final = tampered_attempt / "final.txt"
            tampered_final.write_bytes(final_content)
            tampered_final.chmod(0o600)
            tampered_identity = identity_from_stat(os.lstat(tampered_final))
            tampered_seal = {
                "path": str(tampered_final),
                "identity": tampered_identity.to_json(),
                "length": len(final_content),
                "sha256": sha256_bytes(final_content),
            }
            tampered_state = {
                "schema_version": SCHEMA_VERSION,
                "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                "attempt_id": f"2-{'f' * 32}",
                "record_generation": 1,
                "previous_record_sha256": None,
            }
            tampered_state_path = tampered_attempt / "state.json"
            tampered_state_path.write_bytes(canonical_json(tampered_state))
            tampered_state_path.chmod(0o600)
            tampered_state, _, tampered_digest = read_attempt_state(tampered_attempt)
            tampered_final.write_bytes(b"DIRTY\n")
            outer, peer = socket_pair()
            try:
                with acquire_retention_lease(
                    retention,
                    deadline=time.monotonic() + 5,
                ) as lease:
                    with self.assertRaises(OuterAbandoned):
                        authorize_terminal_via_helper(
                            entrypoint=ENTRYPOINT,
                            attempt_dir=tampered_attempt,
                            lease_fd=lease.fd,
                            outer=outer,
                            state=tampered_state,
                            state_digest=tampered_digest,
                            leader_exit=0,
                            final_seal=tampered_seal,
                            deadline=time.monotonic() + 10,
                        )
            finally:
                outer.close()
                peer.close()

    def test_handoff_complete_waits_for_exact_outer_ack_before_checkout(self) -> None:
        for exact_ack in (False, True):
            with (
                self.subTest(exact_ack=exact_ack),
                owned_temporary_directory("handoff-final-ack-") as root,
            ):
                attempt = root / "attempt"
                attempt.mkdir(mode=0o700)
                token = "a" * 64
                state = {
                    "schema_version": SCHEMA_VERSION,
                    "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                    "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                    "attempt_id": f"1-{'a' * 32}",
                    "record_generation": 1,
                    "previous_record_sha256": None,
                    "phase": "reserved",
                    "handoff": "pending",
                    "handoff_token": token,
                    "supervisor": {
                        "pid": os.getpid(),
                        "start_identity": process_start_identity(os.getpid()),
                    },
                    "helper_custody": {},
                }
                state_path = attempt / "state.json"
                state_path.write_bytes(canonical_json(state))
                state_path.chmod(0o600)
                cleanup_path = root / "cleanup.lock"
                source_path = root / "source.diff"
                cleanup_path.write_bytes(b"lock")
                source_path.write_bytes(b"diff")
                cleanup_fd = os.open(cleanup_path, os.O_RDONLY | os.O_CLOEXEC)
                source_fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC)
                lease_fd = os.open(root / "lease", os.O_RDWR | os.O_CREAT, 0o600)
                outer, peer = socket_pair()
                checkout = mock.Mock(side_effect=RuntimeError("stop after ACK"))
                thread_errors: list[BaseException] = []

                def drive_outer() -> None:
                    try:
                        deadline = time.monotonic() + 5
                        ready, _ = receive_record(peer, deadline=deadline)
                        self.assertEqual(ready["type"], "attempt-supervisor-ready")
                        custody_accepted, _ = receive_record(peer, deadline=deadline)
                        self.assertEqual(
                            custody_accepted,
                            {"type": "source-custody-accepted", "token": token},
                        )
                        accepted, _ = receive_record(peer, deadline=deadline)
                        self.assertEqual(accepted["type"], "handoff-accepted")
                        complete, _ = receive_record(peer, deadline=deadline)
                        self.assertEqual(complete["type"], "handoff-complete")
                        self.assertFalse(checkout.called)
                        time.sleep(0.05)
                        self.assertFalse(checkout.called)
                        send_record(
                            peer,
                            {
                                "type": "handoff-complete-ack",
                                "token": token,
                                "state_sha256": (
                                    complete["state_sha256"] if exact_ack else "f" * 64
                                ),
                            },
                            deadline=deadline,
                        )
                    except BaseException as error:
                        thread_errors.append(error)

                driver = threading.Thread(target=drive_outer)
                try:
                    send_record(
                        peer,
                        {
                            "type": "source-custody",
                            "token": token,
                            "helper_custody": {},
                        },
                        deadline=time.monotonic() + 5,
                        fds=(cleanup_fd, source_fd),
                    )
                    send_record(
                        peer,
                        {"type": "prompt-offer", "token": token},
                        deadline=time.monotonic() + 5,
                    )
                    send_blob(
                        peer,
                        token,
                        b"private prompt",
                        deadline=time.monotonic() + 5,
                    )
                    send_record(
                        peer,
                        {"type": "handoff-start", "token": token},
                        deadline=time.monotonic() + 5,
                    )
                    driver.start()

                    digests = iter(("accepted-digest", "complete-digest"))

                    def commit(**kwargs: object) -> tuple[dict[str, object], str]:
                        next_state = dict(kwargs["state"])
                        next_state.update(kwargs["updates"])
                        return next_state, next(digests)

                    custody = SimpleNamespace(
                        cleanup_lock_identity=identity_from_stat(os.fstat(cleanup_fd)),
                        source_identity=identity_from_stat(os.fstat(source_fd)),
                    )
                    with (
                        mock.patch(
                            "review_supervisor.runtime._custody",
                            return_value=custody,
                        ),
                        mock.patch("review_supervisor.runtime._verify_prompt_artifact"),
                        mock.patch(
                            "review_supervisor.runtime.commit_via_helper",
                            side_effect=commit,
                        ),
                        mock.patch(
                            "review_supervisor.runtime._run_checkout",
                            checkout,
                        ),
                        mock.patch(
                            "review_supervisor.runtime._record_failure",
                            side_effect=RuntimeError("stop failure recording"),
                        ),
                    ):
                        result = attempt_supervisor_main(
                            entrypoint=ENTRYPOINT,
                            attempt_dir=attempt,
                            control_fd=os.dup(outer.fileno()),
                            lease_fd=os.dup(lease_fd),
                            handoff_token=token,
                        )
                    self.assertEqual(result, 2)
                    self.assertEqual(checkout.called, exact_ack)
                finally:
                    driver.join(timeout=5)
                    peer.close()
                    outer.close()
                    os.close(cleanup_fd)
                    os.close(source_fd)
                    os.close(lease_fd)
                self.assertFalse(driver.is_alive())
                if thread_errors:
                    raise thread_errors[0]


if __name__ == "__main__":
    unittest.main()
