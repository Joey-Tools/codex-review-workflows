from __future__ import annotations

import dataclasses
import hashlib
import json
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
    MAX_EVIDENCE_CONTEXT_BYTES,
    MAX_EVIDENCE_CONTEXT_FILE_BYTES,
    MAX_EVIDENCE_CONTEXT_FILES,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.evidence import ManifestEntry, manifest_sha256
from review_supervisor.errors import SupervisorError, inconclusive
from review_supervisor.ledger import (
    acquire_retention_lease,
    open_attempt_lease,
    read_attempt_state,
)
from review_supervisor.models import TreeEntry, TreeManifest
from review_supervisor.process import (
    ForkExecReceipt,
    ForkExecResultOwner,
    ForkedProcessClosureUnproven,
    ForkedProcessOwnershipUnproven,
    SpawnedProcess,
    TerminationSchedule,
    process_start_identity,
)
from review_supervisor.runtime import (
    DirectProcessClosureUnproven,
    DirectProcessOwnershipUnproven,
    DurableProcessLifecycle,
    OuterAbandoned,
    PrelaunchWorkerClosureUnproven,
    _MAX_NEARBY_CONTEXT_CANDIDATES,
    _build_appserver_evidence_attestation,
    _kill_direct,
    _persist_attempt_git_closure_receipt,
    _record_failure,
    _read_checkout_closure_receipt,
    _run_checkout,
    _run_authenticated_review_boundary,
    _spawn_internal,
    _validate_checkout_failed_record,
    _validate_final_authorization_updates,
    authorize_terminal_via_helper,
    attempt_supervisor_main,
    commit_via_helper,
    direct_process_closure_failure,
    publish_terminal_review,
    _publish_checkout_closure_receipt,
    run_reviewer,
    settle_process_via_helper,
    validate_checkout_closure_receipt,
    validate_retained_git_control_paths,
    verify_prompt_via_helper,
)
from review_supervisor.secureio import (
    allocated_bytes_fd,
    canonical_json,
    identity_from_stat,
    publish_bytes,
    sha256_bytes,
)
from review_supervisor.wire import receive_record, send_blob, send_record, socket_pair

from tests.support import bind_attempt_state, owned_temporary_directory


ENTRYPOINT = (
    pathlib.Path(__file__).resolve().parent.parent / "independent-codex-pr-review"
)


def _fake_attempt(path: pathlib.Path = pathlib.Path("/attempt")) -> SimpleNamespace:
    return SimpleNamespace(
        path=path,
        fd=-1,
        retention=SimpleNamespace(fd=-1, root_fd=-1),
        revalidate=mock.Mock(),
        transfer_binding=mock.Mock(return_value={"fixture": True}),
    )


def _tracked_blob(path: bytes, content: bytes, object_number: int) -> TreeEntry:
    return TreeEntry(
        mode=0o100644,
        object_type="blob",
        object_id=f"{object_number:040x}",
        size=len(content),
        path=path,
    )


def _tree_manifest(entries: tuple[TreeEntry, ...]) -> TreeManifest:
    return TreeManifest(
        commit="2" * 40,
        entries=entries,
        metadata_bytes=0,
        aggregate_regular_bytes=sum(entry.size or 0 for entry in entries),
        gitlink_count=0,
    )


class _FakeCatFileBatch:
    def __init__(
        self,
        blobs: dict[str, bytes],
        inspected_paths: list[bytes],
    ) -> None:
        self._blobs = blobs
        self._inspected_paths = inspected_paths

    def __enter__(self) -> _FakeCatFileBatch:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read_blob(self, entry: TreeEntry, *, capture: bool) -> bytes:
        if not capture:
            raise AssertionError("nearby context blob was not captured")
        self._inspected_paths.append(entry.path)
        return self._blobs[entry.object_id]


class RuntimeHelperTests(unittest.TestCase):
    def test_retained_git_control_paths_are_closed_to_the_temporary_root(self) -> None:
        attempt_dir = pathlib.Path("/private/review/attempt-1")
        retained = attempt_dir / "codex-git-control-synthetic"
        self.assertEqual(
            validate_retained_git_control_paths(
                [str(retained)],
                attempt_dir=attempt_dir,
            ),
            (retained,),
        )
        self.assertEqual(
            validate_retained_git_control_paths([], attempt_dir=attempt_dir),
            (),
        )
        for malformed in (
            [str(retained), str(retained)],
            [str(retained.parent / "other-control")],
            [str(retained / "nested")],
            ["/tmp/codex-git-control-synthetic"],
            ["relative/codex-git-control-synthetic"],
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    validate_retained_git_control_paths(
                        malformed,
                        attempt_dir=attempt_dir,
                    )

    def test_checkout_closure_receipt_is_durable_and_failure_schema_is_closed(
        self,
    ) -> None:
        invalid_handoffs = (
            {
                "handoff": "incomplete",
                "process_owner": "attempt-supervisor",
                "handoff_token": "a" * 64,
            },
            {
                "handoff": "complete",
                "process_owner": "checkout-worker",
                "handoff_token": "a" * 64,
            },
            {
                "handoff": "complete",
                "process_owner": "attempt-supervisor",
                "handoff_token": "b" * 64,
            },
        )
        for invalid_state in invalid_handoffs:
            with (
                self.subTest(invalid_state=invalid_state),
                mock.patch(
                    "review_supervisor.runtime._build_checkout_closure_receipt"
                ) as build_receipt,
                mock.patch(
                    "review_supervisor.runtime._publish_checkout_closure_receipt"
                ) as publish_receipt,
                self.assertRaisesRegex(
                    ValueError,
                    "durable ownership binding",
                ),
            ):
                _persist_attempt_git_closure_receipt(
                    attempt=_fake_attempt(),
                    state=invalid_state,
                    error=mock.Mock(),
                    token="a" * 64,
                    owner_start_identity="synthetic-owner",
                )
            build_receipt.assert_not_called()
            publish_receipt.assert_not_called()

        with owned_temporary_directory("checkout-closure-receipt-") as root:
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
            }
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            token = "a" * 64
            worker = SpawnedProcess(
                pid=200,
                pgid=200,
                acknowledgement_fd=-1,
                passed_fd_numbers=(),
                start_identity="darwin-proc-start:200:1",
            )
            receipt = validate_checkout_closure_receipt(
                {
                    "version": 1,
                    "token": token,
                    "worker": {
                        "pid": worker.pid,
                        "start_identity": worker.start_identity,
                    },
                    "process": {
                        "identity_status": "anchored",
                        "pid": 201,
                        "pgid": 201,
                        "start_identity": "darwin-proc-start:201:1",
                    },
                    "control_scope": "temporary",
                    "retained_cleanup_paths": [
                        str(attempt / "codex-git-control-synthetic")
                    ],
                },
                attempt_dir=attempt,
                token=token,
                expected_worker=worker,
            )
            process_free_receipt = validate_checkout_closure_receipt(
                {
                    **receipt,
                    "process": {
                        "identity_status": "not-applicable",
                        "pid": None,
                        "pgid": None,
                        "start_identity": None,
                    },
                },
                attempt_dir=attempt,
                token=token,
                expected_worker=worker,
            )
            self.assertEqual(
                process_free_receipt["process"]["identity_status"],
                "not-applicable",
            )
            with self.assertRaisesRegex(
                ValueError,
                "process-free checkout closure receipt",
            ):
                validate_checkout_closure_receipt(
                    {
                        **receipt,
                        "process": {
                            "identity_status": "not-applicable",
                            "pid": 201,
                            "pgid": None,
                            "start_identity": None,
                        },
                    },
                    attempt_dir=attempt,
                    token=token,
                    expected_worker=worker,
                )
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                with open_attempt_lease(lease, attempt) as attempt_lease:
                    payload, digest = _publish_checkout_closure_receipt(
                        attempt_lease,
                        receipt,
                    )
                    self.assertEqual(payload, canonical_json(receipt))
                    self.assertEqual(digest, sha256_bytes(payload))
                    self.assertEqual(
                        _read_checkout_closure_receipt(
                            attempt_lease,
                            token=token,
                            expected_worker=worker,
                        ),
                        (receipt, digest),
                    )
            record = {
                "type": "checkout-failed",
                "token": token,
                "status": "inconclusive",
                "stage": "checkout",
                "code": "checkout-worker-failed",
                "error": "synthetic closure gap",
                "closure": "unproven",
                "closure_receipt": receipt,
                "closure_receipt_sha256": digest,
                "closure_receipt_status": "published",
            }
            self.assertEqual(
                _validate_checkout_failed_record(
                    record,
                    attempt_dir=attempt,
                    token=token,
                    expected_worker=worker,
                ),
                record,
            )
            for field in record:
                with self.subTest(field=field):
                    malformed = dict(record)
                    malformed.pop(field)
                    with self.assertRaises(ValueError):
                        _validate_checkout_failed_record(
                            malformed,
                            attempt_dir=attempt,
                            token=token,
                            expected_worker=worker,
                        )
            wrong_worker = dataclasses.replace(
                worker,
                start_identity="darwin-proc-start:200:2",
            )
            with self.assertRaisesRegex(ValueError, "wrong worker"):
                _validate_checkout_failed_record(
                    record,
                    attempt_dir=attempt,
                    token=token,
                    expected_worker=wrong_worker,
                )

    def test_checkout_phase0_failure_reaps_worker_before_classification(self) -> None:
        token = "01" * 32
        worker = SpawnedProcess(
            pid=123,
            pgid=123,
            acknowledgement_fd=-1,
            passed_fd_numbers=(),
            start_identity="darwin-proc-start:123:456",
            fork_exec_receipt=ForkExecReceipt(
                creator_pid=os.getpid(),
                own_process_group=True,
                acknowledgement_read_fd=-1,
                acknowledgement_write_fd=-1,
                acknowledgement_read_close_outcome="closed",
                acknowledgement_write_close_outcome="closed",
            ),
        )
        parent = mock.Mock()
        child = mock.Mock()
        registration = SimpleNamespace(
            descendant_count=0,
            descendant_path_bytes=0,
        )
        control_binding = {"synthetic": True}
        registration_value = {
            "control": control_binding,
            "synthetic": True,
        }
        records = (
            {
                "type": "git-control-created",
                "token": token,
                "binding": control_binding,
                "state_sha256": "control-digest",
            },
            {
                "type": "worktree-created",
                "token": token,
                "registration": registration_value,
                "state_sha256": "worker-digest",
            },
            {
                "type": "index-initialized",
                "token": token,
                "registration_descendant_count": 1,
                "registration_descendant_path_bytes": 2,
            },
            {
                "type": "checkout-failed",
                "token": token,
                "status": "inconclusive",
                "stage": "checkout",
                "code": "synthetic-phase0-failure",
                "error": "synthetic phase-0 failure",
                "closure": "proven",
                "closure_receipt": None,
                "closure_receipt_sha256": None,
                "closure_receipt_status": "not-applicable",
            },
        )

        def commit(**kwargs: object) -> tuple[dict[str, object], str]:
            next_state = dict(kwargs["state"])
            next_state.update(kwargs["updates"])
            next_state["record_generation"] = (
                int(next_state.get("record_generation", 0)) + 1
            )
            next_state["previous_record_sha256"] = kwargs["state_digest"]
            return next_state, "next-digest"

        initial_state = {
            "record_generation": 1,
            "worktree_path": "/tmp/review-worktree",
            "common_git_dir_binding": {"path": "/tmp/repository.git"},
            "handoff": "complete",
            "process_owner": "attempt-supervisor",
            "handoff_token": token,
        }
        durable_control_state = {
            **initial_state,
            "record_generation": 3,
            "previous_record_sha256": "next-digest",
            "phase": "worktree-adding",
            "worktree_status": "adding",
            "worktree_create_intent": {
                "version": 2,
                "worktree": "/tmp/review-worktree",
                "control_git_dir": str(ENTRYPOINT.parent / "git-control"),
                "registration_parent": str(
                    ENTRYPOINT.parent / "git-control" / "worktrees"
                ),
                "lock_reason": f"independent-codex-pr-review:{token}",
            },
            "git_control_binding": control_binding,
            "registration": None,
        }
        durable_worker_state = {
            **durable_control_state,
            "record_generation": 4,
            "previous_record_sha256": "control-digest",
            "worktree_status": "active",
            "registration": registration_value,
        }

        def spawn_worker(*args: object, **kwargs: object) -> SpawnedProcess:
            del args
            result_owner = kwargs["result_owner"]
            assert isinstance(result_owner, ForkExecResultOwner)
            assert worker.fork_exec_receipt is not None
            result_owner.publish_receipt(worker.fork_exec_receipt)
            result_owner.publish(worker)
            return worker

        with (
            mock.patch(
                "review_supervisor.runtime.socket_pair",
                return_value=(parent, child),
            ),
            mock.patch(
                "review_supervisor.runtime.os.urandom", return_value=b"\x01" * 32
            ),
            mock.patch(
                "review_supervisor.runtime._spawn_internal",
                side_effect=spawn_worker,
            ),
            mock.patch("review_supervisor.runtime.await_exec"),
            mock.patch(
                "review_supervisor.runtime._wait_child_record",
                side_effect=records,
            ),
            mock.patch("review_supervisor.runtime.send_record"),
            mock.patch(
                "review_supervisor.runtime.commit_via_helper",
                side_effect=commit,
            ),
            mock.patch("review_supervisor.runtime._authenticate_attempt_transfer"),
            mock.patch(
                "review_supervisor.runtime._read_checkout_closure_receipt",
                return_value=None,
            ),
            mock.patch(
                "review_supervisor.runtime._registration",
                return_value=registration,
            ),
            mock.patch(
                "review_supervisor.runtime._registration_json",
                return_value={"synthetic": True},
            ),
            mock.patch(
                "review_supervisor.runtime.read_bound_attempt_state",
                side_effect=(
                    (durable_control_state, b"{}", "control-digest"),
                    (durable_worker_state, b"{}", "worker-digest"),
                ),
            ),
            mock.patch("review_supervisor.runtime.wait_terminal") as wait_terminal,
            mock.patch("review_supervisor.runtime.reap", return_value=1) as reap,
            mock.patch("review_supervisor.runtime._terminate_group") as terminate,
            self.assertRaises(SupervisorError) as raised,
        ):
            _run_checkout(
                entrypoint=ENTRYPOINT,
                attempt=_fake_attempt(ENTRYPOINT.parent),
                outer=mock.Mock(),
                state=initial_state,
                state_digest="initial-digest",
                source_fd=-1,
                token=token,
            )

        self.assertEqual(raised.exception.failure.code, "synthetic-phase0-failure")
        wait_terminal.assert_called_once_with(worker.pid, deadline=mock.ANY)
        reap.assert_called_once_with(worker.pid, deadline=mock.ANY)
        terminate.assert_not_called()

    def test_direct_helper_cleanup_timeout_is_not_suppressed(self) -> None:
        process = SpawnedProcess(
            pid=123,
            pgid=456,
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
                "review_supervisor.runtime.terminate_direct_process",
                side_effect=TimeoutError("synthetic cleanup timeout"),
            ),
            self.assertRaises(DirectProcessClosureUnproven) as raised,
        ):
            _kill_direct(process)
            self.fail("direct helper cleanup timeout did not fail closed")

        with mock.patch(
            "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
            raised.exception,
        ):
            self.assertIs(direct_process_closure_failure(), raised.exception)
            with (
                mock.patch("review_supervisor.runtime.fork_exec") as fork_exec,
                self.assertRaises(DirectProcessClosureUnproven),
            ):
                _spawn_internal(
                    entrypoint=ENTRYPOINT,
                    mode="_phase-helper",
                    arguments=(),
                    cwd=ENTRYPOINT.parent,
                    pass_fds=(),
                    own_process_group=False,
                    result_owner=ForkExecResultOwner(),
                )
            fork_exec.assert_not_called()

        self.assertIs(raised.exception.process, process)
        self.assertIsInstance(raised.exception.__cause__, TimeoutError)

        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.terminate_direct_process",
                side_effect=(TimeoutError("synthetic first timeout"), 0),
            ) as terminate,
        ):
            _kill_direct(process)
            self.assertIsNone(direct_process_closure_failure())
        self.assertEqual(terminate.call_count, 2)

        fork_failure = ForkedProcessClosureUnproven(
            process,
            ValueError("synthetic identity failure"),
            PermissionError("synthetic cleanup failure"),
        )
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.fork_exec",
                side_effect=fork_failure,
            ),
            self.assertRaises(DirectProcessClosureUnproven) as raised,
        ):
            _spawn_internal(
                entrypoint=ENTRYPOINT,
                mode="_phase-helper",
                arguments=(),
                cwd=ENTRYPOINT.parent,
                pass_fds=(),
                own_process_group=False,
                result_owner=ForkExecResultOwner(),
            )
        self.assertIs(raised.exception.process, process)
        self.assertIs(raised.exception.__cause__, fork_failure)

        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.terminate_direct_process",
                side_effect=PermissionError("synthetic signaling failure"),
            ),
            self.assertRaises(DirectProcessClosureUnproven) as raised,
        ):
            _kill_direct(process)
        self.assertIs(raised.exception.process, process)
        self.assertIsInstance(raised.exception.__cause__, PermissionError)

        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.terminate_direct_process",
                side_effect=(PermissionError("synthetic first failure"), 0),
            ) as terminate,
        ):
            _kill_direct(process)
            self.assertIsNone(direct_process_closure_failure())
        self.assertEqual(terminate.call_count, 2)

    def test_unknown_fork_pid_latches_direct_helper_ownership(self) -> None:
        result_owner = ForkExecResultOwner()
        ownership_failure = ForkedProcessOwnershipUnproven(
            result_owner,
            KeyboardInterrupt(),
            ChildProcessError("synthetic PID receipt failure"),
        )
        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                None,
            ),
            mock.patch(
                "review_supervisor.runtime.fork_exec",
                side_effect=ownership_failure,
            ),
        ):
            with self.assertRaises(DirectProcessOwnershipUnproven) as raised:
                _spawn_internal(
                    entrypoint=ENTRYPOINT,
                    mode="_phase-helper",
                    arguments=(),
                    cwd=ENTRYPOINT.parent,
                    pass_fds=(),
                    own_process_group=False,
                    result_owner=result_owner,
                )
            self.assertIs(direct_process_closure_failure(), raised.exception)
        self.assertIs(raised.exception.result_owner, result_owner)
        self.assertIs(raised.exception.__cause__, ownership_failure)

        with (
            mock.patch(
                "review_supervisor.runtime._DIRECT_PROCESS_CLOSURE_UNPROVEN",
                raised.exception,
            ),
            mock.patch("review_supervisor.runtime.fork_exec") as fork_exec,
            self.assertRaises(DirectProcessOwnershipUnproven),
        ):
            _spawn_internal(
                entrypoint=ENTRYPOINT,
                mode="_phase-helper",
                arguments=(),
                cwd=ENTRYPOINT.parent,
                pass_fds=(),
                own_process_group=False,
                result_owner=ForkExecResultOwner(),
            )
        fork_exec.assert_not_called()

    def test_authenticated_review_boundary_preserves_unproven_helper(self) -> None:
        process = SpawnedProcess(
            pid=124,
            pgid=456,
            acknowledgement_fd=-1,
            passed_fd_numbers=(),
            start_identity="darwin-proc-start:124:456",
        )
        failure = DirectProcessClosureUnproven(process)
        with (
            mock.patch(
                "review_supervisor.runtime.run_authenticated_review",
                side_effect=failure,
            ),
            self.assertRaises(DirectProcessClosureUnproven) as raised,
        ):
            _run_authenticated_review_boundary()
        self.assertIs(raised.exception, failure)

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
            attempt=_fake_attempt(),
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
            attempt=_fake_attempt(),
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
            attempt=_fake_attempt(),
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

    def test_directory_inventory_accepts_child_churn_but_rejects_replacement(
        self,
    ) -> None:
        original_open = os.open
        with owned_temporary_directory("runtime-directory-churn-") as root:
            inventory = root / "inventory"
            inventory.mkdir(mode=0o700)
            child = inventory / "child"
            child.mkdir(mode=0o700)
            root_fd = original_open(inventory, os.O_RDONLY | os.O_DIRECTORY)
            churned = False

            def open_after_child_churn(
                path: bytes | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal churned
                if path == b"child" and not churned:
                    churned = True
                    (child / "materialized").mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with mock.patch(
                    "review_supervisor.secureio.os.open",
                    side_effect=open_after_child_churn,
                ):
                    self.assertGreaterEqual(allocated_bytes_fd(root_fd), 0)
            finally:
                os.close(root_fd)
            self.assertTrue(churned)

        with owned_temporary_directory("runtime-directory-replacement-") as root:
            inventory = root / "inventory"
            inventory.mkdir(mode=0o700)
            child = inventory / "child"
            child.mkdir(mode=0o700)
            moved = root / "original-child"
            root_fd = original_open(inventory, os.O_RDONLY | os.O_DIRECTORY)
            replaced = False

            def open_after_child_replacement(
                path: bytes | str,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if path == b"child" and not replaced:
                    replaced = True
                    child.rename(moved)
                    child.mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with (
                    mock.patch(
                        "review_supervisor.secureio.os.open",
                        side_effect=open_after_child_replacement,
                    ),
                    self.assertRaisesRegex(OSError, "identity changed"),
                ):
                    allocated_bytes_fd(root_fd)
            finally:
                os.close(root_fd)
            self.assertTrue(replaced)

    def test_terminal_review_is_authorized_before_classification_commit(self) -> None:
        with owned_temporary_directory("terminal-review-") as attempt:
            attempt_fd = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY)
            attempt_lease = _fake_attempt(attempt)
            attempt_lease.fd = attempt_fd
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
                        attempt=attempt_lease,
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
                os.close(attempt_fd)

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
                attempt=_fake_attempt(pathlib.Path("/unused")),
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
                attempt=_fake_attempt(pathlib.Path("/unused")),
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
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                attempt_lease = open_attempt_lease(lease, attempt)
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
                            attempt=attempt_lease,
                            state=state,
                            state_digest=digest,
                            updates={field: value},
                            deadline=time.monotonic() + 10,
                        )
                attempt_lease.close()

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
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
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
                attempt_lease = open_attempt_lease(lease, attempt)
                with self.assertRaisesRegex(ValueError, "not allowlisted"):
                    commit_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt=attempt_lease,
                        state=state,
                        state_digest=digest,
                        updates={"boot_id": "forged-boot"},
                        deadline=time.monotonic() + 10,
                    )
                state, digest = commit_via_helper(
                    entrypoint=ENTRYPOINT,
                    attempt=attempt_lease,
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
                        attempt=attempt_lease,
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
                attempt_lease.close()
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
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
            (attempt / "state.json").write_bytes(canonical_json(state))
            (attempt / "state.json").chmod(0o600)
            state, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                with open_attempt_lease(lease, attempt) as attempt_lease:
                    with self.assertRaisesRegex(ValueError, "proven process closure"):
                        settle_process_via_helper(
                            entrypoint=ENTRYPOINT,
                            attempt=attempt_lease,
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
                    attempt=_fake_attempt(attempt),
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
                    attempt=_fake_attempt(attempt),
                    state=state,
                    state_digest="a" * 64,
                    updates={
                        "supervisor_exit_code": 0,
                        "final_authorization": {},
                        "retained_process_bytes": 0,
                        "process_physical_remaining_by_fs": {},
                    },
                )

    def test_nearby_context_skips_git_paths_rejected_by_manifest(self) -> None:
        diff = b"diff --git a/app/page.tsx b/app/page.tsx\n"
        primary_entry = ManifestEntry(
            path=".codex-review/review.diff",
            kind="regular",
            size=len(diff),
            sha256=sha256_bytes(diff),
        )
        contents = {
            b"app/[id]/page.tsx": b"export default function Page() {}\n",
            b"src\\glob*.py": b"VALUE = 1\n",
            b"z-valid.py": b"VALUE = 2\n",
        }
        entries = tuple(
            _tracked_blob(path, content, index)
            for index, (path, content) in enumerate(contents.items(), start=1)
        )
        blobs = {entry.object_id: contents[entry.path] for entry in entries}
        inspected_paths: list[bytes] = []

        with mock.patch(
            "review_supervisor.runtime.CatFileBatch",
            side_effect=lambda _info: _FakeCatFileBatch(blobs, inspected_paths),
        ):
            attestation = _build_appserver_evidence_attestation(
                info=SimpleNamespace(object_format="sha1"),
                base=_tree_manifest(()),
                head=_tree_manifest(tuple(reversed(entries))),
                primary_entry=primary_entry,
            )

        valid_content = contents[b"z-valid.py"]
        valid_entry = ManifestEntry(
            path="z-valid.py",
            kind="regular",
            size=len(valid_content),
            sha256=sha256_bytes(valid_content),
        )
        self.assertEqual(inspected_paths, sorted(contents))
        self.assertEqual(
            [entry["path"] for entry in attestation["nearby_entries"]],
            ["z-valid.py"],
        )
        self.assertEqual(
            attestation["manifest_sha256"],
            manifest_sha256((primary_entry, valid_entry)),
        )

    def test_binary_candidates_do_not_consume_text_context_budget(self) -> None:
        candidate_contents: list[tuple[bytes, bytes]] = []
        binary_size = MAX_EVIDENCE_CONTEXT_BYTES // MAX_EVIDENCE_CONTEXT_FILES
        for index in range(MAX_EVIDENCE_CONTEXT_FILES):
            prefix = b"\x00" if index % 2 == 0 else b"\xff"
            candidate_contents.append(
                (
                    f"a-binary-{index:02d}.bin".encode(),
                    prefix + b"x" * (binary_size - 1),
                )
            )
        candidate_contents.append((b"b-text.py", b"VALUE = 1\n"))
        for index in range(_MAX_NEARBY_CONTEXT_CANDIDATES - MAX_EVIDENCE_CONTEXT_FILES):
            candidate_contents.append((f"z-binary-{index:03d}.bin".encode(), b"\x00"))

        entries = tuple(
            _tracked_blob(path, content, index)
            for index, (path, content) in enumerate(candidate_contents, start=1)
        )
        blobs = {
            entry.object_id: content
            for entry, (_, content) in zip(entries, candidate_contents, strict=True)
        }
        inspected_paths: list[bytes] = []
        primary_content = b"diff\n"
        primary_entry = ManifestEntry(
            path=".codex-review/review.diff",
            kind="regular",
            size=len(primary_content),
            sha256=sha256_bytes(primary_content),
        )

        with mock.patch(
            "review_supervisor.runtime.CatFileBatch",
            side_effect=lambda _info: _FakeCatFileBatch(blobs, inspected_paths),
        ):
            attestation = _build_appserver_evidence_attestation(
                info=SimpleNamespace(object_format="sha1"),
                base=_tree_manifest(()),
                head=_tree_manifest(tuple(reversed(entries))),
                primary_entry=primary_entry,
            )

        expected_inspected = sorted(path for path, _ in candidate_contents)[
            :_MAX_NEARBY_CONTEXT_CANDIDATES
        ]
        self.assertEqual(inspected_paths, expected_inspected)
        self.assertEqual(len(inspected_paths), _MAX_NEARBY_CONTEXT_CANDIDATES)
        self.assertEqual(
            [entry["path"] for entry in attestation["nearby_entries"]],
            ["b-text.py"],
        )

    def test_reviewer_builds_primary_evidence_executes_and_authorizes(self) -> None:
        with owned_temporary_directory("runtime-appserver-gate-") as root:
            control = root / ".codex-review"
            control.mkdir()
            diff = b"diff --git a/a.py b/a.py\n+fixed\n"
            (control / "review.diff").write_bytes(diff)
            source = root / "src"
            source.mkdir()
            old_alpha = b"def alpha():\n    return 1\n"
            alpha = b"def alpha():\n    return 2\n"
            old_zeta = b"def zeta():\n    return 3\n"
            zeta = b"def zeta():\n    return 4\n"
            (source / "a.py").write_bytes(alpha)
            (source / "z.py").write_bytes(zeta)
            (source / "a.py").chmod(0o644)
            (source / "z.py").chmod(0o644)

            def tracked_entry(path: bytes, content: bytes) -> TreeEntry:
                digest = hashlib.sha1()
                digest.update(f"blob {len(content)}\0".encode("ascii"))
                digest.update(content)
                return TreeEntry(
                    mode=0o100644,
                    object_type="blob",
                    object_id=digest.hexdigest(),
                    size=len(content),
                    path=path,
                )

            base_manifest = TreeManifest(
                commit="1" * 40,
                entries=(
                    tracked_entry(b"src/a.py", old_alpha),
                    tracked_entry(b"src/z.py", old_zeta),
                ),
                metadata_bytes=0,
                aggregate_regular_bytes=len(old_alpha) + len(old_zeta),
                gitlink_count=0,
            )
            head_manifest = TreeManifest(
                commit="2" * 40,
                entries=(
                    tracked_entry(b"src/z.py", zeta),
                    tracked_entry(b"src/a.py", alpha),
                ),
                metadata_bytes=0,
                aggregate_regular_bytes=len(alpha) + len(zeta),
                gitlink_count=0,
            )
            oversized_manifest = TreeManifest(
                commit="2" * 40,
                entries=head_manifest.entries
                + (
                    TreeEntry(
                        mode=0o100644,
                        object_type="blob",
                        object_id="0" * 40,
                        size=MAX_EVIDENCE_CONTEXT_FILE_BYTES + 1,
                        path=b"generated/oversized.txt",
                    ),
                ),
                metadata_bytes=0,
                aggregate_regular_bytes=(
                    head_manifest.aggregate_regular_bytes
                    + MAX_EVIDENCE_CONTEXT_FILE_BYTES
                    + 1
                ),
                gitlink_count=0,
            )
            primary_entry = ManifestEntry(
                path=".codex-review/review.diff",
                kind="regular",
                size=len(diff),
                sha256=sha256_bytes(diff),
            )
            tracked_blobs = {
                tracked_entry(b"src/a.py", alpha).object_id: alpha,
                tracked_entry(b"src/z.py", zeta).object_id: zeta,
            }

            class FakeCatFileBatch:
                def __init__(self, info: object) -> None:
                    self.info = info

                def __enter__(self) -> FakeCatFileBatch:
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

                def read_blob(
                    self,
                    entry: TreeEntry,
                    *,
                    capture: bool,
                ) -> bytes:
                    if not capture:
                        raise AssertionError("nearby context blob was not captured")
                    return tracked_blobs[entry.object_id]

            with mock.patch(
                "review_supervisor.runtime.CatFileBatch",
                FakeCatFileBatch,
            ):
                appserver_evidence = _build_appserver_evidence_attestation(
                    info=SimpleNamespace(object_format="sha1"),
                    base=base_manifest,
                    head=oversized_manifest,
                    primary_entry=primary_entry,
                )
            self.assertEqual(
                [entry["path"] for entry in appserver_evidence["nearby_entries"]],
                ["src/a.py", "src/z.py"],
            )

            identity = identity_from_stat(os.stat(root, follow_symlinks=False))
            state = {
                "base_sha": "1" * 40,
                "checkout_evidence": {
                    "appserver_evidence": appserver_evidence,
                    "sealed_diff_sha256": sha256_bytes(diff),
                },
                "diff_length": len(diff),
                "diff_sha256": sha256_bytes(diff),
                "head_sha": "2" * 40,
                "pr_url": "https://github.example/owner/repo/pull/1",
                "repo": str(root),
                "codex_executable": "/authenticated/codex",
                "registration": {
                    "control": {
                        "path": str(root),
                        "root_identity": identity.to_json(),
                        "config_identity": identity.to_json(),
                        "config_sha256": "0" * 64,
                    },
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
                        attempt=_fake_attempt(root),
                        outer=outer,
                        state=state,
                        state_digest="digest",
                        prompt=b"control prompt",
                    )

                    (source / "a.py").write_bytes(b"def alpha():\n    return 9\n")
                    tampered_outer, tampered_peer = socket_pair()
                    try:
                        with self.assertRaises(SupervisorError) as raised:
                            run_reviewer(
                                entrypoint=ENTRYPOINT,
                                attempt=_fake_attempt(root),
                                outer=tampered_outer,
                                state=state,
                                state_digest="digest",
                                prompt=b"control prompt",
                            )
                    finally:
                        tampered_outer.close()
                        tampered_peer.close()
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
        bundle_payload = model_prompt.split(
            b"BEGIN_AUTHENTICATED_EVIDENCE_BUNDLE\n", 1
        )[1].split(b"\nEND_AUTHENTICATED_EVIDENCE_BUNDLE", 1)[0]
        evidence_bundle = json.loads(bundle_payload)
        self.assertEqual(
            [artifact["role"] for artifact in evidence_bundle["artifacts"]],
            ["primary_diff", "nearby_context", "nearby_context"],
        )
        self.assertEqual(
            [artifact["content"] for artifact in evidence_bundle["artifacts"]],
            [diff.decode(), alpha.decode(), zeta.decode()],
        )
        self.assertEqual(
            evidence_bundle["manifest_sha256"],
            appserver_evidence["manifest_sha256"],
        )
        observed = publish.call_args.kwargs["observed_runtime"]
        self.assertEqual(
            observed["evidence_bundle_sha256"],
            sha256_bytes(canonical_json(evidence_bundle)),
        )
        self.assertEqual(observed["requested_model"], "gpt-5.6-sol")
        self.assertEqual(observed["transport"], "app-server-stdio")
        self.assertTrue(observed["actual_invocation_enabled"])
        self.assertEqual(
            raised.exception.failure.code, "appserver-evidence-inconclusive"
        )
        self.assertEqual(len(execution_calls), 1)

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
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
            state_path = attempt / "state.json"
            state_path.write_bytes(canonical_json(state))
            state_path.chmod(0o600)
            _, _, digest = read_attempt_state(attempt)
            with acquire_retention_lease(
                retention,
                deadline=time.monotonic() + 5,
            ) as lease:
                with open_attempt_lease(lease, attempt) as attempt_lease:
                    verify_prompt_via_helper(
                        entrypoint=ENTRYPOINT,
                        attempt=attempt_lease,
                        state_digest=digest,
                        prompt=prompt,
                        deadline=time.monotonic() + 10,
                    )
                    prompt_path.write_bytes(b"tampered exact prompt")
                    with self.assertRaises(ValueError):
                        verify_prompt_via_helper(
                            entrypoint=ENTRYPOINT,
                            attempt=attempt_lease,
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
            bind_attempt_state(
                state,
                retention_root=retention,
                attempt_dir=attempt,
            )
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
                    with open_attempt_lease(lease, attempt) as attempt_lease:
                        authorized, _ = authorize_terminal_via_helper(
                            entrypoint=ENTRYPOINT,
                            attempt=attempt_lease,
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
            bind_attempt_state(
                tampered_state,
                retention_root=retention,
                attempt_dir=tampered_attempt,
            )
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
                    with open_attempt_lease(lease, tampered_attempt) as tampered_lease:
                        with self.assertRaises(OuterAbandoned):
                            authorize_terminal_via_helper(
                                entrypoint=ENTRYPOINT,
                                attempt=tampered_lease,
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
        closure_process = SpawnedProcess(
            pid=999,
            pgid=999,
            acknowledgement_fd=-1,
            passed_fd_numbers=(),
            start_identity="darwin-proc-start:999:1",
        )
        cases = (
            ("bad-ack", False, RuntimeError("unused checkout"), True),
            ("ordinary-checkout-failure", True, RuntimeError("stop after ACK"), True),
            (
                "helper-closure-unproven",
                True,
                DirectProcessClosureUnproven(closure_process),
                False,
            ),
            (
                "checkout-worker-closure-unproven",
                True,
                PrelaunchWorkerClosureUnproven("synthetic detached-process gap"),
                False,
            ),
        )
        for case, exact_ack, checkout_error, records_failure in cases:
            with (
                self.subTest(case=case),
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
                bind_attempt_state(
                    state,
                    retention_root=root,
                    attempt_dir=attempt,
                )
                state_path = attempt / "state.json"
                state_path.write_bytes(canonical_json(state))
                state_path.chmod(0o600)
                cleanup_path = root / "cleanup.lock"
                source_path = root / "source.diff"
                cleanup_path.write_bytes(b"lock")
                source_path.write_bytes(b"diff")
                cleanup_fd = os.open(cleanup_path, os.O_RDONLY | os.O_CLOEXEC)
                source_fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC)
                lease = acquire_retention_lease(
                    root,
                    deadline=time.monotonic() + 5,
                )
                attempt_lease = open_attempt_lease(lease, attempt)
                outer, peer = socket_pair()
                checkout = mock.Mock(side_effect=checkout_error)
                record_failure = mock.Mock(
                    side_effect=RuntimeError("stop failure recording")
                )
                cleanup_worktree = mock.Mock(
                    side_effect=AssertionError(
                        "worktree cleanup followed unproven helper closure"
                    )
                )
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
                            "type": "attempt-lease-offer",
                            "token": token,
                            "binding": attempt_lease.transfer_binding(),
                        },
                        deadline=time.monotonic() + 5,
                    )
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
                            record_failure,
                        ),
                        mock.patch(
                            "review_supervisor.runtime._cleanup_worktree",
                            cleanup_worktree,
                        ),
                    ):
                        result = attempt_supervisor_main(
                            entrypoint=ENTRYPOINT,
                            attempt_dir=attempt,
                            control_fd=os.dup(outer.fileno()),
                            lease_fd=os.dup(lease.fd),
                            root_fd=os.dup(lease.root_fd),
                            attempt_fd=os.dup(attempt_lease.fd),
                            handoff_token=token,
                        )
                    self.assertEqual(result, 2)
                    self.assertEqual(checkout.called, exact_ack)
                    self.assertEqual(record_failure.called, records_failure)
                    cleanup_worktree.assert_not_called()
                finally:
                    driver.join(timeout=5)
                    peer.close()
                    outer.close()
                    os.close(cleanup_fd)
                    os.close(source_fd)
                    attempt_lease.close()
                    lease.close()
                self.assertFalse(driver.is_alive())
                if thread_errors:
                    raise thread_errors[0]


if __name__ == "__main__":
    unittest.main()
