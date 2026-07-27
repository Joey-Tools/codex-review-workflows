from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest

from review_supervisor.cli import _emit
from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.secureio import (
    allocated_bytes,
    boot_identifier,
    canonical_json,
    identity_from_stat,
    measure_filesystem,
    sha256_bytes,
)

from tests.support import bind_attempt_state, owned_temporary_directory


TOOL_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENTRYPOINT = TOOL_ROOT / "independent-codex-pr-review"


def _invoke(*arguments: str) -> tuple[int, dict[str, object]]:
    completed = subprocess.run(
        (sys.executable, str(ENTRYPOINT), *arguments),
        cwd=TOOL_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if completed.stderr:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise AssertionError(f"expected one JSON line, got {lines!r}")
    return completed.returncode, json.loads(lines[0])


def _assert_low_level_contract(
    testcase: unittest.TestCase, payload: dict[str, object]
) -> None:
    testcase.assertEqual(payload["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT)
    testcase.assertIs(payload["named_lane_eligible"], False)


def _write_attempt(
    retention: pathlib.Path,
    *,
    suffix: str,
    process_settlement: str,
    retention_state: str,
) -> pathlib.Path:
    attempt_id = f"1-{suffix}"
    attempt = retention / f"attempt-{attempt_id}"
    attempt.mkdir(mode=0o700)
    state = {
        "schema_version": SCHEMA_VERSION,
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "attempt_id": attempt_id,
        "record_generation": 1,
        "previous_record_sha256": None,
        "boot_id": boot_identifier(),
        "phase": "reserved",
        "handoff": "none",
        "closure": "unproven",
        "process_settlement": process_settlement,
        "checkout_settlement": "exact",
        "retention_state": retention_state,
        "prompt_path": str(attempt / "prompt.txt"),
        "prompt_length": 1,
        "prompt_sha256": "2d711642b726b04401627ca9fbac32f5da7e5f7c8f4f5f4f5f4f5f4f5f4f5f4f",
        "review_status": "not-run",
        "launch_status": "not-attempted",
        "cleanup_status": "clean",
        "worktree_status": "absent",
        "reservation_status": "settled"
        if process_settlement == "exact"
        else "outstanding",
        "admission_status": "completed",
        "failure_stage": None,
        "review_range": f"{'1' * 40}..{'2' * 40}",
        "requested_model": "gpt-5.6-sol",
        "requested_reasoning_effort": "xhigh",
        "observed_runtime": {},
        "final_seal": None,
        "unsupported_clauses": [],
        "retained_process_bytes": 0 if process_settlement == "exact" else None,
        "process_physical_remaining_by_fs": {},
        "released_at": None,
        "release_reason": None,
    }
    bind_attempt_state(
        state,
        retention_root=retention,
        attempt_dir=attempt,
    )
    (attempt / "state.json").write_bytes(canonical_json(state))
    os.chmod(attempt / "state.json", 0o600)
    return attempt


def _write_exact_state(attempt: pathlib.Path, state: dict[str, object]) -> None:
    state_path = attempt / "state.json"
    for _ in range(8):
        state_path.write_bytes(canonical_json(state))
        state_path.chmod(0o600)
        retained = allocated_bytes(attempt, entry_cap=1_000)
        identity = measure_filesystem(attempt).identity
        expected_map = {identity: retained}
        if (
            state.get("retained_process_bytes") == retained
            and state.get("process_physical_remaining_by_fs") == expected_map
        ):
            return
        state["retained_process_bytes"] = retained
        state["process_physical_remaining_by_fs"] = expected_map
    raise AssertionError("test attempt allocation did not converge")


def _authorize_final(attempt: pathlib.Path, content: bytes) -> dict[str, object]:
    final_path = attempt / "final.txt"
    final_path.write_bytes(content)
    final_path.chmod(0o600)
    state = json.loads((attempt / "state.json").read_text())
    seal = {
        "path": str(final_path),
        "identity": identity_from_stat(os.stat(final_path)).to_json(),
        "length": len(content),
        "sha256": sha256_bytes(content),
    }
    supervisor = {"pid": 1234, "start_identity": "fixture-supervisor-start"}
    leader = {
        "pid": 5678,
        "pgid": 5678,
        "start_identity": "fixture-reviewer-start",
    }
    predecessor_sha256 = "c" * 64
    runtime_binding = {
        "session_id": leader["pid"],
        "profile_sha256": "e" * 64,
    }
    terminal_predecessor = "f" * 64
    terminal_proof_payload = {
        "predecessor_sha256": terminal_predecessor,
        "leader_exit": 0,
        "final_seal": seal,
    }
    state.update(
        {
            "record_generation": 10,
            "previous_record_sha256": predecessor_sha256,
            "phase": "reviewed",
            "handoff": "complete",
            "handoff_token": "d" * 64,
            "process_owner": "attempt-supervisor",
            "supervisor": supervisor,
            "supervisor_exit_code": 0,
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
            "observed_runtime": {
                "process": {
                    "elapsed_seconds": 1.0,
                    "exit_code": 0,
                    "stderr_bytes": 0,
                    "stdout_bytes": len(content),
                    "streamed_message_bytes": len(content),
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
            },
            "final_seal": seal,
        }
    )
    authorization = {
        "predecessor_generation": 9,
        "predecessor_sha256": predecessor_sha256,
        "supervisor": supervisor,
        "supervisor_exit_code": 0,
        "handoff_token_sha256": sha256_bytes(("d" * 64).encode("ascii")),
        "final_seal": seal,
    }
    state["final_authorization"] = {
        **authorization,
        "binding_sha256": sha256_bytes(canonical_json(authorization)),
    }
    _write_exact_state(attempt, state)
    return state


class CliLifecycleTests(unittest.TestCase):
    def test_emit_overrides_conflicting_contract_metadata(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _emit(
                {
                    "status": "ok",
                    "review_contract": "forged",
                    "named_lane_eligible": True,
                }
            )
        self.assertEqual(
            output.getvalue().encode("ascii"),
            canonical_json(
                {
                    "status": "ok",
                    "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                    "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                }
            ),
        )
        _assert_low_level_contract(self, json.loads(output.getvalue()))

    def test_emit_rejects_non_finite_values_without_output(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(ValueError):
                    _emit({"outer": [{"value": value}]})
                self.assertEqual(output.getvalue(), "")

    def test_invalid_pr_url_fails_before_creating_runtime_directories(self) -> None:
        with owned_temporary_directory("cli-invalid-pr-") as root:
            retention = root / "retention"
            checkout = root / "checkout"
            code, payload = _invoke(
                "preflight",
                "--helper-state",
                str(root / "helper-state"),
                "--repo",
                str(root / "repo"),
                "--base",
                "1" * 40,
                "--head",
                "2" * 40,
                "--pr-url",
                "https://github.example/owner/repo/pull/1?inject=true",
                "--retention-root",
                str(retention),
                "--checkout-parent",
                str(checkout),
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["failure_stage"], "cli")
            self.assertEqual(payload["failure_code"], "cli-failed")
            self.assertFalse(retention.exists())
            self.assertFalse(checkout.exists())

    def test_final_revalidates_the_sealed_artifact(self) -> None:
        with owned_temporary_directory("cli-final-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="e" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            content = b"No findings.\n"
            _authorize_final(attempt, content)
            code, payload = _invoke(
                "final",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["final_message"], "No findings.")
            code, payload = _invoke(
                "release",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
                "--reason",
                "resolved",
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            code, payload = _invoke(
                "final",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["final_message"], "No findings.")
            final_path = attempt / "final.txt"
            final_path.write_bytes(b"No findings?\n")
            code, payload = _invoke(
                "final",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 2)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["overall_status"], "inconclusive")

    def test_final_rejects_each_forged_terminal_binding(self) -> None:
        mutations = {
            "phase": lambda state: state.__setitem__("phase", "spawn-intent"),
            "launch": lambda state: state.__setitem__("launch_status", "spawn-intent"),
            "handoff": lambda state: state.__setitem__("handoff", "accepted"),
            "owner": lambda state: state.__setitem__("process_owner", "outer"),
            "supervisor-binding": lambda state: state.__setitem__(
                "supervisor", {"pid": 9999, "start_identity": "forged"}
            ),
            "leader-binding": lambda state: state["leader"].__setitem__("pgid", 9999),
            "runtime-session": lambda state: state[
                "runtime_process_binding"
            ].__setitem__("session_id", 9999),
            "history-runtime-binding": lambda state: state["process_history"][
                -1
            ].__setitem__(
                "runtime_binding",
                {
                    **state["runtime_process_binding"],
                    "profile_sha256": "f" * 64,
                },
            ),
            "closure": lambda state: state.__setitem__("closure", "unproven"),
            "abandonment": lambda state: state.__setitem__("abandonment", True),
            "custody": lambda state: state.__setitem__(
                "source_custody_released", False
            ),
            "supervisor-exit": lambda state: state.__setitem__(
                "supervisor_exit_code", 1
            ),
            "leader-exit": lambda state: state["terminal_authorization"].__setitem__(
                "leader_exit", 1
            ),
            "predecessor-generation": lambda state: state[
                "final_authorization"
            ].__setitem__("predecessor_generation", 8),
            "predecessor-digest": lambda state: state[
                "final_authorization"
            ].__setitem__("predecessor_sha256", "e" * 64),
            "authorization-seal": lambda state: state[
                "final_authorization"
            ].__setitem__("final_seal", None),
            "terminal-seal": lambda state: state["terminal_authorization"].__setitem__(
                "final_seal", None
            ),
            "binding-digest": lambda state: state["final_authorization"].__setitem__(
                "binding_sha256", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with (
                self.subTest(name=name),
                owned_temporary_directory(f"cli-final-forged-{name}-") as root,
            ):
                retention = root / "retention"
                retention.mkdir(mode=0o700)
                attempt = _write_attempt(
                    retention,
                    suffix="f" * 32,
                    process_settlement="exact",
                    retention_state="held",
                )
                state = _authorize_final(attempt, b"No findings.\n")
                mutate(state)
                _write_exact_state(attempt, state)
                code, payload = _invoke(
                    "final",
                    "--retention-root",
                    str(retention),
                    "--attempt-dir",
                    str(attempt),
                )
                self.assertEqual(code, 2, payload)
                _assert_low_level_contract(self, payload)
                self.assertEqual(payload["failure_code"], "final-authorization-invalid")

    def test_same_boot_recovery_fails_closed_without_mutation(self) -> None:
        with owned_temporary_directory("cli-recover-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="a" * 32,
                process_settlement="outstanding",
                retention_state="active/unsafe",
            )
            before = (attempt / "state.json").read_bytes()
            code, payload = _invoke(
                "recover",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 2)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["overall_status"], "blocked")
            self.assertEqual(payload["failure_code"], "same-boot-owner-required")
            self.assertEqual((attempt / "state.json").read_bytes(), before)

    def test_status_release_and_exact_cleanup(self) -> None:
        with owned_temporary_directory("cli-lifecycle-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt = _write_attempt(
                retention,
                suffix="b" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            code, payload = _invoke(
                "status",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            _assert_low_level_contract(self, payload["attempts"][0])
            self.assertEqual(payload["attempts"][0]["retention_state"], "held")

            code, payload = _invoke(
                "release",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
                "--reason",
                "resolved",
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["status"], "released")

            code, payload = _invoke(
                "cleanup",
                "--retention-root",
                str(retention),
                "--attempt-dir",
                str(attempt),
            )
            self.assertEqual(code, 0, payload)
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["status"], "reclaimed")
            self.assertFalse(attempt.exists())


if __name__ == "__main__":
    unittest.main()
