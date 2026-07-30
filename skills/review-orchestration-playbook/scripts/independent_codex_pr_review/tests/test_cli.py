from __future__ import annotations

import argparse
import contextlib
import dataclasses
import errno
import fcntl
import io
import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import unittest
from unittest import mock

from review_supervisor import cli as cli_module
from review_supervisor import legacy_retention as legacy_retention_module
from review_supervisor.cli import _emit
from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
    default_checkout_parent,
    default_retention_root,
    default_state_root,
)
from review_supervisor.errors import SupervisorError
from review_supervisor.secureio import (
    DirectoryPolicyBinding,
    MacOSDirectoryMetadataBinding,
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
RELATIVE_TOOL = pathlib.Path(
    "personal_codex/skills/review-orchestration-playbook/"
    "scripts/independent_codex_pr_review"
)


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


def _write_retention_lock(retention: pathlib.Path) -> pathlib.Path:
    lock = retention / "retention.lock"
    lock.write_bytes(b"retention-lease-v1:" + b"a" * 32 + b"\n")
    lock.chmod(0o600)
    return lock


def _write_account_local_marker(tool: pathlib.Path) -> pathlib.Path:
    marker = tool / "ACCOUNT_LOCAL_RETENTION_V1"
    marker.write_bytes(b"account-local-retention-v1\n")
    marker.chmod(0o644)
    return marker


def _release_uses_account_local_retention(tool: pathlib.Path) -> bool:
    tool_fd = os.open(
        tool,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        return legacy_retention_module._release_uses_account_local_retention(
            tool_fd,
            tool,
        )
    finally:
        os.close(tool_fd)


def _installed_upgrade_layout(
    root: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    releases = root / "overlays" / "private" / "releases"
    current_release = releases / ("b" * 40)
    old_release = releases / ("a" * 40)
    current_tool = current_release / RELATIVE_TOOL
    current_tool.mkdir(parents=True)
    _write_account_local_marker(current_tool)
    legacy_retention = old_release / RELATIVE_TOOL / "runtime" / "retention"
    legacy_retention.mkdir(parents=True, mode=0o700)
    return releases, current_tool, old_release, legacy_retention


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
    def test_readme_self_contained_examples_pin_distinct_runtime_roots(self) -> None:
        readme = (TOOL_ROOT / "README.md").read_text()

        self.assertIn('RETENTION="$TOOL_DIR/runtime/retention"', readme)
        self.assertIn('CHECKOUTS="$TOOL_DIR/runtime/checkouts"', readme)
        self.assertEqual(readme.count('--retention-root "$RETENTION"'), 9)
        self.assertEqual(readme.count('--checkout-parent "$CHECKOUTS"'), 2)
        self.assertNotIn('RETENTION="$STATE_ROOT/retention"', readme)
        self.assertIn(
            "account-local defaults 只用于标准 installed overlay catalog",
            readme,
        )
        self.assertIn("### Standard Installed Overlay Defaults", readme)
        self.assertEqual(
            readme.count('python3.13 -B "$SUPERVISOR" preflight \\'),
            2,
        )
        self.assertEqual(
            readme.count('python3.13 -B "$SUPERVISOR" run \\'),
            2,
        )

        source_arguments = (
            "--helper-state",
            "/tmp/helper-state",
            "--repo",
            "/tmp/repo",
            "--base",
            "a" * 40,
            "--head",
            "b" * 40,
            "--pr-url",
            "https://github.com/owner/repo/pull/1",
        )
        parser = cli_module._public_parser()
        for command in ("preflight", "run"):
            with self.subTest(command=command, roots="overlay-default"):
                arguments = parser.parse_args((command, *source_arguments))
                self.assertIsNone(arguments.retention_root)
                self.assertIsNone(arguments.checkout_parent)
            with self.subTest(command=command, roots="self-contained"):
                arguments = parser.parse_args(
                    (
                        command,
                        *source_arguments,
                        "--retention-root",
                        "/tmp/tool/runtime/retention",
                        "--checkout-parent",
                        "/tmp/tool/runtime/checkouts",
                    )
                )
                self.assertEqual(
                    arguments.retention_root,
                    pathlib.Path("/tmp/tool/runtime/retention"),
                )
                self.assertEqual(
                    arguments.checkout_parent,
                    pathlib.Path("/tmp/tool/runtime/checkouts"),
                )

        for command, tail in (
            ("status", ()),
            ("final", ()),
            ("recover", ()),
            ("release", ("--reason", "resolved")),
            ("cleanup", ()),
        ):
            with self.subTest(command=command, roots="overlay-default"):
                arguments = parser.parse_args(
                    (command, "--attempt-dir", "/tmp/attempt", *tail)
                )
                self.assertIsNone(arguments.retention_root)
            with self.subTest(command=command, roots="self-contained"):
                arguments = parser.parse_args(
                    (
                        command,
                        "--retention-root",
                        "/tmp/tool/runtime/retention",
                        "--attempt-dir",
                        "/tmp/attempt",
                        *tail,
                    )
                )
                self.assertEqual(
                    arguments.retention_root,
                    pathlib.Path("/tmp/tool/runtime/retention"),
                )

    def test_default_state_roots_are_host_local(self) -> None:
        account_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
        expected = (
            account_home / ".codex" / "review-runtime" / "independent-codex-pr-review"
        )

        self.assertEqual(default_state_root(), expected)
        self.assertEqual(default_retention_root(), expected / "retention")
        self.assertEqual(default_checkout_parent(), expected / "checkouts")
        for path in (
            default_state_root(),
            default_retention_root(),
            default_checkout_parent(),
        ):
            with self.subTest(path=path):
                self.assertFalse(path.resolve().is_relative_to(TOOL_ROOT.resolve()))

    def test_default_account_lookup_failure_uses_json_failure_contract(self) -> None:
        output = io.StringIO()
        with (
            mock.patch(
                "review_supervisor.constants.pwd.getpwuid",
                side_effect=KeyError("account unavailable"),
            ),
            contextlib.redirect_stdout(output),
        ):
            code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

        self.assertEqual(code, 2)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        _assert_low_level_contract(self, payload)
        self.assertEqual(payload["failure_stage"], "cli")
        self.assertEqual(payload["failure_code"], "cli-failed")
        self.assertIn("current POSIX account home is unavailable", payload["message"])

    def test_public_defaults_share_one_account_state_snapshot(self) -> None:
        with owned_temporary_directory("cli-default-root-snapshot-") as root:
            first_home = root / "account-a"
            second_home = root / "account-b"
            first_home.mkdir(mode=0o700)
            second_home.mkdir(mode=0o700)
            first_account = mock.Mock(pw_dir=str(first_home))
            second_account = mock.Mock(pw_dir=str(second_home))
            binding = mock.Mock(equivalent=False)
            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.constants.pwd.getpwuid",
                    side_effect=(first_account, second_account),
                ) as account_lookup,
                mock.patch.object(
                    cli_module,
                    "bind_directory_path_equivalence",
                    return_value=contextlib.nullcontext(binding),
                ),
                mock.patch.object(
                    cli_module,
                    "preflight",
                    return_value={"status": "admitted"},
                ) as preflight_mock,
                contextlib.redirect_stdout(output),
            ):
                code = cli_module.main(
                    (
                        "preflight",
                        "--helper-state",
                        str(root / "helper"),
                        "--repo",
                        str(root / "repo"),
                        "--base",
                        "a" * 40,
                        "--head",
                        "b" * 40,
                        "--pr-url",
                        "https://github.com/owner/repo/pull/1",
                    ),
                    entrypoint=ENTRYPOINT,
                )

        self.assertEqual(code, 0)
        account_lookup.assert_called_once_with(os.getuid())
        expected_state = (
            first_home / ".codex" / "review-runtime" / "independent-codex-pr-review"
        )
        self.assertEqual(
            preflight_mock.call_args.kwargs["retention_root"],
            expected_state / "retention",
        )
        self.assertEqual(
            preflight_mock.call_args.kwargs["checkout_parent"],
            expected_state / "checkouts",
        )
        binding.revalidate.assert_called_once_with()

    def test_explicit_distinct_roots_skip_only_the_legacy_scan(self) -> None:
        with owned_temporary_directory("cli-explicit-roots-") as root:
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            account_default = root / "account-default"
            account_default.mkdir(mode=0o700)
            checkout = root / "checkouts"
            helper_state = root / "helper"
            repo = root / "repo"
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ) as default_retention_mock,
                mock.patch.object(
                    cli_module,
                    "default_checkout_parent",
                    side_effect=AssertionError("checkout default must stay lazy"),
                ),
                mock.patch.object(
                    cli_module,
                    "installed_legacy_retention_fence",
                    side_effect=AssertionError("legacy scan must stay lazy"),
                ),
                mock.patch.object(
                    cli_module,
                    "preflight",
                    return_value={"status": "admitted"},
                ) as preflight_mock,
                contextlib.redirect_stdout(output),
            ):
                code = cli_module.main(
                    (
                        "preflight",
                        "--helper-state",
                        str(helper_state),
                        "--repo",
                        str(repo),
                        "--base",
                        "a" * 40,
                        "--head",
                        "b" * 40,
                        "--pr-url",
                        "https://github.com/owner/repo/pull/1",
                        "--retention-root",
                        str(retention),
                        "--checkout-parent",
                        str(checkout),
                    ),
                    entrypoint=ENTRYPOINT,
                )

        self.assertEqual(code, 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        default_retention_mock.assert_called_once()
        preflight_mock.assert_called_once()
        self.assertEqual(preflight_mock.call_args.kwargs["retention_root"], retention)
        self.assertEqual(preflight_mock.call_args.kwargs["checkout_parent"], checkout)

    def test_selected_retention_replacement_fails_before_lock_creation(self) -> None:
        with owned_temporary_directory("cli-selected-root-replaced-") as root:
            selected = root / "selected"
            selected.mkdir(mode=0o700)
            account_default = root / "account-default"
            account_default.mkdir(mode=0o700)
            displaced = root / "displaced"
            original_status = cli_module.status
            replaced = False

            def replace_then_status(**kwargs: object) -> dict[str, object]:
                nonlocal replaced
                selected.rename(displaced)
                account_default.rename(selected)
                replaced = True
                return original_status(**kwargs)

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch.object(
                    cli_module,
                    "installed_legacy_retention_fence",
                    side_effect=AssertionError("distinct roots must skip the fence"),
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=replace_then_status,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(selected),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(exit_code, 2)
            self.assertTrue(replaced)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "directory path changed while comparing account-local roots",
                payload["message"],
            )
            self.assertFalse((selected / "retention.lock").exists())
            self.assertFalse((displaced / "retention.lock").exists())

    def test_selected_retention_binding_allows_child_entry_churn(self) -> None:
        with owned_temporary_directory("cli-selected-root-churn-") as root:
            selected = root / "selected"
            selected.mkdir(mode=0o700)
            account_default = root / "account-default"
            account_default.mkdir(mode=0o700)
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch.object(
                    cli_module,
                    "installed_legacy_retention_fence",
                    side_effect=AssertionError("distinct roots must skip the fence"),
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(selected),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["retention_root"], str(selected))
            self.assertTrue((selected / "retention.lock").is_file())

    def test_installed_upgrade_blocks_until_legacy_attempt_is_drained(
        self,
    ) -> None:
        with owned_temporary_directory("cli-legacy-upgrade-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )

            blocked_output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(blocked_output),
            ):
                blocked_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(blocked_code, 2)
            blocked_lines = blocked_output.getvalue().splitlines()
            self.assertEqual(len(blocked_lines), 1)
            blocked_payload = json.loads(blocked_lines[0])
            _assert_low_level_contract(self, blocked_payload)
            self.assertEqual(blocked_payload["failure_stage"], "cli")
            self.assertIn(
                "legacy release-local attempts require explicit draining",
                blocked_payload["message"],
            )
            self.assertIn(str(legacy_retention), blocked_payload["message"])

            drain_output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(drain_output),
            ):
                drain_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(legacy_retention),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(drain_code, 0)
            drain_lines = drain_output.getvalue().splitlines()
            self.assertEqual(len(drain_lines), 1)
            drain_payload = json.loads(drain_lines[0])
            _assert_low_level_contract(self, drain_payload)
            self.assertEqual(drain_payload["retention_root"], str(legacy_retention))
            self.assertEqual(drain_payload["attempt_count"], 1)

    def test_installed_upgrade_case_alias_still_scans_sibling_releases(
        self,
    ) -> None:
        with owned_temporary_directory("cli-legacy-case-alias-") as root:
            releases, current_tool, _, legacy_retention = _installed_upgrade_layout(
                root
            )
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            alias_tool = (
                root
                / "OVERLAYS"
                / "PRIVATE"
                / "RELEASES"
                / ("B" * 40)
                / pathlib.Path(
                    "PERSONAL_CODEX/SKILLS/REVIEW-ORCHESTRATION-PLAYBOOK/"
                    "SCRIPTS/INDEPENDENT_CODEX_PR_REVIEW"
                )
            )
            try:
                alias_is_same_object = alias_tool.is_dir() and os.path.samefile(
                    alias_tool,
                    current_tool,
                )
            except OSError:
                alias_is_same_object = False
            if not alias_is_same_object:
                self.skipTest("requires a case-insensitive filesystem")

            catalog = legacy_retention_module._installed_release_catalog(alias_tool)
            self.assertIsNotNone(catalog)
            assert catalog is not None
            try:
                self.assertTrue(os.path.samefile(catalog.releases_root, releases))
                self.assertEqual(
                    catalog.current_release_name,
                    os.fsencode("b" * 40),
                )
            finally:
                catalog.close()

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=alias_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            _assert_low_level_contract(self, payload)
            self.assertIn(
                "legacy release-local attempts require explicit draining",
                payload["message"],
            )

    def test_installed_upgrade_rejects_attempt_created_during_command(
        self,
    ) -> None:
        with owned_temporary_directory("cli-legacy-attempt-race-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            account_default = root / "account-default"
            original_status = cli_module.status
            attempt_created = False

            def create_attempt_then_return(**kwargs: object) -> dict[str, object]:
                nonlocal attempt_created
                result = original_status(**kwargs)
                _write_attempt(
                    legacy_retention,
                    suffix="a" * 32,
                    process_settlement="exact",
                    retention_state="held",
                )
                attempt_created = True
                return result

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=create_attempt_then_return,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            self.assertTrue(attempt_created)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy retention attempts appeared while migration fence was active",
                payload["message"],
            )

    def test_installed_upgrade_rejects_release_replacement_after_catalog(
        self,
    ) -> None:
        with owned_temporary_directory("cli-legacy-replacement-") as root:
            releases, current_tool, old_release, legacy_retention = (
                _installed_upgrade_layout(root)
            )
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            original_scan = legacy_retention_module._stable_directory_entries_fd
            replacement_done = False

            def replace_after_catalog(
                directory_fd: int,
                *,
                path_hint: pathlib.Path,
                private: bool,
                label: str,
            ) -> tuple[tuple[bytes, os.stat_result], ...]:
                nonlocal replacement_done
                entries = original_scan(
                    directory_fd,
                    path_hint=path_hint,
                    private=private,
                    label=label,
                )
                if label == "installed release directory" and not replacement_done:
                    replacement_done = True
                    old_release.rename(releases / "displaced-release")
                    old_release.mkdir(mode=0o700)
                return entries

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "_stable_directory_entries_fd",
                    side_effect=replace_after_catalog,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            _assert_low_level_contract(self, payload)
            self.assertEqual(payload["failure_stage"], "cli")
            self.assertIn(
                "installed release changed while being inspected",
                payload["message"],
            )

    def test_installed_upgrade_retains_catalog_descriptors_after_discovery(
        self,
    ) -> None:
        with owned_temporary_directory("cli-catalog-custody-race-") as root:
            releases, current_tool, _, legacy_retention = _installed_upgrade_layout(
                root
            )
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            displaced_releases = root / "displaced-releases"
            original_catalog = legacy_retention_module._installed_release_catalog
            replacement_done = False

            def replace_after_discovery(
                tool_path: pathlib.Path,
            ) -> object:
                nonlocal replacement_done
                catalog = original_catalog(tool_path)
                self.assertIsNotNone(catalog)
                releases.rename(displaced_releases)
                replacement_current = releases / ("b" * 40) / RELATIVE_TOOL
                replacement_sibling = releases / ("a" * 40) / RELATIVE_TOOL
                replacement_current.mkdir(parents=True)
                replacement_sibling.mkdir(parents=True)
                _write_account_local_marker(replacement_current)
                _write_account_local_marker(replacement_sibling)
                replacement_done = True
                return catalog

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "_installed_release_catalog",
                    side_effect=replace_after_discovery,
                ),
                mock.patch.object(cli_module, "status") as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            self.assertTrue(replacement_done)
            status_mock.assert_not_called()
            payload = json.loads(output.getvalue())
            _assert_low_level_contract(self, payload)
            self.assertIn(
                "installed release changed while being inspected",
                payload["message"],
            )

    def test_catalog_tool_walk_closes_new_fd_after_parent_close_failure(
        self,
    ) -> None:
        with owned_temporary_directory("cli-catalog-tool-close-") as root:
            release_root = root / "release"
            (release_root / RELATIVE_TOOL).mkdir(parents=True)
            release_fd = os.open(
                release_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            opened_fds: list[int] = []
            original_open = legacy_retention_module.open_directory_at
            original_close = os.close
            close_failed = False

            def track_open(*args: object, **kwargs: object) -> tuple[int, object]:
                fd, identity = original_open(*args, **kwargs)
                opened_fds.append(fd)
                return fd, identity

            def close_parent_then_fail(fd: int) -> None:
                nonlocal close_failed
                original_close(fd)
                if not close_failed and opened_fds and fd == opened_fds[0]:
                    close_failed = True
                    raise OSError(errno.EIO, "simulated parent close failure")

            try:
                with (
                    mock.patch.object(
                        legacy_retention_module,
                        "open_directory_at",
                        side_effect=track_open,
                    ),
                    mock.patch.object(
                        legacy_retention_module.os,
                        "close",
                        side_effect=close_parent_then_fail,
                    ),
                    self.assertRaisesRegex(
                        OSError,
                        "simulated parent close failure",
                    ),
                ):
                    legacy_retention_module._open_installed_tool_from_release(
                        release_fd,
                        release_root,
                    )
            finally:
                os.close(release_fd)

            self.assertTrue(close_failed)
            self.assertGreaterEqual(len(opened_fds), 2)
            for fd in opened_fds:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_bound_current_root_walk_closes_new_fd_after_parent_close_failure(
        self,
    ) -> None:
        with owned_temporary_directory("cli-bound-root-close-") as root:
            _, current_tool, _, _ = _installed_upgrade_layout(root)
            (current_tool / "runtime" / "retention").mkdir(
                parents=True,
                mode=0o700,
            )
            catalog = legacy_retention_module._installed_release_catalog(current_tool)
            self.assertIsNotNone(catalog)
            assert catalog is not None
            opened_fds: list[int] = []
            original_open = legacy_retention_module.open_directory_at
            original_close = os.close
            close_failed = False

            def track_open(*args: object, **kwargs: object) -> tuple[int, object]:
                fd, identity = original_open(*args, **kwargs)
                opened_fds.append(fd)
                return fd, identity

            def close_parent_then_fail(fd: int) -> None:
                nonlocal close_failed
                original_close(fd)
                if not close_failed and opened_fds and fd == opened_fds[0]:
                    close_failed = True
                    raise OSError(errno.EIO, "simulated parent close failure")

            try:
                with (
                    mock.patch.object(
                        legacy_retention_module,
                        "open_directory_at",
                        side_effect=track_open,
                    ),
                    mock.patch.object(
                        legacy_retention_module.os,
                        "close",
                        side_effect=close_parent_then_fail,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "cannot inspect current helper legacy retention path safely",
                    ),
                ):
                    legacy_retention_module._open_bound_current_tool_legacy_retention_root(
                        catalog
                    )
            finally:
                catalog.close()

            self.assertTrue(close_failed)
            self.assertEqual(len(opened_fds), 2)
            for fd in opened_fds:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_catalog_revalidation_attempts_every_descriptor_cleanup(self) -> None:
        with owned_temporary_directory("cli-catalog-revalidate-close-") as root:
            _, current_tool, _, _ = _installed_upgrade_layout(root)
            catalog = legacy_retention_module._installed_release_catalog(current_tool)
            self.assertIsNotNone(catalog)
            assert catalog is not None
            refreshed_fds: list[int] = []
            original_open = legacy_retention_module.open_absolute_directory_chain
            original_close = os.close
            failed_fd = -1
            close_failed = False

            def track_open(
                path: pathlib.Path,
                **kwargs: object,
            ) -> tuple[int, object]:
                nonlocal failed_fd
                fd, identity = original_open(path, **kwargs)
                refreshed_fds.append(fd)
                if path == catalog.tool_path:
                    failed_fd = fd
                return fd, identity

            def close_tool_then_fail(fd: int) -> None:
                nonlocal close_failed
                original_close(fd)
                if not close_failed and fd == failed_fd:
                    close_failed = True
                    raise OSError(errno.EIO, "simulated tool close failure")

            try:
                with (
                    mock.patch.object(
                        legacy_retention_module,
                        "open_absolute_directory_chain",
                        side_effect=track_open,
                    ),
                    mock.patch.object(
                        legacy_retention_module.os,
                        "close",
                        side_effect=close_tool_then_fail,
                    ),
                    self.assertRaisesRegex(
                        OSError,
                        "simulated tool close failure",
                    ),
                ):
                    legacy_retention_module._revalidate_installed_release_catalog(
                        catalog
                    )
            finally:
                catalog.close()

            self.assertTrue(close_failed)
            self.assertEqual(len(refreshed_fds), 3)
            for fd in refreshed_fds:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_current_root_revalidation_preserves_mismatch_on_cleanup_failure(
        self,
    ) -> None:
        with owned_temporary_directory("cli-current-root-cleanup-") as root:
            _, current_tool, _, _ = _installed_upgrade_layout(root)
            retention = current_tool / "runtime" / "retention"
            retention.mkdir(parents=True, mode=0o700)
            catalog = legacy_retention_module._installed_release_catalog(current_tool)
            self.assertIsNotNone(catalog)
            assert catalog is not None
            current_root = (
                legacy_retention_module._open_bound_current_tool_legacy_retention_root(
                    catalog
                )
            )
            self.assertIsNotNone(current_root)
            assert current_root is not None
            original_open = (
                legacy_retention_module._open_bound_current_tool_legacy_retention_root
            )
            original_close = legacy_retention_module._LegacyRetentionRoot.close

            def open_with_mismatched_policy(
                selected_catalog: object,
            ) -> object:
                refreshed = original_open(selected_catalog)
                self.assertIsNotNone(refreshed)
                assert refreshed is not None
                refreshed.retention_binding = dataclasses.replace(
                    refreshed.retention_binding,
                    gid=refreshed.retention_binding.gid + 1,
                )
                return refreshed

            def close_then_fail(selected_root: object) -> None:
                original_close(selected_root)
                raise OSError(errno.EIO, "simulated refreshed-root close failure")

            try:
                with (
                    mock.patch.object(
                        legacy_retention_module,
                        "_open_bound_current_tool_legacy_retention_root",
                        side_effect=open_with_mismatched_policy,
                    ),
                    mock.patch.object(
                        legacy_retention_module._LegacyRetentionRoot,
                        "close",
                        autospec=True,
                        side_effect=close_then_fail,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "current helper legacy retention path changed",
                    ) as raised,
                ):
                    legacy_retention_module._revalidate_current_tool_legacy_retention_root(
                        current_root,
                        catalog=catalog,
                    )
            finally:
                current_root.close()
                catalog.close()

            self.assertIn(
                "refreshed current legacy retention cleanup failed",
                "\n".join(raised.exception.__notes__),
            )

    def test_installed_release_gid_drift_fails_catalog_revalidation(self) -> None:
        with owned_temporary_directory("cli-release-gid-drift-") as root:
            releases, _, _, _ = _installed_upgrade_layout(root)
            releases_fd, _ = legacy_retention_module.open_absolute_directory_chain(
                releases
            )
            try:
                releases_policy = legacy_retention_module.validate_directory_policy_fd(
                    releases_fd,
                    releases,
                    private=False,
                )
                releases_entries = legacy_retention_module._stable_directory_entries_fd(
                    releases_fd,
                    path_hint=releases,
                    private=False,
                    label="installed release directory",
                )
            finally:
                os.close(releases_fd)

            changed_policy = dataclasses.replace(
                releases_policy,
                gid=releases_policy.gid + 1,
            )
            original_validate = legacy_retention_module.validate_directory_policy_fd

            def change_gid(
                fd: int,
                path: pathlib.Path,
                *,
                private: bool,
            ) -> DirectoryPolicyBinding:
                policy = original_validate(fd, path, private=private)
                return changed_policy if path == releases else policy

            with (
                mock.patch.object(
                    legacy_retention_module,
                    "validate_directory_policy_fd",
                    side_effect=change_gid,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "installed release directory changed",
                ),
            ):
                legacy_retention_module._revalidate_releases_root(
                    releases,
                    releases_policy,
                    releases_entries,
                )

    def test_explicit_account_local_default_still_runs_legacy_gate(self) -> None:
        with owned_temporary_directory("cli-explicit-default-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            account_default = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
                / "retention"
            )
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(account_default),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy release-local attempts require explicit draining",
                payload["message"],
            )

    def test_account_local_path_drift_fails_before_public_command(self) -> None:
        with owned_temporary_directory("cli-retention-drift-") as root:
            account_default = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
                / "retention"
            )
            opaque_alias = root / "mounted-account-state"
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch.object(
                    cli_module,
                    "bind_directory_path_equivalence",
                    side_effect=OSError(
                        errno.ESTALE,
                        "directory path changed while comparing account-local roots",
                    ),
                ),
                mock.patch.object(cli_module, "status") as status_mock,
                mock.patch.object(
                    cli_module,
                    "installed_legacy_retention_fence",
                ) as fence_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(opaque_alias),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "directory path changed while comparing account-local roots",
                payload["message"],
            )
            status_mock.assert_not_called()
            fence_mock.assert_not_called()

    def test_nonmatching_lexical_alias_uses_equivalence_and_legacy_fence(
        self,
    ) -> None:
        explicit_alias = pathlib.Path("/opaque/account-state")
        account_default = pathlib.Path("/account/default-retention")
        arguments = argparse.Namespace(retention_root=explicit_alias)
        binding = mock.Mock(equivalent=True)
        with (
            mock.patch.object(
                cli_module,
                "default_retention_root",
                return_value=account_default,
            ),
            mock.patch.object(
                cli_module,
                "bind_directory_path_equivalence",
                return_value=contextlib.nullcontext(binding),
            ) as binding_mock,
            mock.patch.object(
                cli_module,
                "installed_legacy_retention_fence",
                return_value=contextlib.nullcontext(()),
            ) as fence_mock,
            cli_module._resolve_public_default_roots(arguments),
        ):
            pass

        binding_mock.assert_called_once_with(explicit_alias, account_default)
        binding.revalidate.assert_called_once_with()
        fence_mock.assert_called_once()

    def test_darwin_root_alias_still_identifies_explicit_account_default(
        self,
    ) -> None:
        default_root = pathlib.Path(
            "/var/tmp/codex-review-alias/.codex/review-runtime/"
            "independent-codex-pr-review/retention"
        )
        explicit_root = pathlib.Path(
            "/private/var/tmp/codex-review-alias/.codex/review-runtime/"
            "independent-codex-pr-review/retention"
        )
        arguments = argparse.Namespace(retention_root=explicit_root)
        alias_metadata = mock.Mock(
            st_mode=stat.S_IFLNK | 0o777,
            st_uid=0,
        )
        with (
            mock.patch.object(
                cli_module,
                "default_retention_root",
                return_value=default_root,
            ),
            mock.patch(
                "review_supervisor.secureio.sys.platform",
                "darwin",
            ),
            mock.patch(
                "review_supervisor.secureio.os.lstat",
                return_value=alias_metadata,
            ),
            mock.patch(
                "review_supervisor.secureio.os.readlink",
                return_value="private/var",
            ),
        ):
            self.assertTrue(cli_module._uses_account_local_retention_root(arguments))

    def test_double_leading_slash_still_identifies_explicit_account_default(
        self,
    ) -> None:
        with owned_temporary_directory("cli-double-root-alias-") as root:
            parent = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
            )
            parent.mkdir(parents=True)
            default_root = parent / "retention"
            explicit_root = pathlib.Path(f"//{default_root.as_posix().lstrip('/')}")
            arguments = argparse.Namespace(retention_root=explicit_root)
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=default_root,
                ),
                mock.patch.object(
                    cli_module,
                    "installed_legacy_retention_fence",
                    return_value=contextlib.nullcontext(()),
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertTrue(
                    cli_module._uses_account_local_retention_root(arguments)
                )
                exit_code = cli_module.main(
                    (
                        "status",
                        "--retention-root",
                        str(explicit_root),
                    ),
                    entrypoint=ENTRYPOINT,
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["retention_root"], str(explicit_root))
            self.assertTrue((default_root / "retention.lock").is_file())

    def test_case_alias_uses_existing_object_identity_or_missing_leaf_policy(
        self,
    ) -> None:
        with owned_temporary_directory("cli-case-root-alias-") as root:
            parent = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
            )
            parent.mkdir(parents=True)
            default_root = parent / "retention"
            explicit_root = parent / "RETENTION"
            arguments = argparse.Namespace(retention_root=explicit_root)
            with mock.patch.object(
                cli_module,
                "default_retention_root",
                return_value=default_root,
            ):
                self.assertTrue(
                    cli_module._uses_account_local_retention_root(arguments)
                )
                default_root.mkdir(mode=0o700)
                if explicit_root.exists():
                    self.assertTrue(
                        cli_module._uses_account_local_retention_root(arguments)
                    )
                else:
                    explicit_root.mkdir(mode=0o700)
                    self.assertFalse(
                        cli_module._uses_account_local_retention_root(arguments)
                    )

    def test_installed_upgrade_rejects_active_legacy_writer(self) -> None:
        with owned_temporary_directory("cli-active-legacy-writer-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            lock = _write_retention_lock(legacy_retention)
            lock_fd = os.open(lock, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                output = io.StringIO()
                with (
                    mock.patch(
                        "review_supervisor.legacy_retention.tool_root",
                        return_value=current_tool,
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)
            finally:
                os.close(lock_fd)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy retention root has an active writer", payload["message"]
            )

    def test_non_overlay_upgrade_blocks_current_tool_legacy_attempt(
        self,
    ) -> None:
        with owned_temporary_directory("cli-non-overlay-upgrade-") as root:
            current_tool = root / "self-contained" / "independent-review"
            legacy_retention = current_tool / "runtime" / "retention"
            legacy_retention.mkdir(parents=True, mode=0o700)
            _write_retention_lock(legacy_retention)
            _write_attempt(
                legacy_retention,
                suffix="a" * 32,
                process_settlement="exact",
                retention_state="held",
            )
            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy release-local attempts require explicit draining",
                payload["message"],
            )
            self.assertIn(str(legacy_retention), payload["message"])

    def test_empty_legacy_retention_without_lock_fails_closed(self) -> None:
        with owned_temporary_directory("cli-legacy-no-lock-") as root:
            _, current_tool, _, _ = _installed_upgrade_layout(root)
            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "empty legacy retention root has no lock for a migration fence",
                payload["message"],
            )

    def test_legacy_migration_fence_is_held_through_default_command(self) -> None:
        with owned_temporary_directory("cli-legacy-fence-held-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            lock = _write_retention_lock(legacy_retention)
            account_default = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
                / "retention"
            )

            def status_while_fenced(
                *,
                retention_root: pathlib.Path,
                attempt_dir: pathlib.Path | None,
            ) -> dict[str, object]:
                self.assertEqual(retention_root, account_default)
                self.assertIsNone(attempt_dir)
                probe_fd = os.open(lock, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe_fd)
                return {
                    "retention_root": str(retention_root),
                    "attempt_count": 0,
                }

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=status_while_fenced,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["attempt_count"], 0)

    def test_legacy_retention_appearing_during_default_command_fails_closed(
        self,
    ) -> None:
        with owned_temporary_directory("cli-legacy-appears-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_release = releases / ("b" * 40)
            old_release = releases / ("a" * 40)
            current_tool = current_release / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            old_release.mkdir(mode=0o700)
            legacy_retention = old_release / RELATIVE_TOOL / "runtime" / "retention"

            def create_legacy_root(
                *,
                retention_root: pathlib.Path,
                attempt_dir: pathlib.Path | None,
            ) -> dict[str, object]:
                self.assertIsNone(attempt_dir)
                legacy_retention.mkdir(parents=True, mode=0o700)
                _write_retention_lock(legacy_retention)
                return {
                    "retention_root": str(retention_root),
                    "attempt_count": 0,
                }

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=create_legacy_root,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy retention path appeared while migration fence was active",
                payload["message"],
            )

    def test_current_tool_legacy_retention_appearing_fails_closed(self) -> None:
        with owned_temporary_directory("cli-current-legacy-appears-") as root:
            current_tool = root / "self-contained" / "independent-review"
            current_tool.mkdir(parents=True)
            legacy_retention = current_tool / "runtime" / "retention"
            original_open = (
                legacy_retention_module._open_current_tool_legacy_retention_root
            )
            absence_checks = 0

            def create_after_final_absence(
                path: pathlib.Path,
            ) -> legacy_retention_module._LegacyRetentionRoot | None:
                nonlocal absence_checks
                result = original_open(path)
                if result is None:
                    absence_checks += 1
                    if absence_checks == 2:
                        legacy_retention.mkdir(parents=True, mode=0o700)
                        _write_retention_lock(legacy_retention)
                return result

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "_open_current_tool_legacy_retention_root",
                    side_effect=create_after_final_absence,
                ),
                mock.patch.object(cli_module, "status") as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            status_mock.assert_not_called()
            self.assertEqual(absence_checks, 1)
            self.assertFalse(legacy_retention.exists())
            payload = json.loads(output.getvalue())
            self.assertIn(
                "non-catalog helper has no stable migration fence",
                payload["message"],
            )

    def test_unmarked_legacy_helper_without_root_fails_before_command(
        self,
    ) -> None:
        with owned_temporary_directory("cli-unfenced-legacy-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_release = releases / ("b" * 40)
            old_release = releases / ("a" * 40)
            current_tool = current_release / RELATIVE_TOOL
            old_tool = old_release / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            old_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            legacy_retention = old_tool / "runtime" / "retention"

            def late_legacy_start(**_: object) -> dict[str, object]:
                legacy_retention.mkdir(parents=True, mode=0o700)
                _write_retention_lock(legacy_retention)
                return {"attempt_count": 0}

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=late_legacy_start,
                ) as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            status_mock.assert_not_called()
            self.assertFalse(legacy_retention.exists())
            payload = json.loads(output.getvalue())
            self.assertIn(
                "installed legacy helper has no stable retention fence",
                payload["message"],
            )
            self.assertIn(str(old_tool), payload["message"])

    def test_unmarked_current_release_fails_before_command(self) -> None:
        with owned_temporary_directory("cli-unmarked-current-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_tool = releases / ("b" * 40) / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(cli_module, "status") as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            status_mock.assert_not_called()
            payload = json.loads(output.getvalue())
            self.assertIn(
                "current installed helper lost its account-local retention policy",
                payload["message"],
            )

    def test_current_release_replacement_after_catalog_snapshot_fails_closed(
        self,
    ) -> None:
        with owned_temporary_directory("cli-current-replaced-") as root:
            releases, current_tool, _, legacy_retention = _installed_upgrade_layout(
                root
            )
            _write_retention_lock(legacy_retention)
            current_release = releases / ("b" * 40)
            removed_release = releases / ("c" * 40)
            original_entries = legacy_retention_module._stable_directory_entries_fd
            replaced = False

            def replace_after_snapshot(*args: object, **kwargs: object) -> object:
                nonlocal replaced
                entries = original_entries(*args, **kwargs)
                if not replaced:
                    replaced = True
                    current_release.rename(removed_release)
                    current_tool.mkdir(parents=True)
                    _write_account_local_marker(current_tool)
                return entries

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "_stable_directory_entries_fd",
                    side_effect=replace_after_snapshot,
                ),
                mock.patch.object(cli_module, "status") as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            self.assertTrue(replaced)
            status_mock.assert_not_called()
            payload = json.loads(output.getvalue())
            self.assertIn(
                "installed release changed while being inspected",
                payload["message"],
            )

    def test_marked_account_local_sibling_without_legacy_root_is_allowed(
        self,
    ) -> None:
        with owned_temporary_directory("cli-marked-sibling-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_tool = releases / ("b" * 40) / RELATIVE_TOOL
            sibling_tool = releases / ("a" * 40) / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            sibling_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            _write_account_local_marker(sibling_tool)
            account_default = (
                root
                / "account"
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
                / "retention"
            )
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    return_value={
                        "retention_root": str(account_default),
                        "attempt_count": 0,
                    },
                ) as status_mock,
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 0)
            status_mock.assert_called_once()
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["attempt_count"], 0)

    def test_current_helper_replacement_during_command_fails_closed(self) -> None:
        with owned_temporary_directory("cli-current-helper-replaced-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            account_default = root / "account-default"
            displaced_tool = current_tool.with_name("displaced-current-tool")
            original_status = cli_module.status

            def replace_current_tool(**kwargs: object) -> dict[str, object]:
                result = original_status(**kwargs)
                current_tool.rename(displaced_tool)
                current_tool.mkdir(mode=0o755)
                _write_account_local_marker(current_tool)
                return result

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=replace_current_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "installed helper path or retention policy changed",
                payload["message"],
            )

    def test_marked_sibling_replacement_during_command_fails_closed(self) -> None:
        with owned_temporary_directory("cli-sibling-helper-replaced-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_tool = releases / ("b" * 40) / RELATIVE_TOOL
            sibling_tool = releases / ("a" * 40) / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            sibling_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            _write_account_local_marker(sibling_tool)
            account_default = root / "account-default"
            displaced_tool = sibling_tool.with_name("displaced-sibling-tool")
            original_status = cli_module.status

            def replace_sibling_tool(**kwargs: object) -> dict[str, object]:
                result = original_status(**kwargs)
                sibling_tool.rename(displaced_tool)
                sibling_tool.mkdir(mode=0o755)
                _write_account_local_marker(sibling_tool)
                return result

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=replace_sibling_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "installed helper path or retention policy changed",
                payload["message"],
            )

    def test_current_helper_child_churn_preserves_catalog_binding(self) -> None:
        with owned_temporary_directory("cli-current-helper-churn-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_tool = releases / ("b" * 40) / RELATIVE_TOOL
            sibling_tool = releases / ("a" * 40) / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            sibling_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            _write_account_local_marker(sibling_tool)
            account_default = root / "account-default"
            original_status = cli_module.status

            def add_benign_child(**kwargs: object) -> dict[str, object]:
                result = original_status(**kwargs)
                (current_tool / "benign-child").write_text(
                    "child churn does not change directory custody\n",
                    encoding="utf-8",
                )
                return result

            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=add_benign_child,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["attempt_count"], 0)

    def test_invalid_account_local_policy_marker_fails_closed(self) -> None:
        with owned_temporary_directory("cli-invalid-policy-marker-") as root:
            releases = root / "overlays" / "private" / "releases"
            current_tool = releases / ("b" * 40) / RELATIVE_TOOL
            sibling_tool = releases / ("a" * 40) / RELATIVE_TOOL
            current_tool.mkdir(parents=True)
            sibling_tool.mkdir(parents=True)
            _write_account_local_marker(current_tool)
            marker = _write_account_local_marker(sibling_tool)
            marker.write_bytes(b"account-local-retention-v2\n")

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "installed retention policy marker is invalid",
                payload["message"],
            )

    def test_policy_marker_rejects_same_inode_same_length_mutation(self) -> None:
        with owned_temporary_directory("cli-policy-marker-mutate-") as root:
            tool = root / "tool"
            tool.mkdir(mode=0o700)
            marker = _write_account_local_marker(tool)
            original_identity = os.stat(marker)
            original_read = legacy_retention_module.read_fd_exact
            read_count = 0

            def read_then_mutate(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal read_count
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                read_count += 1
                if read_count == 1:
                    marker.write_bytes(b"account-local-retention-v2\n")
                return content

            with (
                mock.patch.object(
                    legacy_retention_module,
                    "read_fd_exact",
                    side_effect=read_then_mutate,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "marker changed while being inspected",
                ),
            ):
                _release_uses_account_local_retention(tool)

            changed_identity = os.stat(marker)
            self.assertEqual(read_count, 2)
            self.assertEqual(
                (
                    changed_identity.st_dev,
                    changed_identity.st_ino,
                    changed_identity.st_size,
                ),
                (
                    original_identity.st_dev,
                    original_identity.st_ino,
                    original_identity.st_size,
                ),
            )

    def test_policy_marker_rejects_mutation_restored_after_final_read(
        self,
    ) -> None:
        with owned_temporary_directory("cli-policy-marker-restore-") as root:
            tool = root / "tool"
            tool.mkdir(mode=0o700)
            marker = _write_account_local_marker(tool)
            expected = marker.read_bytes()
            original_read = legacy_retention_module.read_fd_exact
            read_count = 0

            def read_mutate_then_restore(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal read_count
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                read_count += 1
                if read_count == 1:
                    marker.write_bytes(b"account-local-retention-v2\n")
                elif read_count == 2:
                    marker.write_bytes(expected)
                return content

            with (
                mock.patch.object(
                    legacy_retention_module,
                    "read_fd_exact",
                    side_effect=read_mutate_then_restore,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "marker changed while being inspected",
                ),
            ):
                _release_uses_account_local_retention(tool)

            self.assertEqual(read_count, 2)
            self.assertEqual(marker.read_bytes(), expected)

    def test_policy_marker_preserves_mutation_error_when_probe_close_fails(
        self,
    ) -> None:
        with owned_temporary_directory("cli-policy-marker-cleanup-") as root:
            tool = root / "tool"
            tool.mkdir(mode=0o700)
            marker = _write_account_local_marker(tool)
            original_open = legacy_retention_module.open_regular_at
            original_read = legacy_retention_module.read_fd_exact
            original_close = os.close
            marker_fds: list[int] = []
            read_count = 0

            def tracked_open(*args: object, **kwargs: object) -> tuple[int, object]:
                result = original_open(*args, **kwargs)
                marker_fds.append(result[0])
                return result

            def read_then_mutate(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal read_count
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                read_count += 1
                if read_count == 1:
                    marker.write_bytes(b"account-local-retention-v2\n")
                return content

            def close_probe_with_error(fd: int) -> None:
                original_close(fd)
                if len(marker_fds) >= 2 and fd == marker_fds[1]:
                    raise OSError(errno.EIO, "simulated probe close failure")

            with (
                mock.patch.object(
                    legacy_retention_module,
                    "open_regular_at",
                    side_effect=tracked_open,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "read_fd_exact",
                    side_effect=read_then_mutate,
                ),
                mock.patch.object(
                    legacy_retention_module.os,
                    "close",
                    side_effect=close_probe_with_error,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "marker changed while being inspected",
                ) as raised,
            ):
                _release_uses_account_local_retention(tool)

            self.assertEqual(read_count, 2)
            self.assertIn(
                "marker path descriptor cleanup failed",
                "\n".join(raised.exception.__notes__),
            )

    def test_policy_marker_allows_benign_timestamp_change(self) -> None:
        with owned_temporary_directory("cli-policy-marker-metadata-") as root:
            tool = root / "tool"
            tool.mkdir(mode=0o700)
            marker = _write_account_local_marker(tool)
            original_read = legacy_retention_module.read_fd_exact
            read_count = 0

            def read_then_touch(
                fd: int,
                *,
                max_bytes: int,
                expected_size: int | None = None,
            ) -> bytes:
                nonlocal read_count
                content = original_read(
                    fd,
                    max_bytes=max_bytes,
                    expected_size=expected_size,
                )
                read_count += 1
                if read_count == 1:
                    metadata = os.stat(marker)
                    os.utime(
                        marker,
                        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                    )
                return content

            with mock.patch.object(
                legacy_retention_module,
                "read_fd_exact",
                side_effect=read_then_touch,
            ):
                self.assertTrue(_release_uses_account_local_retention(tool))

            self.assertEqual(read_count, 2)

    def test_legacy_migration_fence_revalidates_after_command_failure(self) -> None:
        with owned_temporary_directory("cli-legacy-failed-command-") as root:
            releases, current_tool, _, legacy_retention = _installed_upgrade_layout(
                root
            )
            _write_retention_lock(legacy_retention)
            displaced_releases = root / "displaced-releases"

            def replace_catalog_then_fail(**_: object) -> dict[str, object]:
                releases.rename(displaced_releases)
                raise RuntimeError("synthetic command failure")

            output = io.StringIO()
            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=replace_catalog_then_fail,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn("synthetic command failure", payload["message"])
            self.assertTrue(
                any(
                    "legacy retention fence finalization failed" in error
                    for error in payload["secondary_errors"]
                )
            )

    def test_legacy_migration_fence_preserves_command_os_and_value_errors(
        self,
    ) -> None:
        failures = (
            OSError("synthetic command os failure"),
            ValueError("synthetic command value failure"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                owned_temporary_directory("cli-legacy-command-error-") as root,
            ):
                _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
                _write_retention_lock(legacy_retention)
                output = io.StringIO()
                with (
                    mock.patch(
                        "review_supervisor.legacy_retention.tool_root",
                        return_value=current_tool,
                    ),
                    mock.patch.object(
                        cli_module,
                        "status",
                        side_effect=failure,
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

                self.assertEqual(exit_code, 2)
                payload = json.loads(output.getvalue())
                self.assertEqual(
                    payload["message"],
                    f"{type(failure).__name__}: {failure}",
                )
                self.assertNotIn(
                    "cannot inspect installed legacy retention safely",
                    payload["message"],
                )

    def test_legacy_fence_preserves_primary_during_finalization_failure(
        self,
    ) -> None:
        failures = (
            SupervisorError(
                "synthetic structured command failure",
                status="blocked",
                stage="recovery",
                code="synthetic-primary",
            ),
            OSError("synthetic command os failure"),
            ValueError("synthetic command value failure"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                owned_temporary_directory("cli-legacy-dual-failure-") as root,
            ):
                releases, current_tool, _, legacy_retention = _installed_upgrade_layout(
                    root
                )
                _write_retention_lock(legacy_retention)
                displaced_releases = root / "displaced-releases"

                with (
                    mock.patch(
                        "review_supervisor.legacy_retention.tool_root",
                        return_value=current_tool,
                    ),
                    self.assertRaises(type(failure)) as raised,
                ):
                    with legacy_retention_module.installed_legacy_retention_fence():
                        releases.rename(displaced_releases)
                        raise failure

                self.assertIs(raised.exception, failure)
                self.assertIn(
                    "legacy retention fence finalization failed",
                    "\n".join(raised.exception.__notes__),
                )
                payload = cli_module._failure_payload(raised.exception)
                self.assertIn(
                    "legacy retention fence finalization failed",
                    "\n".join(payload["secondary_errors"]),
                )
                if isinstance(failure, SupervisorError):
                    self.assertEqual(failure.failure.status, "blocked")
                    self.assertEqual(failure.failure.stage, "recovery")
                    self.assertEqual(failure.failure.code, "synthetic-primary")
                    self.assertEqual(
                        failure.failure.message,
                        "synthetic structured command failure",
                    )
                    failure.add_note("unrelated internal diagnostic")
                    for index in range(5):
                        legacy_retention_module._record_secondary_error(
                            failure,
                            label=f"bounded-secondary-{index}",
                            secondary_error=RuntimeError("x" * 600),
                        )
                    bounded_payload = cli_module._failure_payload(failure)
                    self.assertEqual(len(bounded_payload["secondary_errors"]), 4)
                    self.assertNotIn(
                        "unrelated internal diagnostic",
                        "\n".join(bounded_payload["secondary_errors"]),
                    )
                    self.assertTrue(
                        all(
                            len(note) <= cli_module._MAX_SECONDARY_ERROR_CHARACTERS
                            for note in bounded_payload["secondary_errors"]
                        )
                    )

    def test_legacy_fence_preserves_primary_during_cleanup_failure(self) -> None:
        with owned_temporary_directory("cli-legacy-cleanup-failure-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            failure = SupervisorError(
                "synthetic structured command failure",
                status="blocked",
                stage="recovery",
                code="synthetic-primary",
            )
            original_close = contextlib.ExitStack.close

            def close_then_fail(stack: contextlib.ExitStack) -> None:
                original_close(stack)
                raise OSError(errno.EIO, "synthetic cleanup failure")

            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    legacy_retention_module.contextlib.ExitStack,
                    "close",
                    autospec=True,
                    side_effect=close_then_fail,
                ),
                self.assertRaises(SupervisorError) as raised,
            ):
                with legacy_retention_module.installed_legacy_retention_fence():
                    raise failure

            self.assertIs(raised.exception, failure)
            self.assertEqual(failure.failure.status, "blocked")
            self.assertEqual(failure.failure.stage, "recovery")
            self.assertEqual(failure.failure.code, "synthetic-primary")
            self.assertEqual(
                failure.failure.message,
                "synthetic structured command failure",
            )
            self.assertIn(
                "legacy retention fence cleanup failed",
                "\n".join(raised.exception.__notes__),
            )
            payload = cli_module._failure_payload(raised.exception)
            self.assertEqual(payload["failure_code"], "synthetic-primary")
            self.assertIn(
                "legacy retention fence cleanup failed",
                "\n".join(payload["secondary_errors"]),
            )

    def test_legacy_retention_permitted_metadata_drift_fails_closed(self) -> None:
        with owned_temporary_directory("cli-legacy-acl-drift-") as root:
            _, current_tool, _, legacy_retention = _installed_upgrade_layout(root)
            _write_retention_lock(legacy_retention)
            account_default = root / "account-default"
            output = io.StringIO()
            original_validate = legacy_retention_module.validate_directory_policy_fd
            original_status = cli_module.status
            command_completed = False

            def change_permitted_metadata_after_command(
                fd: int,
                path: pathlib.Path,
                *,
                private: bool,
            ) -> DirectoryPolicyBinding:
                policy = original_validate(fd, path, private=private)
                if command_completed and path == legacy_retention:
                    current = policy.macos_metadata
                    provenance_present = (
                        current is not None and "com.apple.provenance" in current.xattrs
                    )
                    changed = MacOSDirectoryMetadataBinding(
                        acl_entry_count=0,
                        acl_entries=(),
                        xattrs=() if provenance_present else ("com.apple.provenance",),
                        quarantine_present=False,
                    )
                    return dataclasses.replace(
                        policy,
                        macos_metadata=changed,
                    )
                return policy

            def complete_command_then_drift(
                **kwargs: object,
            ) -> dict[str, object]:
                nonlocal command_completed
                result = original_status(**kwargs)
                command_completed = True
                return result

            with (
                mock.patch(
                    "review_supervisor.legacy_retention.tool_root",
                    return_value=current_tool,
                ),
                mock.patch.object(
                    cli_module,
                    "default_retention_root",
                    return_value=account_default,
                ),
                mock.patch.object(
                    legacy_retention_module,
                    "validate_directory_policy_fd",
                    side_effect=change_permitted_metadata_after_command,
                ),
                mock.patch.object(
                    cli_module,
                    "status",
                    side_effect=complete_command_then_drift,
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = cli_module.main(("status",), entrypoint=ENTRYPOINT)

            self.assertEqual(exit_code, 2)
            payload = json.loads(output.getvalue())
            self.assertIn(
                "legacy retention path changed while being inspected",
                payload["message"],
                payload,
            )

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
