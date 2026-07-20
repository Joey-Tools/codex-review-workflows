from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_linux,
    claude_provenance,
    common,
    providers,
    workspace as workspace_runtime,
)
from review_runtime.common import Completed, ReviewError  # noqa: E402
from review_runtime.workspace import ReviewWorkspace  # noqa: E402


CLAUDE_SAFE_MODE_DESCRIPTION = (
    "Start with all customizations (CLAUDE.md, skills, plugins, hooks, MCP "
    "servers, custom commands and agents, output styles, workflows, custom "
    "themes, keybindings, and more) disabled. Admin-managed (policy) settings "
    "still apply. Auth, model selection, built-in tools, and permissions work "
    "normally. Sets CLAUDE_CODE_SAFE_MODE=1."
)
CLAUDE_REQUIRED_OPTIONS_FIXTURE = (
    "--print",
    "--model",
    "--effort",
    "--permission-mode",
    "--output-format",
    "--no-session-persistence",
    "--safe-mode",
    "--no-chrome",
    "--disable-slash-commands",
    "--strict-mcp-config",
    "--mcp-config",
    "--setting-sources",
    "--settings",
    "--tools",
    "--allowedTools",
    "--disallowedTools",
)


def claude_help_fixture(*, safe_mode: str | None = None) -> bytes:
    safe_mode = safe_mode or CLAUDE_SAFE_MODE_DESCRIPTION
    lines = ["Usage: claude [options]", "", "Options:"]
    for option in CLAUDE_REQUIRED_OPTIONS_FIXTURE:
        if option == "--safe-mode":
            description = safe_mode
        elif option == "--permission-mode":
            description = "Permission mode (choices: default, dontAsk, plan)."
        else:
            description = "Supported option."
        lines.append(f"  {option} <value>  {description}")
    return ("\n".join(lines) + "\n").encode()


def claude_auth_status_fixture(source: str) -> bytes:
    if source == "api-key":
        payload = {
            "loggedIn": True,
            "authMethod": "api_key",
            "apiProvider": "firstParty",
            "apiKeySource": "ANTHROPIC_API_KEY",
        }
    elif source == "oauth-token":
        payload = {
            "loggedIn": True,
            "authMethod": "oauth_token",
            "apiProvider": "firstParty",
        }
    elif source == "local-login":
        payload = {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": "reviewer@example.invalid",
            "subscriptionType": "max",
        }
    else:
        raise AssertionError(f"unsupported auth fixture source: {source}")
    return json.dumps(payload).encode()


def claude_stream_fixture(
    review: ReviewWorkspace,
    *,
    model: str = "claude-opus-4-8",
    auth_source: str = "local-login",
    init_updates: dict[str, object] | None = None,
    result_updates: dict[str, object] | None = None,
) -> bytes:
    init: dict[str, object] = {
        "type": "system",
        "subtype": "init",
        "cwd": str(review.workspace_root),
        "session_id": "11111111-1111-4111-8111-111111111111",
        "tools": ["Bash", "Glob", "Grep", "Read"],
        "mcp_servers": [],
        "model": model,
        "permissionMode": "dontAsk",
        "slash_commands": [],
        "apiKeySource": ("ANTHROPIC_API_KEY" if auth_source == "api-key" else "none"),
        "claude_code_version": "2.1.212",
        "output_style": "default",
        "agents": ["claude", "Explore", "general-purpose", "Plan"],
        "skills": [],
        "plugins": [],
        "capabilities": ["interrupt_receipt_v1", "msg_lifecycle_v1"],
        "analytics_disabled": True,
        "product_feedback_disabled": False,
        "uuid": "22222222-2222-4222-8222-222222222222",
        "fast_mode_state": "off",
    }
    if init_updates:
        init.update(init_updates)
    result: dict[str, object] = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "No findings.",
        "modelUsage": {model: {}},
    }
    if result_updates:
        result.update(result_updates)
    return (json.dumps(init) + "\n" + json.dumps(result) + "\n").encode()


class ProviderPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name).resolve()
        # Security fixtures must not inherit a permissive host or CI umask.
        source_root = root / "source"
        source_root.mkdir(mode=0o700)
        subprocess.run(
            ("git", "init", "-b", "master", str(source_root)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._git(source_root, "config", "user.name", "Provider Test")
        self._git(source_root, "config", "user.email", "provider@example.com")
        self._git(source_root, "config", "commit.gpgsign", "false")
        (source_root / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
        self._git(source_root, "add", ".gitignore")
        self._git(source_root, "commit", "-m", "Base endpoint")
        base_ref = self._git(source_root, "rev-parse", "HEAD")
        (source_root / "fixture.txt").write_text("head endpoint\n", encoding="utf-8")
        self._git(source_root, "add", "fixture.txt")
        self._git(source_root, "commit", "-m", "Head endpoint")
        head_ref = self._git(source_root, "rev-parse", "HEAD")
        handed_off: list[ReviewWorkspace] = []
        self.review = workspace_runtime.prepare_workspace(
            repo=source_root,
            base_ref=base_ref,
            head_ref=head_ref,
            ownership_handoff=handed_off.append,
        )
        if handed_off != [self.review]:
            raise AssertionError("workspace ownership was not handed off exactly once")
        self.claude_pwd_home = root / "pwd-home"
        self.claude_pwd_home.mkdir(mode=0o700)
        self.claude_pwd_home_patcher = mock.patch.object(
            providers,
            "_claude_pwd_home",
            return_value=self.claude_pwd_home,
        )
        self.claude_pwd_home_patcher.start()
        self.native_macho_dependencies = providers._native_macho_dependencies
        self.native_dependency_patcher = mock.patch.object(
            providers,
            "_native_macho_dependencies",
            side_effect=lambda path, *, label: tuple(
                dict.fromkeys((path.absolute(), path.resolve()))
            ),
        )
        self.native_dependency_patcher.start()
        self.claude_macos_platform_key = providers._claude_macos_platform_key
        self.macos_platform_patcher = mock.patch.object(
            providers,
            "_claude_macos_platform_key",
            return_value="darwin-arm64",
        )
        self.macos_platform_patcher.start()
        # Generic provider-policy tests exercise the macOS lane. Dedicated Linux
        # tests opt into the Linux runtime explicitly at their narrow call site.
        self.claude_linux_platform_patcher = mock.patch.object(
            providers,
            "_is_claude_linux_host",
            return_value=False,
        )
        self.claude_macos_platform_patcher = mock.patch.object(
            providers,
            "_is_claude_macos_host",
            return_value=True,
        )
        self.claude_linux_platform_patcher.start()
        self.claude_macos_platform_patcher.start()
        self.require_trusted_claude_release = providers._require_trusted_claude_release
        self.trusted_release_patcher = mock.patch.object(
            providers,
            "_require_trusted_claude_release",
        )
        self.trusted_release = self.trusted_release_patcher.start()

    @staticmethod
    def _git(repo: pathlib.Path, *args: str) -> str:
        return (
            workspace_runtime._git(repo, *args)
            .stdout.decode("ascii", errors="strict")
            .strip()
        )

    def _review_with_scope(
        self,
        *,
        content_variant: str | None = None,
        snapshot_tree_sha: str | None = None,
    ) -> ReviewWorkspace:
        variant = content_variant or self.review.content_variant
        snapshot = snapshot_tree_sha or self.review.snapshot_tree_sha
        return replace(
            self.review,
            content_variant=variant,
            snapshot_tree_sha=snapshot,
            scope_identity=workspace_runtime._review_scope_identity(
                base_sha=self.review.base_ref,
                head_sha=self.review.head_ref,
                content_variant=variant,
                snapshot_tree_sha=snapshot,
            ),
        )

    def _refresh_control_artifact_state(self) -> None:
        control_dir = self.review.workspace_root / ".codex-review"
        state = workspace_runtime._build_control_artifact_state(
            control_dir=control_dir,
        )
        workspace_runtime._write_bounded_json(
            self.review.container_dir / workspace_runtime.CONTROL_ARTIFACT_STATE_NAME,
            state,
            label="helper-private review control state",
        )

    def tearDown(self) -> None:
        self.trusted_release_patcher.stop()
        self.claude_macos_platform_patcher.stop()
        self.claude_linux_platform_patcher.stop()
        self.macos_platform_patcher.stop()
        self.native_dependency_patcher.stop()
        self.claude_pwd_home_patcher.stop()
        review_root = self.review.container_dir.parent
        if self.review.container_dir.exists():
            workspace_runtime.cleanup_workspace(
                self.review,
                keep_container=False,
            )
        if review_root.is_dir() and not review_root.is_symlink():
            for container in review_root.glob("isolated-review-*"):
                shutil.rmtree(container)
            review_root.rmdir()
        self.temporary.cleanup()

    def attempt(
        self,
        runtime: str,
        model: str,
        category: str,
        *,
        final_text: str | None = None,
    ) -> providers.Attempt:
        effort = "xhigh" if runtime == "codex" else "max"
        return providers.Attempt(
            runtime=runtime,
            requested_model=model,
            effective_model=model if final_text else None,
            requested_effort=effort,
            effective_effort=effort if final_text else None,
            returncode=0 if final_text else 1,
            category=category,
            final_text=final_text,
            stdout_path=str(self.review.container_dir / "stdout"),
            stderr_path=str(self.review.container_dir / "stderr"),
        )

    def write_private_source(self, path: pathlib.Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o600)

    @staticmethod
    def host_ca_safety_rejection(error: ReviewError, *, source: str) -> bool:
        detail = str(error)
        return any(
            detail.startswith(prefix) and detail.removeprefix(prefix).startswith(source)
            for prefix in (
                "Claude review CA source has an unsafe owner: ",
                "Claude review CA source is group- or world-writable: ",
                "Claude review CA directory has an unsafe owner: ",
                "Claude review CA directory is group- or world-writable: ",
                "Claude review CA directory symlink has an unsafe owner: ",
            )
        )

    def test_capacity_wins_over_unavailable_wording(self) -> None:
        category = providers.classify_failure(
            "",
            "Selected model is temporarily unavailable because it is at capacity",
        )
        self.assertEqual(category, "transient")

    def test_host_ca_skip_guard_requires_expected_source_and_safety_error(
        self,
    ) -> None:
        unsafe_host_source = ReviewError(
            "Claude review CA directory is group- or world-writable: "
            "SSL_CERT_DIR:deadbeef.0"
        )
        unsafe_destination = ReviewError(
            "Claude review CA directory is group- or world-writable: "
            "private destination"
        )
        unrelated_host_failure = ReviewError(
            "Claude review CA symlink path contains a loop: SSL_CERT_DIR:deadbeef.0"
        )
        adversarial_host_failure = ReviewError(
            "Claude review CA symlink path contains a loop: "
            "SSL_CERT_DIR:unsafe owner.pem"
        )

        self.assertTrue(
            self.host_ca_safety_rejection(
                unsafe_host_source,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                unsafe_destination,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                unrelated_host_failure,
                source="SSL_CERT_DIR:",
            )
        )
        self.assertFalse(
            self.host_ca_safety_rejection(
                adversarial_host_failure,
                source="SSL_CERT_DIR:",
            )
        )

    def test_native_macho_dependencies_rejects_interpreter_wrapper(self) -> None:
        wrapper = self.review.source_root / "rg-wrapper"
        wrapper.write_text('#!/bin/sh\nexec /usr/bin/rg "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)

        with self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "native Mach-O executable",
        ):
            self.native_macho_dependencies(wrapper, label="ripgrep")

    def test_native_macho_dependencies_accepts_native_magic(self) -> None:
        executable = self.review.source_root / "native-rg"
        executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 32)
        executable.chmod(0o755)

        dependencies = self.native_macho_dependencies(executable, label="ripgrep")

        self.assertEqual(
            dependencies,
            tuple(dict.fromkeys((executable.absolute(), executable.resolve()))),
        )

    def test_claude_macho_platform_key_uses_artifact_architecture(self) -> None:
        executable = self.review.source_root / "claude"
        for cpu_type, expected in (
            (0x0100000C, "darwin-arm64"),
            (0x01000007, "darwin-x64"),
        ):
            with self.subTest(expected=expected):
                executable.write_bytes(
                    b"\xcf\xfa\xed\xfe"
                    + cpu_type.to_bytes(4, byteorder="little")
                    + b"\x00" * 24
                )
                self.assertEqual(
                    self.claude_macos_platform_key(executable),
                    expected,
                )

    def test_claude_macho_platform_key_rejects_wrapper_or_fat_binary(self) -> None:
        executable = self.review.source_root / "claude"
        executable.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 28)

        with self.assertRaisesRegex(
            providers.InvalidReviewerExecutable,
            "thin 64-bit Mach-O",
        ):
            self.claude_macos_platform_key(executable)

    def test_claude_release_provenance_maps_invalid_candidate(self) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceInvalid("bad signature"),
            ),
            self.assertRaisesRegex(
                providers.ClaudePublisherProvenanceInvalid,
                "bad signature",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.212",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_release_provenance_maps_missing_verifier_dependency(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceDependencyUnavailable(
                    "missing trusted GPG"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceVerifierUnavailable,
                "missing trusted GPG",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.212",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_release_provenance_maps_runtime_io_to_inconclusive(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "verify_claude_release",
                side_effect=providers.ClaudeProvenanceUnavailable(
                    "cannot write verifier snapshot: ENOSPC"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "ENOSPC",
            ),
        ):
            self.require_trusted_claude_release(
                pathlib.Path("/bin/claude"),
                version="2.1.212",
                platform_key="darwin-arm64",
                gpg_temp_root=self.review.container_dir,
            )

    def test_claude_safe_mode_security_failure_is_not_candidate_unavailability(
        self,
    ) -> None:
        with (
            mock.patch.object(
                providers,
                "_run_claude_probe",
                return_value=Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=claude_help_fixture(
                        safe_mode=CLAUDE_SAFE_MODE_DESCRIPTION.replace(
                            "hooks, MCP",
                            "hooks still load, MCP",
                        )
                    ),
                    stderr=b"",
                ),
            ),
            self.assertRaises(providers.ClaudeSafeModeContractInvalid),
        ):
            providers._require_claude_safe_mode(
                pathlib.Path("/bin/claude"),
                {"HOME": str(self.review.container_dir)},
            )

    def test_native_executable_inspection_race_is_inconclusive(self) -> None:
        missing = self.review.source_root / "disappeared-claude"

        with self.assertRaisesRegex(
            providers.ClaudeExecutableInspectionInconclusive,
            "cannot inspect Claude Code executable",
        ):
            self.native_macho_dependencies(missing, label="Claude Code")

    def test_model_match_is_normalized_but_not_prefix_based(self) -> None:
        self.assertTrue(providers._model_matches("claude-opus-4-8", "claude-opus-4.8"))
        self.assertFalse(providers._model_matches("gpt-5.5", "gpt-5.5-mini"))
        self.assertFalse(providers._model_matches("gpt-5.5", "gpt-5.5-codex"))

    def test_entitlement_is_fallback_eligible(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Model is not available for your account"),
            "entitlement",
        )
        self.assertEqual(
            providers.classify_failure(
                "",
                "Your account does not have access to this model",
            ),
            "entitlement",
        )

    def test_structured_model_access_code_is_fallback_eligible(self) -> None:
        stdout = json.dumps(
            {
                "type": "error",
                "error": {
                    "code": "model_access_denied",
                    "message": "request rejected",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_ambiguous_model_not_found_without_access_context_does_not_fallback(
        self,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "error",
                "error": {
                    "type": "model_not_found",
                    "message": "requested model identifier does not exist",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "other")
        self.assertEqual(
            providers.classify_failure(
                "",
                "This model is not supported with your ChatGPT account",
            ),
            "entitlement",
        )

    def test_auth_is_not_entitlement(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Authentication failed: invalid token"),
            "auth",
        )

    def test_current_claude_auth_diagnostics_are_classified_as_auth(self) -> None:
        diagnostics = (
            "Login expired",
            "Please run /login",
            "Run claude auth login to continue",
            "OAuth refresh failed",
            "Token refresh failed",
            "HTTP 401 Unauthorized",
            "status 401",
            "OAuth refresh failed after a network timeout",
            "HTTP 401 while the service is temporarily unavailable",
        )
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(
                    providers.classify_failure("", diagnostic),
                    "auth",
                )
        structured = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "message": "request failed for the selected model",
                "errors": ["Login expired · Please run /login"],
                "result": "partial review text mentioning HTTP 503",
            }
        )
        self.assertEqual(providers.classify_failure(structured, ""), "auth")

        for code in providers.STRUCTURED_AUTH_CODES:
            with self.subTest(code=code):
                coded = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "code": code,
                        "message": "model is not available for your account",
                        "result": "the service is temporarily unavailable",
                    }
                )
                self.assertEqual(providers.classify_failure(coded, ""), "auth")

    def test_auth_wins_over_entitlement_wording(self) -> None:
        self.assertEqual(
            providers.classify_failure(
                "",
                "Unauthorized: model is not available for your account",
            ),
            "auth",
        )

    def test_repository_text_in_structured_tool_output_cannot_trigger_fallback(
        self,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "aggregated_output": "not available for your account; timeout",
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, "review failed"), "other")

    def test_nested_tool_error_data_cannot_trigger_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "item.completed",
                "data": {
                    "error": {
                        "message": "Model is not available for your account; timeout"
                    }
                },
            }
        )
        self.assertEqual(providers.classify_failure(stdout, "review failed"), "other")

    def test_partial_result_is_never_failure_classification_evidence(self) -> None:
        repository_controlled_fragments = (
            "Login expired · Please run /login",
            "HTTP 401 Unauthorized",
            "authentication_error",
            "Model is not available for your account",
            "model_access_denied",
            "HTTP 429 rate limit exceeded",
            "the service is temporarily unavailable",
        )
        for fragment in repository_controlled_fragments:
            with self.subTest(fragment=fragment):
                stdout = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "message": "review failed",
                        "result": fragment,
                    }
                )
                self.assertEqual(
                    providers.classify_failure(stdout, ""),
                    "other",
                )

    def test_structured_error_event_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "turn.failed",
                "error": {"message": "Model is not available for your account"},
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_structured_api_error_event_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "api_error",
                "message": "Model is not available for your account",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_errors_field_can_trigger_entitlement_fallback(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_api_error_status_can_trigger_transient_classification(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "api_error_status": 429,
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "transient")

    def test_claude_partial_result_cannot_override_entitlement_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
                "result": "partial review text mentioning timeout",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_claude_partial_result_cannot_override_transient_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "api_error_status": 429,
                "result": "model is not available for your account",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "transient")

    def test_claude_partial_auth_cannot_override_transient_error(self) -> None:
        for status in (429, 503):
            with self.subTest(status=status):
                stdout = json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "api_error_status": status,
                        "result": "Login expired · Please run /login",
                    }
                )
                self.assertEqual(
                    providers.classify_failure(stdout, ""),
                    "transient",
                )

    def test_claude_partial_auth_cannot_override_entitlement_error(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["Model is not available for your account"],
                "result": "Authentication failed: invalid token",
            }
        )
        self.assertEqual(providers.classify_failure(stdout, ""), "entitlement")

    def test_structured_error_result_cannot_be_accepted_as_final_text(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "result": "partial findings",
                "modelUsage": {"claude-opus-4-8": {}},
            }
        ).encode()
        final_text, effective_model = providers._parse_claude_output(stdout)
        self.assertIsNone(final_text)
        self.assertEqual(effective_model, "claude-opus-4-8")

    def test_requested_model_wins_over_auxiliary_claude_model_usage(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "modelUsage": {
                    "claude-haiku-4-5-20251001": {},
                    "claude-opus-4-8": {},
                },
            }
        ).encode()
        final_text, effective_model = providers._parse_claude_output(
            stdout, requested_model="claude-opus-4-8"
        )
        self.assertEqual(final_text, "No findings.")
        self.assertEqual(effective_model, "claude-opus-4-8")

    def test_claude_rejects_malformed_model_usage_entry(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "modelUsage": {"claude-opus-4-8": None},
            }
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_success_with_nonempty_errors(self) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": "No findings.",
                "errors": [{"message": "contradictory failure"}],
                "modelUsage": {"claude-opus-4-8": {}},
            }
        ).encode()

        self.assertEqual(
            providers._parse_claude_output(stdout),
            (None, "claude-opus-4-8"),
        )

    def test_claude_rejects_unknown_or_malformed_error_payloads(self) -> None:
        for field, value in (
            ("errors", [{"exception": "failed"}]),
            ("api_error_status", {"code": 500}),
        ):
            with self.subTest(field=field):
                payload = {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                    field: value,
                }

                self.assertEqual(
                    providers._parse_claude_output(json.dumps(payload).encode()),
                    (None, "claude-opus-4-8"),
                )

    def test_nonterminal_claude_payload_cannot_supply_final_text(self) -> None:
        stdout = json.dumps(
            {
                "type": "progress",
                "data": {
                    "message": "LGTM",
                    "model": "claude-opus-4-8",
                },
            }
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_non_json_prefix_before_success_object(self) -> None:
        stdout = (
            b"warning: degraded output\n"
            + json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                }
            ).encode()
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_unicode_separator_prefix_before_success(self) -> None:
        stdout = (
            "\u2028"
            + json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "No findings.",
                    "modelUsage": {"claude-opus-4-8": {}},
                }
            )
        ).encode()

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_nonstandard_json_constant(self) -> None:
        stdout = (
            b'{"type":"result","subtype":"success","is_error":false,'
            b'"result":"No findings.","modelUsage":{"claude-opus-4-8":{}},'
            b'"metric":NaN}'
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_rejects_duplicate_json_object_key(self) -> None:
        stdout = (
            b'{"type":"result","subtype":"success","is_error":true,'
            b'"is_error":false,"result":"No findings.",'
            b'"modelUsage":{"claude-opus-4-8":{}}}'
        )

        self.assertEqual(providers._parse_claude_output(stdout), (None, None))

    def test_claude_preserves_unicode_separator_at_result_edges(self) -> None:
        result = "\u2028No findings.\u2029"
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "result": result,
                "modelUsage": {"claude-opus-4-8": {}},
            },
            ensure_ascii=False,
        ).encode()

        self.assertEqual(
            providers._parse_claude_output(stdout),
            (result, "claude-opus-4-8"),
        )

    def test_copilot_requires_terminal_message_for_the_ended_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "tool.execution_complete",
                    "data": {
                        "message": "LGTM",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_non_json_line_before_terminal_events(self) -> None:
        stdout = (
            "warning: degraded output\n"
            + "\n".join(
                json.dumps(item)
                for item in (
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                )
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_error_preserves_mismatched_effective_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, "claude-opus-4.7"),
        )

    def test_copilot_error_without_turn_is_unverifiable(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, None),
        )

    def test_copilot_error_does_not_inherit_previous_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {"type": "session.start", "data": {}},
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, None),
        )

    def test_copilot_error_rejects_malformed_model_evidence(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.message",
                    "data": {"model": 123},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, None),
        )

    def test_copilot_error_after_completed_turn_is_unverifiable(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, None),
        )

    def test_copilot_error_cannot_be_hidden_by_empty_completed_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-2"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, None),
        )

    def test_copilot_error_in_open_turn_after_completed_turn_keeps_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout, requested_model="claude-opus-4.8"),
            (None, "claude-opus-4.8"),
        )

    def test_copilot_preserves_unicode_separators_at_content_edges(self) -> None:
        content = "\u2028No findings.\u2029"
        stdout = "\n".join(
            json.dumps(item, ensure_ascii=False)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": content,
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            (content, "claude-opus-4.8"),
        )

    def test_copilot_rejects_nonstandard_json_constant(self) -> None:
        stdout = "\n".join(
            (
                '{"type":"assistant.turn_start","data":{"turnId":"turn-1"}}',
                '{"type":"assistant.message","data":{"content":"No findings.",'
                '"model":"claude-opus-4.8","metric":Infinity}}',
                '{"type":"assistant.turn_end","data":{"turnId":"turn-1"}}',
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_duplicate_json_object_key(self) -> None:
        stdout = "\n".join(
            (
                '{"type":"assistant.turn_start","data":{"turnId":"turn-1"}}',
                '{"type":"assistant.message","data":{"content":"No findings.",'
                '"model":"claude-opus-4.7","model":"claude-opus-4.8"}}',
                '{"type":"assistant.turn_end","data":{"turnId":"turn-1"}}',
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_unicode_separator_only_record(self) -> None:
        stdout = (
            "\u2028\n"
            + "\n".join(
                json.dumps(item)
                for item in (
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                )
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_nested_or_interleaved_turn_boundaries(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-a"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-a"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_unclosed_outer_turn_before_completed_inner(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-a"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-b"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-b"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_malformed_later_top_level_message(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "stale findings",
                        "model": "claude-opus-4.8",
                    },
                },
                {"type": "assistant.message", "data": None},
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_malformed_terminal_usage_event(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {"type": "assistant.usage", "data": {"model": None}},
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_accepts_only_tool_free_message_for_ended_turn(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "intermediate LGTM",
                        "toolRequests": [{"name": "view"}],
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                    },
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            ("No findings.", "claude-opus-4.8"),
        )

    def test_copilot_does_not_fall_back_past_terminal_tool_request(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "premature LGTM",
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "checking one more file",
                        "toolRequests": [{"name": "view"}],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_accepts_current_cli_model_extension(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "messageId": "message-1",
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                        "toolRequests": [],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(
            providers._parse_copilot_output(stdout),
            ("No findings.", "claude-opus-4.8"),
        )

    def test_copilot_success_does_not_inherit_previous_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {"type": "session.start", "data": {}},
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-2"},
                },
                {
                    "type": "assistant.message",
                    "data": {"content": "No findings.", "toolRequests": []},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-2"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_streams_complete_jsonl_larger_than_memory_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout_path = pathlib.Path(temporary) / "copilot.stdout.log"
            progress = json.dumps({"type": "progress", "data": {"padding": "x" * 4096}})
            with stdout_path.open("w", encoding="utf-8") as handle:
                while handle.tell() <= 4 * 1024 * 1024:
                    handle.write(progress + "\n")
                for item in (
                    {
                        "type": "session.start",
                        "data": {"selectedModel": "claude-opus-4.8"},
                    },
                    {
                        "type": "assistant.turn_start",
                        "data": {"turnId": "turn-1"},
                    },
                    {
                        "type": "assistant.message",
                        "data": {
                            "content": "No findings.",
                            "model": "claude-opus-4.8",
                        },
                    },
                    {
                        "type": "assistant.turn_end",
                        "data": {"turnId": "turn-1"},
                    },
                ):
                    handle.write(json.dumps(item) + "\n")

            result = providers._parse_copilot_output_file(stdout_path)

        self.assertEqual(result, ("No findings.", "claude-opus-4.8"))

    def test_copilot_rejects_malformed_terminal_message_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": 123,
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_session_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_usage_before_terminal_message(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_earlier_message_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "draft",
                        "model": "claude-opus-4.7",
                    },
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_conflicting_terminal_usage_model(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    def test_copilot_rejects_usage_after_turn_end(self) -> None:
        stdout = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.usage",
                    "data": {"model": "claude-opus-4.7"},
                },
            )
        ).encode()

        self.assertEqual(providers._parse_copilot_output(stdout), (None, None))

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_falls_back_from_56_to_55_only_on_entitlement(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.side_effect = (
            self.attempt("codex", "gpt-5.6-sol", "entitlement"),
            self.attempt("codex", "gpt-5.5", "success", final_text="No findings."),
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [item.requested_model for item in outcome.attempts],
            list(providers.CODEX_MODELS),
        )
        self.assertEqual(
            _environment.call_args.kwargs["passthrough_keys"],
            providers.CODEX_ENV_KEYS,
        )

    def test_prompt_projects_default_paths_to_host_absolutes(self) -> None:
        default_prompt = (
            b"- Workspace: .\n- Primary diff file: .codex-review/review.diff\n"
        )

        projected = providers._claude_review_prompt(
            self.review,
            default_prompt,
        )

        self.assertIn(str(self.review.workspace_root).encode(), projected)
        self.assertIn(str(self.review.diff_file).encode(), projected)
        self.assertNotIn(b"Linux/WSL2 runtime tool boundary", projected)

    def test_prompt_projection_rechecks_size_limit(self) -> None:
        prefix = b"- Workspace: .\n"
        prompt = prefix + b"x" * (providers.MAX_REVIEW_PROMPT_BYTES - len(prefix))
        with self.assertRaisesRegex(ReviewError, "projected review prompt exceeds"):
            providers._claude_review_prompt(
                self.review,
                prompt,
            )

    def test_model_chain_persists_each_completed_attempt(self) -> None:
        first = self.attempt("codex", "gpt-5.6-sol", "entitlement")
        runner = mock.Mock(side_effect=(first, RuntimeError("interrupted fallback")))
        attempts: list[providers.Attempt] = []
        with self.assertRaisesRegex(RuntimeError, "interrupted fallback"):
            providers._run_model_chain(
                review=self.review,
                models=providers.CODEX_MODELS,
                runner=runner,
                runtime="codex",
                requested_effort=providers.CODEX_REASONING_EFFORT,
                env={},
                attempts=attempts,
            )

        persisted = json.loads(
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["requested_model"], "gpt-5.6-sol")
        self.assertEqual(persisted[0]["category"], "entitlement")
        self.assertEqual(persisted[0]["content_variant"], self.review.content_variant)
        self.assertEqual(persisted[0]["base_ref"], self.review.base_ref)
        self.assertEqual(persisted[0]["head_ref"], self.review.head_ref)
        self.assertEqual(
            persisted[0]["snapshot_tree_sha"], self.review.snapshot_tree_sha
        )
        self.assertEqual(persisted[0]["scope_identity"], self.review.scope_identity)
        self.assertNotIn("final_text", persisted[0])
        self.assertFalse(persisted[0]["final_available"])

    def test_model_chain_does_not_persist_successful_final_text(self) -> None:
        final_text = "sensitive terminal artifact"
        runner = mock.Mock(
            return_value=self.attempt(
                "codex",
                "gpt-5.6-sol",
                "success",
                final_text=final_text,
            )
        )
        attempts: list[providers.Attempt] = []

        category, returned_text = providers._run_model_chain(
            review=self.review,
            models=("gpt-5.6-sol",),
            runner=runner,
            runtime="codex",
            requested_effort=providers.CODEX_REASONING_EFFORT,
            env={},
            attempts=attempts,
        )

        self.assertEqual(category, "success")
        self.assertEqual(returned_text, final_text)
        persisted = json.loads(
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("final_text", persisted[0])
        self.assertTrue(persisted[0]["final_available"])
        self.assertNotIn(
            final_text,
            (self.review.container_dir / "attempts.json").read_text(encoding="utf-8"),
        )

    def test_finish_preserves_unicode_separator_at_result_edges(self) -> None:
        final_text = "\u2028No findings.\u2029"

        outcome = providers._finish(self.review, [], final_text)

        self.assertEqual(outcome.final_text, final_text)
        self.assertEqual(
            (self.review.container_dir / "final.txt").read_text(encoding="utf-8"),
            final_text + "\n",
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_capacity_does_not_downgrade(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.return_value = self.attempt("codex", "gpt-5.6-sol", "transient")
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(codex_attempt.call_count, 1)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_codex_attempt",
        side_effect=providers.ReviewTimeoutError("review timed out"),
    )
    def test_codex_attempt_timeout_is_inconclusive(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(review=self.review, reviewer="codex")

        self.assertEqual(outcome.returncode, 75)
        codex_attempt.assert_called_once()
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.attempts[0].runtime, "codex")
        self.assertEqual(outcome.attempts[0].requested_model, "gpt-5.6-sol")
        self.assertEqual(outcome.attempts[0].category, "inconclusive")
        self.assertTrue(pathlib.Path(outcome.attempts[0].stderr_path).is_file())
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_family_order_is_opus_4_8_then_4_7_on_both_runtimes(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = tuple(
            self.attempt("claude", model, "entitlement")
            for model in providers.CLAUDE_MODELS
        )
        copilot_attempt.side_effect = tuple(
            self.attempt("copilot", model, "entitlement")
            for model in providers.COPILOT_MODELS[:-1]
        ) + (
            self.attempt(
                "copilot",
                providers.COPILOT_MODELS[-1],
                "success",
                final_text="No findings.",
            ),
        )
        review = self._review_with_scope(content_variant="source-wip")
        outcome = providers.run_review(
            review=review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [(item.runtime, item.requested_model) for item in outcome.attempts],
            [
                ("claude", "claude-opus-4-8"),
                ("claude", "claude-opus-4-7"),
                ("copilot", "claude-opus-4.8"),
                ("copilot", "claude-opus-4.7"),
            ],
        )
        self.assertEqual(
            [call.kwargs["passthrough_keys"] for call in _environment.call_args_list],
            [providers.CLAUDE_ENV_KEYS, providers.COPILOT_ENV_KEYS],
        )
        egress = json.loads(
            (self.review.container_dir / "egress.json").read_text(encoding="utf-8")
        )
        self.assertEqual(egress["content_variant"], "source-wip")
        self.assertEqual(egress["snapshot_tree_sha"], review.snapshot_tree_sha)
        self.assertEqual(egress["scope_identity"], review.scope_identity)
        self.assertIn("digest-bound source WIP snapshot", egress["included"][0])
        self.assertIn("endpoint commit metadata", egress["included"][1])
        self.assertIn("WIP snapshot tree/blob closure", egress["included"][2])
        self.assertIn(
            "intermediate commit history and history-only tree/blob objects",
            egress["excluded"],
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={
            "HOME": "/Users/reviewer",
            "XDG_CONFIG_HOME": "/outside/real-home/config",
        },
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_local_login_is_default_without_api_key(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        claude_attempt.assert_called_once()
        self.assertEqual(
            claude_attempt.call_args.kwargs["env"]["HOME"],
            str(self.claude_pwd_home),
        )
        for key in ("TMPDIR", "TMP", "TEMP", "CLAUDE_CODE_TMPDIR"):
            self.assertEqual(
                claude_attempt.call_args.kwargs["env"][key],
                str(self.review.container_dir / "tmp"),
            )
        self.assertNotIn(
            "ANTHROPIC_API_KEY",
            claude_attempt.call_args.kwargs["env"],
        )
        self.assertNotIn("XDG_CONFIG_HOME", claude_attempt.call_args.kwargs["env"])
        copilot_attempt.assert_not_called()

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        return_value=(None, {}),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(
        providers,
        "_copilot_attempt",
        side_effect=providers.ReviewOutputLimitError("review output exceeded limit"),
    )
    def test_copilot_attempt_output_limit_is_inconclusive(
        self,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_called_once()
        self.assertEqual(len(outcome.attempts), 1)
        self.assertEqual(outcome.attempts[0].runtime, "copilot")
        self.assertEqual(
            outcome.attempts[0].requested_model,
            providers.COPILOT_MODELS[0],
        )
        self.assertEqual(outcome.attempts[0].category, "inconclusive")
        self.assertTrue(pathlib.Path(outcome.attempts[0].stderr_path).is_file())
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_capacity_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude", providers.CLAUDE_MODELS[0], "transient"
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers, "resolve_reviewer_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_model_mismatch_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            "claude-opus-4-8",
            "model-mismatch",
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=ReviewError("Claude Code --version timed out"),
    )
    def test_claude_cli_validation_failure_refuses_copilot_fallback(
        self,
        _resolve: mock.Mock,
        copilot_attempt: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=providers.ClaudeExecutableInspectionInconclusive(
            "Claude executable disappeared during inspection"
        ),
    )
    def test_claude_inspection_race_refuses_copilot_fallback(
        self,
        _resolve: mock.Mock,
        copilot_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_disappearance_is_inconclusive_not_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = FileNotFoundError("claude disappeared")
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProbeSandboxUnavailable("sandbox unavailable"),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_missing_claude_probe_sandbox_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "secure runtime is unavailable",
            (self.review.container_dir / "claude-skip.txt").read_text(encoding="utf-8"),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProbeSandboxUnavailable("sandbox unavailable"),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_missing_probe_sandbox_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "Explicit CODEX_REVIEW_CLAUDE_PATH",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableUnavailable(
            "explicit executable is unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_unavailable_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.dict(
        os.environ,
        {"CODEX_REVIEW_CLAUDE_PATH": "/explicit/claude"},
    )
    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProvenanceVerifierUnavailable(
            "trusted GPG unavailable"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_explicit_claude_missing_gpg_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "trusted GPG unavailable",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeProvenanceVerifierUnavailable(
            "trusted GPG unavailable"
        ),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_claude_missing_gpg_allows_authorized_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableInspectionInconclusive(
            "GPG snapshot write failed: ENOSPC"
        ),
    )
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_claude_provenance_io_blocks_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        resolve.assert_not_called()
        self.assertIn(
            "ENOSPC",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "_resolve_validated_claude_executable",
        side_effect=providers.ClaudeExecutableUnavailable("only wrapper found"),
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    def test_automatic_non_native_claude_allows_authorized_copilot_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _resolve_claude: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        copilot_attempt.return_value = self.attempt(
            "copilot",
            providers.COPILOT_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 0)
        copilot_attempt.assert_called_once()
        resolve.assert_called_once_with("copilot")
        self.assertIn(
            "only wrapper found",
            (self.review.container_dir / "claude-skip.txt").read_text(encoding="utf-8"),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_partial_result_cannot_authorize_model_or_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "message": "review failed",
                "result": (
                    "Repository text: authentication_error; model is not "
                    "available for your account"
                ),
            }
        )
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            providers.classify_failure(stdout, ""),
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 1)
        claude_attempt.assert_called_once()
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(outcome.attempts[0].category, "other")

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_auth_result_blocks_authorized_copilot_fallback(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        diagnostics = tuple(
            ("", diagnostic)
            for diagnostic in (
                "Login expired",
                "Please run /login",
                "Run claude auth login to continue",
                "OAuth refresh failed",
                "Token refresh failed",
                "HTTP 401 Unauthorized",
                "OAuth refresh failed after a network timeout",
                "HTTP 401 while the service is temporarily unavailable",
            )
        ) + (
            (
                json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "message": "request failed for the selected model",
                        "errors": ["Login expired · Please run /login"],
                        "result": "partial review text mentioning HTTP 503",
                    }
                ),
                "",
            ),
            (
                json.dumps(
                    {
                        "type": "result",
                        "subtype": "error_during_execution",
                        "is_error": True,
                        "code": "authentication_error",
                        "message": "model is not available for your account",
                        "result": "the service is temporarily unavailable",
                    }
                ),
                "",
            ),
        )
        for stdout, stderr in diagnostics:
            with self.subTest(stdout=stdout, stderr=stderr):
                claude_attempt.reset_mock()
                copilot_attempt.reset_mock()
                resolve.reset_mock()
                claude_attempt.return_value = self.attempt(
                    "claude",
                    providers.CLAUDE_MODELS[0],
                    providers.classify_failure(stdout, stderr),
                )
                outcome = providers.run_review(
                    review=self.review,
                    reviewer="claude",
                    egress_consent="double-review",
                )

                self.assertEqual(outcome.returncode, 2)
                claude_attempt.assert_called_once()
                copilot_attempt.assert_not_called()
                self.assertEqual(resolve.call_count, 1)
                self.assertEqual(
                    outcome.attempts[0].category,
                    "blocked-authentication",
                )
                self.assertIn(
                    "claude auth login",
                    (self.review.container_dir / "runner-error.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "fixture-api-key"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_api_key_auth_failure_blocks_with_api_key_action(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            providers.classify_failure("", "HTTP 401 invalid API key"),
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertEqual(resolve.call_count, 1)
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("Unset or replace `ANTHROPIC_API_KEY`", error)
        self.assertNotIn("claude auth login", error)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_invalid_explicit_claude_override_blocks_without_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        def reject_override(_name: str, **kwargs):
            self.assertTrue(callable(kwargs["candidate_validator"]))
            raise ReviewError("invalid explicit override")

        resolve.side_effect = reject_override

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_timeout_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewTimeoutError("probe timed out")

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_output_limit_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewOutputLimitError(
            "probe output exceeded limit"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_drain_failure_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewOutputDrainError(
            "probe output drain failed"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "resolve_reviewer_executable")
    @mock.patch.object(providers, "_copilot_attempt")
    def test_claude_probe_process_leak_is_inconclusive_not_fallback(
        self,
        copilot_attempt: mock.Mock,
        resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        resolve.side_effect = providers.ReviewProcessLeakError(
            "probe left descendant process"
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 75)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "inconclusive",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers,
        "child_environment",
        return_value={"ANTHROPIC_API_KEY": "secret"},
    )
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/true"),
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_attempt_validation_failure_still_blocks_copilot(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = ReviewError("unsafe executable identity")

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="triple-review",
        )

        self.assertEqual(outcome.returncode, 2)
        copilot_attempt.assert_not_called()
        self.assertIn(
            "refusing Copilot fallback",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=None,
    )
    def test_explicit_claude_consent_does_not_authorize_copilot_fallback(
        self,
        resolve: mock.Mock,
        copilot_attempt: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="explicit-claude-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_called_once()
        self.assertEqual(resolve.call_args.args, ("claude",))
        self.assertTrue(callable(resolve.call_args.kwargs["candidate_validator"]))
        copilot_attempt.assert_not_called()
        self.assertIn(
            "does not authorize GitHub Copilot",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_effective_model_substitution_does_not_infer_entitlement(self) -> None:
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=json.dumps(
                {"result": "No findings.", "modelUsage": {"claude-opus-4-7": {}}}
            ).encode(),
            stderr=b"",
        )

        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="claude",
            model="claude-opus-4-8",
            completed=completed,
            final_text="No findings.",
            effective_model="claude-opus-4-7",
            requested_effort="max",
            effective_effort=None,
        )
        self.assertEqual(attempt.category, "model-mismatch")
        self.assertIsNone(attempt.final_text)

    def test_failed_attempt_metadata_mismatch_blocks_fallback(self) -> None:
        completed = Completed(
            argv=("codex",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                }
            ).encode(),
            stderr=b"",
        )
        cases = (
            (1, "gpt-5.5", "xhigh", "model-mismatch"),
            (2, "gpt-5.6-sol", "high", "effort-mismatch"),
        )
        for index, effective_model, effective_effort, expected_category in cases:
            with self.subTest(expected_category=expected_category):
                attempt = providers._record_attempt(
                    review=self.review,
                    index=index,
                    runtime="codex",
                    model="gpt-5.6-sol",
                    completed=completed,
                    final_text=None,
                    effective_model=effective_model,
                    requested_effort="xhigh",
                    effective_effort=effective_effort,
                )
                self.assertEqual(attempt.category, expected_category)
                self.assertIsNone(attempt.final_text)

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/codex"),
    )
    @mock.patch.object(providers, "_codex_session_metadata")
    @mock.patch.object(providers, "run")
    def test_failed_codex_permission_mismatch_blocks_fallback(
        self,
        run_command: mock.Mock,
        session_metadata: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("codex",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                }
            ).encode(),
            stderr=b"",
        )
        session_metadata.return_value = ("gpt-5.6-sol", "xhigh", False)

        attempt = providers._codex_attempt(
            review=self.review,
            model="gpt-5.6-sol",
            index=1,
            env={},
        )

        self.assertEqual(attempt.category, "permission-mismatch")
        self.assertIsNone(attempt.final_text)

    def test_success_without_verified_runtime_metadata_is_not_accepted(self) -> None:
        completed = Completed(
            argv=("codex",),
            returncode=0,
            stdout=b'{"type":"thread.started","thread_id":"missing"}\n',
            stderr=b"",
        )
        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="codex",
            model="gpt-5.6-sol",
            completed=completed,
            final_text="No findings.",
            effective_model=None,
            requested_effort="xhigh",
            effective_effort=None,
            require_verified_model=True,
            require_verified_effort=True,
        )
        self.assertEqual(attempt.category, "runtime-unverified")
        self.assertIsNone(attempt.final_text)

    def test_entitlement_without_verified_model_cannot_authorize_fallback(
        self,
    ) -> None:
        completed = Completed(
            argv=("copilot",),
            returncode=1,
            stdout=json.dumps(
                {
                    "type": "turn.failed",
                    "error": {"message": "Model is not available for your account"},
                }
            ).encode(),
            stderr=b"",
        )
        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="copilot",
            model="claude-opus-4.8",
            completed=completed,
            final_text=None,
            effective_model=None,
            requested_effort="max",
            effective_effort=None,
            require_verified_model=True,
        )

        self.assertEqual(attempt.category, "runtime-unverified")
        self.assertIsNone(attempt.final_text)

    @mock.patch.object(providers, "child_environment", return_value={})
    def test_claude_lane_requires_explicit_egress_consent(
        self,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
        )
        self.assertEqual(outcome.returncode, 2)
        self.assertIn(
            "explicit egress-consent",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_sensitive_content_blocks_external_reviewer_before_launch(
        self,
        resolve: mock.Mock,
    ) -> None:
        secret = "AKIA" + "A" * 16
        (self.review.source_root / "secret.txt").write_text(
            secret + "\n",
            encoding="utf-8",
        )
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])
        outcome = providers.run_review(
            review=review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        self.assertFalse((review.container_dir / "egress.json").exists())
        self.assertFalse((review.container_dir / "preflight.json").exists())
        error = (review.container_dir / "runner-error.txt").read_text(encoding="utf-8")
        self.assertIn("sensitive content preflight", error)
        self.assertNotIn(secret, error)

    @mock.patch.object(providers, "_codex_attempt")
    def test_sensitive_content_blocks_codex_before_launch(
        self,
        codex_attempt: mock.Mock,
    ) -> None:
        secret = "AKIA" + "B" * 16
        self.review.diff_file.write_text(
            "diff --git a/config b/config\n-AWS_KEY=" + secret + "\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
        )
        self.assertEqual(outcome.returncode, 2)
        codex_attempt.assert_not_called()
        self.assertFalse((self.review.container_dir / "preflight.json").exists())
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("sensitive content preflight", error)
        self.assertNotIn(secret, error)

    @mock.patch.object(providers, "_review_environment", return_value={})
    @mock.patch.object(providers, "_run_model_chain")
    def test_codex_preflight_evidence_precedes_model_launch(
        self,
        run_model_chain: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        review = self.review

        def inspect_preflight(**_kwargs):
            evidence = json.loads(
                (self.review.container_dir / "preflight.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                evidence["review_range"],
                f"{self.review.base_ref}..{self.review.head_ref}",
            )
            self.assertEqual(evidence["content_variant"], "head")
            self.assertEqual(evidence["snapshot_tree_sha"], review.snapshot_tree_sha)
            self.assertEqual(evidence["scope_identity"], review.scope_identity)
            self.assertEqual(
                evidence["scope"],
                "detached clean head worktree, scanned endpoint Git objects, "
                "diff, and review prompt",
            )
            diff_bytes = self.review.diff_file.read_bytes()
            self.assertEqual(
                evidence["primary_diff"],
                {
                    "path": ".codex-review/review.diff",
                    "sha256": hashlib.sha256(diff_bytes).hexdigest(),
                    "size": len(diff_bytes),
                },
            )
            return "success", "No findings."

        run_model_chain.side_effect = inspect_preflight

        outcome = providers.run_review(
            review=review,
            reviewer="codex",
        )

        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.final_text, "No findings.")

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_deleted_generic_token_in_diff_blocks_external_reviewer(
        self,
        resolve: mock.Mock,
    ) -> None:
        token = "z9Y8x7W6v5U4t3S2r1Q0p9O8n7M6"
        self.review.diff_file.write_text(
            "diff --git a/config b/config\n-AUTH_TOKEN=" + token + "\n",
            encoding="utf-8",
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("review.diff (generic-secret-assignment)", error)
        self.assertNotIn(token, error)

    @mock.patch.object(providers, "resolve_reviewer_executable")
    def test_deleted_sensitive_path_blocks_external_reviewer(
        self,
        resolve: mock.Mock,
    ) -> None:
        (self.review.workspace_root / ".codex-review/changed-paths.z").write_bytes(
            b"config/.env.production\0"
        )
        self._refresh_control_artifact_state()
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 2)
        resolve.assert_not_called()
        error = (self.review.container_dir / "runner-error.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(".env.production (environment-file; changed-path)", error)

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/codex"),
    )
    @mock.patch.object(providers, "run")
    def test_codex_command_pins_model_and_reasoning(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        thread_id = "019f18a6-ed56-7ff3-af51-08703a6d225a"
        codex_home = pathlib.Path(self.temporary.name) / "codex-home"
        rollout = (
            codex_home
            / "sessions/2026/06/30"
            / f"rollout-2026-06-30T21-10-20-{thread_id}.jsonl"
        )
        rollout.parent.mkdir(parents=True)
        rollout.write_text(
            json.dumps(
                {
                    "type": "turn_context",
                    "payload": {
                        "model": "gpt-5.6-sol",
                        "effort": "xhigh",
                        "approval_policy": "never",
                        "sandbox_policy": {"type": "read-only"},
                        "permission_profile": {
                            "type": "managed",
                            "network": "restricted",
                            "file_system": {
                                "type": "restricted",
                                "glob_scan_max_depth": 8,
                                "entries": [
                                    {
                                        "path": {
                                            "type": "special",
                                            "value": {"kind": "minimal"},
                                        },
                                        "access": "read",
                                    },
                                    {
                                        "path": {
                                            "type": "path",
                                            "path": str(
                                                self.review.workspace_root.resolve()
                                            ),
                                        },
                                        "access": "read",
                                    },
                                    *[
                                        {
                                            "path": {
                                                "type": "path",
                                                "path": str(
                                                    (
                                                        self.review.workspace_root
                                                        / name
                                                    ).resolve()
                                                ),
                                            },
                                            "access": "deny",
                                        }
                                        for name in (".git", ".codex", ".agents")
                                    ],
                                    *[
                                        {
                                            "path": {
                                                "type": "glob_pattern",
                                                "pattern": str(
                                                    self.review.workspace_root.resolve()
                                                    / pattern
                                                ),
                                            },
                                            "access": "deny",
                                        }
                                        for pattern in ("*.env", "**/*.env")
                                    ],
                                ],
                            },
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        def complete(argv, **_kwargs):
            argv = tuple(argv)
            final_path = pathlib.Path(argv[argv.index("-o") + 1])
            final_path.parent.mkdir(parents=True, exist_ok=True)
            final_path.write_text("No findings.\n", encoding="utf-8")
            stdout = json.dumps(
                {"type": "thread.started", "thread_id": thread_id}
            ).encode()
            return Completed(argv=argv, returncode=0, stdout=stdout, stderr=b"")

        run_command.side_effect = complete
        attempt = providers._codex_attempt(
            review=self.review,
            model="gpt-5.6-sol",
            index=1,
            env={
                "CODEX_HOME": str(codex_home),
                "OPENAI_API_KEY": "parent-only-secret",
            },
        )
        argv = run_command.call_args.args[0]
        self.assertIn("gpt-5.6-sol", argv)
        self.assertIn('model_reasoning_effort="xhigh"', argv)
        configs = [argv[index + 1] for index, value in enumerate(argv) if value == "-c"]
        self.assertIn('approval_policy="never"', configs)
        self.assertIn('default_permissions="isolated_review"', configs)
        permission_configs = [
            value
            for value in configs
            if value.startswith("permissions.isolated_review=")
        ]
        self.assertEqual(len(permission_configs), 1)
        permission_config = permission_configs[0]
        parsed_permissions = tomllib.loads(
            f"profile = {permission_config.partition('=')[2]}"
        )["profile"]
        self.assertEqual(
            set(parsed_permissions["filesystem"]),
            {"glob_scan_max_depth", ":minimal", ":workspace_roots"},
        )
        self.assertIn('"glob_scan_max_depth"=8', permission_config)
        self.assertIn('":minimal"="read"', permission_config)
        self.assertIn('":workspace_roots"={"."="read"', permission_config)
        self.assertIn('".git"="deny"', permission_config)
        self.assertTrue(
            any("shell_environment_policy.inherit" in value for value in configs)
        )
        self.assertTrue(
            any("shell_environment_policy.set" in value for value in configs)
        )
        self.assertIn("project_doc_max_bytes=0", configs)
        self.assertNotIn("parent-only-secret", "\n".join(configs))
        self.assertIn("--skip-git-repo-check", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("--strict-config", argv)
        self.assertNotIn("-s", argv)
        final_path = pathlib.Path(argv[argv.index("-o") + 1])
        self.assertTrue(final_path.parent.is_dir())
        self.assertEqual(attempt.effective_model, "gpt-5.6-sol")
        self.assertEqual(attempt.effective_effort, "xhigh")
        self.assertEqual(attempt.category, "success")
        self.assertEqual(
            run_command.call_args.kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args.kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        )

    def test_codex_rejects_legacy_sandbox_override(self) -> None:
        payload = {
            "approval_policy": "never",
            "sandbox_policy": {"type": "workspace-write"},
            "permission_profile": {
                "type": "managed",
                "network": "restricted",
                "file_system": {"type": "restricted", "entries": []},
            },
        }
        self.assertFalse(
            providers._codex_permissions_match(
                payload,
                review_root=self.review.workspace_root,
            )
        )

    def test_codex_rejects_extra_permission_profile_read_path(self) -> None:
        root = self.review.workspace_root.resolve()
        payload = {
            "approval_policy": "never",
            "sandbox_policy": {"type": "read-only"},
            "permission_profile": {
                "type": "managed",
                "network": "restricted",
                "file_system": {
                    "type": "restricted",
                    "glob_scan_max_depth": 8,
                    "entries": [
                        {
                            "path": {
                                "type": "special",
                                "value": {"kind": "minimal"},
                            },
                            "access": "read",
                        },
                        {"path": {"type": "path", "path": str(root)}, "access": "read"},
                        *[
                            {
                                "path": {
                                    "type": "path",
                                    "path": str((root / name).resolve()),
                                },
                                "access": "deny",
                            }
                            for name in (".git", ".codex", ".agents")
                        ],
                        *[
                            {
                                "path": {
                                    "type": "glob_pattern",
                                    "pattern": str(root / pattern),
                                },
                                "access": "deny",
                            }
                            for pattern in ("*.env", "**/*.env")
                        ],
                        {
                            "path": {"type": "path", "path": str(root.parent)},
                            "access": "read",
                        },
                    ],
                },
            },
        }
        self.assertFalse(
            providers._codex_permissions_match(
                payload,
                review_root=self.review.workspace_root,
            )
        )

    def test_codex_allows_only_one_direct_arg_transport_file(self) -> None:
        root = self.review.workspace_root.resolve()
        codex_home = pathlib.Path(self.temporary.name) / "codex-home"
        arg_root = codex_home.resolve() / "tmp/arg0"

        def payload(extra_entries):
            return {
                "approval_policy": "never",
                "sandbox_policy": {"type": "read-only"},
                "permission_profile": {
                    "type": "managed",
                    "network": "restricted",
                    "file_system": {
                        "type": "restricted",
                        "glob_scan_max_depth": 8,
                        "entries": [
                            {
                                "path": {
                                    "type": "special",
                                    "value": {"kind": "minimal"},
                                },
                                "access": "read",
                            },
                            {
                                "path": {"type": "path", "path": str(root)},
                                "access": "read",
                            },
                            *[
                                {
                                    "path": {
                                        "type": "path",
                                        "path": str((root / name).resolve()),
                                    },
                                    "access": "deny",
                                }
                                for name in (".git", ".codex", ".agents")
                            ],
                            *[
                                {
                                    "path": {
                                        "type": "glob_pattern",
                                        "pattern": str(root / pattern),
                                    },
                                    "access": "deny",
                                }
                                for pattern in ("*.env", "**/*.env")
                            ],
                            *extra_entries,
                        ],
                    },
                },
            }

        def read_entry(path: pathlib.Path):
            return {
                "path": {"type": "path", "path": str(path)},
                "access": "read",
            }

        direct = read_entry(arg_root / "codex-arg0AbE73u")
        nested = read_entry(arg_root / "private/codex-arg0AbE73u")
        second = read_entry(arg_root / "codex-arg0Second")
        self.assertTrue(
            providers._codex_permissions_match(
                payload([direct]),
                review_root=root,
                codex_home=codex_home,
            )
        )
        for extras in ([nested], [direct, second]):
            with self.subTest(extras=extras):
                self.assertFalse(
                    providers._codex_permissions_match(
                        payload(extras),
                        review_root=root,
                        codex_home=codex_home,
                    )
                )

    @mock.patch.object(
        providers,
        "_native_macho_dependencies",
        return_value=(
            pathlib.Path("/review-install/claude"),
            pathlib.Path("/review-real/claude"),
        ),
    )
    def test_claude_probe_profile_only_reads_runtime_and_probe_roots(
        self,
        _dependencies: mock.Mock,
    ) -> None:
        profile = providers._claude_probe_sandbox_profile(
            pathlib.Path("/review-install/claude"),
            pathlib.Path("/isolated/probe-home"),
        )

        self.assertIn("(deny default)", profile)
        self.assertNotIn("(allow default)", profile)
        self.assertIn('(literal "/review-install/claude")', profile)
        self.assertIn('(literal "/review-real/claude")', profile)
        self.assertIn('(subpath "/isolated/probe-home")', profile)
        self.assertIn('(subpath "/review-install")', profile)
        self.assertIn('(subpath "/review-real")', profile)
        self.assertNotIn("(allow file-read-metadata)", profile)
        self.assertIn(
            '(allow file-read-metadata (literal "/")',
            profile,
        )
        self.assertNotIn("/Users/joey", profile)

    def test_claude_probe_profile_rejects_overly_broad_dependency_roots(
        self,
    ) -> None:
        for dependency in (
            pathlib.Path("/Users/joey/claude"),
            pathlib.Path("/claude"),
        ):
            with (
                self.subTest(dependency=dependency),
                mock.patch.object(
                    providers,
                    "_native_macho_dependencies",
                    return_value=(dependency,),
                ),
                mock.patch.dict(providers.os.environ, {"HOME": "/Users/joey"}),
            ):
                with self.assertRaisesRegex(
                    providers.InvalidReviewerExecutable, "overly broad"
                ):
                    providers._claude_probe_sandbox_profile(
                        dependency,
                        pathlib.Path("/isolated/probe-home"),
                    )

    @mock.patch.object(providers, "_run_claude_probe")
    def test_claude_identity_accepts_semantics_verified_version(
        self,
        run_probe: mock.Mock,
    ) -> None:
        run_probe.return_value = Completed(
            argv=("claude", "--version"),
            returncode=0,
            stdout=b"2.1.212 (Claude Code)\n",
            stderr=b"",
        )

        version = providers._require_claude_identity(
            pathlib.Path("/bin/claude"),
            {"HOME": "/isolated/probe-home"},
        )

        self.assertEqual(version.text, "2.1.212")

    @mock.patch.object(providers, "_run_claude_probe")
    def test_claude_identity_rejects_every_other_stable_version(
        self,
        run_probe: mock.Mock,
    ) -> None:
        for output in (
            b"2.1.211 (Claude Code)\n",
            b"2.1.213 (Claude Code)\n",
            b"2.99.999 (Claude Code)\n",
            b"3.0.0 (Claude Code)\n",
        ):
            with self.subTest(output=output):
                run_probe.return_value = Completed(
                    argv=("claude", "--version"),
                    returncode=0,
                    stdout=output,
                    stderr=b"",
                )
                with self.assertRaisesRegex(
                    providers.InvalidReviewerExecutable,
                    "review semantics are verified only for 2.1.212",
                ):
                    providers._require_claude_identity(
                        pathlib.Path("/bin/claude"),
                        {"HOME": "/isolated/probe-home"},
                    )

    def test_real_resolver_types_rejected_automatic_claude_candidate(
        self,
    ) -> None:
        wrapper = self.review.source_root / "claude"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)

        def reject_candidate(_candidate: pathlib.Path) -> None:
            raise providers.InvalidReviewerExecutable("not native")

        with (
            mock.patch.object(
                common,
                "_user_executable_candidates",
                return_value=(wrapper,),
            ),
            mock.patch.object(common.shutil, "which", return_value=None),
            mock.patch.object(
                common.pathlib.Path,
                "is_file",
                autospec=True,
                side_effect=lambda path: path == wrapper,
            ),
            mock.patch.object(
                common.os,
                "access",
                side_effect=lambda path, _mode: pathlib.Path(path) == wrapper,
            ),
            mock.patch.dict(common.os.environ, {}, clear=True),
            self.assertRaises(common.RejectedReviewerCandidates),
        ):
            common.resolve_reviewer_executable(
                "claude",
                candidate_validator=reject_candidate,
            )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        side_effect=common.RejectedReviewerCandidates("only wrapper found"),
    )
    def test_claude_resolver_maps_automatic_rejection_to_unavailable(
        self,
        _resolve: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            providers.ClaudeExecutableUnavailable,
            "only wrapper found",
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={"HOME": str(self.review.container_dir / "home")},
            )

    def test_claude_linux_probe_uses_bounded_host_probe_backend(self) -> None:
        host = mock.Mock()
        executable = pathlib.Path("/opt/claude")
        info = mock.Mock(path=executable)
        toolchain = mock.Mock()
        library_roots = (pathlib.Path("/lib"), pathlib.Path("/usr/lib"))
        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                return_value=info,
            ),
            mock.patch.object(
                providers,
                "discover_claude_linux_toolchain",
                return_value=toolchain,
            ),
            mock.patch.object(
                providers,
                "_claude_linux_bootstrap_library_roots",
                return_value=library_roots,
            ),
            mock.patch.object(
                providers,
                "build_claude_linux_probe_command",
                return_value=("/usr/bin/bwrap", "--probe"),
            ) as build_probe,
        ):
            command = providers._claude_probe_command(
                executable,
                self.review.container_dir,
                "--version",
            )

        self.assertEqual(command, ("/usr/bin/bwrap", "--probe"))
        build_probe.assert_called_once_with(
            host,
            toolchain,
            executable,
            self.review.container_dir,
            ("--version",),
            library_roots=library_roots,
        )

    def test_claude_wsl2_rejects_source_or_container_on_windows_drive(self) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        cases = (
            (
                "source",
                pathlib.Path("/mnt/c/review-source"),
                pathlib.Path("/home/reviewer/review-container"),
            ),
            (
                "container",
                pathlib.Path("/home/reviewer/review-source"),
                pathlib.Path("/mnt/c/review-container"),
            ),
        )

        for label, source_root, container_dir in cases:
            workspace_root = container_dir / "workspace"
            review = ReviewWorkspace(
                source_root=source_root,
                container_dir=container_dir,
                workspace_root=workspace_root,
                base_ref="a" * 40,
                head_ref="b" * 40,
                diff_file=workspace_root / ".codex-review" / "review.diff",
                prompt_file=workspace_root / ".codex-review" / "review.prompt",
            )
            with (
                self.subTest(path=label),
                mock.patch.object(
                    providers,
                    "_is_claude_linux_host",
                    return_value=True,
                ),
                mock.patch.object(
                    providers,
                    "_claude_linux_host",
                    return_value=host,
                ),
                self.assertRaisesRegex(
                    providers.LinuxRuntimeUnsafe,
                    "Windows drive",
                ),
            ):
                providers._resolve_validated_claude_executable(
                    review=review,
                    env={},
                )

    def test_claude_wsl2_review_state_mountinfo_failure_is_inconclusive(
        self,
    ) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        failure = providers.LinuxRuntimeInspectionInconclusive(
            "cannot read WSL2 mountinfo"
        )

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "reject_claude_wsl_windows_paths",
                side_effect=failure,
            ) as reject_windows_paths,
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        reject_windows_paths.assert_called_once_with(
            (self.review.source_root, self.review.container_dir),
            host,
        )
        self.assertFalse((self.review.container_dir / "claude-home").exists())

    def test_claude_gpg_temp_root_does_not_repair_existing_mode(self) -> None:
        temp_root = self.review.container_dir / "claude-runtime" / "gpg-tmp"
        temp_root.mkdir(parents=True, mode=0o700)
        temp_root.chmod(0o755)

        with self.assertRaisesRegex(ReviewError, "must be 0700"):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        self.assertEqual(stat.S_IMODE(temp_root.stat().st_mode), 0o755)

    def test_claude_wsl2_rejects_drvfs_gpg_temp_root_as_invalid(self) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        validator = providers._claude_gpg_temp_root_validator(host)
        mountinfo = "24 1 0:22 / / rw,relatime - 9p drvfs rw,aname=drvfs"

        with (
            mock.patch.object(
                claude_linux,
                "_read_mountinfo",
                return_value=mountinfo,
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceInvalid,
                "Linux-native filesystem",
            ),
        ):
            validator((self.review.container_dir,))

    def test_claude_wsl2_gpg_temp_mountinfo_failure_is_inconclusive(self) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        validator = providers._claude_gpg_temp_root_validator(host)

        with (
            mock.patch.object(
                claude_linux,
                "_read_mountinfo",
                side_effect=claude_linux.LinuxRuntimeError(
                    "cannot read WSL2 mountinfo"
                ),
            ),
            self.assertRaisesRegex(
                providers.ClaudeProvenanceInconclusive,
                "cannot prove",
            ),
        ):
            validator((self.review.container_dir,))

    def test_claude_wsl2_gpg_verifier_fails_before_creating_private_home(
        self,
    ) -> None:
        host = providers.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )
        temp_root = self.review.container_dir / "claude-runtime" / "gpg-tmp"
        temp_root.mkdir(parents=True)
        temp_root.chmod(0o700)
        temp_root = temp_root.resolve(strict=True)
        bundle = claude_provenance.SignedClaudeManifest(
            version="2.1.212",
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            manifest=b"{}",
            signature=b"signature",
        )
        cases = (
            (
                "24 1 0:22 / / rw,relatime - 9p drvfs rw,aname=drvfs",
                providers.ClaudeProvenanceInvalid,
                "Linux-native filesystem",
            ),
            (
                "",
                providers.ClaudeProvenanceInconclusive,
                "cannot prove",
            ),
        )

        for mountinfo, error_type, message in cases:
            with (
                self.subTest(message=message),
                mock.patch.object(
                    claude_linux,
                    "_read_mountinfo",
                    return_value=mountinfo,
                ),
                mock.patch.object(
                    claude_provenance,
                    "_run_gpg",
                ) as run_gpg,
                mock.patch.object(
                    claude_provenance.tempfile,
                    "TemporaryDirectory",
                ) as temporary_home,
                self.assertRaisesRegex(error_type, message),
            ):
                claude_provenance.verify_manifest_signature(
                    bundle,
                    temp_root=temp_root,
                    temp_root_validator=(
                        providers._claude_gpg_temp_root_validator(host)
                    ),
                    gpg_candidates=(),
                )

            run_gpg.assert_not_called()
            temporary_home.assert_not_called()

    def test_claude_resolver_uses_linux_manifest_platform(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()
        info = mock.Mock(path=candidate, manifest_platform_key="linux-x64")
        snapshot = self.review.container_dir / "verified-claude"
        self.trusted_release.return_value = providers.VerifiedClaudeExecutable(
            executable=snapshot,
            artifact=claude_provenance.ClaudeReleaseArtifact(
                version="2.1.212",
                platform_key="linux-x64",
                binary="claude",
                checksum="a" * 64,
                size=123,
            ),
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            gpg_path=pathlib.Path("/usr/bin/gpg"),
        )

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                return_value=info,
            ),
            mock.patch.object(
                providers,
                "_require_claude_identity",
                return_value=providers.ClaudeVersion("2.1.212", (2, 1, 202)),
            ),
            mock.patch.object(
                providers,
                "_require_claude_safe_mode",
            ) as require_safe_mode,
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
        ):
            executable, _env = providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

        self.assertEqual(executable, snapshot)
        require_safe_mode.assert_called_once_with(snapshot, mock.ANY)
        preflight_env = require_safe_mode.call_args.args[1]
        self.assertNotIn("ANTHROPIC_API_KEY", preflight_env)
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", preflight_env)
        self.trusted_release.assert_called_once_with(
            candidate,
            version="2.1.212",
            platform_key="linux-x64",
            gpg_temp_root=(self.review.container_dir / "claude-runtime" / "gpg-tmp"),
            gpg_temp_root_validator=mock.ANY,
            cache_dir=(
                self.review.container_dir / "claude-runtime" / "provenance-cache"
            ),
            snapshot_dir=(
                self.review.container_dir / "claude-runtime" / "verified-executables"
            ),
        )
        report = json.loads(
            (self.review.container_dir / "claude-runtime.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["source_executable"], str(candidate.absolute()))
        self.assertEqual(report["verified_executable"], str(snapshot))
        self.assertEqual(
            report["gpg_verifier_trust"],
            "fixed-path-native-host-tool",
        )
        self.assertEqual(
            report["phase"],
            "publisher-and-cli-contract-verified",
        )
        self.assertEqual(report["content_variant"], self.review.content_variant)
        self.assertEqual(report["base_ref"], self.review.base_ref)
        self.assertEqual(report["head_ref"], self.review.head_ref)
        self.assertEqual(report["snapshot_tree_sha"], self.review.snapshot_tree_sha)
        self.assertEqual(report["scope_identity"], self.review.scope_identity)

    def test_claude_linux_candidate_mountinfo_failure_is_inconclusive(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(providers, "reject_claude_wsl_windows_paths"),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                side_effect=providers.LinuxRuntimeInspectionInconclusive(
                    "mountinfo changed during inspection"
                ),
            ),
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
            self.assertRaisesRegex(
                providers.ClaudeExecutableInspectionInconclusive,
                "mountinfo",
            ),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

    def test_claude_linux_candidate_windows_filesystem_is_blocked(self) -> None:
        candidate = self.review.source_root / "claude"
        candidate.write_bytes(b"fixture")
        candidate.chmod(0o700)
        host = mock.Mock()

        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            kwargs["candidate_validator"](candidate)
            return candidate

        with (
            mock.patch.object(providers, "_is_claude_linux_host", return_value=True),
            mock.patch.object(providers, "_claude_linux_host", return_value=host),
            mock.patch.object(providers, "reject_claude_wsl_windows_paths"),
            mock.patch.object(
                providers,
                "validate_claude_linux_executable",
                side_effect=providers.LinuxRuntimeUnsafe(
                    "Claude executable is on DrvFS"
                ),
            ),
            mock.patch.object(
                providers,
                "resolve_reviewer_executable",
                side_effect=resolve_and_validate,
            ),
            self.assertRaisesRegex(providers.LinuxRuntimeUnsafe, "DrvFS"),
        ):
            providers._resolve_validated_claude_executable(
                review=self.review,
                env={},
            )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/claude"),
    )
    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_refuses_unverified_safe_mode_semantics(
        self,
        run_command: mock.Mock,
        resolve: mock.Mock,
    ) -> None:
        def resolve_and_validate(_name: str, **kwargs) -> pathlib.Path:
            candidate = pathlib.Path("/bin/claude")
            kwargs["candidate_validator"](candidate)
            return candidate

        resolve.side_effect = resolve_and_validate
        run_command.side_effect = (
            Completed(
                argv=("claude", "--version"),
                returncode=0,
                stdout=b"2.1.212 (Claude Code)\n",
                stderr=b"",
            ),
            Completed(
                argv=("claude", "--help"),
                returncode=0,
                stdout=b"generic help",
                stderr=b"",
            ),
        )

        with self.assertRaisesRegex(ReviewError, "required review option"):
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={"HOME": "/Users/reviewer"},
            )

        self.assertEqual(run_command.call_count, 2)

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_accepts_semantic_safe_mode_option_block(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("claude", "--help"),
            returncode=0,
            stdout=claude_help_fixture(),
            stderr=b"",
        )

        providers._require_claude_safe_mode(
            pathlib.Path("/bin/claude"),
            {"HOME": str(self.review.container_dir)},
        )

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_rejects_safe_mode_option_mutations(
        self,
        run_command: mock.Mock,
    ) -> None:
        form = CLAUDE_SAFE_MODE_DESCRIPTION
        for mutated_form in (
            form.replace("plugins, hooks", "plugins", 1),
            form.replace("Auth, model selection", "Model selection", 1),
            form.replace("CLAUDE_CODE_SAFE_MODE=1", "CLAUDE_CODE_SAFE_MODE=0", 1),
            form.replace("all customizations", "some customizations", 1),
        ):
            with self.subTest(mutated_form=mutated_form):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=claude_help_fixture(safe_mode=mutated_form),
                    stderr=b"",
                )

                with self.assertRaisesRegex(ReviewError, "safe-mode semantics"):
                    providers._require_claude_safe_mode(
                        pathlib.Path("/bin/claude"),
                        {"HOME": str(self.review.container_dir)},
                    )

    @mock.patch.object(
        providers,
        "CLAUDE_PROBE_SANDBOX",
        pathlib.Path("/usr/bin/true"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_rejects_duplicate_or_conflicting_safe_mode_descriptions(
        self,
        run_command: mock.Mock,
    ) -> None:
        for help_text in (
            claude_help_fixture() + b"  --safe-mode hooks still load\n",
            claude_help_fixture(
                safe_mode=CLAUDE_SAFE_MODE_DESCRIPTION.replace(
                    "plugins, hooks, MCP",
                    "plugins, hooks still load, MCP",
                )
            ),
        ):
            with self.subTest(help_text=help_text):
                run_command.return_value = Completed(
                    argv=("claude", "--help"),
                    returncode=0,
                    stdout=help_text,
                    stderr=b"",
                )

                with self.assertRaises(ReviewError):
                    providers._require_claude_safe_mode(
                        pathlib.Path("/bin/claude"),
                        {"HOME": str(self.review.container_dir)},
                    )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "run")
    def test_copilot_command_pins_opus_and_max(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        payload = "\n".join(
            json.dumps(item)
            for item in (
                {
                    "type": "session.start",
                    "data": {"selectedModel": "claude-opus-4.8"},
                },
                {
                    "type": "assistant.turn_start",
                    "data": {"turnId": "turn-1"},
                },
                {
                    "type": "assistant.message",
                    "data": {
                        "messageId": "message-1",
                        "content": "No findings.",
                        "model": "claude-opus-4.8",
                        "toolRequests": [],
                    },
                },
                {
                    "type": "assistant.turn_end",
                    "data": {"turnId": "turn-1"},
                },
            )
        )
        permission_help = " ".join(providers.COPILOT_PERMISSION_HELP_FRAGMENTS)
        run_command.side_effect = (
            Completed(
                argv=("copilot", "help", "permissions"),
                returncode=0,
                stdout=permission_help.encode(),
                stderr=b"",
            ),
            Completed(
                argv=("copilot",),
                returncode=0,
                stdout=payload.encode(),
                stderr=b"",
            ),
        )
        providers._copilot_attempt(
            review=self.review,
            model="claude-opus-4.8",
            index=1,
            env={"GH_TOKEN": "secret"},
        )
        argv = run_command.call_args_list[1].args[0]
        self.assertEqual(argv[argv.index("-C") + 1], str(self.review.workspace_root))
        self.assertEqual(
            argv[argv.index("--prompt") + 1],
            self.review.prompt_file.read_text(encoding="utf-8"),
        )
        self.assertIn("claude-opus-4.8", argv)
        self.assertEqual(argv[argv.index("--reasoning-effort") + 1], "max")
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertIn("--available-tools=view,glob,grep", argv)
        self.assertIn("--disable-builtin-mcps", argv)
        self.assertIn("--no-custom-instructions", argv)
        self.assertIn("--deny-tool=write", argv)
        self.assertIn("--deny-tool=shell", argv)
        self.assertIn("--deny-tool=url", argv)
        self.assertIn("--disallow-temp-dir", argv)
        self.assertNotIn("--allow-all-paths", argv)
        self.assertNotIn("--add-dir", argv)
        self.assertIn("--no-auto-update", argv)
        self.assertIn("--secret-env-vars=GH_TOKEN", argv)
        self.assertEqual(
            run_command.call_args_list[1].kwargs["env"]["COPILOT_HOME"],
            str(self.review.container_dir / "copilot-home"),
        )
        self.assertTrue((self.review.container_dir / "copilot-home").is_dir())
        self.assertEqual(
            run_command.call_args_list[0].kwargs["timeout_seconds"],
            providers.COPILOT_PROBE_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[0].kwargs["capture_limit_bytes"],
            providers.COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
        )
        self.assertEqual(
            run_command.call_args_list[0].kwargs["output_file_limit_bytes"],
            providers.COPILOT_PROBE_OUTPUT_LIMIT_BYTES,
        )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["timeout_seconds"],
            providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["output_file_limit_bytes"],
            providers.REVIEW_ATTEMPT_OUTPUT_LIMIT_BYTES,
        )

    @mock.patch.object(
        providers,
        "resolve_reviewer_executable",
        return_value=pathlib.Path("/bin/copilot"),
    )
    @mock.patch.object(providers, "run")
    def test_copilot_refuses_unverified_path_permission_semantics(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("copilot", "help", "permissions"),
            returncode=0,
            stdout=b"generic help",
            stderr=b"",
        )
        with self.assertRaisesRegex(ReviewError, "cwd-only path verifier"):
            providers._copilot_attempt(
                review=self.review,
                model="claude-opus-4.8",
                index=1,
                env={"GH_TOKEN": "secret"},
            )
        self.assertEqual(run_command.call_count, 1)

    def test_claude_authentication_precedence_removes_loser(self) -> None:
        selected, redact_values = providers._select_claude_authentication(
            {
                "ANTHROPIC_API_KEY": "alpha",
                "CLAUDE_CODE_OAUTH_TOKEN": "omega",
                "HTTPS_PROXY": "http://proxy.example.invalid:8080",
                "NO_PROXY": "*",
                "HOME": str(self.claude_pwd_home),
            }
        )

        self.assertEqual(selected["ANTHROPIC_API_KEY"], "alpha")
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", selected)
        self.assertEqual(
            redact_values,
            ("alpha", "omega"),
        )
        self.assertEqual(selected["HTTPS_PROXY"], "http://proxy.example.invalid:8080")
        self.assertEqual(selected["NO_PROXY"], "*")
        self.assertEqual(providers._claude_authentication_source(selected), "api-key")

        selected, redact_values = providers._select_claude_authentication(
            {
                "CLAUDE_CODE_OAUTH_TOKEN": "omega",
                "HOME": str(self.claude_pwd_home),
            }
        )
        self.assertNotIn("ANTHROPIC_API_KEY", selected)
        self.assertEqual(selected["CLAUDE_CODE_OAUTH_TOKEN"], "omega")
        self.assertEqual(redact_values, ("omega",))
        self.assertEqual(
            providers._claude_authentication_source(selected),
            "oauth-token",
        )

        selected, redact_values = providers._select_claude_authentication(
            {"HOME": str(self.claude_pwd_home)}
        )
        self.assertEqual(redact_values, ())
        self.assertEqual(
            providers._claude_authentication_source(selected),
            "local-login",
        )

    def test_claude_output_redaction_only_includes_credential_proxy_urls(self) -> None:
        credential_proxy = (
            "http://reviewer:proxy-secret@proxy.example.invalid:8080/route"
        )
        values = providers.claude_output_redact_values(
            {
                "HTTPS_PROXY": credential_proxy,
                "HTTP_PROXY": "http://proxy.example.invalid:8080",
                "NO_PROXY": "*",
                "no_proxy": "e",
            }
        )

        self.assertEqual(values, (credential_proxy,))
        variants = common.output_redact_values(values)
        self.assertIn(credential_proxy, variants)
        self.assertIn(
            json.dumps(credential_proxy, ensure_ascii=True)[1:-1],
            variants,
        )
        self.assertNotIn("*", variants)
        self.assertNotIn("e", variants)

    @mock.patch.object(providers, "_run_review_impl")
    @mock.patch.object(providers, "_review_environment")
    def test_claude_model_run_opts_out_of_broad_subprocess_scrub(
        self,
        review_environment: mock.Mock,
        run_review_impl: mock.Mock,
    ) -> None:
        review_environment.side_effect = lambda **kwargs: {
            "HOME": str(self.claude_pwd_home),
            **kwargs["extra"],
        }
        run_review_impl.return_value = providers.Outcome(0, "No findings.", tuple())

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="explicit-claude-review",
        )

        self.assertEqual(outcome.returncode, 0)
        extra = review_environment.call_args.kwargs["extra"]
        self.assertEqual(extra["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "0")
        claude_env = run_review_impl.call_args.kwargs["claude_env"]
        self.assertEqual(claude_env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "0")
        probe_env = providers._claude_preflight_probe_environment(
            home=self.claude_pwd_home,
            tmp=self.review.container_dir / "tmp",
        )
        self.assertEqual(probe_env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "1")

    def test_claude_auth_status_proves_each_supported_effective_source(self) -> None:
        for source in ("api-key", "oauth-token", "local-login"):
            with self.subTest(source=source):
                evidence = providers._claude_effective_authentication(
                    claude_auth_status_fixture(source),
                    requested_source=source,
                )
                self.assertEqual(evidence.requested_source, source)
                self.assertEqual(evidence.api_provider, "firstParty")

    def test_claude_auth_status_rejects_higher_priority_or_unsupported_source(
        self,
    ) -> None:
        cases = (
            (
                "api-key",
                {
                    "loggedIn": True,
                    "authMethod": "oauth_token",
                    "apiProvider": "firstParty",
                },
            ),
            (
                "local-login",
                {
                    "loggedIn": True,
                    "authMethod": "api_key",
                    "apiProvider": "firstParty",
                    "apiKeySource": "apiKeyHelper",
                },
            ),
            (
                "oauth-token",
                {
                    "loggedIn": True,
                    "authMethod": "third_party",
                    "apiProvider": "bedrock",
                },
            ),
            (
                "local-login",
                {
                    "loggedIn": True,
                    "authMethod": "oauth_token",
                    "apiProvider": "claude-apps-gateway",
                },
            ),
        )
        for requested_source, payload in cases:
            with self.subTest(requested_source=requested_source, payload=payload):
                with self.assertRaisesRegex(
                    providers.ClaudeAuthenticationPreflightBlocked,
                    "unsupported or higher-priority",
                ):
                    providers._claude_effective_authentication(
                        json.dumps(payload).encode(),
                        requested_source=requested_source,
                    )

    def test_claude_auth_status_rejects_logged_out_or_ambiguous_json(self) -> None:
        with self.assertRaises(providers.ClaudeAuthenticationPreflightBlocked):
            providers._claude_effective_authentication(
                json.dumps(
                    {
                        "loggedIn": False,
                        "authMethod": "none",
                        "apiProvider": "firstParty",
                    }
                ).encode(),
                requested_source="local-login",
            )
        with self.assertRaisesRegex(ReviewError, "strict JSON"):
            providers._claude_effective_authentication(
                b'{"loggedIn":true,"loggedIn":false}',
                requested_source="local-login",
            )

    def test_claude_stream_requires_effective_init_and_terminal_contract(self) -> None:
        auth = providers.ClaudeAuthenticationEvidence(
            requested_source="local-login",
            api_provider="firstParty",
            auth_method="claude.ai",
            api_key_source=None,
        )
        valid = providers._strict_jsonl_objects(claude_stream_fixture(self.review))
        assert valid is not None
        self.assertEqual(
            providers._parse_claude_stream_objects(
                valid,
                review=self.review,
                requested_model="claude-opus-4-8",
                authentication=auth,
            ),
            ("No findings.", "claude-opus-4-8", True),
        )

        for label, payload in (
            (
                "managed permission override",
                claude_stream_fixture(
                    self.review,
                    init_updates={"permissionMode": "plan"},
                ),
            ),
            (
                "tool widening",
                claude_stream_fixture(
                    self.review,
                    init_updates={"tools": ["Bash", "Glob", "Grep", "Read", "Write"]},
                ),
            ),
            (
                "auth source mismatch",
                claude_stream_fixture(
                    self.review,
                    init_updates={"apiKeySource": "ANTHROPIC_API_KEY"},
                ),
            ),
            (
                "model override",
                claude_stream_fixture(
                    self.review,
                    init_updates={"model": "claude-opus-4-7"},
                ),
            ),
        ):
            with self.subTest(label=label):
                objects = providers._strict_jsonl_objects(payload)
                assert objects is not None
                final_text, _effective_model, contract = (
                    providers._parse_claude_stream_objects(
                        objects,
                        review=self.review,
                        requested_model="claude-opus-4-8",
                        authentication=auth,
                    )
                )
                self.assertEqual(final_text, "No findings.")
                self.assertFalse(contract)

    def test_claude_stream_allows_additive_nonsecurity_init_metadata(self) -> None:
        auth = providers.ClaudeAuthenticationEvidence(
            requested_source="local-login",
            api_provider="firstParty",
            auth_method="claude.ai",
            api_key_source=None,
        )
        objects = providers._strict_jsonl_objects(
            claude_stream_fixture(
                self.review,
                init_updates={"additive_metadata": {"releaseChannel": "stable"}},
            )
        )
        assert objects is not None
        self.assertTrue(
            providers._parse_claude_stream_objects(
                objects,
                review=self.review,
                requested_model="claude-opus-4-8",
                authentication=auth,
            )[2]
        )

    def test_claude_stream_parser_does_not_materialize_the_event_iterable(self) -> None:
        auth = providers.ClaudeAuthenticationEvidence(
            requested_source="local-login",
            api_provider="firstParty",
            auth_method="claude.ai",
            api_key_source=None,
        )
        events = providers._strict_jsonl_objects(claude_stream_fixture(self.review))
        assert events is not None

        class SinglePassEvents:
            def __init__(self) -> None:
                self._events = iter(events)

            def __iter__(self):
                return self

            def __next__(self):
                return next(self._events)

            def __length_hint__(self) -> int:
                raise AssertionError("Claude stream events must not be materialized")

        self.assertEqual(
            providers._parse_claude_stream_objects(
                SinglePassEvents(),
                review=self.review,
                requested_model="claude-opus-4-8",
                authentication=auth,
            ),
            ("No findings.", "claude-opus-4-8", True),
        )

    def test_claude_stream_rejects_duplicate_or_misordered_contract_events(
        self,
    ) -> None:
        auth = providers.ClaudeAuthenticationEvidence(
            requested_source="local-login",
            api_provider="firstParty",
            auth_method="claude.ai",
            api_key_source=None,
        )
        valid = providers._strict_jsonl_objects(claude_stream_fixture(self.review))
        assert valid is not None
        for objects in ((valid[0], valid[0], valid[1]), (valid[1], valid[0])):
            with self.subTest(types=[item["type"] for item in objects]):
                self.assertFalse(
                    providers._parse_claude_stream_objects(
                        objects,
                        review=self.review,
                        requested_model="claude-opus-4-8",
                        authentication=auth,
                    )[2]
                )

    def test_claude_arguments_and_native_sandbox_are_read_only(self) -> None:
        assert self.review.git_dir is not None
        git_view = self.review.git_dir
        review_user_root = self.review.container_dir.resolve().parents[1]
        settings = providers._claude_review_settings(
            review=self.review,
            home=self.claude_pwd_home,
        )
        arguments = providers._claude_review_arguments(
            model="claude-opus-4-8",
            settings=settings,
        )

        self.assertEqual(arguments[arguments.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(
            arguments[arguments.index("--tools") + 1], "Read,Grep,Glob,Bash"
        )
        self.assertEqual(arguments[arguments.index("--allowedTools") + 1], "Read(./**)")
        self.assertEqual(
            arguments[arguments.index("--disallowedTools") + 1],
            "Edit,Write,NotebookEdit,WebFetch,WebSearch,Task,"
            "Read(//proc),Read(//proc/**),Read(//dev),Read(//dev/**)",
        )
        self.assertIn("--no-session-persistence", arguments)
        self.assertIn("--verbose", arguments)
        self.assertEqual(
            arguments[arguments.index("--output-format") + 1], "stream-json"
        )
        self.assertIn("--safe-mode", arguments)
        self.assertEqual(arguments[arguments.index("--setting-sources") + 1], "")
        self.assertEqual(
            arguments[arguments.index("--mcp-config") + 1], '{"mcpServers":{}}'
        )

        parsed = json.loads(settings)
        sandbox = parsed["sandbox"]
        self.assertEqual(
            {
                "enabled": sandbox["enabled"],
                "failIfUnavailable": sandbox["failIfUnavailable"],
                "autoAllowBashIfSandboxed": sandbox["autoAllowBashIfSandboxed"],
                "allowUnsandboxedCommands": sandbox["allowUnsandboxedCommands"],
            },
            {
                "enabled": True,
                "failIfUnavailable": True,
                "autoAllowBashIfSandboxed": False,
                "allowUnsandboxedCommands": False,
            },
        )
        filesystem = sandbox["filesystem"]
        self.assertEqual(
            filesystem["denyRead"],
            [
                str(self.claude_pwd_home),
                str(self.review.source_root.resolve()),
                str(review_user_root),
                "/proc",
                "/dev",
            ],
        )
        self.assertEqual(
            filesystem["allowRead"],
            [str(self.review.workspace_root.resolve()), str(git_view.resolve())],
        )
        self.assertEqual(
            filesystem["denyWrite"],
            [
                str(self.claude_pwd_home),
                str(self.review.workspace_root.resolve()),
                str(git_view.resolve()),
            ],
        )
        self.assertEqual(
            sandbox["credentials"]["envVars"],
            [
                {"name": name, "mode": "deny"}
                for name in providers.CLAUDE_MODEL_SECRET_ENV_KEYS
            ],
        )
        absolute_read_denies = [
            "Read(//proc)",
            "Read(//proc/**)",
            "Read(//dev)",
            "Read(//dev/**)",
        ]
        self.assertEqual(
            parsed["permissions"]["deny"],
            [
                *absolute_read_denies,
                "Read(~/.aws/**)",
                "Read(~/.claude/**)",
                "Read(~/.codex/**)",
                "Read(~/.config/**)",
                "Read(~/.copilot/**)",
                "Read(~/.gnupg/**)",
                "Read(~/.kube/**)",
                "Read(~/.ssh/**)",
                "Read(~/.git-credentials)",
                "Read(~/.netrc)",
            ],
        )
        cli_denies = arguments[arguments.index("--disallowedTools") + 1].split(",")
        self.assertEqual(cli_denies[-len(absolute_read_denies) :], absolute_read_denies)

    def test_claude_sandbox_denies_other_same_uid_review_containers(self) -> None:
        assert self.review.git_dir is not None
        review_user_root = self.review.container_dir.resolve().parents[1]
        sibling_container = (
            review_user_root / ("f" * 64) / "isolated-review-20260719-000000-0000000000"
        )
        parsed = json.loads(
            providers._claude_review_settings(
                review=self.review,
                home=self.claude_pwd_home,
            )
        )

        self.assertTrue(sibling_container.is_relative_to(review_user_root))
        self.assertTrue(
            self.review.workspace_root.resolve().is_relative_to(review_user_root)
        )
        self.assertFalse(
            sibling_container.is_relative_to(self.review.container_dir.resolve())
        )
        self.assertIn(
            str(review_user_root), parsed["sandbox"]["filesystem"]["denyRead"]
        )
        self.assertIn(
            str(self.review.source_root.resolve()),
            parsed["sandbox"]["filesystem"]["denyRead"],
        )
        self.assertEqual(
            parsed["sandbox"]["filesystem"]["allowRead"],
            [
                str(self.review.workspace_root.resolve()),
                str(self.review.git_dir.resolve()),
            ],
        )
        self.assertNotIn(f"Read(/{review_user_root}/**)", parsed["permissions"]["deny"])

    @mock.patch.object(
        providers,
        "validate_external_workspace",
        wraps=providers.validate_external_workspace,
    )
    @mock.patch.object(providers, "run")
    def test_claude_attempt_runs_directly_with_real_home(
        self,
        run_command: mock.Mock,
        validate_workspace: mock.Mock,
    ) -> None:
        def complete(argv: tuple[str, ...], **kwargs: object) -> Completed:
            is_auth = "auth" in argv
            payload = (
                claude_auth_status_fixture("local-login")
                if is_auth
                else claude_stream_fixture(self.review)
            )
            if not is_auth:
                parent = self.review.workspace_root / ".claude"
                parent.mkdir(mode=0o755)
                (parent / ".cc-writes").mkdir(mode=0o700)
            stdout_path = pathlib.Path(kwargs["stdout_path"])
            stderr_path = pathlib.Path(kwargs["stderr_path"])
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_bytes(payload)
            stderr_path.write_bytes(b"")
            return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")

        run_command.side_effect = complete
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"schema": 1, "phase": "publisher-and-cli-contract-verified"},
        )
        common.write_json(
            self.review.container_dir / "egress.json",
            {
                "authentication": {
                    "requested_source": "local-login",
                    "status": "pending-effective-preflight",
                }
            },
        )
        attempt = providers._claude_attempt(
            review=self.review,
            model="claude-opus-4-8",
            index=1,
            env={
                "HOME": str(self.claude_pwd_home),
                "TMPDIR": str(temporary),
                "TMP": str(temporary),
                "TEMP": str(temporary),
                "CLAUDE_CODE_TMPDIR": str(temporary),
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
            },
            executable=pathlib.Path("/bin/claude"),
            redact_values=("alpha", "omega"),
        )

        self.assertEqual(attempt.category, "success")
        self.assertFalse((self.review.workspace_root / ".claude").exists())
        self.assertEqual(run_command.call_count, 2)
        validate_workspace.assert_called_once_with(self.review)
        auth_argv = run_command.call_args_list[0].args[0]
        self.assertEqual(auth_argv[-3:], ("auth", "status", "--json"))
        argv = run_command.call_args_list[1].args[0]
        self.assertEqual(argv[0], "/bin/claude")
        self.assertNotIn("sandbox-exec", argv)
        self.assertNotIn("bwrap", argv)
        expected_settings = providers._claude_review_settings(
            review=self.review,
            home=self.claude_pwd_home,
        )
        for call in run_command.call_args_list:
            call_argv = call.args[0]
            self.assertEqual(call.kwargs["cwd"], self.review.workspace_root)
            self.assertEqual(call.kwargs["env"]["HOME"], str(self.claude_pwd_home))
            self.assertEqual(
                call.kwargs["env"]["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"],
                "0",
            )
            self.assertEqual(
                call_argv[call_argv.index("--settings") + 1],
                expected_settings,
            )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["env"][
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"
            ],
            "0",
        )
        self.assertEqual(
            run_command.call_args_list[1].kwargs["redact_values"],
            ("alpha", "omega"),
        )
        report = json.loads(
            (self.review.container_dir / "claude-runtime.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["sandbox"]["implementation"], "claude-native-sandbox")
        self.assertEqual(report["authentication"]["requested_source"], "local-login")
        self.assertEqual(report["authentication"]["effective_auth_method"], "claude.ai")
        self.assertEqual(report["authentication"]["status"], "used")
        self.assertEqual(report["capabilities"]["effective_init_contract"], "verified")
        self.assertEqual(
            report["capabilities"]["claude_bash_staging_contract"],
            "verified-and-removed",
        )
        self.assertEqual(
            report["sandbox"]["status"],
            "requested-not-independently-observable",
        )
        self.assertEqual(report["content_variant"], self.review.content_variant)
        self.assertEqual(report["base_ref"], self.review.base_ref)
        self.assertEqual(report["head_ref"], self.review.head_ref)
        self.assertEqual(report["snapshot_tree_sha"], self.review.snapshot_tree_sha)
        self.assertEqual(report["scope_identity"], self.review.scope_identity)
        egress = json.loads(
            (self.review.container_dir / "egress.json").read_text(encoding="utf-8")
        )
        self.assertEqual(egress["authentication"]["status"], "used")
        self.assertEqual(egress["authentication"]["effective_auth_method"], "claude.ai")
        self.assertEqual(
            egress["authentication"]["effective_init_contract"], "verified"
        )

    @mock.patch.object(
        providers,
        "validate_external_workspace",
        wraps=providers.validate_external_workspace,
    )
    @mock.patch.object(providers, "run")
    def test_claude_attempt_cleans_staging_after_timeout(
        self,
        run_command: mock.Mock,
        validate_workspace: mock.Mock,
    ) -> None:
        primary = providers.ReviewTimeoutError("review timed out")

        def run_or_timeout(argv: tuple[str, ...], **kwargs: object) -> Completed:
            if "auth" in argv:
                payload = claude_auth_status_fixture("local-login")
                stdout_path = pathlib.Path(kwargs["stdout_path"])
                stderr_path = pathlib.Path(kwargs["stderr_path"])
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_path.write_bytes(payload)
                stderr_path.write_bytes(b"")
                return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")
            parent = self.review.workspace_root / ".claude"
            parent.mkdir(mode=0o755)
            (parent / ".cc-writes").mkdir(mode=0o700)
            raise primary

        run_command.side_effect = run_or_timeout
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)

        with self.assertRaises(providers.ReviewTimeoutError) as caught:
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={
                    "HOME": str(self.claude_pwd_home),
                    "TMPDIR": str(temporary),
                    "TMP": str(temporary),
                    "TEMP": str(temporary),
                    "CLAUDE_CODE_TMPDIR": str(temporary),
                    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
                },
                executable=pathlib.Path("/bin/claude"),
            )

        self.assertIs(caught.exception, primary)
        self.assertFalse((self.review.workspace_root / ".claude").exists())
        validate_workspace.assert_called_once_with(self.review)

    @mock.patch.object(
        providers,
        "validate_external_workspace",
        wraps=providers.validate_external_workspace,
    )
    @mock.patch.object(providers, "run")
    def test_claude_attempt_cleans_staging_after_output_limit(
        self,
        run_command: mock.Mock,
        validate_workspace: mock.Mock,
    ) -> None:
        primary = providers.ReviewOutputLimitError("review output exceeded limit")

        def run_or_limit(argv: tuple[str, ...], **kwargs: object) -> Completed:
            if "auth" in argv:
                payload = claude_auth_status_fixture("local-login")
                stdout_path = pathlib.Path(kwargs["stdout_path"])
                stderr_path = pathlib.Path(kwargs["stderr_path"])
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_path.write_bytes(payload)
                stderr_path.write_bytes(b"")
                return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")
            parent = self.review.workspace_root / ".claude"
            parent.mkdir(mode=0o755)
            (parent / ".cc-writes").mkdir(mode=0o700)
            raise primary

        run_command.side_effect = run_or_limit
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)

        with self.assertRaises(providers.ReviewOutputLimitError) as caught:
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={
                    "HOME": str(self.claude_pwd_home),
                    "TMPDIR": str(temporary),
                    "TMP": str(temporary),
                    "TEMP": str(temporary),
                    "CLAUDE_CODE_TMPDIR": str(temporary),
                    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
                },
                executable=pathlib.Path("/bin/claude"),
            )

        self.assertIs(caught.exception, primary)
        self.assertFalse((self.review.workspace_root / ".claude").exists())
        validate_workspace.assert_called_once_with(self.review)

    @mock.patch.object(
        providers,
        "validate_external_workspace",
        wraps=providers.validate_external_workspace,
    )
    @mock.patch.object(providers, "run")
    def test_claude_attempt_cleanup_rejection_preserves_primary_and_evidence(
        self,
        run_command: mock.Mock,
        validate_workspace: mock.Mock,
    ) -> None:
        primary = providers.ReviewTimeoutError("review timed out")
        retained_detail = "do not persist this staging detail"

        def run_or_timeout(argv: tuple[str, ...], **kwargs: object) -> Completed:
            stdout_path = pathlib.Path(kwargs["stdout_path"])
            stderr_path = pathlib.Path(kwargs["stderr_path"])
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            if "auth" in argv:
                payload = claude_auth_status_fixture("local-login")
                stdout_path.write_bytes(payload)
                stderr_path.write_bytes(b"")
                return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")
            staging = self.review.workspace_root / ".claude" / ".cc-writes"
            staging.mkdir(mode=0o700, parents=True)
            (staging / "retained.txt").write_text(
                retained_detail,
                encoding="utf-8",
            )
            stderr_path.write_bytes(b"primary supervision evidence\n")
            raise primary

        run_command.side_effect = run_or_timeout
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)

        with self.assertRaises(providers.ReviewTimeoutError) as caught:
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={
                    "HOME": str(self.claude_pwd_home),
                    "TMPDIR": str(temporary),
                    "TMP": str(temporary),
                    "TEMP": str(temporary),
                    "CLAUDE_CODE_TMPDIR": str(temporary),
                    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
                },
                executable=pathlib.Path("/bin/claude"),
            )

        self.assertIs(caught.exception, primary)
        validate_workspace.assert_called_once_with(self.review)
        retained = (
            self.review.workspace_root / ".claude" / ".cc-writes" / "retained.txt"
        )
        self.assertEqual(retained.read_text(encoding="utf-8"), retained_detail)
        diagnostic = (
            self.review.container_dir
            / "attempts"
            / "01-claude-claude-opus-4-8.stderr.log"
        ).read_text(encoding="utf-8")
        self.assertIn("primary supervision evidence", diagnostic)
        self.assertIn(
            "post-exception Claude staging cleanup or external review workspace "
            "validation failed",
            diagnostic,
        )
        self.assertNotIn(retained_detail, diagnostic)

        retained.unlink()
        retained.parent.rmdir()
        retained.parent.parent.rmdir()

    @mock.patch.object(
        providers,
        "_append_attempt_diagnostic",
        side_effect=OSError("diagnostic write failed"),
    )
    @mock.patch.object(
        providers,
        "_remove_claude_bash_staging_directory",
        side_effect=ReviewError("cleanup rejected"),
    )
    @mock.patch.object(providers, "run")
    def test_claude_attempt_diagnostic_failure_preserves_primary(
        self,
        run_command: mock.Mock,
        _remove_staging: mock.Mock,
        append_diagnostic: mock.Mock,
    ) -> None:
        primary = providers.ReviewOutputLimitError("review output exceeded limit")

        def run_or_limit(argv: tuple[str, ...], **kwargs: object) -> Completed:
            if "auth" in argv:
                payload = claude_auth_status_fixture("local-login")
                return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")
            raise primary

        run_command.side_effect = run_or_limit
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)

        with self.assertRaises(providers.ReviewOutputLimitError) as caught:
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={
                    "HOME": str(self.claude_pwd_home),
                    "TMPDIR": str(temporary),
                    "TMP": str(temporary),
                    "TEMP": str(temporary),
                    "CLAUDE_CODE_TMPDIR": str(temporary),
                    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
                },
                executable=pathlib.Path("/bin/claude"),
            )

        self.assertIs(caught.exception, primary)
        _remove_staging.assert_called_once()
        append_diagnostic.assert_called_once()

    def test_claude_bash_staging_cleanup_rejects_nonempty_directory(self) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)
        (staging / "unexpected").write_text("unexpected\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "is not empty"):
            providers._remove_claude_bash_staging_directory(
                self.review,
                baseline=baseline,
            )

        self.assertTrue((staging / "unexpected").is_file())

    def test_claude_bash_staging_baseline_requires_no_follow_support(self) -> None:
        with mock.patch.object(providers.os, "O_NOFOLLOW", None):
            with self.assertRaisesRegex(ReviewError, "does not support no-follow"):
                providers._claude_bash_staging_baseline(self.review)

    def test_claude_bash_staging_cleanup_rejects_symlink(self) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        target = self.review.workspace_root / "staging-target"
        target.mkdir(mode=0o700)
        (parent / ".cc-writes").symlink_to(target, target_is_directory=True)

        with self.assertRaises(ReviewError):
            providers._remove_claude_bash_staging_directory(
                self.review,
                baseline=baseline,
            )

        self.assertTrue((parent / ".cc-writes").is_symlink())

    def test_claude_bash_staging_cleanup_rejects_wrong_mode(self) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)
        staging.chmod(0o755)

        with self.assertRaisesRegex(ReviewError, "is unsafe"):
            providers._remove_claude_bash_staging_directory(
                self.review,
                baseline=baseline,
            )

        self.assertTrue(staging.is_dir())

    def test_claude_bash_staging_cleanup_preserves_other_topology(self) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)
        sibling = parent / "unexpected"
        sibling.write_text("unexpected\n", encoding="utf-8")

        self.assertEqual(
            providers._remove_claude_bash_staging_directory(
                self.review,
                baseline=baseline,
            ),
            "verified-and-removed",
        )
        self.assertFalse(staging.exists())
        self.assertTrue(sibling.is_file())
        with self.assertRaisesRegex(ReviewError, "topology"):
            workspace_runtime.validate_external_workspace(self.review)

    def test_claude_bash_staging_cleanup_preserves_snapshotted_parent(self) -> None:
        source_parent = self.review.source_root / ".claude"
        source_parent.mkdir(mode=0o755)
        (source_parent / "review-policy.txt").write_text(
            "snapshotted\n",
            encoding="utf-8",
        )
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])
        parent = review.workspace_root / ".claude"
        baseline = providers._claude_bash_staging_baseline(review)
        (parent / ".cc-writes").mkdir(mode=0o700)

        self.assertEqual(
            providers._remove_claude_bash_staging_directory(
                review,
                baseline=baseline,
            ),
            "verified-and-removed",
        )
        self.assertEqual(
            (parent / "review-policy.txt").read_text(encoding="utf-8"),
            "snapshotted\n",
        )
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    def test_claude_bash_staging_cleanup_rejects_replaced_parent_symlink(
        self,
    ) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        self.assertTrue(baseline.staging_was_absent)
        self.assertIsNone(baseline.parent_identity)
        outside_parent = pathlib.Path(self.temporary.name) / "outside-claude"
        outside_parent.mkdir(mode=0o700)
        outside_staging = outside_parent / ".cc-writes"
        outside_staging.mkdir(mode=0o700)
        (self.review.workspace_root / ".claude").symlink_to(
            outside_parent,
            target_is_directory=True,
        )

        with self.assertRaises(ReviewError):
            providers._remove_claude_bash_staging_directory(
                self.review,
                baseline=baseline,
            )

        self.assertTrue(outside_staging.is_dir())
        self.assertTrue((self.review.workspace_root / ".claude").is_symlink())

    def test_claude_bash_staging_cleanup_rejects_replaced_existing_parent(
        self,
    ) -> None:
        source_parent = self.review.source_root / ".claude"
        source_parent.mkdir(mode=0o755)
        (source_parent / "review-policy.txt").write_text(
            "snapshotted\n",
            encoding="utf-8",
        )
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])
        baseline = providers._claude_bash_staging_baseline(review)
        self.assertTrue(baseline.staging_was_absent)
        self.assertIsNotNone(baseline.parent_identity)
        parent = review.workspace_root / ".claude"
        moved_parent = pathlib.Path(self.temporary.name) / "moved-claude-parent"
        parent.rename(moved_parent)
        parent.mkdir(mode=0o755)
        (parent / "review-policy.txt").write_text(
            "snapshotted\n",
            encoding="utf-8",
        )
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)

        with self.assertRaisesRegex(ReviewError, "changed after launch"):
            providers._remove_claude_bash_staging_directory(
                review,
                baseline=baseline,
            )

        self.assertTrue(staging.is_dir())
        staging.rmdir()
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    def test_claude_bash_staging_cleanup_rejects_parent_replaced_mid_cleanup(
        self,
    ) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)
        moved_parent = pathlib.Path(self.temporary.name) / "mid-cleanup-parent"
        real_rename = os.rename
        replaced = False

        def replace_parent_before_staging_quarantine(
            source: str,
            destination: str,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal replaced
            if source == ".cc-writes" and destination == "staging" and not replaced:
                real_rename(parent, moved_parent)
                parent.mkdir(mode=0o755)
                replaced = True
            real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            providers.os,
            "rename",
            side_effect=replace_parent_before_staging_quarantine,
        ):
            with self.assertRaisesRegex(ReviewError, "changed during cleanup"):
                providers._remove_claude_bash_staging_directory(
                    self.review,
                    baseline=baseline,
                )

        self.assertTrue(replaced)
        self.assertTrue(moved_parent.is_dir())
        self.assertFalse((moved_parent / ".cc-writes").exists())
        self.assertTrue(parent.is_dir())
        parent.rmdir()
        workspace_runtime.validate_external_workspace(self.review)

    def test_claude_bash_staging_cleanup_rejects_staging_swap_before_quarantine(
        self,
    ) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        staging = parent / ".cc-writes"
        staging.mkdir(mode=0o700)
        original = staging.stat()
        moved_staging = pathlib.Path(self.temporary.name) / "verified-staging"
        real_rename = os.rename
        real_stat = os.stat
        staging_validations = 0
        replacement_identity: tuple[int, int] | None = None

        def replace_staging_after_final_identity_validation(
            path: str | os.PathLike[str],
            *args: object,
            **kwargs: object,
        ) -> os.stat_result:
            nonlocal staging_validations, replacement_identity
            result = real_stat(path, *args, **kwargs)
            if (
                path == ".cc-writes"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                staging_validations += 1
                if staging_validations == 1:
                    real_rename(staging, moved_staging)
                    staging.mkdir(mode=stat.S_IMODE(original.st_mode))
                    replacement = real_stat(staging, follow_symlinks=False)
                    replacement_identity = (
                        replacement.st_dev,
                        replacement.st_ino,
                    )
            return result

        with mock.patch.object(
            providers.os,
            "stat",
            side_effect=replace_staging_after_final_identity_validation,
        ):
            with self.assertRaisesRegex(
                ReviewError,
                "changed before quarantine removal",
            ):
                providers._remove_claude_bash_staging_directory(
                    self.review,
                    baseline=baseline,
                )

        self.assertEqual(staging_validations, 1)
        self.assertIsNotNone(replacement_identity)
        moved = moved_staging.stat()
        self.assertEqual(
            (moved.st_dev, moved.st_ino),
            (original.st_dev, original.st_ino),
        )
        self.assertFalse(staging.exists())
        quarantine_roots = list(
            self.review.container_dir.glob(".claude-bash-entry-quarantine-*")
        )
        self.assertEqual(len(quarantine_roots), 1)
        quarantined_replacement = quarantine_roots[0] / "staging"
        quarantined = quarantined_replacement.stat()
        self.assertEqual(
            (quarantined.st_dev, quarantined.st_ino),
            replacement_identity,
        )
        self.assertEqual(stat.S_IMODE(quarantined.st_mode), 0o700)

        moved_staging.rmdir()
        quarantined_replacement.rmdir()
        quarantine_roots[0].rmdir()
        parent.rmdir()
        workspace_runtime.validate_external_workspace(self.review)

    def test_claude_bash_staging_cleanup_rejects_final_parent_swap(self) -> None:
        baseline = providers._claude_bash_staging_baseline(self.review)
        parent = self.review.workspace_root / ".claude"
        parent.mkdir(mode=0o755)
        (parent / ".cc-writes").mkdir(mode=0o700)
        moved_parent = pathlib.Path(self.temporary.name) / "final-parent"
        real_rename = os.rename
        swapped = False

        def replace_parent_before_quarantine(
            source: str,
            destination: str,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal swapped
            if source == ".claude" and not swapped:
                real_rename(parent, moved_parent)
                parent.mkdir(mode=0o755)
                swapped = True
            real_rename(source, destination, *args, **kwargs)

        with mock.patch.object(
            providers.os,
            "rename",
            side_effect=replace_parent_before_quarantine,
        ):
            with self.assertRaisesRegex(
                ReviewError,
                "changed before quarantine removal",
            ):
                providers._remove_claude_bash_staging_directory(
                    self.review,
                    baseline=baseline,
                )

        self.assertTrue(swapped)
        self.assertTrue(moved_parent.is_dir())
        self.assertFalse((moved_parent / ".cc-writes").exists())
        self.assertFalse(parent.exists())
        quarantine_roots = list(
            self.review.container_dir.glob(".claude-bash-staging-quarantine-*")
        )
        self.assertEqual(len(quarantine_roots), 1)
        quarantined_parent = quarantine_roots[0] / "parent"
        self.assertTrue(quarantined_parent.is_dir())
        quarantined_parent.rmdir()
        quarantine_roots[0].rmdir()
        workspace_runtime.validate_external_workspace(self.review)

    def test_claude_bash_staging_cleanup_skips_snapshotted_directory(
        self,
    ) -> None:
        source_staging = self.review.source_root / ".claude" / ".cc-writes"
        source_staging.mkdir(parents=True, mode=0o700)
        tracked = source_staging / "tracked.txt"
        tracked.write_text("snapshotted\n", encoding="utf-8")
        self._git(self.review.source_root, "add", "-f", str(tracked))
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])

        baseline = providers._claude_bash_staging_baseline(review)
        self.assertFalse(baseline.staging_was_absent)
        self.assertEqual(
            providers._remove_claude_bash_staging_directory(
                review,
                baseline=baseline,
            ),
            "preexisting-not-removed",
        )
        self.assertEqual(
            (
                review.workspace_root / ".claude" / ".cc-writes" / "tracked.txt"
            ).read_text(encoding="utf-8"),
            "snapshotted\n",
        )
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    def test_claude_bash_staging_cleanup_rejects_replaced_preexisting_parent(
        self,
    ) -> None:
        source_staging = self.review.source_root / ".claude" / ".cc-writes"
        source_staging.mkdir(parents=True, mode=0o700)
        tracked = source_staging / "tracked.txt"
        tracked.write_text("snapshotted\n", encoding="utf-8")
        self._git(self.review.source_root, "add", "-f", str(tracked))
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])
        baseline = providers._claude_bash_staging_baseline(review)
        self.assertFalse(baseline.staging_was_absent)
        self.assertIsNotNone(baseline.parent_identity)
        parent = review.workspace_root / ".claude"
        moved_parent = pathlib.Path(self.temporary.name) / "preexisting-parent"
        parent.rename(moved_parent)
        replacement_staging = parent / ".cc-writes"
        replacement_staging.mkdir(parents=True, mode=0o700)
        (replacement_staging / "tracked.txt").write_text(
            "snapshotted\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ReviewError, "changed after launch"):
            providers._remove_claude_bash_staging_directory(
                review,
                baseline=baseline,
            )

        self.assertEqual(
            (replacement_staging / "tracked.txt").read_text(encoding="utf-8"),
            "snapshotted\n",
        )
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    def test_claude_bash_staging_cleanup_rechecks_preexisting_parent_path(
        self,
    ) -> None:
        source_staging = self.review.source_root / ".claude" / ".cc-writes"
        source_staging.mkdir(parents=True, mode=0o700)
        tracked = source_staging / "tracked.txt"
        tracked.write_text("snapshotted\n", encoding="utf-8")
        self._git(self.review.source_root, "add", "-f", str(tracked))
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])
        baseline = providers._claude_bash_staging_baseline(review)
        self.assertFalse(baseline.staging_was_absent)
        self.assertIsNotNone(baseline.parent_identity)
        parent = review.workspace_root / ".claude"
        moved_parent = pathlib.Path(self.temporary.name) / "opened-parent"
        real_fstat = os.fstat
        replaced = False

        def replace_parent_after_open(descriptor: int) -> os.stat_result:
            nonlocal replaced
            metadata = real_fstat(descriptor)
            if (
                not replaced
                and providers._claude_directory_identity(metadata)
                == baseline.parent_identity
            ):
                parent.rename(moved_parent)
                replacement_staging = parent / ".cc-writes"
                replacement_staging.mkdir(parents=True, mode=0o700)
                (replacement_staging / "tracked.txt").write_text(
                    "snapshotted\n",
                    encoding="utf-8",
                )
                replaced = True
            return metadata

        with mock.patch.object(
            providers.os,
            "fstat",
            side_effect=replace_parent_after_open,
        ):
            with self.assertRaisesRegex(ReviewError, "changed during cleanup"):
                providers._remove_claude_bash_staging_directory(
                    review,
                    baseline=baseline,
                )

        self.assertTrue(replaced)
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    def test_claude_bash_staging_cleanup_skips_snapshotted_symlink(self) -> None:
        source_parent = self.review.source_root / ".claude"
        source_parent.mkdir(mode=0o755)
        source_staging = source_parent / ".cc-writes"
        source_staging.symlink_to("../review-staging-target")
        self._git(self.review.source_root, "add", "-f", str(source_staging))
        handed_off: list[ReviewWorkspace] = []
        review = workspace_runtime.prepare_workspace(
            repo=self.review.source_root,
            base_ref=self.review.base_ref,
            head_ref=self.review.head_ref,
            include_source_wip=True,
            ownership_handoff=handed_off.append,
        )
        self.assertEqual(handed_off, [review])

        baseline = providers._claude_bash_staging_baseline(review)
        self.assertFalse(baseline.staging_was_absent)
        self.assertEqual(
            providers._remove_claude_bash_staging_directory(
                review,
                baseline=baseline,
            ),
            "preexisting-not-removed",
        )
        materialized = review.workspace_root / ".claude" / ".cc-writes"
        self.assertTrue(materialized.is_symlink())
        self.assertEqual(os.readlink(materialized), "../review-staging-target")
        workspace_runtime.validate_external_workspace(review)
        self.assertIsNone(
            workspace_runtime.cleanup_workspace(review, keep_container=False)
        )

    @mock.patch.object(providers, "_parse_claude_stream_output_file")
    @mock.patch.object(providers, "run")
    def test_claude_attempt_rejects_post_run_workspace_mutation_before_acceptance(
        self,
        run_command: mock.Mock,
        parse_stream: mock.Mock,
    ) -> None:
        def complete(argv: tuple[str, ...], **kwargs: object) -> Completed:
            if "auth" in argv:
                payload = claude_auth_status_fixture("local-login")
            else:
                payload = claude_stream_fixture(self.review)
                (self.review.workspace_root / "managed-policy-write.txt").write_text(
                    "observable post-launch mutation\n",
                    encoding="utf-8",
                )
            stdout_path = pathlib.Path(kwargs["stdout_path"])
            stderr_path = pathlib.Path(kwargs["stderr_path"])
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_bytes(payload)
            stderr_path.write_bytes(b"")
            return Completed(argv=argv, returncode=0, stdout=payload, stderr=b"")

        run_command.side_effect = complete
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)
        common.write_json(
            self.review.container_dir / "claude-runtime.json",
            {"schema": 1, "phase": "publisher-and-cli-contract-verified"},
        )
        common.write_json(
            self.review.container_dir / "egress.json",
            {
                "authentication": {
                    "requested_source": "local-login",
                    "status": "pending-effective-preflight",
                }
            },
        )

        attempt = providers._claude_attempt(
            review=self.review,
            model="claude-opus-4-8",
            index=1,
            env={
                "HOME": str(self.claude_pwd_home),
                "TMPDIR": str(temporary),
                "TMP": str(temporary),
                "TEMP": str(temporary),
                "CLAUDE_CODE_TMPDIR": str(temporary),
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
            },
            executable=pathlib.Path("/bin/claude"),
        )

        self.assertEqual(attempt.returncode, 65)
        self.assertEqual(attempt.category, "permission-mismatch")
        self.assertIsNone(attempt.final_text)
        parse_stream.assert_not_called()
        diagnostic = pathlib.Path(attempt.stderr_path).read_text(encoding="utf-8")
        self.assertIn(
            "post-attempt external review workspace validation failed", diagnostic
        )
        self.assertNotIn("managed-policy-write.txt", diagnostic)
        report = common.read_json(self.review.container_dir / "claude-runtime.json")
        self.assertEqual(
            report["capabilities"]["post_attempt_workspace_contract"],
            "rejected",
        )
        self.assertEqual(report["authentication"]["status"], "effective-auth-verified")
        self.assertEqual(report["attempt"]["category"], "permission-mismatch")
        egress = common.read_json(self.review.container_dir / "egress.json")
        self.assertEqual(
            egress["authentication"]["status"],
            "effective-auth-verified",
        )
        self.assertNotIn("effective_init_contract", egress["authentication"])

    @mock.patch.object(
        providers,
        "validate_external_workspace",
        side_effect=ReviewError("do not persist this mutation detail"),
    )
    @mock.patch.object(providers, "_parse_claude_stream_output_file")
    @mock.patch.object(providers, "run")
    def test_claude_attempt_validates_workspace_after_nonzero_completion(
        self,
        run_command: mock.Mock,
        parse_stream: mock.Mock,
        validate_workspace: mock.Mock,
    ) -> None:
        def complete(argv: tuple[str, ...], **kwargs: object) -> Completed:
            is_auth = "auth" in argv
            payload = claude_auth_status_fixture("local-login") if is_auth else b""
            stderr = b"" if is_auth else b"review command failed\n"
            stdout_path = pathlib.Path(kwargs["stdout_path"])
            stderr_path = pathlib.Path(kwargs["stderr_path"])
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_bytes(payload)
            stderr_path.write_bytes(stderr)
            return Completed(
                argv=argv,
                returncode=0 if is_auth else 1,
                stdout=payload,
                stderr=stderr,
            )

        run_command.side_effect = complete
        temporary = self.review.container_dir / "tmp"
        temporary.mkdir(exist_ok=True)

        attempt = providers._claude_attempt(
            review=self.review,
            model="claude-opus-4-8",
            index=1,
            env={
                "HOME": str(self.claude_pwd_home),
                "TMPDIR": str(temporary),
                "TMP": str(temporary),
                "TEMP": str(temporary),
                "CLAUDE_CODE_TMPDIR": str(temporary),
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
            },
            executable=pathlib.Path("/bin/claude"),
        )

        validate_workspace.assert_called_once_with(self.review)
        self.assertEqual(attempt.returncode, 65)
        self.assertEqual(attempt.category, "permission-mismatch")
        self.assertIsNone(attempt.final_text)
        parse_stream.assert_not_called()
        diagnostic = pathlib.Path(attempt.stderr_path).read_text(encoding="utf-8")
        self.assertNotIn("do not persist this mutation detail", diagnostic)

    @mock.patch.object(providers, "run")
    def test_claude_auth_preflight_expands_escaped_output_redactions_before_run(
        self,
        run_command: mock.Mock,
    ) -> None:
        secret = 'line\n"slash\\snowman☃'
        payload = claude_auth_status_fixture("api-key")
        run_command.return_value = Completed(
            argv=("claude", "auth", "status", "--json"),
            returncode=0,
            stdout=payload,
            stderr=b"",
        )

        providers._claude_authentication_preflight(
            review=self.review,
            executable=pathlib.Path("/bin/claude"),
            env={
                "HOME": str(self.claude_pwd_home),
                "ANTHROPIC_API_KEY": secret,
            },
            settings="{}",
            index=1,
            redact_values=(secret,),
        )

        variants = run_command.call_args.kwargs["redact_values"]
        self.assertEqual(variants, common.output_redact_values((secret,)))
        self.assertIn(secret, variants)
        self.assertIn(json.dumps(secret, ensure_ascii=True)[1:-1], variants)
        self.assertIn(json.dumps(secret, ensure_ascii=False)[1:-1], variants)
        self.assertIn(repr(secret)[1:-1], variants)
        self.assertIn(ascii(secret)[1:-1], variants)

    @mock.patch.object(providers, "run")
    def test_claude_auth_preflight_maps_nonzero_logged_out_status_to_blocked_auth(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("claude", "auth", "status", "--json"),
            returncode=1,
            stdout=json.dumps(
                {
                    "loggedIn": False,
                    "authMethod": "none",
                    "apiProvider": "firstParty",
                }
            ).encode(),
            stderr=b"",
        )
        api_key = "<ANTHROPIC_API_KEY>"
        oauth_token = "<CLAUDE_CODE_OAUTH_TOKEN>"
        cases = (
            (
                "local-login",
                {"HOME": str(self.claude_pwd_home)},
                providers.CLAUDE_AUTH_LOGIN_ACTION,
            ),
            (
                "api-key",
                {
                    "HOME": str(self.claude_pwd_home),
                    "ANTHROPIC_API_KEY": api_key,
                },
                providers.CLAUDE_API_KEY_ACTION,
            ),
            (
                "oauth-token",
                {
                    "HOME": str(self.claude_pwd_home),
                    "CLAUDE_CODE_OAUTH_TOKEN": oauth_token,
                },
                providers.CLAUDE_OAUTH_TOKEN_ACTION,
            ),
        )
        for index, (source, env, expected_action) in enumerate(cases, start=1):
            with self.subTest(source=source):
                for name in ("claude-runtime.json", "egress.json"):
                    common.write_json(
                        self.review.container_dir / name,
                        {
                            "authentication": {
                                "requested_source": source,
                                "status": "pending-effective-preflight",
                            }
                        },
                    )

                with self.assertRaises(
                    providers.ClaudeAuthenticationPreflightBlocked
                ) as blocked:
                    providers._claude_authentication_preflight(
                        review=self.review,
                        executable=pathlib.Path("/bin/claude"),
                        env=env,
                        settings="{}",
                        index=index,
                        redact_values=tuple(
                            value
                            for key, value in env.items()
                            if key in providers.CLAUDE_EXPLICIT_AUTH_ENV_KEYS
                        ),
                    )

                self.assertEqual(blocked.exception.action, expected_action)
                for name in ("claude-runtime.json", "egress.json"):
                    authentication = json.loads(
                        (self.review.container_dir / name).read_text(encoding="utf-8")
                    )["authentication"]
                    self.assertEqual(authentication["requested_source"], source)
                    self.assertIs(authentication["logged_in"], False)
                    self.assertEqual(
                        authentication["effective_api_provider"], "firstParty"
                    )
                    self.assertEqual(authentication["effective_auth_method"], "none")
                    self.assertIsNone(authentication["effective_api_key_source"])
                    self.assertEqual(
                        authentication["status"], "effective-auth-rejected"
                    )

    @mock.patch.object(providers, "run")
    def test_claude_auth_preflight_rejects_nonzero_malformed_status_as_runtime_failure(
        self,
        run_command: mock.Mock,
    ) -> None:
        cases = (
            {"authMethod": "none", "apiProvider": "firstParty"},
            {
                "loggedIn": "false",
                "authMethod": "none",
                "apiProvider": "firstParty",
            },
            {"loggedIn": 0, "authMethod": "none", "apiProvider": "firstParty"},
        )
        for index, payload in enumerate(cases, start=1):
            with self.subTest(payload=payload):
                run_command.return_value = Completed(
                    argv=("claude", "auth", "status", "--json"),
                    returncode=1,
                    stdout=json.dumps(payload).encode(),
                    stderr=b"",
                )
                for name in ("claude-runtime.json", "egress.json"):
                    common.write_json(
                        self.review.container_dir / name,
                        {
                            "authentication": {
                                "requested_source": "local-login",
                                "status": "pending-effective-preflight",
                            }
                        },
                    )

                with self.assertRaisesRegex(
                    ReviewError,
                    "auth-status preflight failed",
                ):
                    providers._claude_authentication_preflight(
                        review=self.review,
                        executable=pathlib.Path("/bin/claude"),
                        env={"HOME": str(self.claude_pwd_home)},
                        settings="{}",
                        index=index,
                        redact_values=(),
                    )

                for name in ("claude-runtime.json", "egress.json"):
                    authentication = json.loads(
                        (self.review.container_dir / name).read_text(encoding="utf-8")
                    )["authentication"]
                    self.assertEqual(
                        authentication["status"], "pending-effective-preflight"
                    )

    @mock.patch.object(providers, "run")
    def test_claude_auth_preflight_rejects_nonzero_usable_status_as_runtime_failure(
        self,
        run_command: mock.Mock,
    ) -> None:
        run_command.return_value = Completed(
            argv=("claude", "auth", "status", "--json"),
            returncode=1,
            stdout=claude_auth_status_fixture("local-login"),
            stderr=b"",
        )
        for name in ("claude-runtime.json", "egress.json"):
            common.write_json(
                self.review.container_dir / name,
                {
                    "authentication": {
                        "requested_source": "local-login",
                        "status": "pending-effective-preflight",
                    }
                },
            )

        with self.assertRaisesRegex(
            ReviewError,
            "returned failure despite reporting usable authentication",
        ):
            providers._claude_authentication_preflight(
                review=self.review,
                executable=pathlib.Path("/bin/claude"),
                env={"HOME": str(self.claude_pwd_home)},
                settings="{}",
                index=1,
                redact_values=(),
            )

        for name in ("claude-runtime.json", "egress.json"):
            authentication = json.loads(
                (self.review.container_dir / name).read_text(encoding="utf-8")
            )["authentication"]
            self.assertEqual(authentication["status"], "pending-effective-preflight")

    @mock.patch.object(providers, "run")
    def test_claude_auth_preflight_records_observed_mismatch_without_claiming_carrier(
        self,
        run_command: mock.Mock,
    ) -> None:
        payload = json.dumps(
            {
                "loggedIn": True,
                "authMethod": "api_key",
                "apiProvider": "firstParty",
                "apiKeySource": "apiKeyHelper",
            }
        ).encode()
        run_command.return_value = Completed(
            argv=("claude", "auth", "status", "--json"),
            returncode=0,
            stdout=payload,
            stderr=b"",
        )
        for name in ("claude-runtime.json", "egress.json"):
            common.write_json(
                self.review.container_dir / name,
                {
                    "authentication": {
                        "requested_source": "local-login",
                        "status": "pending-effective-preflight",
                    }
                },
            )

        with self.assertRaises(providers.ClaudeAuthenticationPreflightBlocked):
            providers._claude_authentication_preflight(
                review=self.review,
                executable=pathlib.Path("/bin/claude"),
                env={"HOME": str(self.claude_pwd_home)},
                settings="{}",
                index=1,
                redact_values=(),
            )

        for name in ("claude-runtime.json", "egress.json"):
            authentication = json.loads(
                (self.review.container_dir / name).read_text(encoding="utf-8")
            )["authentication"]
            self.assertEqual(authentication["requested_source"], "local-login")
            self.assertEqual(authentication["effective_auth_method"], "api_key")
            self.assertEqual(authentication["effective_api_key_source"], "apiKeyHelper")
            self.assertEqual(authentication["status"], "effective-auth-rejected")
            self.assertNotIn("source", authentication)
            self.assertNotIn("effective_source", authentication)

    @mock.patch.object(providers, "_claude_review_prompt")
    @mock.patch.object(
        providers,
        "_claude_authentication_preflight",
        side_effect=providers.ClaudeAuthenticationPreflightBlocked(
            "unsupported auth source",
            action="Remove it.",
        ),
    )
    def test_claude_auth_preflight_blocks_before_review_prompt_projection(
        self,
        _authentication_preflight: mock.Mock,
        review_prompt: mock.Mock,
    ) -> None:
        with self.assertRaises(providers.ClaudeAuthenticationPreflightBlocked):
            providers._claude_attempt(
                review=self.review,
                model="claude-opus-4-8",
                index=1,
                env={"HOME": str(self.claude_pwd_home)},
                executable=pathlib.Path("/bin/claude"),
            )

        review_prompt.assert_not_called()

    @mock.patch.object(providers, "_claude_attempt")
    @mock.patch.object(providers, "_resolve_validated_claude_executable")
    @mock.patch.object(providers, "child_environment")
    def test_claude_local_login_does_not_use_keychain_broker(
        self,
        environment: mock.Mock,
        resolve: mock.Mock,
        claude_attempt: mock.Mock,
    ) -> None:
        environment.return_value = {"HOME": str(self.claude_pwd_home)}
        resolve.return_value = (
            pathlib.Path("/bin/claude"),
            {"HOME": str(self.claude_pwd_home)},
        )
        claude_attempt.return_value = self.attempt(
            "claude",
            providers.CLAUDE_MODELS[0],
            "success",
            final_text="No findings.",
        )

        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            egress_consent="explicit-claude-review",
        )

        error_path = self.review.container_dir / "runner-error.txt"
        self.assertEqual(
            outcome.returncode,
            0,
            error_path.read_text(encoding="utf-8") if error_path.exists() else "",
        )
        self.assertFalse(hasattr(providers, "_prepare_claude_keychain_broker"))
        self.assertEqual(
            claude_attempt.call_args.kwargs["env"]["HOME"],
            str(self.claude_pwd_home),
        )


if __name__ == "__main__":
    unittest.main()
