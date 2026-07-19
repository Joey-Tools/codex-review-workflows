from __future__ import annotations

import inspect
import pathlib
import subprocess
import sys
import tempfile
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_SCOPE_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_linux,
    claude_refresh_lock,
    providers,
)


EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS = {
    (
        "2.1.211",
        "darwin-arm64",
        "5a728a76198b6eca7f3c7cdbff43bab44b77b48c2108f7a3107d889773382629",
    ),
    (
        "2.1.211",
        "darwin-x64",
        "33049eb14cf4702b992b7eda41ec077fc6e76539f7fd046e6d32538757235da4",
    ),
    (
        "2.1.211",
        "linux-arm64",
        "1fff7e8f947c07b19d10b1fbf714b7e547e9536253b9b58230d8adbc4624f867",
    ),
    (
        "2.1.211",
        "linux-x64",
        "8272c8a474ac9ea1bc35f19b9f7c7e7dc4dc4eb6d5ad3e484b19335ac72446b2",
    ),
    (
        "2.1.211",
        "linux-arm64-musl",
        "ca094a85ea464b2ebec2ecfcc9e2c056573d4ca95ebe12ffae2c7dccb722e17b",
    ),
    (
        "2.1.211",
        "linux-x64-musl",
        "c99bd7934ac841d5be6ee7d3644cb63bccef2cd495c6c1bb982a1b1deac1b466",
    ),
}


CI_FIXTURE_ROOT = SKILL_ROOT / "tests" / "fixtures" / "ci"
CI_PROFILE_BY_SKILL_LAYOUT = {
    pathlib.Path("skills/review-orchestration-playbook"): "canonical",
    pathlib.Path(
        "personal_codex/skills/review-orchestration-playbook"
    ): "private",
}


def _ci_contract_context(skill_root: pathlib.Path) -> tuple[pathlib.Path, str]:
    layouts = sorted(
        CI_PROFILE_BY_SKILL_LAYOUT.items(),
        key=lambda item: len(item[0].parts),
        reverse=True,
    )
    for layout, profile in layouts:
        layout_depth = len(layout.parts)
        if skill_root.parts[-layout_depth:] != layout.parts:
            continue
        repo_root = skill_root.parents[layout_depth - 1]
        if repo_root / layout != skill_root:
            continue
        return repo_root, profile
    raise AssertionError(f"unsupported review skill layout: {skill_root}")


REPO_ROOT, CI_PROFILE = _ci_contract_context(SKILL_ROOT)


def _claude_auth_repository_policy_files(
    repo_root: pathlib.Path,
    profile: str,
) -> dict[str, str]:
    policy_paths: dict[str, pathlib.Path] = {}
    if profile == "canonical":
        policy_paths = {
            "AGENTS.md": repo_root / "AGENTS.md",
            "README.md": repo_root / "README.md",
            "project journal": (
                repo_root
                / "docs/project_journal/2026/07/"
                / "2026-07-17-claude-auth-carriers-c17a11.md"
            ),
        }
    elif profile != "private":
        raise AssertionError(f"unsupported repository policy profile: {profile}")
    return {
        name: path.read_text(encoding="utf-8")
        for name, path in policy_paths.items()
    }


class RepositoryContractTest(unittest.TestCase):
    def test_only_canonical_review_skill_entrypoint_remains(self) -> None:
        self.assertTrue((SKILL_ROOT / "SKILL.md").is_file())
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("installs a readonly Git shim", skill)
        for relative in (
            "skills/external-review-playbook/SKILL.md",
            "skills/pr-readiness-review-workflow/SKILL.md",
            "skills/copilot-review-playbook/SKILL.md",
            "skills/review-orchestration-playbook/scripts/isolated_external_review",
            "skills/review-orchestration-playbook/scripts/isolated_copilot_review",
            "skills/review-orchestration-playbook/scripts/git_readonly_shim",
        ):
            self.assertFalse((SKILL_SCOPE_ROOT / relative).exists(), relative)

    def test_healthy_bounded_wait_is_not_task_completion(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("only an intermediate poll, not task completion", skill)
        self.assertIn("Keep the parent task active", skill)
        self.assertIn("do not end the task merely because one wait window expires", skill)

    def test_models_are_pinned_in_runtime_and_clean_context_agent(self) -> None:
        self.assertEqual(providers.CODEX_MODELS, ("gpt-5.6-sol", "gpt-5.5"))
        self.assertEqual(providers.CODEX_REASONING_EFFORT, "xhigh")
        self.assertEqual(
            providers.CLAUDE_MODELS,
            ("claude-opus-4-8", "claude-opus-4-7"),
        )
        self.assertEqual(
            providers.COPILOT_MODELS,
            ("claude-opus-4.8", "claude-opus-4.7"),
        )
        for candidate in (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/helper-contract.md",
        ):
            self.assertNotIn(
                "claude-sonnet-5",
                candidate.read_text(encoding="utf-8"),
                str(candidate),
            )
        with (SKILL_SCOPE_ROOT / "agents/reviewer.toml").open("rb") as handle:
            reviewer = tomllib.load(handle)
        self.assertEqual(reviewer["model"], "gpt-5.6-sol")
        self.assertEqual(reviewer["model_reasoning_effort"], "xhigh")

    def test_claude_policy_defaults_to_local_login_in_safe_mode(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("ordinary local Claude login by default", skill)
        self.assertIn("runs in safe mode", helper_contract)
        self.assertIn(
            "hardening-compatible `default` permission mode",
            helper_contract,
        )
        self.assertIn(
            "helper-owned outer sandbox",
            helper_contract,
        )
        self.assertNotIn("safe mode with `dontAsk` permissions", helper_contract)
        self.assertIn("per-version signed manifest", helper_contract)
        self.assertIn("manifest checksum", helper_contract)
        self.assertIn("downloads.claude.ai", helper_contract)
        self.assertIn("deny-by-default Seatbelt profile", helper_contract)
        self.assertIn("current-account `Claude Code-credentials`", helper_contract)
        self.assertIn("helper-controlled proxy", helper_contract)
        self.assertIn(">=2.1.211,<3.0.0", helper_contract)
        self.assertIn("Linux and WSL2", helper_contract)
        self.assertNotIn("requires `ANTHROPIC_API_KEY`", skill)

    def test_claude_auth_carriers_refresh_without_a_freshness_gate(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (
            SKILL_ROOT / "references/claude-runtime-trust.md"
        ).read_text(encoding="utf-8")

        egress_consent = (
            SKILL_ROOT / "references/egress-consent.md"
        ).read_text(encoding="utf-8")
        repository_policy_files = _claude_auth_repository_policy_files(
            REPO_ROOT,
            CI_PROFILE,
        )

        self.assertEqual(claude_capabilities.CLAUDE_MINIMUM_VERSION, (2, 1, 211))
        self.assertEqual(claude_linux.DEFAULT_CREDENTIAL_VALIDITY_SECONDS, 0.0)
        self.assertFalse(hasattr(providers, "CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS"))
        self.assertFalse(
            hasattr(providers, "CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS")
        )

        attempt_source = inspect.getsource(providers._claude_attempt)
        pwd_home_source = inspect.getsource(providers._claude_pwd_home)
        select_source = inspect.getsource(providers._select_claude_macos_credential)
        validate_source = inspect.getsource(
            providers._validate_claude_local_credential
        )
        macos_runtime_source = inspect.getsource(providers._claude_keychain_runtime)
        macos_persist_source = inspect.getsource(
            providers._persist_claude_macos_refreshed_credential
        ) + inspect.getsource(
            providers._persist_claude_macos_refreshed_credential_impl
        )
        macos_recovery_report_source = inspect.getsource(
            providers._record_claude_secondary_persistence_failure
        )
        run_review_source = inspect.getsource(providers.run_review)
        auth_outcome_source = inspect.getsource(
            providers._finish_claude_auth_required
        )
        linux_runtime_source = inspect.getsource(
            providers._claude_linux_review_runtime
        )
        linux_command_source = inspect.getsource(claude_linux.build_sandbox_command)
        keychain_write_source = inspect.getsource(
            providers._write_claude_keychain_credential
        )
        file_write_source = inspect.getsource(
            providers._write_claude_file_credential
        )
        linux_write_source = inspect.getsource(
            claude_linux._writeback_refreshed_credential_impl
        )
        linux_staging_source = inspect.getsource(
            claude_linux.stage_claude_credentials
        )
        linux_anchored_staging_source = inspect.getsource(
            claude_linux._stage_claude_credentials_anchored
        )
        refresh_lock_source = inspect.getsource(
            claude_refresh_lock.acquire_claude_refresh_lock
        )
        staged_lock_recovery_source = inspect.getsource(
            claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks
        )

        self.assertNotIn("_warm_claude_local_login", attempt_source)
        self.assertNotIn("authentication-preflight-entitlement", attempt_source)
        self.assertNotIn("freshness-verified", attempt_source)
        self.assertIn("_prepare_claude_tls_environment", attempt_source)
        self.assertIn("_claude_keychain_runtime", attempt_source)
        self.assertIn("_claude_linux_review_runtime", attempt_source)

        self.assertIn("pwd.getpwuid(os.getuid()).pw_dir", pwd_home_source)
        self.assertNotIn('os.environ.get("HOME")', pwd_home_source)
        self.assertIn("_read_claude_keychain_credential", select_source)
        self.assertIn("_read_claude_macos_file_credential", select_source)
        self.assertIn("selected = max(", select_source)
        self.assertIn("candidate.expires_at_ms", select_source)
        self.assertIn("selected.carrier_snapshot", select_source)
        self.assertIn("refreshToken", validate_source)
        self.assertIn(
            "_persist_claude_macos_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "_retain_claude_macos_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "_replace_claude_macos_recovery_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "durable-recovery-before-ack",
            macos_runtime_source,
        )
        self.assertIn("commit_pending", macos_runtime_source)
        self.assertIn(
            "update_callback=stage_refreshed_credential",
            macos_runtime_source,
        )
        self.assertNotIn(
            "update_callback=accept_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn("_write_claude_keychain_credential", macos_persist_source)
        self.assertIn("_write_claude_file_credential", macos_persist_source)
        self.assertNotIn("require_unexpired=True", macos_runtime_source)
        self.assertNotIn("require_unexpired=True", macos_persist_source)
        self.assertIn(
            'authentication_report["recovery_cleanup_artifact"]',
            macos_recovery_report_source,
        )

        self.assertIn("stage_claude_credentials", linux_runtime_source)
        self.assertIn("writer_started", linux_runtime_source)
        self.assertIn("writer_quiescent", linux_runtime_source)
        self.assertIn("on_process_started=writer_started.set", attempt_source)
        self.assertIn("writer_quiescent.set()", attempt_source)
        self.assertIn(
            "retain_for_recovery",
            linux_staging_source + linux_anchored_staging_source,
        )
        self.assertIn("writer_quiescent is not True", staged_lock_recovery_source)
        self.assertIn("reversed(locks)", staged_lock_recovery_source)
        self.assertNotIn("math.nextafter", linux_runtime_source)
        self.assertNotIn("staged.expires_at_ms <= time.time()", linux_runtime_source)
        self.assertNotIn("_require_fresh_claude_linux_credential", run_review_source)
        self.assertEqual(str(claude_linux.SANDBOX_AUTH_ROOT), "/auth")
        self.assertEqual(str(claude_linux.SANDBOX_CONFIG), "/auth/config")
        self.assertIn(
            '"CLAUDE_CONFIG_DIR": str(SANDBOX_CONFIG)',
            linux_command_source,
        )

        carrier_policy_files = {
            "SKILL.md": skill,
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
        }
        for name in ("README.md", "project journal"):
            if policy := repository_policy_files.get(name):
                carrier_policy_files[name] = policy
        for name, policy in carrier_policy_files.items():
            with self.subTest(policy=name):
                normalized = policy.lower()
                self.assertIn("/auth/config", policy)
                self.assertIn("final drain", normalized)
                self.assertIn("recovery carrier", normalized)
                self.assertNotIn("read(//config", normalized)
                self.assertNotIn("at `/config`", policy)
                self.assertNotIn("mounts only that carrier at `/config`", policy)

        macos_recovery_policy_files = {
            "SKILL.md": skill,
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
        }
        if journal := repository_policy_files.get("project journal"):
            macos_recovery_policy_files["project journal"] = journal
        for name, policy in macos_recovery_policy_files.items():
            with self.subTest(macos_recovery_policy=name):
                normalized = policy.lower()
                self.assertIn("macos", normalized)
                self.assertIn("private recovery carrier", normalized)
                self.assertIn("copilot fallback", normalized)

        macos_quiescence_policy_files = {
            "SKILL.md": skill,
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
            **repository_policy_files,
        }
        for name, policy in macos_quiescence_policy_files.items():
            with self.subTest(macos_quiescence_policy=name):
                normalized = policy.lower()
                self.assertRegex(normalized, r"quiesc(?:e|ence)")
                self.assertIn("recovery_cleanup_artifact", policy)
                self.assertIn("incomplete", normalized)
                self.assertNotIn("before acknowledging", normalized)
                self.assertNotIn("every accepted rotation", normalized)
                self.assertNotIn(
                    "persist macos broker rotations before",
                    normalized,
                )

        macos_terminal_reserve_policy_files = {
            "SKILL.md": skill,
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
            **repository_policy_files,
        }
        for name, policy in macos_terminal_reserve_policy_files.items():
            with self.subTest(macos_terminal_reserve_policy=name):
                normalized = policy.lower()
                self.assertIn("admitted to durable staging", normalized)
                self.assertIn("last generation and 1 mib", normalized)
                self.assertNotIn(
                    "reaching either journal cap nacks the generation",
                    normalized,
                )
                self.assertNotIn(
                    "nack the generation before filesystem work",
                    normalized,
                )

        self.assertIn(
            "durably stages its exact payload",
            skill,
        )
        self.assertIn(
            "later requests are NACKed before callbacks",
            skill,
        )
        self.assertIn(
            "durably stage that current update in the terminal recovery slot",
            runtime_trust,
        )
        self.assertIn(
            "NACK later requests before their callbacks or filesystem work",
            runtime_trust,
        )

        protocol = claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211
        self.assertEqual(protocol.primary_lock_name, ".oauth_refresh.lock")
        self.assertEqual(protocol.legacy_suffix, ".lock")
        self.assertEqual(protocol.stale_seconds, 60.0)
        self.assertEqual(protocol.update_seconds, 5.0)
        self.assertEqual(
            set(claude_refresh_lock.CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS),
            EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS,
        )
        self.assertLess(
            refresh_lock_source.index('label="primary"'),
            refresh_lock_source.index('label="legacy"'),
        )
        for write_source in (keychain_write_source, file_write_source):
            self.assertIn("claude_refresh_lock", write_source)
            self.assertIn("_claude_macos_carriers_match", write_source)
            self.assertIn("refresh_lock.assert_held()", write_source)
            self.assertIn("refresh_lock_protocol", write_source)
        self.assertIn("acquire_claude_refresh_lock", linux_write_source)
        self.assertIn("refresh_lock.assert_held()", linux_write_source)
        self.assertIn("refresh_lock_protocol", linux_write_source)
        self.assertIn("_certified_claude_refresh_lock_protocol", attempt_source)
        self.assertIn('env.get("ANTHROPIC_API_KEY")', attempt_source)

        self.assertIn('"phase": "blocked-authentication"', auth_outcome_source)
        self.assertIn("CLAUDE_AUTH_LOGIN_ACTION", auth_outcome_source)
        self.assertIn("_finish_claude_auth_required", run_review_source)
        self.assertIn("validate_external_workspace", run_review_source)
        self.assertIn("sensitive-content and escaping-symlink checks passed", run_review_source)

        current_policy = "\n".join(
            (
                skill,
                helper_contract,
                runtime_trust,
                egress_consent,
                repository_policy_files.get("AGENTS.md", ""),
            )
        )
        self.assertIn(">=2.1.211,<3.0.0", current_policy)
        self.assertIn("pwd.getpwuid(os.getuid())", current_policy)
        self.assertIn("empirically compatible", current_policy)
        self.assertIn("not an officially guaranteed storage contract", current_policy)
        self.assertIn("guarded writeback", current_policy)
        self.assertIn("not an atomic compare-and-swap guarantee", current_policy)
        self.assertIn("primary `.oauth_refresh.lock`", current_policy)
        self.assertIn("legacy sibling lock", current_policy)
        self.assertIn("bypass both locks", current_policy)
        self.assertIn("credential-lock protocol catalog", current_policy)
        self.assertIn("certified 5-second heartbeat", current_policy)
        self.assertIn("both carriers", current_policy)
        self.assertIn("inspection-inconclusive", current_policy)
        self.assertIn("Access-token expiry alone is not login expiry", current_policy)
        self.assertIn("blocked-authentication", current_policy)
        self.assertIn("claude auth login", current_policy)
        for policy in (skill, helper_contract, runtime_trust):
            self.assertIn("claude auth login", policy)
            self.assertIn("ANTHROPIC_API_KEY", policy)
            self.assertIn("unset or replace", policy)
        self.assertIn("secure Claude runtime is deterministically absent/unavailable", current_policy)
        self.assertIn("model entitlement", current_policy)
        self.assertNotIn("has no usable local/API authentication", current_policy)
        self.assertNotIn("1920", current_policy)

    def test_claude_linux_file_tools_are_workspace_only_across_supported_versions(
        self,
    ) -> None:
        self.assertEqual(claude_linux.CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS, "Read")
        self.assertEqual(
            claude_linux.CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS,
            "Read(./**)",
        )
        self.assertEqual(
            claude_linux.CLAUDE_LINUX_REVIEW_PERMISSION_MODE,
            "dontAsk",
        )
        cli_denies = set(
            claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS.split(",")
        )
        self.assertTrue({"Grep", "Glob"}.issubset(cli_denies))
        self.assertIn(
            "Read(//auth/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertIn(
            "Read(//proc/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertNotIn(
            "Read(/auth/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )

    def test_ci_targets_only_the_canonical_runtime_and_tests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("review-orchestration-playbook/tests", workflow)
        self.assertNotIn("external-review-playbook", workflow)
        self.assertNotIn("copilot-review-playbook", workflow)

    def test_ci_matches_the_reviewed_repo_profile_snapshot(self) -> None:
        actual = (REPO_ROOT / ".github/workflows/ci.yml").read_bytes()
        expected = (CI_FIXTURE_ROOT / f"{CI_PROFILE}.yml").read_bytes()

        self.assertEqual(
            actual,
            expected,
            f"CI workflow differs from reviewed {CI_PROFILE} snapshot",
        )

    def test_ci_contract_context_accepts_only_supported_layouts(self) -> None:
        cases = (
            (
                pathlib.Path("/repo/skills/review-orchestration-playbook"),
                (pathlib.Path("/repo"), "canonical"),
            ),
            (
                pathlib.Path(
                    "/repo/personal_codex/skills/review-orchestration-playbook"
                ),
                (pathlib.Path("/repo"), "private"),
            ),
        )
        for skill_root, expected in cases:
            with self.subTest(skill_root=skill_root):
                self.assertEqual(_ci_contract_context(skill_root), expected)

        with self.assertRaisesRegex(AssertionError, "unsupported review skill layout"):
            _ci_contract_context(pathlib.Path("/repo/custom/review-playbook"))

    def test_ci_contract_carries_every_reviewed_profile_snapshot(self) -> None:
        self.assertEqual(
            set(CI_PROFILE_BY_SKILL_LAYOUT.values()),
            {"canonical", "private"},
        )
        for profile in CI_PROFILE_BY_SKILL_LAYOUT.values():
            with self.subTest(profile=profile):
                self.assertTrue((CI_FIXTURE_ROOT / f"{profile}.yml").is_file())

    def test_claude_auth_policy_files_match_distribution_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir)
            (repo_root / "README.md").write_text("unrelated\n", encoding="utf-8")

            self.assertEqual(
                _claude_auth_repository_policy_files(repo_root, "private"),
                {},
            )
            with self.assertRaises(FileNotFoundError):
                _claude_auth_repository_policy_files(repo_root, "canonical")
            with self.assertRaisesRegex(
                AssertionError,
                "unsupported repository policy profile",
            ):
                _claude_auth_repository_policy_files(repo_root, "unknown")

    def test_reviewed_ci_snapshots_keep_the_intended_status_guards(self) -> None:
        canonical = (CI_FIXTURE_ROOT / "canonical.yml").read_text(encoding="utf-8")
        private = (CI_FIXTURE_ROOT / "private.yml").read_text(encoding="utf-8")

        self.assertIn(
            """  test:
    name: test
    if: ${{ always() }}
    needs: platform_tests
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
""",
            canonical,
        )
        self.assertIn(
            """  test:
    name: test
    if: ${{ always() }}
    needs:
      - platform_tests
      - python-39-compatibility
      - platform-safety
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
          PYTHON_39_RESULT: ${{ needs.python-39-compatibility.result }}
          PLATFORM_SAFETY_RESULT: ${{ needs.platform-safety.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
          test "$PYTHON_39_RESULT" = "success"
          test "$PLATFORM_SAFETY_RESULT" = "success"
""",
            private,
        )

    def test_helper_declares_and_tests_its_minimum_python_runtime(self) -> None:
        entrypoint = (SCRIPTS / "isolated_review").read_text(encoding="utf-8")
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        guard = "if sys.version_info < (3, 10):"
        self.assertIn(guard, entrypoint)
        self.assertLess(entrypoint.index(guard), entrypoint.index("from review_runtime"))
        self.assertIn('python-version: "3.10"', workflow)
        self.assertIn("tomli==2.2.1", workflow)
        self.assertIn("requires Python 3.10 or later", readme)

    def test_full_pr_readiness_retains_both_local_codex_gates(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        for value in (readiness, contracts):
            self.assertIn("independent-codex-pr-review", value)
            self.assertIn("offline-frozen-diff-review", value)
        self.assertIn("standalone double/triple-review", readiness)
        self.assertLess(
            readiness.index("3. Run `offline-frozen-diff-review` first"),
            readiness.index("4. After the helper preflight passes"),
        )
        self.assertIn("Require its retained `preflight.json`", readiness)

    def test_independent_codex_process_output_is_task_scoped_and_bounded(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("stdout and stderr in task-scoped bounded sinks", readiness)
        self.assertIn("--output-last-message <task-scoped-target>", readiness)
        self.assertIn("byte limits for each process log and the final-message", readiness)
        self.assertIn("default 30-minute / 16-MiB / 64-KiB limits", readiness)
        self.assertIn("deadline expires or any output limit", readiness)
        self.assertIn("limit-terminated attempt is inconclusive", readiness)
        self.assertIn("bounded sinks", readiness)
        self.assertIn("bounded FIFO/pipe", readiness)
        self.assertIn("distinct fresh ordinary artifact", readiness)
        self.assertIn("only that ordinary artifact", readiness)
        self.assertIn(
            "Never implement the final-message cap with process-wide `RLIMIT_FSIZE`",
            readiness,
        )
        self.assertIn("terminate the reviewer with `SIGXFSZ`", readiness)
        self.assertIn(
            "a parent supervisor that enforces the caps on parent-owned bounded sinks",
            readiness,
        )
        self.assertIn("Enforce every cap while the reviewer runs", readiness)
        self.assertIn("OS-enforced job/cgroup/container", readiness)
        self.assertIn("survives `setsid` / `setpgid`", readiness)
        self.assertIn("verified kernel no-child-process policy", readiness)
        self.assertIn("fully self-contained artifact-only review", readiness)
        self.assertIn("complete diff and permitted neighboring evidence", readiness)
        self.assertIn("tool calls are forbidden", readiness)
        self.assertIn("report `blocked` and do not launch", readiness)
        self.assertIn("descendant polling is not a substitute", readiness)
        self.assertIn("separate 10-second deadline", readiness)
        self.assertIn("stat every ordinary output artifact again", readiness)
        self.assertIn("never use FIFO metadata", readiness)
        self.assertIn("even after exit zero", readiness)
        self.assertIn("quiescence or sink closure cannot be confirmed", readiness)
        self.assertIn("Poll only with bounded status probes", readiness)
        self.assertIn("Parent-Process Output Budget", readiness)
        self.assertIn("do not stream either process output", contracts)
        self.assertIn("--output-last-message <task-scoped-target>", contracts)
        self.assertIn("unique path that does not exist before the attempt", contracts)
        self.assertIn("freshly created before launch at one path", contracts)
        self.assertIn("different ordinary artifact path", contracts)
        self.assertIn("byte limit for the final-message artifact", contracts)
        self.assertIn("30-minute deadline, 16 MiB", contracts)
        self.assertIn("64 KiB for the final-message artifact", contracts)
        self.assertIn("send `TERM`", contracts)
        self.assertIn("send `KILL`", contracts)
        self.assertIn("when the deadline expires", contracts)
        self.assertIn("hard per-file quota or bounded sink", contracts)
        self.assertIn("bounded FIFO/pipe reader", contracts)
        self.assertIn(
            "Do not set process-wide file-size limits such as `RLIMIT_FSIZE`",
            contracts,
        )
        self.assertIn("unrelated internal session and state files", contracts)
        self.assertIn("terminate the reviewer with `SIGXFSZ`", contracts)
        self.assertIn("invalid harness attempt, not review evidence", contracts)
        self.assertIn(
            "a parent supervisor enforces the relevant byte ceilings",
            contracts,
        )
        self.assertIn("Direct-path monitoring or a post-exit size check alone", contracts)
        self.assertIn("OS-enforced job, cgroup, or container", contracts)
        self.assertIn("survives `setsid` / `setpgid`", contracts)
        self.assertIn("kernel-enforced no-child-process policy", contracts)
        self.assertIn("fully self-contained artifact-only review", contracts)
        self.assertIn("complete diff and permitted neighboring evidence", contracts)
        self.assertIn("prompt forbids tool calls", contracts)
        self.assertIn("report `blocked` and do not launch", contracts)
        self.assertIn("descendant polling may provide diagnostics", contracts)
        self.assertIn("never substitute for containment", contracts)
        self.assertIn("separate 10-second close deadline", contracts)
        self.assertIn("waiting indefinitely", contracts)
        self.assertIn("Do not accept a final-message artifact", contracts)
        self.assertIn("file byte or line counts", contracts)
        self.assertIn("attempt exits zero", contracts)
        self.assertIn("creates it as a nonempty file", contracts)
        self.assertIn("stat both process logs and the ordinary final-message artifact", contracts)
        self.assertIn("Never use a FIFO's `st_size`", contracts)
        self.assertIn("even when it exited zero", contracts)
        self.assertIn("reaches or exceeds", contracts)
        self.assertIn("record only the byte counts", contracts)
        self.assertIn("remove the oversized artifact", contracts)
        self.assertIn("reject any stale or partial result", contracts)
        self.assertIn("On a nonzero exit or a missing/empty file", contracts)
        self.assertIn("read at most the final 8 KiB of stderr", contracts)
        self.assertIn("byte-count-limited read", contracts)
        self.assertIn("truncates before inserting text", contracts)
        self.assertIn("line-count-only command", contracts)
        self.assertIn("single long JSON or trace line", contracts)
        self.assertIn("runtime-verification failure as `blocked`", contracts)
        self.assertIn("otherwise report `inconclusive`", contracts)
        self.assertIn("Never read the complete stderr", contracts)
        self.assertIn(
            "Remove task-scoped process logs and the final-message file",
            contracts,
        )
        self.assertIn("reported blocker or recovery handoff", contracts)
        self.assertIn("remove the oversized log", contracts)
        self.assertIn("read at most the final 8 KiB of stderr", readiness)
        self.assertIn("line-count-only tail is not bounded", readiness)

    def test_review_prompts_do_not_use_unbounded_only_matching_samples(self) -> None:
        forbidden = "rg -o --max-count 80"
        candidates = [SKILL_ROOT / "SKILL.md", SKILL_ROOT / "scripts/review_runtime/prompt.py"]
        candidates.extend((SKILL_ROOT / "references").glob("*.md"))
        for candidate in candidates:
            self.assertNotIn(
                forbidden,
                candidate.read_text(encoding="utf-8"),
                str(candidate),
            )

    def test_cli_rejects_claude_lane_without_visible_consent(self) -> None:
        completed = subprocess.run(
            (
                str(SCRIPTS / "isolated_review"),
                "--reviewer",
                "claude",
                "--base-ref",
                "base",
                "--head-ref",
                "head",
            ),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--egress-consent", completed.stderr)

    def test_approval_template_excludes_authentication_from_copilot_fallback(
        self,
    ) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "secure Claude runtime is deterministically absent/unavailable",
            consent,
        )
        self.assertIn(
            "both pinned Claude Opus models are entitlement-blocked",
            consent,
        )
        self.assertIn(
            "Claude authentication failure pauses as `blocked-authentication`",
            consent,
        )
        self.assertNotIn("has no usable local/API authentication", consent)

    def test_triple_review_consent_names_all_provider_organizations(self) -> None:
        candidates = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/egress-consent.md",
        ]
        repo_agents = REPO_ROOT / "AGENTS.md"
        if repo_agents.is_file():
            candidates.append(repo_agents)
        for candidate in candidates:
            content = candidate.read_text(encoding="utf-8")
            self.assertIn(
                "OpenAI, Anthropic, and Microsoft/GitHub",
                content,
                str(candidate),
            )


if __name__ == "__main__":
    unittest.main()
