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
    pathlib.Path("personal_codex/skills/review-orchestration-playbook"): "private",
}
REPOSITORY_POLICY_SCOPE_BY_PROFILE = {
    "canonical": pathlib.Path("."),
    "private": pathlib.Path("personal_codex"),
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


def _repository_policy_scope_root(
    repo_root: pathlib.Path,
    profile: str,
) -> pathlib.Path:
    try:
        relative_scope = REPOSITORY_POLICY_SCOPE_BY_PROFILE[profile]
    except KeyError as error:
        raise AssertionError(
            f"unsupported repository policy profile: {profile}"
        ) from error
    return repo_root / relative_scope


def _repository_agents_path(repo_root: pathlib.Path, profile: str) -> pathlib.Path:
    return _repository_policy_scope_root(repo_root, profile) / "AGENTS.md"


def _claude_auth_repository_policy_files(
    repo_root: pathlib.Path,
    profile: str,
) -> dict[str, str]:
    policy_paths: dict[str, pathlib.Path] = {}
    if profile == "canonical":
        policy_paths = {
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
        name: path.read_text(encoding="utf-8") for name, path in policy_paths.items()
    }


class RepositoryContractTest(unittest.TestCase):
    def test_cleanup_only_legacy_0664_lock_migration_is_private_and_ordered(
        self,
    ) -> None:
        contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )

        anchors = (
            "empty owner-owned mode-`0664` `cleanup.lock`",
            "non-group/other-writable owner-owned `.codex-tmp` root",
            "exact-mode-`0700` state directory",
            "exclusive lock is acquired",
            "revalidates both directories and the lock identity/mode",
            "`fchmod(0600)`",
            "`fsync`",
            "exact mode-`0600` validation",
        )
        cursor = 0
        for anchor in anchors:
            cursor = contract.index(anchor, cursor) + len(anchor)
        self.assertIn("Every other group/other-writable", contract)
        self.assertIn("nonempty legacy lock fails closed", contract)

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

    def test_pr_readiness_continues_until_clean_or_a_crisp_blocker(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "until the effective shape and all delivery gates are clean or a crisp blocker remains",
            readiness,
        )
        self.assertIn("Stop after bounded retries", readiness)

    def test_claude_runtime_and_clear_context_codex_agent_models_are_pinned(
        self,
    ) -> None:
        self.assertEqual(
            providers.CLAUDE_MODELS,
            ("claude-opus-4-8", "claude-opus-4-7"),
        )
        self.assertEqual(
            providers.COPILOT_MODELS,
            ("claude-opus-4.8", "claude-opus-4.7"),
        )
        self.assertEqual(
            providers.CLAUDE_EGRESS_CONSENTS,
            (
                "explicit-claude-review",
                "explicit-claude-with-copilot-fallback",
            ),
        )
        self.assertEqual(
            providers.COPILOT_EGRESS_CONSENTS,
            ("explicit-claude-with-copilot-fallback",),
        )
        self.assertEqual(
            providers.LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "supplied-diff-no-git",
        )
        self.assertFalse(providers.NAMED_LANE_ELIGIBLE)
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
        self.assertEqual(reviewer["sandbox_mode"], "read-only")
        reviewer_instructions = reviewer["developer_instructions"]
        for anchor in (
            "required local Codex reviewer lane",
            "sole lane that satisfies a named single review",
            "separate clean Git worktree",
            "Keep the workspace read-only",
            "authoritative review-skill path/version",
            "load that review skill",
            "domain skill",
            "AGENTS.md",
            "project-guidance document",
            "exact base_sha and head_sha",
            "not a prebuilt or injected full diff",
            "obtain base_sha..head_sha metadata, changed paths, hunks",
            "state-changing MCP, Plugin, connector, GitHub",
            "read-only filesystem sandbox is not proof",
        ):
            self.assertIn(anchor, reviewer_instructions)

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
            "outer sandbox",
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
        runtime_trust = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )

        egress_consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
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
        validate_source = inspect.getsource(providers._validate_claude_local_credential)
        macos_runtime_source = inspect.getsource(providers._claude_keychain_runtime)
        macos_persist_source = inspect.getsource(
            providers._persist_claude_macos_refreshed_credential
        ) + inspect.getsource(providers._persist_claude_macos_refreshed_credential_impl)
        macos_recovery_report_source = inspect.getsource(
            providers._record_claude_secondary_persistence_failure
        )
        run_review_source = inspect.getsource(providers.run_review)
        auth_outcome_source = inspect.getsource(providers._finish_claude_auth_required)
        linux_runtime_source = inspect.getsource(providers._claude_linux_review_runtime)
        linux_command_source = inspect.getsource(claude_linux.build_sandbox_command)
        keychain_write_source = inspect.getsource(
            providers._write_claude_keychain_credential
        )
        file_write_source = inspect.getsource(providers._write_claude_file_credential)
        linux_write_source = inspect.getsource(
            claude_linux._writeback_refreshed_credential_impl
        )
        linux_staging_source = inspect.getsource(claude_linux.stage_claude_credentials)
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
        self.assertIn(
            "sensitive-content and escaping-symlink checks passed", run_review_source
        )

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
        self.assertIn("5-second heartbeat", current_policy)
        self.assertIn("both carriers", current_policy)
        self.assertIn("inspection-inconclusive", current_policy)
        self.assertIn("Access-token expiry alone is not login expiry", current_policy)
        self.assertIn("blocked-authentication", current_policy)
        self.assertIn("claude auth login", current_policy)
        for policy in (helper_contract, runtime_trust):
            self.assertIn("claude auth login", policy)
            self.assertIn("ANTHROPIC_API_KEY", policy)
            self.assertIn("unset or replace", policy)
        self.assertIn(
            "GitHub Copilot requires a separate explicit request", current_policy
        )
        self.assertIn("does not silently change providers", current_policy)
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
        cli_denies = set(claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS.split(","))
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

    def test_repository_policy_scope_matches_distribution_profile(self) -> None:
        repo_root = pathlib.Path("/repo")

        self.assertEqual(
            _repository_policy_scope_root(repo_root, "canonical"),
            repo_root,
        )
        self.assertEqual(
            _repository_policy_scope_root(repo_root, "private"),
            repo_root / "personal_codex",
        )
        self.assertEqual(
            _repository_agents_path(repo_root, "canonical"),
            repo_root / "AGENTS.md",
        )
        self.assertEqual(
            _repository_agents_path(repo_root, "private"),
            repo_root / "personal_codex/AGENTS.md",
        )
        with self.assertRaisesRegex(
            AssertionError,
            "unsupported repository policy profile",
        ):
            _repository_policy_scope_root(repo_root, "unknown")

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
        self.assertLess(
            entrypoint.index(guard), entrypoint.index("from review_runtime")
        )
        self.assertIn('python-version: "3.10"', workflow)
        self.assertIn("tomli==2.2.1", workflow)
        self.assertIn("requires Python 3.10 or later", readme)

    def test_core_policy_defines_progressive_provider_strict_review_shapes(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        for anchor in (
            "Single / single review / single internal review | One fresh-context Codex reviewer.",
            "Double / double review / local double review | Single plus one actual Claude Code reviewer.",
            "Triple / triple review | Double plus exact `@codex review` on a supported GitHub Cloud PR",
            "Each logical lane receives its own workspace",
            "intentional review-anchor commit",
            "separate clean Git worktree at `head_sha` for each lane",
            "Enforce read-only reviewer behavior",
            '`fork_turns="none"`',
            "review-control metadata",
            "authoritative active playbook version before launch",
            "Both local lanes follow the same discovery order",
            "path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks",
            "Codex first loads the authoritative active playbook",
            "Do not prepare, paste, attach, or point it to a full diff",
            "existing frozen-diff Codex helper is not this lane and does not satisfy single review",
            "actual Claude Code process in a second clean Git worktree",
            "A Copilot, Cursor, OpenCode, or other model-family result does not satisfy the Claude Code lane",
        ):
            self.assertIn(anchor, skill)

        for anchor in (
            "lane-unique clean Git worktree at `head_sha`",
            "Never derive a formal named-lane range from a dirty working tree",
            "Expose the workspace and Git metadata for read-only reviewer behavior",
            "free of generated prompts, diff files, manifests, state directories, and helper control artifacts",
            "The reviewer prompt contains only review-control metadata:",
            "instruction-loading order, read-only and evidence limits",
            "for both local lanes, the same discovery order",
            "path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks",
            "load the authoritative active playbook",
            "compute or persist a reviewer-visible full diff",
            '`fork_turns="none"`',
            "Use an actual Claude Code process in a second lane-unique clean Git worktree",
            "A different provider cannot satisfy this lane",
        ):
            self.assertIn(anchor, contracts)

    def test_github_codex_fallback_and_pr_readiness_preserve_the_shape(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")

        for anchor in (
            "missing PR, unsupported host or integration, unavailable GitHub Codex service, or unsupported enterprise identity",
            "sqbu-github.cisco.com",
            "operating identity is in `{hoteng, hoteng_cisco}`",
            "Report `requested: triple`, `effective: double`, and the concrete reason",
            "exact `@codex review`",
        ):
            self.assertIn(anchor, skill)
        for anchor in (
            "It never adds a hidden local Codex review",
            "Each lane gets its own clean Git worktree, clear reviewer context, and read-only access",
            "Never generate or inject a full diff for the reviewer",
            "persist `requested: triple`, `effective: double`, and a concrete reason",
            "exact `@codex review` comment",
            "effective: triple-inconclusive",
        ):
            self.assertIn(anchor, readiness)
        self.assertIn(
            "GitHub Codex unavailability changes only triple to effective double",
            contracts,
        )
        self.assertIn("effective: triple-inconclusive", contracts)
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            contracts,
        )
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            readiness,
        )
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            probes,
        )
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", contracts)
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", readiness)
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", probes)
        self.assertIn(
            "No PR or proved integration/host/identity/service unavailability means effective double",
            interface,
        )
        self.assertIn("after service start means triple-inconclusive", interface)

    def test_named_single_prompt_uses_clear_context_codex_without_a_full_diff(
        self,
    ) -> None:
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        single = templates[
            templates.index(
                "## Named Single: Fresh-Context Codex Reviewer"
            ) : templates.index("## Named Double: Actual Claude Code Lane")
        ]

        for anchor in (
            "Workspace: {clean_worktree}",
            "Base SHA: {base_sha}",
            "Head SHA: {head_sha}",
            "Frozen review range: {base_sha}..{head_sha}",
            "Authoritative review instruction source/version: {review_skill_path_or_version}",
            "clean, independent, read-only Git worktree",
            "does not include a prebuilt full diff",
            "obtain range metadata, changed paths, hunks",
            "load the review skill",
            "domain skill",
            "AGENTS.md",
            "project-guidance document",
            '`fork_turns="none"`',
        ):
            self.assertIn(anchor, single)
        self.assertNotIn("{diff_file}", single)
        self.assertNotIn("Primary diff:", single)

    def test_named_double_and_triple_prompts_require_the_actual_provider_lanes(
        self,
    ) -> None:
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        double = templates[
            templates.index(
                "## Named Double: Actual Claude Code Lane"
            ) : templates.index("## Named Triple: GitHub Cloud Codex Trigger")
        ]
        triple = templates[
            templates.index(
                "## Named Triple: GitHub Cloud Codex Trigger"
            ) : templates.index("## Low-Level Helper Results")
        ]

        for anchor in (
            "actual Anthropic Claude Code",
            "independent from the Codex reviewer worktree and read-only",
            "Workspace: {claude_readonly_workspace}",
            "Frozen review range: {base_sha}..{head_sha}",
            "Canonical Claude lane contract version: {review_contract_version}",
            "Explicitly read repository-wide AGENTS.md",
            "domain skills",
            "no prepared diff or other reviewer's output is supplied",
            "supplemental Copilot diagnostic",
            "does not complete named double",
        ):
            self.assertIn(anchor, double)

        def assert_shared_discovery_order(prompt: str) -> None:
            anchors = (
                "repository-wide AGENTS.md",
                "changed-path metadata",
                "path-scoped AGENTS.md",
                "domain skill",
                "before inspecting hunks",
            )
            positions = [prompt.index(anchor) for anchor in anchors]
            self.assertEqual(positions, sorted(positions))
            project_guidance_position = min(
                position
                for phrase in ("project-guidance", "project guidance")
                if (position := prompt.find(phrase)) >= 0
            )
            self.assertGreater(project_guidance_position, positions[3])
            self.assertLess(project_guidance_position, positions[4])

        assert_shared_discovery_order(
            templates[
                templates.index(
                    "## Named Single: Fresh-Context Codex Reviewer"
                ) : templates.index("## Named Double: Actual Claude Code Lane")
            ]
        )
        assert_shared_discovery_order(double)
        for anchor in (
            "@codex review",
            "supported GitHub Cloud PR",
            "sqbu-github.cisco.com",
            "identity in `{hoteng, hoteng_cisco}`",
            "requested triple; effective double",
            "Posting the comment requests the third lane but does not complete it",
            "trustworthy terminal current-head result",
        ):
            self.assertIn(anchor, triple)
        self.assertNotIn("equivalent", triple)

    def test_canonical_claude_lane_has_a_direct_nonhelper_launch_contract(
        self,
    ) -> None:
        contract = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "Do not route this lane through `isolated_review`",
            "Start a new actual `claude` process",
            "working directory set to that worktree",
            "Send the small control prompt through stdin",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--tools Read,Grep,Glob,Bash",
            "--disallowedTools Edit,Write,NotebookEdit,WebFetch,WebSearch,Task",
            '"denyWrite": ["/"]',
            "lane-private local clone or private bare object store plus worktree",
            "not a network clone or prepared-diff materialization",
            "GIT_NO_LAZY_FETCH=1",
            "locally complete",
            "never run `fetch`, `pull`",
            "global write denial",
            "critical sensitive roots",
            "not a global host-read whitelist",
            "Claude Code 2.1.212",
            "cannot attest the final merged sandbox",
            "actual Claude process",
        ):
            self.assertIn(anchor, contract)
        self.assertNotIn("Primary diff:", contract)

    def test_named_lanes_block_lazy_fetch_before_reviewer_launch(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts):
            self.assertIn("GIT_NO_LAZY_FETCH=1", content)
            self.assertIn("GIT_TERMINAL_PROMPT=0", content)
            self.assertIn("locally complete", content)
        self.assertIn("without rendering or persisting a full diff", contracts)
        self.assertIn("never let the reviewer trigger an on-demand fetch", skill)
        self.assertIn("forbid `fetch`, `pull`", templates)
        self.assertNotIn("prepared full diff", contracts)

    def test_named_lane_keeps_raw_findings_separate_from_parent_metadata(
        self,
    ) -> None:
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "raw findings-only terminal output",
            "exactly `No findings.` when clean",
            "orchestrator stores that verbatim reviewer output in a separate lane record",
            "logical lane and actual runtime/provider",
            "full frozen range and workspace identity",
            "Commands, tests, or residual risk may be added",
            "optional metadata",
            "must not be demanded from a reviewer whose raw output contract is findings-only",
        ):
            self.assertIn(anchor, contracts)
        self.assertIn("Return findings only", templates)
        self.assertIn("reply exactly: No findings.", templates)

    def test_native_claude_selected_deny_policy_does_not_overclaim_host_read_isolation(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts, runtime):
            self.assertIn("not a global host-read whitelist", content)
            self.assertIn("global `denyWrite`", content)
            self.assertIn("critical-sensitive-root", content)
            self.assertIn("Claude Code 2.1.212", content)
            self.assertIn("final merged", content)

        for anchor in (
            '"denyRead"',
            '"allowRead"',
            '"denyWrite": ["/"]',
            "critical sensitive roots",
            "not a global host-read whitelist",
            "Claude Code 2.1.212",
            "final merged sandbox",
        ):
            self.assertIn(anchor, canonical)

        self.assertIn("Sandboxed Bash can technically read", runtime)
        self.assertIn(
            "The prompt/model scope therefore explicitly forbids all outside-workspace reads",
            runtime,
        )
        self.assertIn(
            "Do not directly read any path outside this detached workspace",
            templates,
        )
        self.assertIn(
            "outside-workspace exclusion is a model/prompt scope rule",
            templates,
        )
        self.assertIn(
            "do not describe the selected-deny policy as re-opening only the current workspace",
            runtime,
        )
        self.assertNotIn("selected-deny policy re-opens only", runtime)
        self.assertNotIn("re-open only the current workspace", skill)
        for content in (skill, contracts, runtime):
            self.assertIn("requested configuration", content)
            self.assertNotIn(
                "native sandbox enforces global write denial",
                content.lower(),
            )

    def test_canonical_claude_auth_control_plane_is_not_helper_broker(self) -> None:
        agents = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        lane_contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "ordinary Claude CLI authentication",
            "trusted control plane",
            "own ordinary authentication",
            "does not use the low-level helper's credential broker",
            "blocked-authentication",
            "claude auth login",
        ):
            self.assertIn(anchor, canonical)
        self.assertIn("The canonical lane does not use or", runtime)
        self.assertIn("helper's credential-lock catalog", runtime)
        self.assertIn("Do not apply its catalog, broker, carrier, lock", runtime)
        self.assertIn("do not apply to this direct real-`HOME` lane", skill)
        self.assertIn("a narrow CLI control-plane exception", skill)
        self.assertIn("Apply **Canonical Executable Provenance**", lane_contracts)
        self.assertIn("recovery rules do not apply to this direct lane", lane_contracts)
        self.assertNotIn("authentication, credential-recovery", lane_contracts)
        if CI_PROFILE == "canonical":
            self.assertIn("Those guarantees do not apply", agents)
        else:
            self.assertIn(
                "never count a supplied-diff helper as a named lane",
                agents,
            )
            self.assertIn("Named double adds actual Claude Code", agents)
        for retired_global_detail in (
            "Local-login writeback requires",
            "broker `W` generation",
            "primary `.oauth_refresh.lock`",
            "last generation and 1 MiB",
        ):
            self.assertNotIn(retired_global_detail, agents)

    def test_canonical_claude_provenance_is_direct_not_helper_snapshot(self) -> None:
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        for anchor in (
            "## Canonical Executable Provenance",
            "one exact resolved path",
            "fixed credential-free environment",
            "`>=2.1.211,<3.0.0`",
            "fixed Anthropic release-signing key",
            "signed per-version manifest",
            "`verify_claude_release` or equivalent checks",
            "immediately before launch",
            "revalidate it again after process completion",
            "does not call `snapshot_verified_claude_executable`",
            "do not claim the stronger immutability of the helper snapshot",
        ):
            self.assertIn(anchor, canonical)
        self.assertIn("do not create a helper snapshot", runtime)
        self.assertIn("For the low-level helper, after the signed manifest", runtime)
        self.assertIn("Follow **Canonical Executable Provenance**", skill)

    def test_all_superseded_auth_journals_are_historical_helper_only(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("public project journals are not packaged in private overlay")
        journal_names = (
            "2026-07-03-claude-local-login-b4e9d1.md",
            "2026-07-15-claude-cli-platform-capabilities-7c1501.md",
            "2026-07-16-claude-oauth-per-attempt-freshness-662f2c.md",
            "2026-07-17-claude-auth-carriers-c17a11.md",
        )

        for journal_name in journal_names:
            journal = (
                REPO_ROOT / "docs/project_journal/2026/07" / journal_name
            ).read_text(encoding="utf-8")
            normalized = " ".join(
                line.removeprefix("> ").strip() for line in journal.splitlines()
            )
            with self.subTest(journal=journal_name):
                for anchor in (
                    "Historical helper record",
                    "low-level `isolated_review` helper",
                    "do not define named single, double, or triple review",
                    "do not apply to the canonical direct Claude lane",
                ):
                    self.assertIn(anchor, normalized)
                self.assertRegex(journal, r"superseded_by: 202607(?:17|20)-")
                self.assertIn("## Historical Helper State", journal)
                self.assertNotIn("## Current State", journal)

    def test_migration_journal_requires_zero_inherited_turns_for_single(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("public project journals are not packaged in private overlay")
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-20-review-policy-migration-7f2001.md"
        ).read_text(encoding="utf-8")

        self.assertIn("one dedicated fresh-context Codex reviewer", journal)
        self.assertIn("zero inherited turns", journal)
        self.assertNotIn("fresh or otherwise clear-context", journal)

    def test_readme_separates_canonical_claude_from_helper_only_details(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest(
                "canonical public README section layout is not part of private profile"
            )
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        boundary = readme.index("## Low-Level `isolated_review` Helper Only")

        self.assertLess(readme.index("accepted real-`HOME`"), boundary)
        for helper_detail in (
            "private, checksum-keyed executable snapshot",
            "dedicated writable `/auth` carrier root",
            "Low-level helper Claude authentication",
            "Low-level helper local-login refresh writeback",
            "For the low-level helper, missing, malformed, unsafe",
        ):
            self.assertGreater(readme.index(helper_detail), boundary)
        self.assertIn(
            "not requirements or guarantees of the canonical direct Claude lane",
            readme,
        )
        self.assertIn("cannot satisfy named double or triple review", readme)

    def test_core_active_policy_has_no_retired_codex_pr_gate_names(self) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        active_policy = [
            _repository_agents_path(REPO_ROOT, CI_PROFILE),
            policy_scope_root / "agents/reviewer.toml",
            policy_scope_root / "skills/change-delivery-workflow/SKILL.md",
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "agents/openai.yaml",
            SKILL_ROOT / "references/canonical-claude-lane.md",
            SKILL_ROOT / "references/egress-consent.md",
            SKILL_ROOT / "references/github-pr-probes.md",
            SKILL_ROOT / "references/pr-readiness.md",
            SKILL_ROOT / "references/review-lane-contracts.md",
            SKILL_ROOT / "references/review-prompt-templates.md",
        ]
        if CI_PROFILE == "canonical":
            active_policy.append(REPO_ROOT / "README.md")
        retired = (
            "independent-codex-pr-review",
            "offline-frozen-diff-review",
        )

        for candidate in active_policy:
            content = candidate.read_text(encoding="utf-8")
            for name in retired:
                with self.subTest(candidate=candidate, retired=name):
                    self.assertNotIn(name, content)

    def test_active_named_lane_policy_has_no_unimplemented_overstrict_contracts(
        self,
    ) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        active_policy = [
            _repository_agents_path(REPO_ROOT, CI_PROFILE),
            policy_scope_root / "agents/reviewer.toml",
            policy_scope_root / "skills/change-delivery-workflow/SKILL.md",
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "agents/openai.yaml",
            SKILL_ROOT / "references/canonical-claude-lane.md",
            SKILL_ROOT / "references/egress-consent.md",
            SKILL_ROOT / "references/pr-readiness.md",
            SKILL_ROOT / "references/review-lane-contracts.md",
            SKILL_ROOT / "references/review-prompt-templates.md",
        ]
        if CI_PROFILE == "canonical":
            active_policy.append(REPO_ROOT / "README.md")
        retired_overstrict_terms = (
            "raw-object-equivalent",
            "range-scoped endpoint object closure",
            "only executable Git surface",
            "immutable instruction snapshot",
            "provider-neutral sensitive-content preflight",
        )

        for candidate in active_policy:
            content = candidate.read_text(encoding="utf-8")
            for term in retired_overstrict_terms:
                with self.subTest(candidate=candidate, term=term):
                    self.assertNotIn(term, content)

    def test_foreground_helper_does_not_claim_a_machine_labeled_envelope(self) -> None:
        cli_source = (SKILL_ROOT / "scripts/review_runtime/cli.py").read_text(
            encoding="utf-8"
        )
        completed = subprocess.run(
            (str(SCRIPTS / "isolated_review"), "--help"),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        help_text = " ".join(completed.stdout.split())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(
            "Results are diagnostic and machine-labeled",
            help_text,
        )
        self.assertIn(
            "the foreground command prints only the raw helper artifact",
            help_text,
        )
        self.assertIn(
            "The foreground compatibility command likewise prints only the raw helper artifact",
            helper_contract,
        )
        self.assertIn(
            "Automation that needs machine-readable contract metadata must use `stateful status`",
            helper_contract,
        )
        self.assertNotIn("render_success_envelope", cli_source)

    def test_review_prompts_do_not_use_unbounded_only_matching_samples(self) -> None:
        forbidden = "rg -o --max-count 80"
        candidates = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "scripts/review_runtime/prompt.py",
        ]
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

    def test_named_review_consent_does_not_authorize_copilot(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "These requests do not authorize GitHub Copilot",
            consent,
        )
        self.assertIn(
            "GitHub Copilot requires a separate explicit request and consent",
            consent,
        )
        self.assertIn(
            "does not expand the named request to another provider",
            consent,
        )
        self.assertEqual(
            providers.COPILOT_EGRESS_CONSENTS,
            ("explicit-claude-with-copilot-fallback",),
        )
        self.assertNotIn("double-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertNotIn("triple-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertNotIn("has no usable local/API authentication", consent)

    def test_named_review_egress_is_provider_specific_without_substitutes(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("Single authorizes OpenAI Codex", skill)
        self.assertIn("Double additionally authorizes Anthropic Claude Code", skill)
        self.assertIn(
            "Triple additionally authorizes, when supported, current-head GitHub Codex",
            skill,
        )
        self.assertIn("No named shape authorizes a substitute external reviewer", skill)


if __name__ == "__main__":
    unittest.main()
