from __future__ import annotations

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
RUNTIME = SCRIPTS / "review_runtime"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import providers  # noqa: E402


CI_FIXTURE_ROOT = SKILL_ROOT / "tests" / "fixtures" / "ci"
CI_PROFILE_BY_SKILL_LAYOUT = {
    pathlib.Path("skills/review-orchestration-playbook"): "canonical",
    pathlib.Path("personal_codex/skills/review-orchestration-playbook"): "private",
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


def _claude_repository_policy_files(
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
                / "2026-07-19-real-home-read-only-claude-c63d11.md"
            ),
        }
    elif profile != "private":
        raise AssertionError(f"unsupported repository policy profile: {profile}")
    return {
        name: path.read_text(encoding="utf-8") for name, path in policy_paths.items()
    }


def _current_claude_contract_files() -> dict[str, str]:
    candidates = {
        "SKILL.md": SKILL_ROOT / "SKILL.md",
        "helper-contract.md": SKILL_ROOT / "references/helper-contract.md",
        "claude-runtime-trust.md": (SKILL_ROOT / "references/claude-runtime-trust.md"),
        "egress-consent.md": SKILL_ROOT / "references/egress-consent.md",
        "pr-readiness.md": SKILL_ROOT / "references/pr-readiness.md",
        **{
            name: REPO_ROOT / name
            for name in ("AGENTS.md", "README.md")
            if (REPO_ROOT / name).is_file()
        },
    }
    return {name: path.read_text(encoding="utf-8") for name, path in candidates.items()}


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
        self.assertIn(
            "do not end the task merely because one wait window expires",
            skill,
        )

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

    def test_claude_uses_one_real_home_read_only_worktree_mode(self) -> None:
        policies = _current_claude_contract_files()
        combined = "\n".join(policies.values())
        required = (
            "real `HOME`",
            "detached Git worktree",
            "2.1.212",
            "Every other release fails closed",
            "`dontAsk` mode",
            "Read",
            "Grep",
            "Glob",
            "Read(./**)",
            "read-only command policy",
            "recognized Bash file",
            "native sandbox",
            "unsandboxed",
            "original source checkout",
            "per-UID review namespace",
            "/proc",
            "/dev",
        )
        for phrase in required:
            self.assertIn(phrase, combined)
        for name in (
            "SKILL.md",
            "helper-contract.md",
            "claude-runtime-trust.md",
            "README.md",
        ):
            if policy := policies.get(name):
                with self.subTest(policy=name):
                    self.assertIn("worktree", policy.lower())
                    self.assertIn("HOME", policy)
                    self.assertIn("sandbox", policy.lower())

        self.assertIn("control plane", combined)
        self.assertIn("write denials", combined)
        self.assertIn("requested rather than claiming independent proof", combined)
        self.assertIn("model tools", combined)
        self.assertIn("authentication", combined)
        self.assertIn("exact-version pin", combined)
        self.assertNotIn("separate HOME/runtime modes", combined)

        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        self.assertIn('"autoAllowBashIfSandboxed": False', provider_source)
        self.assertIn('"allowUnsandboxedCommands": False', provider_source)
        self.assertIn("str(source)", provider_source)
        self.assertIn("str(review_user_root)", provider_source)
        self.assertIn("model-backed behavioral probe", combined)
        for stale_range_claim in (
            "floating Claude Code",
            "accepted range advances",
            "publisher-verified release range",
            "publisher-verified version floor",
        ):
            self.assertNotIn(stale_range_claim, combined + provider_source)
        for stale_claim in (
            "helper-controlled route",
            "materializes certificate-only",
            "effort mismatch fail closed",
        ):
            self.assertNotIn(stale_claim, combined)

    def test_claude_auth_precedence_delegates_to_verified_cli(self) -> None:
        policies = _current_claude_contract_files()
        combined = "\n".join(policies.values())
        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")

        precedence = (
            "`ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login"
        )
        self.assertIn(precedence, combined)
        self.assertIn("ANTHROPIC_API_KEY", provider_source)
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", provider_source)
        self.assertIn("blocked-authentication", combined)
        self.assertIn("claude auth login", combined)
        self.assertIn("unset or replace `ANTHROPIC_API_KEY`", combined)
        self.assertIn("unset or replace `CLAUDE_CODE_OAUTH_TOKEN`", combined)

        self.assertIn("opaque-forward", policies["SKILL.md"])
        self.assertIn("never parses", policies["SKILL.md"])
        self.assertIn("opaque-forward", policies["helper-contract.md"])
        self.assertIn("never parses", policies["helper-contract.md"])
        self.assertIn("auth status --json", combined)
        self.assertIn("loggedIn: false", combined)
        self.assertIn("system/init", combined)
        self.assertIn("The helper never:", policies["claude-runtime-trust.md"])
        for name in ("SKILL.md", "helper-contract.md", "claude-runtime-trust.md"):
            with self.subTest(policy=name):
                self.assertIn("persist", policies[name])

    def test_helper_managed_credential_protocol_is_retired(self) -> None:
        for relative in (
            "claude_keychain_macos.py",
            "claude_keychain_broker.c",
            "claude_refresh_lock.py",
        ):
            self.assertFalse((RUNTIME / relative).exists(), relative)

        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        linux_source = (RUNTIME / "claude_linux.py").read_text(encoding="utf-8")
        for symbol in (
            "_prepare_claude_keychain_broker",
            "_claude_keychain_runtime",
            "_persist_claude_macos_refreshed_credential",
            "_write_claude_keychain_credential",
            "stage_claude_credentials",
            "acquire_claude_refresh_lock",
        ):
            with self.subTest(symbol=symbol):
                self.assertNotIn(symbol, provider_source + linux_source)

        forbidden_policy_terms = (
            "SecKeychainItemRef",
            "credential-lock protocol catalog",
            "certified 5-second heartbeat",
            "recovery_artifact",
            "recovery carrier",
            "/auth/config",
            "guarded writeback",
            "helper-controlled broker",
        )
        for name, policy in _current_claude_contract_files().items():
            with self.subTest(policy=name):
                for term in forbidden_policy_terms:
                    self.assertNotIn(term, policy)

    def test_workspace_defaults_clean_and_wip_is_explicit_review_only(self) -> None:
        cli_source = (RUNTIME / "cli.py").read_text(encoding="utf-8")
        workspace_source = (RUNTIME / "workspace.py").read_text(encoding="utf-8")
        policies = _current_claude_contract_files()

        self.assertIn("--include-source-wip", cli_source)
        self.assertIn("include_source_wip", cli_source + workspace_source)
        for name in ("SKILL.md", "helper-contract.md", "egress-consent.md"):
            policy = policies[name]
            with self.subTest(policy=name):
                self.assertIn("--include-source-wip", policy)
                self.assertIn("staged", policy)
                self.assertIn("unstaged", policy)
                self.assertIn("untracked", policy)

        helper = policies["helper-contract.md"]
        self.assertIn("helper-owned minimal Git database", helper)
        self.assertIn("source repository/common Git directory", helper)
        self.assertIn("WIP digest", helper)
        self.assertIn("source checkout", helper)

        readiness = policies["pr-readiness.md"]
        self.assertIn("always uses clean exact-commit mode", readiness)
        self.assertIn("must be committed", readiness)
        self.assertIn("omit `--include-source-wip`", readiness)
        self.assertIn("never report a WIP digest", readiness)

    def test_review_workspace_and_state_use_external_system_temp_root(self) -> None:
        workspace_source = (RUNTIME / "workspace.py").read_text(encoding="utf-8")
        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        policies = _current_claude_contract_files()
        combined = "\n".join(policies.values())

        self.assertIn('REVIEW_ROOT_BASE = pathlib.Path("/tmp")', workspace_source)
        self.assertIn(
            'REVIEW_USER_ROOT_PREFIX = "codex-isolated-review-uid-"',
            workspace_source,
        )
        self.assertIn(
            "hashlib.sha256(os.fsencode(str(canonical_source))).hexdigest()",
            workspace_source,
        )
        self.assertIn(
            "helper review root must be outside the source repository",
            workspace_source,
        )
        self.assertNotIn("_without_helper_container_status", workspace_source)
        self.assertIn('".codex-review", ".codex-tmp"', workspace_source)
        self.assertIn("(review.source_root, review.container_dir)", provider_source)

        for phrase in (
            "fixed system temporary root `/tmp`",
            "outside the source checkout",
            "`01777`",
            "`0700`",
            "effective UID",
            "canonical source path",
            "Source `.codex-tmp`",
            "ordinary Git ignore/status",
            "reserved",
            "reboot",
            "host temporary-file cleanup",
            "both the source checkout and external review container",
        ):
            self.assertIn(phrase, combined)

        for stale_claim in (
            "excluded from clean/WIP source status",
            "Filtering is limited to porcelain",
            "filter applies only to untracked porcelain",
            "no longer blocks the next clean or WIP review",
            "does not itself block the next clean or WIP preparation",
        ):
            self.assertNotIn(stale_claim, combined)

    def test_wip_consent_includes_untracked_but_excludes_home(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("separate explicit authorization", consent)
        self.assertIn("non-ignored untracked files", consent)
        self.assertIn("sensitive-content", consent)
        self.assertIn("does not add HOME files", consent)
        self.assertIn("reviewer prompt forbids", consent)
        self.assertIn("explicit deny rules", consent)
        self.assertIn("real `HOME`", consent)

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

    def test_claude_policy_files_match_distribution_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir)
            (repo_root / "README.md").write_text("unrelated\n", encoding="utf-8")

            self.assertEqual(
                _claude_repository_policy_files(repo_root, "private"),
                {},
            )
            with self.assertRaises(FileNotFoundError):
                _claude_repository_policy_files(repo_root, "canonical")
            with self.assertRaisesRegex(
                AssertionError,
                "unsupported repository policy profile",
            ):
                _claude_repository_policy_files(repo_root, "unknown")

    def test_reviewed_ci_snapshots_keep_the_intended_status_guards(self) -> None:
        canonical = (CI_FIXTURE_ROOT / "canonical.yml").read_text(encoding="utf-8")
        private = (CI_FIXTURE_ROOT / "private.yml").read_text(encoding="utf-8")

        self.assertIn("PLATFORM_TESTS_RESULT", canonical)
        self.assertIn('test "$PLATFORM_TESTS_RESULT" = "success"', canonical)
        self.assertIn("PLATFORM_TESTS_RESULT", private)
        self.assertIn("PYTHON_39_RESULT", private)
        self.assertIn("PLATFORM_SAFETY_RESULT", private)
        self.assertIn('test "$PYTHON_39_RESULT" = "success"', private)

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
            readiness.index("3. Require a clean source checkout"),
            readiness.index("4. After the helper preflight passes"),
        )
        self.assertIn("Require its retained `preflight.json`", readiness)
        self.assertIn("WIP artifact cannot be substituted", contracts)

    def test_independent_codex_process_output_is_task_scoped_and_bounded(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for value in (readiness, contracts):
            normalized = value.replace("-", " ")
            self.assertIn("--output-last-message <task-scoped-target>", value)
            self.assertIn("30-minute", value)
            self.assertIn("16 MiB", normalized)
            self.assertIn("64 KiB", normalized)
            self.assertIn("RLIMIT_FSIZE", value)
            self.assertIn("OS-enforced", value)
            self.assertIn("inconclusive", value)
        self.assertIn("read at most the final 8 KiB of stderr", readiness)
        self.assertIn("Never read the complete stderr", contracts)

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

    def test_approval_template_excludes_authentication_from_fallback(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "verified Claude runtime is deterministically unavailable", consent
        )
        self.assertIn("both pinned Claude models are entitlement-blocked", consent)
        self.assertIn(
            "Claude authentication failure pauses as `blocked-authentication`",
            consent,
        )

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
