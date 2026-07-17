from __future__ import annotations

import inspect
import pathlib
import subprocess
import sys
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_SCOPE_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_linux, providers  # noqa: E402


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
        self.assertIn("current-account Keychain item", helper_contract)
        self.assertIn("helper-controlled proxy", helper_contract)
        self.assertIn(">=2.1.187,<3.0.0", helper_contract)
        self.assertIn("Linux and WSL2", helper_contract)
        self.assertNotIn("requires `ANTHROPIC_API_KEY`", skill)

    def test_claude_oauth_freshness_is_per_model_attempt(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (
            SKILL_ROOT / "references/claude-runtime-trust.md"
        ).read_text(encoding="utf-8")

        self.assertEqual(providers.REVIEW_ATTEMPT_TIMEOUT_SECONDS, 1800.0)
        self.assertEqual(providers.CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS, 120.0)
        self.assertEqual(
            providers.CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS,
            1920.0,
        )
        self.assertEqual(
            claude_linux.DEFAULT_CREDENTIAL_VALIDITY_SECONDS,
            providers.CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS,
        )
        self.assertNotIn(
            "attempt_count",
            inspect.signature(
                providers._validate_fresh_claude_keychain_credential
            ).parameters,
        )
        attempt_source = inspect.getsource(providers._claude_attempt)
        warmup_source = inspect.getsource(providers._warm_claude_local_login)
        run_review_source = inspect.getsource(providers.run_review)
        linux_runtime_source = inspect.getsource(
            providers._claude_linux_review_runtime
        )
        self.assertIn("_warm_claude_local_login", attempt_source)
        self.assertIn("_prepare_claude_tls_environment", attempt_source)
        self.assertIn("ClaudeKeychainBrokerUnavailable", attempt_source)
        self.assertEqual(
            attempt_source.count("ClaudeLoopbackUnavailable"),
            2,
        )
        self.assertIn('"failure_class": "credential-read"', attempt_source)
        self.assertEqual(
            warmup_source.count(
                "_require_fresh_claude_keychain_credential_for_auth_preflight"
            ),
            2,
        )
        self.assertIn(
            "isinstance(credential_error, ClaudeKeychainBrokerUnavailable)",
            warmup_source,
        )
        self.assertIn("ClaudeAuthWarmupEntitlement", attempt_source)
        self.assertIn("require_verified_model=True", attempt_source)
        self.assertIn("CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS", linux_runtime_source)
        self.assertNotIn("_warm_claude_local_login", run_review_source)
        self.assertNotIn("_prepare_claude_tls_environment", run_review_source)
        self.assertEqual(
            run_review_source.count("ClaudeKeychainBrokerUnavailable"),
            2,
        )
        self.assertNotIn("_require_fresh_claude_linux_credential", run_review_source)

        self.assertIn("current model attempt", skill)
        self.assertIn(
            "Local-login credential freshness is an attempt-boundary property",
            helper_contract,
        )
        self.assertIn(
            "complete 30-minute timeout plus the 2-minute safety margin",
            helper_contract,
        )
        self.assertIn("current attempt's model", helper_contract)
        self.assertIn("Every later Opus attempt repeats", helper_contract)
        self.assertIn("API_KEY` skips local-login warmup and staging", helper_contract)
        self.assertIn("returns exit `75`; it never authorizes Copilot", helper_contract)
        self.assertIn(
            "either the initial or post-warmup credential freshness read",
            helper_contract,
        )
        self.assertIn(
            "attempt-local restricted Keychain broker failure",
            helper_contract,
        )
        self.assertIn(
            "A structured transient warmup remains inconclusive",
            helper_contract,
        )
        self.assertIn(
            "credential-read timeout, output-limit, drain, or process-leak",
            helper_contract,
        )
        self.assertIn(
            "only with `double-review` or `triple-review` consent",
            helper_contract,
        )
        self.assertIn("At every model-attempt boundary", runtime_trust)
        self.assertIn("authentication-preflight-inconclusive", runtime_trust)
        self.assertIn("authentication-preflight-entitlement", runtime_trust)
        self.assertIn("authentication-preflight-unavailable", runtime_trust)
        self.assertIn(
            "while the model whose inconclusive authentication gate failed is not",
            runtime_trust,
        )
        self.assertIn(
            "exact-model-verified entitlement denial",
            helper_contract,
        )
        self.assertIn(
            "with no final text and without claiming that the final broker",
            helper_contract,
        )
        self.assertIn("explicitly in an error state", helper_contract)
        self.assertIn(
            "entitlement-shaped stderr is not fallback evidence",
            helper_contract,
        )
        self.assertIn("overwrites any earlier entitlement model", helper_contract)
        self.assertIn("full stdout/stderr is retained", helper_contract)
        self.assertIn(
            "authentication failure remains unavailable",
            helper_contract,
        )
        self.assertIn(
            "missing or mismatched model metadata stops the",
            runtime_trust,
        )

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
            "Read(//config/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertIn(
            "Read(//proc/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertNotIn(
            "Read(/config/**)",
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

    def test_approval_template_covers_both_copilot_fallback_reasons(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("if Claude Code is unavailable", consent)
        self.assertIn(
            "all pinned Claude models are entitlement-blocked",
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
