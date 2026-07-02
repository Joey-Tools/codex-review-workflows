from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import providers  # noqa: E402


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
            self.assertFalse((REPO_ROOT / relative).exists(), relative)

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
        with (REPO_ROOT / "agents/reviewer.toml").open("rb") as handle:
            reviewer = tomllib.load(handle)
        self.assertEqual(reviewer["model"], "gpt-5.6-sol")
        self.assertEqual(reviewer["model_reasoning_effort"], "xhigh")

    def test_ci_targets_only_the_canonical_runtime_and_tests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("review-orchestration-playbook/tests", workflow)
        self.assertNotIn("external-review-playbook", workflow)
        self.assertNotIn("copilot-review-playbook", workflow)

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
