from __future__ import annotations

from pathlib import Path
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
CHANGE_SKILL = SKILL_ROOT / "SKILL.md"
AGILE_SKILL = SKILL_ROOT.parent / "agile-delivery-workflow" / "SKILL.md"


class DeliveryProfileContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.change = CHANGE_SKILL.read_text(encoding="utf-8")
        self.agile = AGILE_SKILL.read_text(encoding="utf-8")
        self.normalized_change = " ".join(self.change.split())
        self.normalized_agile = " ".join(self.agile.split())

    def test_one_active_entrypoint_declares_three_ordered_profiles(self) -> None:
        self.assertIn("only active delivery entrypoint", self.normalized_change)
        anchors = (
            "### `focused-checkpoint`",
            "### `local-gate`",
            "### `pr-readiness-handoff`",
        )
        positions = tuple(self.change.index(anchor) for anchor in anchors)
        self.assertEqual(positions, tuple(sorted(positions)))
        self.assertIn(
            "Do not downgrade it because a gate is slow",
            self.normalized_change,
        )
        self.assertIn(
            "do not silently promote a local checkpoint",
            self.normalized_change,
        )
        self.assertIn(
            "When a non-trivial delivery request is otherwise ambiguous, use `local-gate`",
            self.normalized_change,
        )

    def test_journal_gate_does_not_force_first_time_adoption(self) -> None:
        for anchor in (
            "repository already adopted the convention",
            "repository policy requires it",
            "task truly crosses a session or PR handoff",
            "existing tracking product is needed for durable recovery",
            "Do not introduce tracking into an unadopted repository",
            "ordinary implementation, test, and review phases",
            "short `focused-checkpoint`",
            "First-time setup still needs an explicit product or recovery need",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_checkpoints_and_landing_commits_are_automatic_and_signed(self) -> None:
        for anchor in (
            "Create a signed local checkpoint automatically",
            "Create a signed landing commit automatically",
            "report-only, probe-only, or no-commit",
            "do not ask again merely to commit",
            "git commit -S",
            "Treat a signing failure as a blocker",
            "Never silently create an unsigned fallback commit",
        ):
            self.assertIn(anchor, self.normalized_change)
        self.assertIn(
            "does not push without separate authorization",
            self.normalized_change,
        )
        self.assertIn(
            "Do not automatically push, open a PR",
            self.normalized_change,
        )

    def test_fixes_invalidate_review_and_require_a_new_frozen_range(self) -> None:
        anchors = (
            "exact frozen range",
            "Any fix after review creates a new head",
            "immediately invalidates every review result",
            "Rerun affected validation and journal work",
            "create a new signed review checkpoint",
            "review the new exact range",
            "latest reviewed head is clean",
        )
        positions = tuple(self.normalized_change.index(anchor) for anchor in anchors)
        self.assertEqual(positions, tuple(sorted(positions)))

    def test_thin_orchestrator_does_not_duplicate_review_state_machines(self) -> None:
        self.assertIn(
            "hand the exact frozen range to the authoritative `$review-orchestration-playbook`",
            self.normalized_change,
        )
        self.assertIn(
            "Do not copy the review skill's materialization, provider, PR-state, or evidence rules",
            self.normalized_change,
        )
        for duplicated_literal in (
            "materialize-worktree",
            "validate-worktree",
            "chatgpt-codex-connector",
            "chatgpt-codex-connector[bot]",
            "Claude Code",
            "2.1.212",
            ">=2.1.211,<3.0.0",
            "baseRefOid",
            "blocked-input",
            "blocked-authorization",
            "triple-inconclusive",
            "scope-mismatch",
            "base-changed-same-head",
            "pr-lifecycle-unverified",
            "selected-pr-closed",
            "selected-pr-merged",
            "GIT_CONFIG_NOSYSTEM",
            "canonical version ordering",
            "supported-version set",
            "CI matrix",
            "multi-version",
        ):
            with self.subTest(duplicated_literal=duplicated_literal):
                self.assertNotIn(duplicated_literal, self.normalized_change)

    def test_retired_agile_skill_is_only_a_compatibility_alias(self) -> None:
        self.assertIn("retired as an independent workflow", self.agile)
        self.assertIn(
            "[$change-delivery-workflow](../change-delivery-workflow/SKILL.md)",
            self.agile,
        )
        for source, target in (
            ("`MVP`", "`focused-checkpoint`"),
            ("full local gate", "`local-gate`"),
            ("merge-ready", "`pr-readiness-handoff`"),
        ):
            source_position = self.agile.index(source)
            self.assertGreater(
                self.agile.index(target, source_position),
                source_position,
            )
        self.assertIn("active delivery skill is authoritative", self.agile)
        self.assertNotIn("## Workflow", self.agile)
        self.assertNotIn("Create the MVP checkpoint", self.agile)


if __name__ == "__main__":
    unittest.main()
