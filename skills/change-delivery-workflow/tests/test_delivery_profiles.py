from __future__ import annotations

from pathlib import Path
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
CHANGE_SKILL = SKILL_ROOT / "SKILL.md"
AGILE_SKILL = SKILL_ROOT.parent / "agile-delivery-workflow" / "SKILL.md"
VALIDATION_ENVIRONMENTS = SKILL_ROOT / "references" / "validation-environments.md"


def documented_profile_cases(skill: str) -> dict[str, tuple[str, str]]:
    cases: dict[str, tuple[str, str]] = {}
    for line in skill.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        prompt, profile, transition = cells
        cases[prompt.strip("`")] = (profile.strip("`"), transition)
    return cases


class DeliveryProfileContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.change = CHANGE_SKILL.read_text(encoding="utf-8")
        self.agile = AGILE_SKILL.read_text(encoding="utf-8")
        self.validation_environments = VALIDATION_ENVIRONMENTS.read_text(
            encoding="utf-8"
        )
        self.normalized_change = " ".join(self.change.split())
        self.normalized_agile = " ".join(self.agile.split())
        self.normalized_validation_environments = " ".join(
            self.validation_environments.split()
        )

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

    def test_prompt_classification_uses_terminal_outcome_precedence(self) -> None:
        expected = {
            "Deliver a quick MVP and stop at a local checkpoint.": (
                "focused-checkpoint",
                "focused checkpoint, then stop",
            ),
            "Deliver an MVP, then open a PR for feedback.": (
                "pr-readiness-handoff",
                "focused slice, full local gate, then PR handoff",
            ),
            "Start with an MVP but complete the full local gate now.": (
                "local-gate",
                "focused slice, full local gate, then stop",
            ),
            "Complete this non-trivial implementation locally.": (
                "local-gate",
                "full local gate, then stop",
            ),
            "Take the implementation to merge-ready and stop before merge.": (
                "pr-readiness-handoff",
                "full local gate, then PR handoff",
            ),
            "Probe local gate readiness, but do not commit.": (
                "local-gate",
                "gate-only report under `no-commit`",
            ),
        }
        self.assertEqual(documented_profile_cases(self.change), expected)
        for anchor in (
            "Choose by the requested terminal outcome, using this precedence",
            "combined MVP-plus-PR request therefore selects `pr-readiness-handoff`",
            "combined MVP-plus-full-local-gate request similarly selects `local-gate`",
            "remote or full-gate work must wait for a later request",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_constraint_precedes_every_checkpoint(self) -> None:
        mode_heading = self.change.index("## Resolve Commit Mode First")
        profile_heading = self.change.index("## Choose The Profile")
        self.assertLess(mode_heading, profile_heading)
        for anchor in (
            "hard constraint for the whole run",
            "before any review checkpoint, anchor, or landing commit",
            "A delivery profile never overrides it",
            "leave Git history unchanged",
            "pre-existing exact committed range",
            "do not create an implicit checkpoint",
            "Under `report-only`, `probe-only`, or `no-commit`, do not create a checkpoint or anchor",
            "otherwise report the formal lane blocked",
        ):
            self.assertIn(anchor, self.normalized_change)

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
            "create a signed local checkpoint automatically",
            "create a signed landing commit automatically",
            "`report-only`, `probe-only`, or `no-commit`",
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

    def test_clean_review_checkpoint_is_the_landing_without_history_churn(
        self,
    ) -> None:
        for anchor in (
            "latest clean reviewed checkpoint is the profile's landing commit",
            "do not create an empty commit",
            "amend, squash, or rewrite history",
            "Reuse the latest clean signed review checkpoint",
            "Never manufacture an empty commit",
            "implicit history rewrite",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_multi_version_validation_is_delegated_and_isolated(self) -> None:
        self.assertIn(
            "[validation-environments.md](references/validation-environments.md)",
            self.change,
        )
        for anchor in (
            "CI matrix",
            "supported-version set",
            "canonical version ordering",
            "minimum supported version or CI matrix does not by itself require",
            "explicitly requires local multi-version validation",
            "change targets cross-version compatibility",
            "version-selection config or pin",
            "installed inventory",
            "highest compatible installed version",
            "finite, non-empty, duplicate-free",
            "Do not compare or merge lower-priority declarations",
            "independent worktree, cache, and state roots",
            "fixed ports",
            "persistent machine-level state",
        ):
            self.assertIn(anchor, self.normalized_validation_environments)

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
