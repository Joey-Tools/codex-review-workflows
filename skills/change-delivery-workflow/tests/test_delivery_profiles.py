from __future__ import annotations

import json
from pathlib import Path
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
CHANGE_SKILL = SKILL_ROOT / "SKILL.md"
AGILE_SKILL = SKILL_ROOT.parent / "agile-delivery-workflow" / "SKILL.md"
VALIDATION_ENVIRONMENTS = SKILL_ROOT / "references" / "validation-environments.md"
DELIVERY_RESULT_SCHEMA = SKILL_ROOT / "references" / "delivery-result.schema.json"
PROFILE_SELECTION_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "profile-selection-cases.json"
)
FORMAL_REVIEW_TERMINAL_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "formal-review-terminal-cases.json"
)
LOCAL_MUTATION_CASES = SKILL_ROOT / "tests" / "fixtures" / "local-mutation-cases.json"
READ_ONLY_PR_PROBE_CASES = (
    SKILL_ROOT / "tests" / "fixtures" / "read-only-pr-probe-cases.json"
)

RESULT_FIELDS = {
    "schema_version",
    "profile",
    "constraints",
    "local_mutation",
    "commit_mode",
    "remote_mutation",
    "handoff",
    "handoff_profile",
}
PROFILES = {
    "focused-checkpoint",
    "local-gate",
    "pr-readiness-handoff",
}
CONSTRAINTS = {
    "local-only",
    "report-only",
    "probe-only",
    "read-only",
    "no-remote",
    "no-commit",
}
REMOTE_LIMITING_CONSTRAINTS = {
    "local-only",
    "report-only",
    "probe-only",
    "read-only",
    "no-remote",
}
REMOTE_READ_LIMITING_CONSTRAINTS = {"local-only"}
LOCAL_MUTATION_LIMITING_CONSTRAINTS = {
    "report-only",
    "probe-only",
    "read-only",
}
COMMIT_LIMITING_CONSTRAINTS = {
    "report-only",
    "probe-only",
    "read-only",
    "no-commit",
}
HANDOFF_PROFILES = {
    "none",
    "pr-readiness",
    "pr-readiness-read-only-probe",
}


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


def profile_selection_cases() -> list[dict[str, object]]:
    payload = json.loads(PROFILE_SELECTION_CASES.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError("unexpected profile-selection fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError("profile-selection cases must be a list")
    return cases


def formal_review_terminal_cases() -> list[dict[str, object]]:
    payload = json.loads(FORMAL_REVIEW_TERMINAL_CASES.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError("unexpected formal-review terminal fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError("formal-review terminal cases must be a list")
    return cases


def fixture_cases(path: Path, label: str) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise AssertionError(f"unexpected {label} fixture version")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise AssertionError(f"{label} cases must be a list")
    return cases


def assert_valid_result_contract(result: object) -> None:
    if not isinstance(result, dict):
        raise AssertionError("delivery result must be an object")
    if set(result) != RESULT_FIELDS:
        raise AssertionError("delivery result fields do not match the closed contract")
    if result["schema_version"] != 1:
        raise AssertionError("unexpected delivery result schema version")
    if result["profile"] not in PROFILES:
        raise AssertionError("unknown delivery profile")

    constraints = result["constraints"]
    if not isinstance(constraints, list):
        raise AssertionError("constraints must be a list")
    if len(constraints) != len(set(constraints)):
        raise AssertionError("constraints must be unique")
    if not set(constraints) <= CONSTRAINTS:
        raise AssertionError("unknown delivery constraint")

    commit_mode = result["commit_mode"]
    if commit_mode not in {"allowed", "forbidden"}:
        raise AssertionError("unknown commit mode")
    remote_mutation = result["remote_mutation"]
    if remote_mutation not in {
        "forbidden",
        "review-authorization-required",
    }:
        raise AssertionError("unknown remote-mutation mode")
    handoff = result["handoff"]
    if handoff not in {"none", "review-orchestration-playbook"}:
        raise AssertionError("unknown handoff")

    constraint_set = set(constraints)
    local_mutation = result["local_mutation"]
    if local_mutation not in {"allowed", "forbidden"}:
        raise AssertionError("unknown local-mutation mode")
    if constraint_set & LOCAL_MUTATION_LIMITING_CONSTRAINTS:
        if local_mutation != "forbidden":
            raise AssertionError("local-mutation-limiting constraint was discarded")
    elif local_mutation != "allowed":
        raise AssertionError(
            "local mutation was forbidden without a limiting constraint"
        )

    if constraint_set & COMMIT_LIMITING_CONSTRAINTS:
        if commit_mode != "forbidden":
            raise AssertionError("commit-limiting constraint was discarded")
    elif commit_mode != "allowed":
        raise AssertionError("commit was forbidden without a limiting constraint")
    if constraint_set & REMOTE_LIMITING_CONSTRAINTS:
        if result["profile"] == "pr-readiness-handoff":
            raise AssertionError(
                "remote-limiting constraint allowed mutable PR handoff"
            )
        if remote_mutation != "forbidden":
            raise AssertionError("remote-limiting constraint was discarded")
    if constraint_set & REMOTE_READ_LIMITING_CONSTRAINTS and handoff != "none":
        raise AssertionError("remote-read-limiting constraint allowed a handoff")

    handoff_profile = result["handoff_profile"]
    if handoff_profile not in HANDOFF_PROFILES:
        raise AssertionError("unknown handoff profile")
    if result["profile"] == "pr-readiness-handoff":
        if remote_mutation != "review-authorization-required":
            raise AssertionError("PR handoff bypassed review authorization")
        if handoff != "review-orchestration-playbook":
            raise AssertionError("PR handoff did not route to the review skill")
        if handoff_profile != "pr-readiness":
            raise AssertionError("PR handoff used the wrong review profile")
    elif handoff_profile == "pr-readiness-read-only-probe":
        if result["profile"] != "local-gate":
            raise AssertionError("read-only PR probe did not use the local gate")
        if remote_mutation != "forbidden":
            raise AssertionError("read-only PR probe allowed remote mutation")
        if handoff != "review-orchestration-playbook":
            raise AssertionError("read-only PR probe did not route to review")
        if not constraint_set & (
            REMOTE_LIMITING_CONSTRAINTS - REMOTE_READ_LIMITING_CONSTRAINTS
        ):
            raise AssertionError("read-only PR probe lacks a mutation limit")
    elif (
        remote_mutation != "forbidden" or handoff != "none" or handoff_profile != "none"
    ):
        raise AssertionError("a local profile attempted an unsupported handoff")


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
            case["prompt"]: (
                case["result"]["profile"],
                case["transition"],
            )
            for case in profile_selection_cases()
        }
        self.assertEqual(documented_profile_cases(self.change), expected)
        for anchor in (
            "After applying hard constraints, choose by the remaining requested terminal outcome",
            "combined MVP-plus-PR request therefore selects `pr-readiness-handoff`",
            "combined MVP-plus-full-local-gate request similarly selects `local-gate`",
            "remote or full-gate work must wait for a later request",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_constraint_precedes_every_checkpoint(self) -> None:
        mode_heading = self.change.index("## Resolve Hard Constraints First")
        profile_heading = self.change.index("## Choose The Profile")
        self.assertLess(mode_heading, profile_heading)
        for anchor in (
            "sets commit mode to `forbidden` for the whole run",
            "before any review checkpoint, anchor, or landing commit",
            "A delivery profile never overrides it",
            "leave Git history unchanged",
            "pre-existing exact committed range",
            "do not create an implicit checkpoint",
            "Under `report-only`, `probe-only`, `read-only`, or `no-commit`, do not create a checkpoint or anchor",
            "otherwise report the formal lane blocked",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_scope_constraints_precede_pr_signals_and_survive_handoff(
        self,
    ) -> None:
        cases = {case["prompt"]: case["result"] for case in profile_selection_cases()}
        constrained_expectations = {
            "Run the full workflow locally, report-only.": {
                "constraints": ["local-only", "report-only"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "none",
            },
            "Run the full workflow with no remote work.": {
                "constraints": ["no-remote"],
                "local_mutation": "allowed",
                "commit_mode": "allowed",
                "handoff_profile": "none",
            },
            "Review full-workflow readiness read-only.": {
                "constraints": ["read-only"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "none",
            },
            "Probe full workflow and PR readiness; do not make remote changes.": {
                "constraints": ["probe-only", "no-remote"],
                "local_mutation": "forbidden",
                "commit_mode": "forbidden",
                "handoff_profile": "pr-readiness-read-only-probe",
            },
        }
        for prompt, expected in constrained_expectations.items():
            with self.subTest(prompt=prompt):
                result = cases[prompt]
                self.assertEqual(result["profile"], "local-gate")
                self.assertEqual(result["constraints"], expected["constraints"])
                self.assertEqual(result["local_mutation"], expected["local_mutation"])
                self.assertEqual(result["commit_mode"], expected["commit_mode"])
                self.assertEqual(result["remote_mutation"], "forbidden")
                self.assertEqual(result["handoff_profile"], expected["handoff_profile"])
                expected_handoff = (
                    "review-orchestration-playbook"
                    if expected["handoff_profile"] == "pr-readiness-read-only-probe"
                    else "none"
                )
                self.assertEqual(result["handoff"], expected_handoff)

        positive = cases["Run the full workflow and open a PR."]
        self.assertEqual(positive["profile"], "pr-readiness-handoff")
        self.assertEqual(positive["constraints"], [])
        self.assertEqual(positive["local_mutation"], "allowed")
        self.assertEqual(
            positive["remote_mutation"],
            "review-authorization-required",
        )
        self.assertEqual(positive["handoff"], "review-orchestration-playbook")
        self.assertEqual(positive["handoff_profile"], "pr-readiness")

        for anchor in (
            "constraints are subtractive and take precedence over `full workflow`",
            "forbids `pr-readiness-handoff` and every remote mutation",
            "a downstream workflow may not reinterpret it",
            "hard constraint that forbids remote mutation always wins at this step",
            "Remote mutation being forbidden does not erase an explicitly requested read-only PR-readiness probe",
            "[delivery-result.schema.json](references/delivery-result.schema.json)",
            "Preserve these fields unchanged across any handoff",
            "Receivers must fail closed",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_read_only_constraints_short_circuit_all_local_mutation(self) -> None:
        profile_results = {
            case["prompt"]: case["result"] for case in profile_selection_cases()
        }
        cases = fixture_cases(LOCAL_MUTATION_CASES, "local-mutation")
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(prompt=case["prompt"]):
                expected = case["expected"]
                self.assertEqual(
                    profile_results[case["prompt"]]["local_mutation"],
                    "forbidden",
                )
                self.assertEqual(expected["local_mutation"], "forbidden")
                for action in (
                    "enter_implementation",
                    "write_journal",
                    "create_commit",
                    "generate_working_result_artifacts",
                    "run_mutating_or_cache_writing_validation",
                ):
                    self.assertFalse(expected[action])
                self.assertEqual(
                    expected["validation_mode"],
                    "read-only-subset",
                )

        for anchor in (
            "Resolve two independent mutation dimensions",
            "`local_mutation` is `forbidden`",
            "short-circuit the implementation and journal steps",
            "Do not edit source or documentation",
            "generate working-result artifacts",
            "validation known to create output, caches, or persistent state",
            "Run only the read-only validation subset",
            "Skip this entire step when `local_mutation` is `forbidden`",
            "Unknown mutation behavior is not read-only",
            "builds, tests, formatters, code generators, dependency resolution",
        ):
            self.assertIn(anchor, self.normalized_change)
        for anchor in (
            "parent workflow's `local_mutation` ceiling",
            "do not create an isolated worktree, cache, generated output, log, environment, or persistent state",
            "report unavailable single- or multi-version gates",
        ):
            self.assertIn(anchor, self.normalized_validation_environments)

    def test_no_commit_alone_keeps_local_mutation_available(self) -> None:
        result = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"]
            == "Implement and validate this locally, but do not commit."
        )
        self.assertEqual(result["constraints"], ["local-only", "no-commit"])
        self.assertEqual(result["local_mutation"], "allowed")
        self.assertEqual(result["commit_mode"], "forbidden")
        self.assertEqual(result["remote_mutation"], "forbidden")
        self.assertEqual(result["handoff"], "none")
        self.assertEqual(result["handoff_profile"], "none")

    def test_remote_mutation_limit_routes_explicit_read_only_pr_probe(self) -> None:
        cases = fixture_cases(READ_ONLY_PR_PROBE_CASES, "read-only-pr-probe")
        self.assertEqual(len(cases), 1)
        case = cases[0]
        selected = next(
            item["result"]
            for item in profile_selection_cases()
            if item["prompt"] == case["prompt"]
        )
        self.assertEqual(selected, case["input"])
        self.assertEqual(
            case["expected"]["allow"],
            [
                "pr-selection",
                "pr-lifecycle",
                "ci-status",
                "conversation-state",
                "base-and-head",
            ],
        )
        self.assertEqual(
            case["expected"]["forbid"],
            [
                "comments",
                "github-codex-request",
                "state-changing-waits",
                "branch-or-pr-metadata-changes",
                "fixes",
                "commits",
                "pushes",
            ],
        )
        self.assertEqual(
            case["expected"]["terminal"],
            "pr-readiness-read-only-report",
        )
        for anchor in (
            "Remote mutation being forbidden does not erase",
            "`pr-readiness-read-only-probe`",
            "PR selection, lifecycle, CI, conversation, base, and head evidence",
            "comment, `@codex review` request, state-changing wait",
            "branch or PR metadata change, fix, commit, push",
            "not a fourth delivery profile",
            "must not start CI, a reviewer, a check",
            "must not persist an authentication refresh or cache",
            "terminal `pr-readiness-read-only-report`",
            "Never call this merge-ready",
            "receiver must preserve that read-only capability ceiling",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_delivery_result_schema_is_closed_and_fixture_cases_conform(
        self,
    ) -> None:
        schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(set(schema["required"]), RESULT_FIELDS)
        self.assertEqual(set(schema["properties"]), RESULT_FIELDS)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["properties"]["profile"]["enum"]),
            PROFILES,
        )
        self.assertEqual(
            set(schema["properties"]["constraints"]["items"]["enum"]),
            CONSTRAINTS,
        )
        self.assertEqual(len(schema["allOf"]), 8)
        (
            local_mutation_constraint,
            commit_constraint,
            profile_constraint,
            remote_constraint,
            local_only_constraint,
            no_handoff_constraint,
            pr_handoff_constraint,
            read_only_handoff_constraint,
        ) = schema["allOf"]
        self.assertEqual(
            set(
                local_mutation_constraint["if"]["properties"]["constraints"][
                    "contains"
                ]["enum"]
            ),
            LOCAL_MUTATION_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            local_mutation_constraint["then"]["properties"]["local_mutation"]["const"],
            "forbidden",
        )
        self.assertEqual(
            local_mutation_constraint["else"]["properties"]["local_mutation"]["const"],
            "allowed",
        )
        self.assertEqual(
            set(
                remote_constraint["if"]["properties"]["constraints"]["contains"]["enum"]
            ),
            REMOTE_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            set(
                commit_constraint["if"]["properties"]["constraints"]["contains"]["enum"]
            ),
            COMMIT_LIMITING_CONSTRAINTS,
        )
        self.assertEqual(
            commit_constraint["then"]["properties"]["commit_mode"]["const"],
            "forbidden",
        )
        self.assertEqual(
            commit_constraint["else"]["properties"]["commit_mode"]["const"],
            "allowed",
        )
        self.assertEqual(
            profile_constraint["if"]["properties"]["profile"]["const"],
            "pr-readiness-handoff",
        )
        self.assertEqual(
            profile_constraint["then"]["properties"]["remote_mutation"]["const"],
            "review-authorization-required",
        )
        self.assertEqual(
            profile_constraint["then"]["properties"]["handoff"]["const"],
            "review-orchestration-playbook",
        )
        self.assertEqual(
            profile_constraint["then"]["properties"]["handoff_profile"]["const"],
            "pr-readiness",
        )
        self.assertEqual(
            profile_constraint["else"]["properties"]["remote_mutation"]["const"],
            "forbidden",
        )
        self.assertEqual(
            local_only_constraint["then"]["properties"]["handoff"]["const"],
            "none",
        )
        self.assertEqual(
            local_only_constraint["then"]["properties"]["handoff_profile"]["const"],
            "none",
        )
        self.assertEqual(
            no_handoff_constraint["then"]["properties"]["handoff"]["const"],
            "none",
        )
        self.assertEqual(
            pr_handoff_constraint["then"]["properties"]["profile"]["const"],
            "pr-readiness-handoff",
        )
        self.assertEqual(
            read_only_handoff_constraint["then"]["properties"]["profile"]["const"],
            "local-gate",
        )
        self.assertEqual(
            read_only_handoff_constraint["then"]["properties"]["handoff"]["const"],
            "review-orchestration-playbook",
        )

        for case in profile_selection_cases():
            with self.subTest(prompt=case["prompt"]):
                assert_valid_result_contract(case["result"])

    def test_constrained_result_cannot_be_reinterpreted_downstream(self) -> None:
        constrained = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"] == "Run the full workflow locally, report-only."
        )
        invalid_results = []

        missing_constraints = dict(constrained)
        del missing_constraints["constraints"]
        invalid_results.append(missing_constraints)

        unknown_field = dict(constrained)
        unknown_field["remote_authorized"] = True
        invalid_results.append(unknown_field)

        widened_profile = dict(constrained)
        widened_profile["profile"] = "pr-readiness-handoff"
        invalid_results.append(widened_profile)

        widened_handoff = dict(constrained)
        widened_handoff["remote_mutation"] = "review-authorization-required"
        widened_handoff["handoff"] = "review-orchestration-playbook"
        widened_handoff["handoff_profile"] = "pr-readiness"
        invalid_results.append(widened_handoff)

        for result in invalid_results:
            with self.subTest(result=result):
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(result)

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
            "`report-only`, `probe-only`, `read-only`, or `no-commit`",
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

    def test_allowed_review_fixes_require_a_new_frozen_range(self) -> None:
        anchors = (
            "exact frozen range",
            "branch on the resolved `commit_mode`",
            "If commit mode is `allowed`",
            "rerun affected validation and journal work",
            "create a new signed review checkpoint",
            "creates a new head and invalidates every review result",
            "review the new exact range",
            "latest reviewed head is clean under an allowed commit mode",
        )
        positions = tuple(self.normalized_change.index(anchor) for anchor in anchors)
        self.assertEqual(positions, tuple(sorted(positions)))

    def test_no_commit_review_findings_preserve_range_and_stop(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["existing-committed-range-no-commit-review-findings"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": "base_sha..head_sha",
                "review_outcome": "findings",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "apply_fixes": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "preserve_committed_range": "base_sha..head_sha",
                "handoff": False,
                "terminal": "review-findings-blocker",
            },
        )
        for anchor in (
            "If commit mode is `forbidden`",
            "do not apply fixes or create or require a new head, checkpoint, anchor, or commit",
            "Preserve the exact existing committed range",
            "report the unresolved findings as a blocker, and stop",
            "Only a later authorization may begin a new mutation-capable run",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_clean_no_commit_review_reports_without_inducing_commit(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["existing-committed-range-no-commit-review-clean"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": "base_sha..head_sha",
                "review_outcome": "clean",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "preserve_committed_range": "base_sha..head_sha",
                "next_step": "profile-terminal",
                "terminal": "clean-range-report",
            },
        )
        for anchor in (
            "Report the exact clean range, bypass the signed-commit step",
            "Do not create, require, amend, or relabel a commit",
            "clean review under forbidden commit mode is complete evidence",
            "Enter this step only when commit mode is `allowed`",
            "bypass this step without asking for or implying commit authorization",
            "clean pre-existing reviewed range is reported directly",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_missing_range_no_commit_blocks_without_inducing_commit(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["missing-committed-range-no-commit-formal-review-required"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": None,
                "formal_review_required": True,
                "review_outcome": "not-started",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "start_formal_review": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "handoff": False,
                "terminal": "missing-committed-range-blocker",
            },
        )
        for anchor in (
            "Report `missing-committed-range` as a blocker and stop",
            "Do not create or require a checkpoint, anchor, or commit to start review",
            "missing exact range or review findings under forbidden commit mode is a terminal blocker",
            "Do not continue to a profile handoff from either blocker",
            "a missing range or findings stop before handoff",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_no_commit_without_required_review_reports_checked_result(self) -> None:
        cases = {case["name"]: case for case in formal_review_terminal_cases()}
        case = cases["uncommitted-no-commit-formal-review-not-required"]
        self.assertEqual(
            case["input"],
            {
                "profile": "local-gate",
                "commit_mode": "forbidden",
                "existing_committed_range": None,
                "formal_review_required": False,
                "review_outcome": "not-required",
            },
        )
        self.assertEqual(
            case["expected"],
            {
                "start_formal_review": False,
                "create_new_head": False,
                "create_signed_review_checkpoint": False,
                "create_profile_commit": False,
                "report_exact_validations": True,
                "missing_committed_range_blocker": False,
                "handoff": False,
                "terminal": "uncommitted-checked-result",
            },
        )
        for anchor in (
            "blocker only when formal review is required",
            "When formal review is not required",
            "report the uncommitted checked result and exact validations directly",
            "without inventing a missing-range blocker or review handoff",
            "`false` | `forbidden`",
            "Do not invent a missing-range blocker",
        ):
            self.assertIn(anchor, self.normalized_change)

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
