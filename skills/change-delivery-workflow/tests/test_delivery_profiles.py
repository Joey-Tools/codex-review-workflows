from __future__ import annotations

import contextlib
import copy
import errno
import io
import json
import os
import runpy
import stat
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

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
REVIEW_SKILL_ROOT = SKILL_ROOT.parent / "review-orchestration-playbook"
REVIEW_SKILL = REVIEW_SKILL_ROOT / "SKILL.md"
PR_READINESS = REVIEW_SKILL_ROOT / "references" / "pr-readiness.md"
READ_ONLY_PR_REPORT_SCHEMA = (
    REVIEW_SKILL_ROOT / "references" / "pr-readiness-read-only-report.schema.json"
)
READ_ONLY_PR_REPORT_RUNTIME = REVIEW_SKILL_ROOT / "scripts" / "read_only_pr_report.py"
READ_ONLY_PR_REPORT_RUNTIME_API = runpy.run_path(
    str(READ_ONLY_PR_REPORT_RUNTIME),
    run_name="read_only_pr_report_contract",
)
new_read_only_report_bindings = READ_ONLY_PR_REPORT_RUNTIME_API["new_bindings"]
validate_read_only_report_semantics = READ_ONLY_PR_REPORT_RUNTIME_API[
    "validate_semantics"
]
read_only_report_payload = READ_ONLY_PR_REPORT_RUNTIME_API["_read_payload"]
read_only_report_main = READ_ONLY_PR_REPORT_RUNTIME_API["main"]
READ_ONLY_PR_REPORT_GLOBALS = read_only_report_main.__globals__
READ_ONLY_REPORT_MAX_BYTES = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_REPORT_BYTES"]
READ_ONLY_REPORT_MAX_DEPTH = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_JSON_DEPTH"]
READ_ONLY_REPORT_MAX_NODES = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_JSON_NODES"]
READ_ONLY_REPORT_MAX_INTEGER_DIGITS = READ_ONLY_PR_REPORT_RUNTIME_API[
    "MAX_INTEGER_DIGITS"
]
READ_ONLY_REPORT_MAX_ERROR_CHARS = READ_ONLY_PR_REPORT_RUNTIME_API["MAX_ERROR_CHARS"]

RESULT_FIELDS = {
    "schema_version",
    "profile",
    "constraints",
    "local_mutation",
    "commit_mode",
    "formal_review_required",
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
READ_ONLY_REPORT_FIELDS = {
    "schema_version",
    "terminal",
    "terminal_state",
    "report_id",
    "handoff_profile",
    "delivery_record",
    "target",
    "snapshot",
    "evidence",
    "unavailable_evidence",
    "blockers",
    "actions",
    "merge_ready",
    "next_handoff",
}
READ_ONLY_EVIDENCE_FIELDS = {
    "pr_selection",
    "pr_lifecycle",
    "ci_status",
    "conversation_state",
    "base_and_head",
}
READ_ONLY_ACTION_FIELDS = {
    "local_lanes_started",
    "secret_admission_started",
    "comments_posted",
    "waits_started",
    "cache_or_state_written",
    "local_mutation_performed",
    "remote_mutation_performed",
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


def read_only_report_validator() -> Draft202012Validator:
    delivery_schema = json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
    report_schema = json.loads(READ_ONLY_PR_REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(delivery_schema)
    Draft202012Validator.check_schema(report_schema)
    registry = Registry().with_resource(
        delivery_schema["$id"],
        Resource.from_contents(delivery_schema),
    )
    return Draft202012Validator(report_schema, registry=registry)


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
    if not isinstance(result["formal_review_required"], bool):
        raise AssertionError("formal-review requirement must be boolean")
    if (
        result["profile"] == "local-gate"
        and commit_mode == "allowed"
        and result["formal_review_required"] is not True
    ):
        raise AssertionError("commit-allowed local gate bypassed formal review")
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
        if result["formal_review_required"] is not True:
            raise AssertionError("PR handoff bypassed required formal review")
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


def assert_read_only_report_contract(report: object) -> None:
    if not isinstance(report, dict) or set(report) != READ_ONLY_REPORT_FIELDS:
        raise AssertionError("read-only PR report fields do not match the contract")
    if report["schema_version"] != 4:
        raise AssertionError("unexpected read-only PR report schema version")
    if report["terminal"] != "pr-readiness-read-only-report":
        raise AssertionError("unexpected read-only PR report terminal")
    if report["handoff_profile"] != "pr-readiness-read-only-probe":
        raise AssertionError("unexpected read-only PR report handoff profile")
    assert_valid_result_contract(report["delivery_record"])
    if report["delivery_record"]["handoff_profile"] != report["handoff_profile"]:
        raise AssertionError("read-only PR report widened its delivery handoff")
    schema_errors = list(read_only_report_validator().iter_errors(report))
    if schema_errors:
        raise AssertionError(schema_errors[0].message)
    try:
        validate_read_only_report_semantics(report)
    except ValueError as exc:
        raise AssertionError(str(exc)) from exc
    actions = report["actions"]
    if not isinstance(actions, dict) or set(actions) != READ_ONLY_ACTION_FIELDS:
        raise AssertionError("read-only PR report actions are not closed")
    if any(actions.values()):
        raise AssertionError("read-only PR report recorded a forbidden action")
    if report["merge_ready"] is not False or report["next_handoff"] != "none":
        raise AssertionError("read-only PR report escaped its terminal boundary")


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
        self.review = REVIEW_SKILL.read_text(encoding="utf-8")
        self.pr_readiness = PR_READINESS.read_text(encoding="utf-8")
        self.normalized_review = " ".join(self.review.split())
        self.normalized_pr_readiness = " ".join(self.pr_readiness.split())

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

    def test_profiles_resolve_formal_review_requirement_deterministically(
        self,
    ) -> None:
        cases = {case["prompt"]: case["result"] for case in profile_selection_cases()}
        expected = {
            "Deliver a quick MVP and stop at a local checkpoint.": False,
            "Complete this non-trivial implementation locally.": True,
            "Probe local gate readiness, but do not commit.": False,
            "Implement and validate this locally, but do not commit.": False,
            "Run the full workflow with no remote work.": True,
            "Probe full workflow and PR readiness; do not make remote changes.": False,
            "Complete the full local workflow, then report PR readiness without remote mutations.": True,
            "Run the full workflow and open a PR.": True,
        }
        for prompt, formal_review_required in expected.items():
            with self.subTest(prompt=prompt):
                self.assertIs(
                    cases[prompt]["formal_review_required"],
                    formal_review_required,
                )

        validator = Draft202012Validator(
            json.loads(DELIVERY_RESULT_SCHEMA.read_text(encoding="utf-8"))
        )
        for prompt in (
            "Run the full workflow and open a PR.",
            "Complete the full local workflow, then report PR readiness without remote mutations.",
        ):
            contradictory = copy.deepcopy(cases[prompt])
            contradictory["formal_review_required"] = not contradictory[
                "formal_review_required"
            ]
            with self.subTest(contradictory_prompt=prompt):
                self.assertTrue(list(validator.iter_errors(contradictory)))
                with self.assertRaises(AssertionError):
                    assert_valid_result_contract(contradictory)

        for anchor in (
            "Resolve `formal_review_required` once after the profile and hard constraints",
            "`pr-readiness-handoff` always resolves to `true`",
            "ordinary mutation-capable `local-gate` with commit mode `allowed` resolves to `true`",
            "constrained `local-gate` with commit mode `forbidden` resolves to `false`",
            "`focused-checkpoint` resolves to `false` by default",
            "may not downgrade either profile-mandated `true`",
            "preserve it unchanged across every handoff",
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
        self.assertEqual(
            {case["name"] for case in cases},
            {
                "resolved-target-snapshot",
                "pre-target-no-match",
                "pre-target-selection-blocked",
                "selected-pr-base-head-blocked",
            },
        )
        case = next(
            case for case in cases if case["name"] == "resolved-target-snapshot"
        )
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
                "local-review-lanes",
                "secret-admission",
                "comments",
                "github-codex-request",
                "waits",
                "cache-or-state-writes",
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
        terminal_result = case["expected"]["terminal_result"]
        self.assertEqual(terminal_result["delivery_record"], case["input"])
        for fixture_case in cases:
            with self.subTest(name=fixture_case["name"]):
                assert_read_only_report_contract(
                    fixture_case["expected"]["terminal_result"]
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
            "pr-readiness-read-only-report.schema.json",
            "fresh instance IDs",
            "real pre-target report",
        ):
            self.assertIn(anchor, self.normalized_change)

    def test_read_only_pr_probe_receiver_precedes_generic_review_and_is_closed(
        self,
    ) -> None:
        workflow = self.review.split("## Workflow", 1)[1]
        receiver = workflow.index("`handoff_profile: pr-readiness-read-only-probe`")
        generic_review = workflow.index("A review-only child")
        generic_pr = workflow.index("A PR/full-workflow request")
        self.assertLess(receiver, generic_review)
        self.assertLess(receiver, generic_pr)
        self.assertLess(
            self.pr_readiness.index(
                "## Read-Only Delivery Probe: Classify And Stop First"
            ),
            self.pr_readiness.index("## Authorization"),
        )

        for anchor in (
            "terminal evidence probe, not PR readiness",
            "Classify this structured handoff before every prose-based PR/review rule",
            "must not start a Codex or Claude local lane",
            "run secret admission or the low-level helper",
            "post a comment",
            "wait or poll",
            "write authentication/cache/state",
            "do not continue to steps 2-9",
            "invalid or widened record",
        ):
            self.assertIn(anchor, self.normalized_review)
        for anchor in (
            "First classify an inbound `pr-readiness-read-only-probe`",
            "Classify it before generic PR/full-workflow language",
            "Do not start any local Codex or Claude lane",
            "exact-secret admission",
            "GitHub Codex request",
            "poll, monitor, or wait",
            "persist authentication refreshes, caches, tool state, or connector state",
            "Then stop without another handoff",
            "never a named-review artifact",
            "pre-target-blocked",
            "target-resolution-blocked",
            "validate-semantics",
        ):
            self.assertIn(anchor, self.normalized_pr_readiness)

        schema = json.loads(READ_ONLY_PR_REPORT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(set(schema["required"]), READ_ONLY_REPORT_FIELDS)
        self.assertEqual(set(schema["properties"]), READ_ONLY_REPORT_FIELDS)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 4)
        self.assertEqual(
            set(schema["properties"]["terminal_state"]["enum"]),
            {
                "pre-target",
                "pre-target-blocked",
                "target-resolution-blocked",
                "target-snapshot",
            },
        )
        self.assertEqual(
            schema["properties"]["report_id"]["$ref"],
            "#/$defs/reportId",
        )
        self.assertEqual(schema["properties"]["target"]["$ref"], "#/$defs/target")
        self.assertEqual(
            schema["properties"]["snapshot"]["$ref"],
            "#/$defs/snapshot",
        )
        Draft202012Validator.check_schema(schema)
        delivery_contract = schema["properties"]["delivery_record"]["allOf"]
        self.assertEqual(
            delivery_contract[0]["$ref"],
            "https://joey-tools.invalid/change-delivery-workflow/delivery-result.schema.json",
        )
        self.assertEqual(
            delivery_contract[1]["properties"]["handoff_profile"]["const"],
            "pr-readiness-read-only-probe",
        )
        self.assertNotIn(
            "formal_review_required",
            delivery_contract[1]["properties"],
        )
        self.assertEqual(
            set(schema["properties"]["evidence"]["required"]),
            READ_ONLY_EVIDENCE_FIELDS,
        )
        evidence_definitions = {
            "pr_selection": "prSelectionEvidence",
            "pr_lifecycle": "prLifecycleEvidence",
            "ci_status": "ciStatusEvidence",
            "conversation_state": "conversationStateEvidence",
            "base_and_head": "baseAndHeadEvidence",
        }
        for field, definition in evidence_definitions.items():
            self.assertEqual(
                schema["properties"]["evidence"]["properties"][field]["$ref"],
                f"#/$defs/{definition}",
            )
            self.assertEqual(
                schema["$defs"][definition]["allOf"],
                [{"$ref": "#/$defs/nonemptyObservedEvidence"}],
            )
        self.assertEqual(
            set(schema["properties"]["actions"]["required"]),
            READ_ONLY_ACTION_FIELDS,
        )
        for field in READ_ONLY_ACTION_FIELDS:
            self.assertIs(
                schema["properties"]["actions"]["properties"][field]["const"],
                False,
            )
        self.assertIs(schema["properties"]["merge_ready"]["const"], False)
        self.assertEqual(schema["properties"]["next_handoff"]["const"], "none")

    def test_read_only_pr_report_schema_rejects_inconsistent_summaries(
        self,
    ) -> None:
        cases = {
            case["name"]: case
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        valid = copy.deepcopy(
            cases["resolved-target-snapshot"]["expected"]["terminal_result"]
        )
        validator = read_only_report_validator()
        for name, case in cases.items():
            with self.subTest(name=name):
                terminal_result = case["expected"]["terminal_result"]
                self.assertEqual(list(validator.iter_errors(terminal_result)), [])
                assert_read_only_report_contract(terminal_result)

        commit_allowed = copy.deepcopy(valid)
        commit_allowed["delivery_record"] = next(
            case["result"]
            for case in profile_selection_cases()
            if case["prompt"]
            == "Complete the full local workflow, then report PR readiness without remote mutations."
        )
        self.assertEqual(list(validator.iter_errors(commit_allowed)), [])
        assert_read_only_report_contract(commit_allowed)

        inconsistent: dict[str, dict[str, object]] = {}

        downgraded_commit_allowed = copy.deepcopy(commit_allowed)
        downgraded_commit_allowed["delivery_record"]["formal_review_required"] = False
        inconsistent["commit-allowed-local-gate-downgraded-review"] = (
            downgraded_commit_allowed
        )

        missing_unavailable = copy.deepcopy(valid)
        missing_unavailable["unavailable_evidence"].remove("ci-status")
        inconsistent["non-observed-without-unavailable-summary"] = missing_unavailable

        missing_blocker = copy.deepcopy(valid)
        missing_blocker["blockers"] = [
            blocker
            for blocker in missing_blocker["blockers"]
            if blocker["evidence"] != "ci-status"
        ]
        inconsistent["non-observed-without-blocker"] = missing_blocker

        observed_with_summaries = copy.deepcopy(valid)
        observed_with_summaries["evidence"]["ci_status"] = {
            "status": "observed",
            "report_binding": valid["report_id"],
            "target_binding": valid["target"]["binding_id"],
            "snapshot_binding": valid["snapshot"]["binding_id"],
            "observed": [
                {
                    "state": "success",
                    "total": 1,
                    "successful": 1,
                    "failed": 0,
                    "pending": 0,
                    "cancelled": 0,
                    "checks": [
                        {
                            "name": "tests",
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ],
                }
            ],
        }
        inconsistent["observed-with-unavailable-and-blocker"] = observed_with_summaries

        wrong_blocker_target = copy.deepcopy(valid)
        wrong_blocker_target["blockers"][0]["evidence"] = "pr-selection"
        inconsistent["blocker-targets-observed-evidence"] = wrong_blocker_target

        duplicate_blocker = copy.deepcopy(valid)
        duplicate_blocker["blockers"].append(
            {
                "evidence": "ci-status",
                "code": "second-ci-blocker",
                "detail": "A second blocker must not summarize the same evidence.",
            }
        )
        inconsistent["duplicate-blocker-for-one-evidence-kind"] = duplicate_blocker

        stale_snapshot = copy.deepcopy(valid)
        stale_snapshot["snapshot"]["freshness"] = "stale"
        inconsistent["stale-report-snapshot"] = stale_snapshot

        empty_observed = copy.deepcopy(valid)
        empty_observed["evidence"]["pr_selection"]["observed"] = []
        inconsistent["observed-status-without-record"] = empty_observed

        extra_observed_field = copy.deepcopy(valid)
        extra_observed_field["evidence"]["pr_lifecycle"]["observed"][0]["summary"] = (
            "open"
        )
        inconsistent["observed-record-with-free-form-field"] = extra_observed_field

        for name, candidate in inconsistent.items():
            with self.subTest(name=name):
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

        schema = validator.schema
        self.assertEqual(len(schema["allOf"]), len(READ_ONLY_EVIDENCE_FIELDS) + 2)
        blocker_schema = schema["properties"]["blockers"]["items"]
        self.assertEqual(
            set(blocker_schema["required"]),
            {"evidence", "code", "detail"},
        )
        self.assertEqual(
            set(schema["$defs"]["evidenceName"]["enum"]),
            {
                "pr-selection",
                "pr-lifecycle",
                "ci-status",
                "conversation-state",
                "base-and-head",
            },
        )

    def test_read_only_pr_report_binds_canonical_pr_url_to_target(self) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        valid = cases["resolved-target-snapshot"]
        validator = read_only_report_validator()
        canonical = "https://github.com/Joey-Tools/codex-review-workflows/pull/42"
        self.assertEqual(valid["target"]["pull_request"]["url"], canonical)
        self.assertEqual(list(validator.iter_errors(valid)), [])
        validate_read_only_report_semantics(valid)

        invalid_urls = {
            "userinfo": (
                "https://attacker@github.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "port": (
                "https://github.com:443/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "query": f"{canonical}?repository=other",
            "fragment": f"{canonical}#other",
            "percent-encoded-owner": (
                "https://github.com/%4aoey-Tools/codex-review-workflows/pull/42"
            ),
            "percent-encoded-slash": (
                "https://github.com/Joey-Tools%2Fother/codex-review-workflows/pull/42"
            ),
            "evil-prefix-host": (
                "https://evil-github.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "suffix-host": (
                "https://github.com.evil.example/"
                "Joey-Tools/codex-review-workflows/pull/42"
            ),
            "other-owner": (
                "https://github.com/Other-Owner/codex-review-workflows/pull/42"
            ),
            "other-repository": ("https://github.com/Joey-Tools/other/pull/42"),
            "other-number": (
                "https://github.com/Joey-Tools/codex-review-workflows/pull/43"
            ),
            "path-traversal": (
                "https://github.com/Joey-Tools/codex-review-workflows/../other/pull/42"
            ),
            "confusable-host": (
                "https://g\u0456thub.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "uppercase-host": (
                "https://GitHub.com/Joey-Tools/codex-review-workflows/pull/42"
            ),
            "trailing-slash": f"{canonical}/",
        }
        for name, url in invalid_urls.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(valid)
                candidate["target"]["pull_request"]["url"] = url
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

    def test_read_only_pr_report_repository_components_are_canonical(
        self,
    ) -> None:
        valid = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "resolved-target-snapshot"
        )
        validator = read_only_report_validator()
        invalid_components = {
            ("host", "GitHub.com"),
            ("host", "github..com"),
            ("host", "-github.com"),
            ("host", "github.com-"),
            ("host", "github_com"),
            ("owner", "-Joey-Tools"),
            ("owner", "Joey--Tools"),
            ("owner", "Joey_Tools"),
            ("owner", "Joey.Tools"),
            ("owner", "Joey\u2010Tools"),
            ("name", ".."),
            ("name", "repo/name"),
            ("name", "repo%2Fname"),
            ("name", "r\u0435po"),
        }
        for field, value in invalid_components:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(valid)
                candidate["target"]["repository"][field] = value
                candidate["target"]["pull_request"]["url"] = (
                    f"https://{candidate['target']['repository']['host']}/"
                    f"{candidate['target']['repository']['owner']}/"
                    f"{candidate['target']['repository']['name']}/pull/42"
                )
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)

    def test_read_only_pr_report_preserves_and_maps_all_ci_conclusions(
        self,
    ) -> None:
        base = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()
        conclusion_buckets = {
            "success": "success",
            "neutral": "success",
            "skipped": "success",
            "failure": "failure",
            "timed_out": "failure",
            "action_required": "failure",
            "stale": "failure",
            "startup_failure": "failure",
            "cancelled": "cancelled",
        }
        for conclusion, bucket in conclusion_buckets.items():
            with self.subTest(conclusion=conclusion):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": bucket,
                        "total": 1,
                        "successful": int(bucket == "success"),
                        "failed": int(bucket == "failure"),
                        "pending": 0,
                        "cancelled": int(bucket == "cancelled"),
                        "checks": [
                            {
                                "name": "tests",
                                "status": "completed",
                                "conclusion": conclusion,
                            }
                        ],
                    }
                )
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                validate_read_only_report_semantics(candidate)
                self.assertEqual(
                    observed["checks"][0]["conclusion"],
                    conclusion,
                )

        for status in (
            "queued",
            "in_progress",
            "requested",
            "waiting",
            "pending",
        ):
            with self.subTest(status=status):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": "pending",
                        "total": 1,
                        "successful": 0,
                        "failed": 0,
                        "pending": 1,
                        "cancelled": 0,
                        "checks": [
                            {
                                "name": "tests",
                                "status": status,
                                "conclusion": None,
                            }
                        ],
                    }
                )
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                validate_read_only_report_semantics(candidate)

        mixed = copy.deepcopy(base)
        mixed_observed = mixed["evidence"]["ci_status"]["observed"][0]
        mixed_observed.update(
            {
                "state": "failure",
                "total": 4,
                "successful": 1,
                "failed": 1,
                "pending": 1,
                "cancelled": 1,
                "checks": [
                    {
                        "name": "docs",
                        "status": "completed",
                        "conclusion": "neutral",
                    },
                    {
                        "name": "lint",
                        "status": "completed",
                        "conclusion": "stale",
                    },
                    {
                        "name": "tests",
                        "status": "waiting",
                        "conclusion": None,
                    },
                    {
                        "name": "e2e",
                        "status": "completed",
                        "conclusion": "cancelled",
                    },
                ],
            }
        )
        self.assertEqual(list(validator.iter_errors(mixed)), [])
        validate_read_only_report_semantics(mixed)

    def test_read_only_pr_report_ci_fails_closed_on_unknown_states(
        self,
    ) -> None:
        base = next(
            case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
            if case["name"] == "selected-pr-base-head-blocked"
        )
        validator = read_only_report_validator()
        invalid_checks = {
            "unknown-status": {
                "name": "tests",
                "status": "unknown",
                "conclusion": None,
            },
            "unknown-completed-conclusion": {
                "name": "tests",
                "status": "completed",
                "conclusion": "unknown",
            },
            "nonterminal-conclusion": {
                "name": "tests",
                "status": "in_progress",
                "conclusion": "success",
            },
            "missing-completed-conclusion": {
                "name": "tests",
                "status": "completed",
                "conclusion": None,
            },
            "legacy-pending-conclusion": {
                "name": "tests",
                "status": "completed",
                "conclusion": "pending",
            },
        }
        for name, check in invalid_checks.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(base)
                observed = candidate["evidence"]["ci_status"]["observed"][0]
                observed.update(
                    {
                        "state": "pending",
                        "total": 1,
                        "successful": 0,
                        "failed": 0,
                        "pending": 1,
                        "cancelled": 0,
                        "checks": [check],
                    }
                )
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)

    def test_read_only_pr_report_uses_real_staged_targets(self) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        no_match = cases["pre-target-no-match"]
        selection_blocked = cases["pre-target-selection-blocked"]
        range_blocked = cases["selected-pr-base-head-blocked"]

        self.assertEqual(no_match["target"]["state"], "pre-target")
        self.assertNotIn("pull_request", no_match["target"])
        self.assertNotIn("base", no_match["target"])
        self.assertNotIn("head", no_match["target"])
        self.assertEqual(selection_blocked["terminal_state"], "pre-target-blocked")
        self.assertNotIn("pull_request", selection_blocked["target"])
        self.assertEqual(
            range_blocked["terminal_state"],
            "target-resolution-blocked",
        )
        self.assertEqual(range_blocked["target"]["state"], "pr-selected")
        self.assertIn("pull_request", range_blocked["target"])
        self.assertNotIn("base", range_blocked["target"])
        self.assertNotIn("head", range_blocked["target"])

    def test_read_only_pr_report_binding_generator_is_instance_unique(self) -> None:
        first = new_read_only_report_bindings()
        second = new_read_only_report_bindings()
        self.assertEqual(
            set(first),
            {
                "report_id",
                "target_binding",
                "snapshot_binding",
                "snapshot_id",
            },
        )
        self.assertEqual(len(set(first.values())), 4)
        self.assertTrue(set(first.values()).isdisjoint(second.values()))
        for field, prefix in (
            ("report_id", "report:"),
            ("target_binding", "target:"),
            ("snapshot_binding", "snapshot:"),
            ("snapshot_id", "observation:"),
        ):
            with self.subTest(field=field):
                self.assertTrue(first[field].startswith(prefix))
                self.assertEqual(len(first[field]), len(prefix) + 32)

        repeated = "a" * 32
        runtime_secrets = new_read_only_report_bindings.__globals__["secrets"]
        with mock.patch.object(
            runtime_secrets,
            "token_hex",
            side_effect=[
                repeated,
                repeated,
                "b" * 32,
                "c" * 32,
                "d" * 32,
            ],
        ) as token_hex:
            collision_recovered = new_read_only_report_bindings()
        self.assertEqual(token_hex.call_count, 5)
        self.assertEqual(
            len({value.split(":", 1)[1] for value in collision_recovered.values()}),
            4,
        )
        binding_attempts = new_read_only_report_bindings.__globals__[
            "MAX_BINDING_ATTEMPTS"
        ]
        with mock.patch.object(
            runtime_secrets,
            "token_hex",
            return_value=repeated,
        ) as token_hex:
            with self.assertRaisesRegex(RuntimeError, "unique report bindings"):
                new_read_only_report_bindings()
        self.assertEqual(token_hex.call_count, binding_attempts + 1)

        with mock.patch.dict(
            READ_ONLY_PR_REPORT_GLOBALS,
            {
                "new_bindings": mock.Mock(
                    side_effect=OSError(
                        errno.EIO,
                        "entropy failure",
                        "untrusted\npath" * 1_000,
                    )
                )
            },
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                return_code = read_only_report_main(["new-bindings"])
        self.assertEqual(return_code, 2)
        rejection = json.loads(stdout.getvalue())
        self.assertEqual(rejection["classification"], "rejected")
        self.assertEqual(rejection["error"], "report binding generation failed (EIO)")

    def test_read_only_pr_report_path_reads_are_descriptor_safe(self) -> None:
        runtime_os = read_only_report_payload.__globals__["os"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "report.json"
            valid.write_bytes(b"{}")

            with mock.patch.object(runtime_os, "open", wraps=os.open) as open_mock:
                self.assertEqual(read_only_report_payload(str(valid)), {})
            flags = open_mock.call_args.args[1]
            for required_flag in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                self.assertEqual(flags & required_flag, required_flag)

            with mock.patch.object(runtime_os, "O_NOFOLLOW", None):
                with self.assertRaisesRegex(ValueError, "open is unavailable"):
                    read_only_report_payload(str(valid))

            missing = root / "missing.json"
            with self.assertRaisesRegex(ValueError, "missing at descriptor admission"):
                read_only_report_payload(str(missing))

            with mock.patch.object(
                runtime_os,
                "open",
                side_effect=PermissionError(
                    errno.EACCES,
                    "denied",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(ValueError, r"open failed \(EACCES\)"):
                    read_only_report_payload(str(valid))

            symlink = root / "report-link.json"
            symlink.symlink_to(valid)
            with self.assertRaisesRegex(ValueError, r"open failed \(ELOOP\)"):
                read_only_report_payload(str(symlink))

            fifo = root / "report.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_only_report_payload(str(fifo))

            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(READ_ONLY_REPORT_MAX_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                read_only_report_payload(str(oversized))

            with mock.patch.object(
                runtime_os,
                "read",
                side_effect=[b"{}", b"", b"[]", b""],
            ):
                with self.assertRaisesRegex(ValueError, "content changed"):
                    read_only_report_payload(str(valid))

            path_info = os.stat(valid, follow_symlinks=False)
            replaced_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino + 1,
                st_mode=path_info.st_mode,
                st_size=path_info.st_size,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=replaced_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path identity changed"):
                    read_only_report_payload(str(valid))

            nonregular_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino,
                st_mode=stat.S_IFIFO | 0o600,
                st_size=path_info.st_size,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=nonregular_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path identity changed"):
                    read_only_report_payload(str(valid))

            oversized_path_info = mock.Mock(
                st_dev=path_info.st_dev,
                st_ino=path_info.st_ino,
                st_mode=path_info.st_mode,
                st_size=READ_ONLY_REPORT_MAX_BYTES + 1,
            )
            with mock.patch.object(
                runtime_os,
                "stat",
                return_value=oversized_path_info,
            ):
                with self.assertRaisesRegex(ValueError, "path size changed"):
                    read_only_report_payload(str(valid))

            with mock.patch.object(
                runtime_os,
                "stat",
                side_effect=FileNotFoundError(
                    errno.ENOENT,
                    "gone",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(ValueError, "disappeared"):
                    read_only_report_payload(str(valid))

            with mock.patch.object(
                runtime_os,
                "stat",
                side_effect=PermissionError(
                    errno.EACCES,
                    "denied",
                    "untrusted-path",
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    r"final revalidation failed \(EACCES\)",
                ):
                    read_only_report_payload(str(valid))

        class FakeStdin:
            def __init__(self, payload: bytes) -> None:
                self.buffer = io.BytesIO(payload)

        runtime_sys = read_only_report_payload.__globals__["sys"]
        with mock.patch.object(
            runtime_sys,
            "stdin",
            FakeStdin(b"x" * (READ_ONLY_REPORT_MAX_BYTES + 1)),
        ):
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                read_only_report_payload("-")
        self.assertIn(
            "caller's transport",
            read_only_report_payload.__doc__ or "",
        )

    def test_read_only_pr_report_json_and_errors_are_bounded_and_strict(
        self,
    ) -> None:
        nested = (
            '{"value":' * (READ_ONLY_REPORT_MAX_DEPTH + 1)
            + "0"
            + "}" * (READ_ONLY_REPORT_MAX_DEPTH + 1)
        ).encode("utf-8")
        too_many_nodes = (
            '{"values":['
            + ",".join("0" for _ in range(READ_ONLY_REPORT_MAX_NODES))
            + "]}"
        ).encode("utf-8")
        invalid_payloads = {
            "invalid-utf8": b'{"value":"\xff"}',
            "malformed-json": b'{"value":',
            "duplicate-key": b'{"value":1,"value":2}',
            "nonfinite-constant": b'{"value":NaN}',
            "nonfinite-exponent": b'{"value":1e9999}',
            "non-object-root": b"[]",
            "oversized-integer": (
                b'{"value":' + b"9" * (READ_ONLY_REPORT_MAX_INTEGER_DIGITS + 1) + b"}"
            ),
            "excessive-depth": nested,
            "excessive-nodes": too_many_nodes,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in invalid_payloads.items():
                with self.subTest(payload=name):
                    path = root / f"{name}.json"
                    path.write_bytes(payload)
                    with self.assertRaises(
                        (
                            UnicodeDecodeError,
                            json.JSONDecodeError,
                            ValueError,
                        )
                    ):
                        read_only_report_payload(str(path))

        injected_errors: list[BaseException] = [
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
            json.JSONDecodeError("malformed", "", 0),
            RecursionError("nested\ninput"),
            ValueError("x" * 1_000 + "\n\x1b\u202e"),
            MemoryError("allocation failed"),
            OSError(
                errno.ENAMETOOLONG,
                "oversized path",
                "untrusted\npath" * 1_000,
            ),
        ]
        for injected in injected_errors:
            with self.subTest(error=type(injected).__name__):
                with mock.patch.dict(
                    READ_ONLY_PR_REPORT_GLOBALS,
                    {"_read_payload": mock.Mock(side_effect=injected)},
                ):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        return_code = read_only_report_main(
                            ["validate-semantics", "ignored"]
                        )
                self.assertEqual(return_code, 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["classification"], "rejected")
                self.assertLessEqual(
                    len(result["error"]),
                    READ_ONLY_REPORT_MAX_ERROR_CHARS,
                )
                self.assertFalse(
                    any(
                        unicodedata.category(character).startswith("C")
                        for character in result["error"]
                    )
                )

        for interrupt in (KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(interrupt=type(interrupt).__name__):
                with mock.patch.dict(
                    READ_ONLY_PR_REPORT_GLOBALS,
                    {"_read_payload": mock.Mock(side_effect=interrupt)},
                ):
                    with self.assertRaises(type(interrupt)):
                        read_only_report_main(["validate-semantics", "ignored"])

    def test_runtime_validator_rejects_splicing_and_cross_field_conflicts(
        self,
    ) -> None:
        cases = {
            case["name"]: case["expected"]["terminal_result"]
            for case in fixture_cases(
                READ_ONLY_PR_PROBE_CASES,
                "read-only-pr-probe",
            )
        }
        resolved = cases["resolved-target-snapshot"]
        range_blocked = cases["selected-pr-base-head-blocked"]
        validator = read_only_report_validator()

        candidates: dict[str, tuple[dict[str, object], bool]] = {}

        spliced_evidence = copy.deepcopy(resolved)
        spliced_evidence["evidence"]["pr_lifecycle"] = copy.deepcopy(
            range_blocked["evidence"]["pr_lifecycle"]
        )
        candidates["cross-report-evidence-splice"] = (spliced_evidence, False)

        spliced_snapshot = copy.deepcopy(resolved)
        spliced_snapshot["snapshot"] = copy.deepcopy(range_blocked["snapshot"])
        candidates["cross-report-snapshot-splice"] = (spliced_snapshot, False)

        reused_instance_token = copy.deepcopy(resolved)
        reused_instance_token["snapshot"]["snapshot_id"] = (
            "observation:33333333333333333333333333333333"
        )
        candidates["reused-instance-token"] = (reused_instance_token, False)

        observed_without_source = copy.deepcopy(resolved)
        observed_without_source["snapshot"]["sources"] = []
        candidates["observed-evidence-without-source"] = (
            observed_without_source,
            True,
        )

        contradictory_lifecycle = copy.deepcopy(resolved)
        contradictory_lifecycle["evidence"]["pr_lifecycle"]["observed"][0].update(
            {
                "merged": True,
                "merged_at": "2026-07-24T06:04:00Z",
            }
        )
        candidates["open-and-merged-lifecycle"] = (
            contradictory_lifecycle,
            True,
        )

        contradictory_selection = copy.deepcopy(resolved)
        contradictory_selection["evidence"]["pr_selection"]["observed"][0][
            "candidate_count"
        ] = 2
        candidates["selected-with-two-candidates"] = (
            contradictory_selection,
            True,
        )

        explicit_ambiguity = copy.deepcopy(cases["pre-target-no-match"])
        explicit_ambiguity["evidence"]["pr_selection"]["observed"][0].update(
            {
                "selection_method": "explicit",
                "outcome": "ambiguous",
                "candidate_count": 2,
            }
        )
        candidates["explicit-selection-cannot-be-ambiguous"] = (
            explicit_ambiguity,
            True,
        )

        aggregate_mismatch = copy.deepcopy(range_blocked)
        aggregate_mismatch["evidence"]["ci_status"]["observed"][0]["successful"] = 2
        candidates["ci-counts-do-not-match-checks"] = (aggregate_mismatch, False)

        duplicate_check_name = copy.deepcopy(range_blocked)
        duplicate_check_name["evidence"]["ci_status"]["observed"][0]["checks"][1][
            "name"
        ] = "lint"
        candidates["duplicate-ci-check-name"] = (duplicate_check_name, False)

        state_mismatch = copy.deepcopy(range_blocked)
        state_mismatch["evidence"]["ci_status"]["observed"][0]["state"] = "success"
        candidates["ci-state-does-not-match-checks"] = (state_mismatch, True)

        thread_mismatch = copy.deepcopy(range_blocked)
        thread_mismatch["evidence"]["conversation_state"]["observed"][0].update(
            {
                "total_threads": 1,
                "unresolved_threads": 2,
            }
        )
        candidates["unresolved-threads-exceed-total"] = (thread_mismatch, False)

        endpoint_mismatch = copy.deepcopy(resolved)
        endpoint_mismatch["evidence"]["base_and_head"]["observed"][0][
            "base_object_present"
        ] = False
        candidates["missing-base-with-merge-base"] = (endpoint_mismatch, True)

        for name, (candidate, schema_must_reject) in candidates.items():
            with self.subTest(name=name):
                schema_errors = list(validator.iter_errors(candidate))
                if schema_must_reject:
                    self.assertTrue(schema_errors)
                else:
                    self.assertEqual(schema_errors, [])
                with self.assertRaises(ValueError):
                    validate_read_only_report_semantics(candidate)
                with self.assertRaises(AssertionError):
                    assert_read_only_report_contract(candidate)

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
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        self.assertEqual(
            set(schema["properties"]["profile"]["enum"]),
            PROFILES,
        )
        self.assertEqual(
            set(schema["properties"]["constraints"]["items"]["enum"]),
            CONSTRAINTS,
        )
        self.assertEqual(len(schema["allOf"]), 9)
        (
            local_mutation_constraint,
            local_gate_formal_review_constraint,
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
            local_gate_formal_review_constraint["if"]["properties"]["profile"]["const"],
            "local-gate",
        )
        self.assertEqual(
            local_gate_formal_review_constraint["if"]["properties"]["commit_mode"][
                "const"
            ],
            "allowed",
        )
        self.assertIs(
            local_gate_formal_review_constraint["then"]["properties"][
                "formal_review_required"
            ]["const"],
            True,
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
        self.assertIs(
            profile_constraint["then"]["properties"]["formal_review_required"]["const"],
            True,
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
        self.assertIs(
            pr_handoff_constraint["then"]["properties"]["formal_review_required"][
                "const"
            ],
            True,
        )
        self.assertEqual(
            read_only_handoff_constraint["then"]["properties"]["profile"]["const"],
            "local-gate",
        )
        self.assertEqual(
            read_only_handoff_constraint["then"]["properties"]["handoff"]["const"],
            "review-orchestration-playbook",
        )
        self.assertNotIn(
            "formal_review_required",
            read_only_handoff_constraint["then"]["properties"],
        )

        for case in profile_selection_cases():
            with self.subTest(prompt=case["prompt"]):
                assert_valid_result_contract(case["result"])
                self.assertEqual(list(validator.iter_errors(case["result"])), [])

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
                "formal_review_required": True,
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
                "formal_review_required": True,
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
