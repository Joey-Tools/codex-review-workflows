from __future__ import annotations

import json
import pathlib
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalize(value: str) -> str:
    return " ".join(value.split()).lower()


class GitHubRecoveryContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.skill = _read(SKILL_ROOT / "SKILL.md")
        cls.probes = _read(REFERENCES / "github-pr-probes.md")
        cls.authority = _read(REFERENCES / "github-codex-evidence-authority.md")
        cls.contracts = _read(REFERENCES / "review-lane-contracts.md")
        cls.prompts = _read(REFERENCES / "review-prompt-templates.md")
        cls.readiness = _read(REFERENCES / "pr-readiness.md")
        cls.carriers = json.loads(
            _read(REFERENCES / "github-codex-terminal-carriers-v1.json")
        )

    def test_actions_repeat_is_exact_tuple_idempotent_and_authorized(self) -> None:
        recovery = self.probes.split("## Reconcile Only Recoverable States", 1)[
            1
        ].split("## Retry Schedule And Cost Control", 1)[0]
        normalized = _normalize(recovery)

        self.assertIn(
            "freeze one exact recovery tuple",
            normalized,
        )
        self.assertIn("repetitions of that same tuple as idempotent", normalized)
        self.assertIn("no repository-specific idempotency", normalized)
        self.assertIn(
            "the current task must still authorize the external mutation", normalized
        )
        self.assertIn("keep the recovery owner in status-only mode", normalized)
        self.assertIn(
            "report the missing authorization instead of triggering",
            normalized,
        )
        self.assertLess(
            normalized.index("freeze one exact recovery tuple"),
            normalized.index("illustrative commands"),
        )
        combined = _normalize(
            self.skill
            + "\n"
            + self.probes
            + "\n"
            + self.authority
            + "\n"
            + self.contracts
            + "\n"
            + self.prompts
        )
        self.assertNotIn("repository-predeclared", combined)
        self.assertNotIn("predeclares it as idempotent", combined)
        for anchor in (
            "single-flight",
            "changed scope",
            "workflow",
            "input set",
            "ordinary confirmation",
            "never reconcile an explicit review finding",
        ):
            self.assertIn(anchor, combined)

    def test_merge_status_basis_binds_subject_scope_and_contract_clean(self) -> None:
        combined = _normalize(self.skill + "\n" + self.probes + "\n" + self.authority)
        for anchor in (
            "feature head",
            "current base",
            "unique merge base",
            "check_subject_sha",
            "github-synthetic-merge",
            "latest-feature-head",
            "current-merge-scope",
            "app/workflow/run/check",
            "does not require a separate terminal clean comment or review",
            "generic successful check",
            "service-start marker",
            "zero unresolved applicable",
            "type-preserving equality",
        ):
            self.assertIn(anchor, combined)

    def test_comment_creation_is_one_shot_across_github_contracts(
        self,
    ) -> None:
        authoritative_documents = {
            "probes": self.probes,
            "authority": self.authority,
        }
        routing_documents = {
            "lane-contracts": self.contracts,
            "prompt-templates": self.prompts,
        }
        authoritative_required = (
            "comment-mutation epoch",
            "at most one possibly delivered create-comment post",
            "complete visible exact-request set",
            "consumes the epoch's comment-mutation budget",
            "never repeat the comment post",
            "request_policy.status: unknown",
            "request-delivery-unproven",
            "audit warning",
            "same logical review lane",
            "never authorizes another comment write",
        )

        for name, document in authoritative_documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                for anchor in authoritative_required:
                    self.assertIn(anchor, normalized)

        routing_required = (
            "possibly delivered",
            "repository/pr/head epoch",
            "complete visible request set",
            "consumes the comment-mutation budget",
            "request_policy.status: unknown",
            "request-delivery-unproven",
            "never repeat the comment post in that epoch",
            "audit warning",
            "same logical",
            "never authorizes another",
        )
        for name, document in routing_documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                for anchor in routing_required:
                    self.assertIn(anchor, normalized)

        documents = authoritative_documents | routing_documents
        for name, document in documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                self.assertNotIn(
                    "the same exact `@codex review` post may be repeated", normalized
                )
                self.assertNotIn("idempotent delivery retry", normalized)
                self.assertNotIn("ambiguous-delivery recovery", normalized)

        combined = _normalize("\n".join(documents.values()))
        self.assertIn("only a new feature head creates a new", combined)
        self.assertIn("only an independently authorized exact actions tuple", combined)
        self.assertIn("never applies to github comment creation", combined)
        self.assertNotIn("before every repetition", combined)

    def test_retry_schedule_cannot_repeat_comment_creation(self) -> None:
        request = self.probes.split("## Request The Review", 1)[1].split(
            "## Discover Related Checks Dynamically", 1
        )[0]
        recovery = self.probes.split("## Reconcile Only Recoverable States", 1)[
            1
        ].split("## Active Thread And Automation", 1)[0]
        failures = self.probes.split("## Probe Failures", 1)[1]
        normalized = _normalize(request + "\n" + recovery + "\n" + failures)

        for anchor in (
            "completely enumerate every page",
            "comment creation is not an idempotent operation",
            "it consumes the epoch's comment-mutation budget",
            "this exact-tuple idempotence applies only to the actions mutations",
            "it never repeats a create-comment post",
            "generic transport retry rule applies to reads and eligible actions mutations only",
        ):
            self.assertIn(anchor, normalized)
        self.assertNotIn("idempotent delivery retry", normalized)

    def test_unbounded_backoff_is_limited_to_typed_retryable_reasons(self) -> None:
        retry = self.probes.split("## Retry Schedule And Cost Control", 1)[1].split(
            "## Active Thread And Automation", 1
        )[0]
        normalized = _normalize(retry)

        self.assertIn(
            "machine-decidable retryable pending or infrastructure reason",
            normalized,
        )
        self.assertIn("1, 2, 4, 8, 16, 32, 60, 60, 60", normalized)
        self.assertIn(
            "there is no retry-count ceiling while the same reason remains machine-decidably retryable",
            normalized,
        )
        self.assertIn("at 60 minutes, report", normalized)
        self.assertIn("then retry hourly", normalized)
        self.assertIn("stable malformed snapshot", normalized)
        self.assertIn("non-retryable inconclusive state stops", normalized)

        combined = _normalize(self.skill + "\n" + self.probes + "\n" + self.authority)
        self.assertNotIn("inconclusive provider collection", combined)
        self.assertIn(
            "other non-retryable inconclusive state terminates recovery",
            combined,
        )

    def test_long_wait_uses_same_thread_and_private_throttling(self) -> None:
        automation = self.probes.split("## Active Thread And Automation", 1)[1]
        retry = self.probes.split("## Retry Schedule And Cost Control", 1)[1]
        normalized = _normalize(automation + "\n" + retry)

        for anchor in (
            "same active thread",
            "never create a new conversation",
            "pollable and cancellable active-thread fallback",
            "rolling budget of four full-run equivalents per 24 hours",
            "status-only hourly checks",
            "public repositories do not use the private-minute budget",
        ):
            self.assertIn(anchor, normalized)

    def test_only_applicable_unresolved_findings_block(self) -> None:
        findings = self.authority.split("## Finding Precedence And Resolution", 1)[
            1
        ].split("## Reaction-Only Fallback", 1)[0]
        normalized = _normalize(findings)

        self.assertIn("typed `isresolved == true`", normalized)
        self.assertIn(
            "removes the finding from `unresolved_provider_findings`", normalized
        )
        self.assertIn(
            "it does not require a replacement request or a new head", normalized
        )
        self.assertIn(
            "trustworthy provider clean correction on the same head", normalized
        )
        self.assertIn("generic correction prose is not enough", normalized)
        self.assertIn("if addressing the finding changes repository code", normalized)
        self.assertIn("commit that change as a new head", normalized)

        combined = _normalize(
            self.skill + "\n" + self.authority + "\n" + self.readiness
        )
        self.assertIn("only applicable unresolved provider findings block", combined)
        self.assertIn("requires fresh review", combined)
        self.assertIn(
            "a typed thread resolution or trustworthy same-head provider correction alone does not require a commit",
            combined,
        )
        self.assertNotIn(
            "provider findings block until fixed and resolved on a new reviewed head",
            combined,
        )

    def test_no_pr_uses_a_terminal_closed_null_scope_variant(self) -> None:
        report = self.authority.split("## Required Report", 1)[1]
        normalized = _normalize(report)
        scope_rule = self.carriers["required_report_schema"]["scope_rules"][
            "no-selected-supported-pr"
        ]

        self.assertIsNone(scope_rule["pull_request"])
        self.assertIsNone(scope_rule["head_sha"])
        self.assertEqual(scope_rule["status"], "not-applicable")
        for field, value in (
            ("status", scope_rule["status"]),
            ("pull_request", "null"),
            ("head_sha", "null"),
            ("scope_assurance", scope_rule["scope_assurance"]),
            ("base_assurance", scope_rule["base_assurance"]),
            ("basis", "null"),
            ("evidence", "null"),
            ("last_reason", scope_rule["last_reason"]),
        ):
            self.assertIn(f"{field}: {value}", report)
        self.assertIn("this no-pr variant is terminal", normalized)
        self.assertIn("it never enters retry recovery", normalized)
        self.assertIn("required null pr/head fields", normalized)


if __name__ == "__main__":
    unittest.main()
