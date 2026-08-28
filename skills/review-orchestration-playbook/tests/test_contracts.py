from __future__ import annotations

import ast
import inspect
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_SCOPE_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
RUNTIME = SCRIPTS / "review_runtime"
REFERENCES = SKILL_ROOT / "references"
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
        depth = len(layout.parts)
        if skill_root.parts[-depth:] != layout.parts:
            continue
        repo_root = skill_root.parents[depth - 1]
        if repo_root / layout == skill_root:
            return repo_root, profile
    raise AssertionError(f"unsupported review skill layout: {skill_root}")


REPO_ROOT, CI_PROFILE = _ci_contract_context(SKILL_ROOT)
POLICY_SCOPE_ROOT = (
    REPO_ROOT if CI_PROFILE == "canonical" else REPO_ROOT / "personal_codex"
)

sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_version_policy,
    named_lane,
    providers,
    state,
)


def _read(relative: str) -> str:
    return (SKILL_ROOT / relative).read_text(encoding="utf-8")


def _normalize(value: str) -> str:
    return " ".join(value.split()).lower()


def _active_policy_paths() -> tuple[pathlib.Path, ...]:
    paths = [
        POLICY_SCOPE_ROOT / "AGENTS.md",
        POLICY_SCOPE_ROOT / "agents/reviewer.toml",
        POLICY_SCOPE_ROOT / "skills/change-delivery-workflow/SKILL.md",
        SKILL_ROOT / "SKILL.md",
        SKILL_ROOT / "agents/openai.yaml",
        REFERENCES / "canonical-claude-lane.md",
        REFERENCES / "egress-consent.md",
        REFERENCES / "github-codex-evidence-authority.md",
        REFERENCES / "github-pr-probes.md",
        REFERENCES / "local-codex-lane.md",
        REFERENCES / "pr-readiness.md",
        REFERENCES / "review-lane-contracts.md",
        REFERENCES / "review-prompt-templates.md",
        REFERENCES / "review-workspace.md",
    ]
    if CI_PROFILE == "canonical":
        paths.append(REPO_ROOT / "README.md")
    return tuple(path for path in paths if path.is_file())


def _has_python_shebang(path: pathlib.Path) -> bool:
    with path.open("rb") as handle:
        first_line = handle.readline(256)
    return first_line.startswith(b"#!") and b"python" in first_line.lower()


class RepositoryContractTest(unittest.TestCase):
    def test_ci_matches_the_reviewed_distribution_profile(self) -> None:
        actual = (REPO_ROOT / ".github/workflows/ci.yml").read_bytes()
        expected = (CI_FIXTURE_ROOT / f"{CI_PROFILE}.yml").read_bytes()
        self.assertEqual(
            actual,
            expected,
            f"CI workflow differs from reviewed {CI_PROFILE} snapshot",
        )

        workflow = expected.decode("utf-8")
        self.assertIn("Require source-only Python tree", workflow)
        self.assertIn("python3 -B -c 'import pathlib, sys;", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("Require every platform test to pass", workflow)

    def test_only_canonical_review_skill_entrypoint_remains(self) -> None:
        self.assertTrue((SKILL_ROOT / "SKILL.md").is_file())
        for relative in (
            "skills/external-review-playbook/SKILL.md",
            "skills/pr-readiness-review-workflow/SKILL.md",
            "skills/copilot-review-playbook/SKILL.md",
            "skills/review-orchestration-playbook/scripts/isolated_external_review",
            "skills/review-orchestration-playbook/scripts/isolated_copilot_review",
            "skills/review-orchestration-playbook/scripts/git_readonly_shim",
        ):
            self.assertFalse((SKILL_SCOPE_ROOT / relative).exists(), relative)

    def test_one_logical_codex_lane_has_peer_adapters(self) -> None:
        skill = _read("SKILL.md")
        contracts = _read("references/review-lane-contracts.md")
        local = _read("references/local-codex-lane.md")
        consent = _read("references/egress-consent.md")

        for document in (skill, contracts, local):
            normalized = _normalize(document)
            self.assertIn("one logical", normalized)
            self.assertIn("subagent", normalized)
            self.assertIn("cli", normalized)
            self.assertIn("peer", normalized)
            self.assertIn("ultra", normalized)
            self.assertIn("internal delegation", normalized)
        self.assertIn("Neither adapter has a standing priority", local)
        self.assertIn('fork_turns="none"', local)
        self.assertIn("new, non-resumed Codex review process", local)
        for cli_control in (
            "--ephemeral",
            "--ignore-user-config",
            "--strict-config",
            "-s read-only",
            "-m gpt-5.6-sol",
            'model_reasoning_effort="ultra"',
            "-C <absolute-validated-workspace>",
            "exact UTF-8 prompt bytes",
            "stdin descriptor",
            "prompt byte length and SHA-256 digest",
            "general `exec -`",
            "hashed-file-redirection",
            "never embed prompt content in the command",
            "interactive PTY injection",
        ):
            self.assertIn(cli_control, local)
        self.assertIn(
            "specialized `review --base` surface rejects a positional custom prompt",
            local,
        )
        self.assertIn(
            "does not provide a receipt proving that an stdin prompt was preserved",
            local,
        )
        self.assertIn(
            "A runtime's default review prompt or range selector never substitutes for this control prompt",
            contracts,
        )
        self.assertIn(
            "use general `codex exec -` with exact prompt bytes on stdin",
            _read("references/review-prompt-templates.md"),
        )
        cli_argv = local.split("normalized direct-argv shape is:", 1)[1].split(
            "```", 2
        )[1]
        self.assertIn("--json\n  -", cli_argv)
        self.assertNotIn("\n  review\n", cli_argv)
        self.assertNotIn("--base", cli_argv)
        self.assertIn("does not by itself suppress global `AGENTS.md`", local)
        self.assertIn(
            "Any unallowlisted external model/tool read invalidates the attempt", local
        )
        self.assertIn("record the effective value as `unknown`", local)
        self.assertIn("An observed mismatch or downgrade is inconclusive", local)
        self.assertIn("PTY bulk writes can drop or transform bytes", local)
        self.assertIn("SHA-256 digest before and after launch", local)
        self.assertIn("requested and effective model and Codex mode", local)
        self.assertIn("using both does not create extra consent", consent)
        self.assertNotIn("sole lane that satisfies", _normalize(skill + local))

    def test_named_shapes_and_prompts_preserve_processor_independence(self) -> None:
        skill = _normalize(_read("SKILL.md"))
        contracts = _normalize(_read("references/review-lane-contracts.md"))
        prompts = _normalize(_read("references/review-prompt-templates.md"))

        for shape in (
            "one fresh-context local codex lane",
            "single plus one actual claude code lane",
            "double plus current-head github codex evidence",
        ):
            self.assertIn(shape, skill)
        for shape in (
            "named single | one clean logical local codex lane",
            "named double | named single plus one clean actual claude code lane",
            "named triple | named double plus a passing current-head github codex lane",
        ):
            self.assertIn(shape, contracts)

        self.assertIn(
            "validated workspace and frozen endpoints, not a pasted diff", prompts
        )
        self.assertIn(
            "do not include parent conclusions, suspected bugs, or another reviewer result",
            prompts,
        )
        self.assertIn(
            "obtain the diff yourself with bounded read-only commands", prompts
        )
        for prompt_binding in (
            "base_sha: <full object id>",
            "head_sha: <full object id>",
            "workspace_receipts:",
            "prompt_transport:",
            "prompt_bytes:",
            "prompt_sha256:",
        ):
            self.assertIn(
                prompt_binding, _read("references/review-prompt-templates.md")
            )
        self.assertIn(
            "claude receives the same metadata and evidence goal but no codex output",
            prompts,
        )
        self.assertIn("one actual supported claude code process", contracts)
        self.assertIn(
            "a claude simulation, another codex process, or github copilot in place of actual claude code",
            contracts,
        )

    def test_report_only_and_pr_range_authority_remain_fail_closed(self) -> None:
        agents = (POLICY_SCOPE_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        skill_raw = _read("SKILL.md")
        readiness = _read("references/pr-readiness.md")
        contracts = _read("references/review-lane-contracts.md")
        combined = _normalize("\n".join((agents, skill_raw, readiness, contracts)))

        self.assertIn(
            "a report-only review request does not authorize a branch, commit, push, pr creation, pr retarget, or metadata change",
            combined,
        )
        self.assertIn("base_sha = pr_merge_base", combined)
        self.assertIn("head_sha = head_ref_oid", combined)
        self.assertIn("current `headrefoid` equals `head_sha`", combined)
        self.assertIn("unique current merge base equals `base_sha`", combined)
        self.assertIn("never silently rewritten", combined)
        for lifecycle in ("state == open", "merged == false", "mergedat == null"):
            self.assertIn(lifecycle, combined)
        self.assertLess(
            skill_raw.index("## Freeze Scope Before Review"),
            skill_raw.index("## Run Local Lanes"),
        )

    def test_range_origin_gates_same_head_merge_base_rederivation(self) -> None:
        skill = _read("SKILL.md")
        readiness = _read("references/pr-readiness.md")
        authority = _read("references/github-codex-evidence-authority.md")
        probes = _read("references/github-pr-probes.md")
        normalized_skill = _normalize(skill)
        normalized_readiness = _normalize(readiness)
        freeze_contract = readiness.split("## Freeze The Whole-PR Range", 1)[1].split(
            "## Lifecycle Gate", 1
        )[0]
        report_contract = readiness.split("## Merge-Ready Report", 1)[1]
        normalized_freeze = _normalize(freeze_contract)

        for document in (normalized_skill, normalized_readiness):
            self.assertIn("parent-owned immutable `range_origin`", document)
            self.assertIn("`caller-supplied`", document)
            self.assertIn("`pr-derived`", document)
            self.assertIn("`lineage_id`", document)
            self.assertIn("`active_record_id`", document)

        for schema_field in (
            "range_origin:",
            "lineage_id: stable-parent-generated-lineage-id",
            "kind: caller-supplied | pr-derived",
            "active_record_id: stable-parent-generated-record-id",
            "record_id: same-as-active-record-id",
            "predecessor_record_id: null | previous-active-record-id",
            "base_sha: record-full-object-id",
            "head_sha: record-full-object-id",
        ):
            self.assertIn(schema_field, freeze_contract)
            self.assertIn(schema_field, report_contract)

        for lineage_anchor in (
            "the first record fixes both for the lifetime of this selected-pr/head lineage",
            "the first record has `predecessor_record_id: null`",
            "every successor must reuse the fixed `lineage_id` and `kind`",
            "name the exact previously active record in `predecessor_record_id`",
            "appending a record never activates it",
            "do not start or substitute a second lineage",
            "a `caller-supplied` lineage can never acquire or activate a `pr-derived` record",
            "only the unique record named by the current `(lineage_id, active_record_id)` binding may count as pr-wide evidence",
            "its endpoints must equal the exact `base_sha..head_sha` used by every counted local lane",
        ):
            self.assertIn(lineage_anchor, normalized_freeze)

        self.assertIn(
            _normalize(
                "For `pr-derived`, the parent may automatically derive the exact new "
                "`pr_merge_base..head_ref_oid` pair"
            ),
            normalized_freeze,
        )
        self.assertIn(
            _normalize(
                "For `caller-supplied`, preserve the original endpoints and do not "
                "silently substitute the new merge base"
            ),
            normalized_freeze,
        )
        self.assertIn(
            _normalize(
                "Only the caller's explicit provision or confirmation of the exact "
                "current `pr_merge_base..head_ref_oid` pair creates an immutable "
                "successor in the same `caller-supplied` lineage"
            ),
            normalized_freeze,
        )
        self.assertIn(
            "never append or activate a `pr-derived` successor to bypass this confirmation",
            normalized_freeze,
        )
        self.assertIn("range-origin-unverified", freeze_contract)
        self.assertIn("a stale or mismatched active record", normalized_freeze)
        self.assertIn("a replacement lineage", normalized_freeze)
        self.assertIn("a kind switch", normalized_freeze)
        self.assertIn(
            "stop before starting or counting a local pr-wide lane",
            normalized_freeze,
        )
        self.assertIn(
            "GitHub Codex result may remain valid as latest-head-only evidence",
            readiness,
        )
        self.assertIn(
            "provenance gate in [pr-readiness.md](pr-readiness.md)", authority
        )
        self.assertIn(
            "neither selects nor rewrites a local range",
            _normalize(authority),
        )
        self.assertIn("This probe layer never selects or rewrites that range", probes)

    def test_q44_strict_freshness_requires_signed_merge_and_full_rerun(
        self,
    ) -> None:
        skill = _read("SKILL.md")
        readiness = _read("references/pr-readiness.md")
        normalized_skill = _normalize(skill)
        authority = _normalize(_read("references/github-codex-evidence-authority.md"))
        freshness_contract = readiness.split(
            "## Branch Freshness Is Not Linear History", 1
        )[1].split("### Head-Only Provider Responsibility Boundary", 1)[0]
        normalized_freshness = _normalize(freshness_contract)

        for exact_github_name in (
            "Require branches to be up to date before merging",
            "Require linear history",
        ):
            self.assertIn(exact_github_name, skill)
            self.assertIn(exact_github_name, freshness_contract)

        self.assertIn(
            "when a merge queue owns freshness, follow the queue's merge-group and check semantics",
            normalized_freshness,
        )
        self.assertIn(
            "when no merge queue owns freshness and strict freshness blocks the authorized pr workflow, merge the current base branch into the feature branch with a signed merge commit",
            normalized_freshness,
        )
        self.assertIn("do not rebase", normalized_freshness)
        self.assertIn("that merge creates a new head", normalized_freshness)
        self.assertIn(
            "freeze the resulting `merge_base..new_head`", normalized_freshness
        )
        self.assertIn(
            "invalidates every old-head positive/pass/clean result and every head-bound readiness gate",
            normalized_skill,
        )
        self.assertIn(
            "every positive, pass, or clean result bound to the old head is stale",
            normalized_freshness,
        )
        self.assertIn(
            "every head-bound readiness gate must be reacquired",
            normalized_freshness,
        )
        for retained_negative in (
            "an ancestry-proven unresolved provider finding that remains applicable to the new head",
            "negative evidence, not reusable positive evidence",
            "continues to block until typed resolution or an accepted later corrective artifact",
        ):
            self.assertIn(retained_negative, normalized_freshness)
        self.assertIn(
            "every old-head positive github codex result is stale; unresolved findings remain applicable",
            authority,
        )
        self.assertNotIn("invalidates all old-head evidence", normalized_skill)
        self.assertNotIn("all old-head evidence", _normalize(readiness))

        for rerun_gate in (
            "local validation and tests",
            "every required local review lane",
            "the github codex lane",
            "ci and status checks",
            "all conversations",
            "lifecycle/base/head and merge-policy checks",
            "the final stable reread",
        ):
            self.assertIn(rerun_gate, normalized_freshness)

    def test_base_tip_change_invalidates_pr_readiness_evidence(self) -> None:
        skill = _normalize(_read("SKILL.md"))
        readiness_raw = _read("references/pr-readiness.md")
        readiness = _normalize(readiness_raw)
        probes = _normalize(_read("references/github-pr-probes.md"))
        authority = _normalize(_read("references/github-codex-evidence-authority.md"))
        invalidation = _normalize(
            readiness_raw.split("## Change Invalidation", 1)[1].split("## Fix Loop", 1)[
                0
            ]
        )
        final_reread = _normalize(
            readiness_raw.split("## Final Reread", 1)[1].split(
                "## Atomic Head Binding For Merge Execution", 1
            )[0]
        )

        for document in (skill, readiness, probes, authority):
            self.assertIn("`baserefname`", document)
            self.assertIn("`baserefoid`", document)
            self.assertIn("readiness", document)

        self.assertIn(
            "even when the head and unique merge base remain unchanged",
            probes,
        )
        self.assertIn(
            "all local pr-wide reviews, all local validation and tests, all ci/status results, all conversation decisions",
            invalidation,
        )
        self.assertIn(
            "the current exact repository, `baserefname`, and `baserefoid` binding",
            final_reread,
        )
        self.assertIn(
            "the same selected repository, current exact `baserefname`, exact `baserefoid`, head, and appropriate merge base",
            final_reread,
        )
        self.assertIn("a stale scope, target-ref, or base-tip binding", final_reread)
        self.assertIn("readiness decisions, and final reread", invalidation)
        self.assertIn(
            "no evidence from the old base tip remains countable",
            invalidation,
        )
        self.assertIn(
            "the range endpoints and active range-origin record are unchanged",
            invalidation,
        )
        self.assertIn(
            "target `baserefname` changes, even when its oid is unchanged",
            invalidation,
        )
        self.assertIn(
            "all local pr-wide reviews, all local validation and tests, all ci/status results, all conversation decisions",
            invalidation,
        )

        for document in (readiness, probes, authority):
            self.assertIn(
                "exact head is still current",
                document,
            )
            self.assertIn(
                "no applicable provider finding remains unresolved",
                document,
            )
            self.assertIn("no base", document)

        self.assertNotIn("base-sensitive local/readiness gates only", probes)
        self.assertNotIn(
            "the frozen local range itself is unchanged",
            invalidation,
        )

    def test_merge_execution_binds_head_and_server_enforces_base_freshness(
        self,
    ) -> None:
        skill = _normalize(_read("SKILL.md"))
        readiness = _read("references/pr-readiness.md")
        probes = _normalize(_read("references/github-pr-probes.md"))
        execution = readiness.split("## Atomic Head Binding For Merge Execution", 1)[
            1
        ].split("## Merge-Ready Report", 1)[0]
        normalized_execution = _normalize(execution)

        for required in (
            "direct merge and to merge-queue enrollment",
            "server-enforced precondition in the operation itself",
            "server-enforced base-freshness binding",
            "--match-head-commit",
            "select the exact repository and pr",
            "a separate `headrefoid` or `baserefoid` read followed by an unconditional mutation "
            "has a race",
            "never emulate either condition with a second read in the client",
            "it does not expose an expected-target-base field",
            "a point read of the base, mergeability, or `mergestatestatus` is not an atomic substitute",
            "the protected property is exactly one of",
            "exact base equality",
            "proven monotonic range contraction",
            "do not retry the stale mutation",
            "the pr's final feature head to remain exactly `merge_expected_head`",
        ):
            self.assertIn(required, normalized_execution)

        self.assertIn(
            "gh pr merge <pr_number> --repo owner/repo --squash",
            normalized_execution,
        )
        self.assertIn(
            "gh pr merge <pr_number> --repo owner/repo",
            normalized_execution,
        )
        self.assertEqual(
            normalized_execution.count("--match-head-commit <head_sha>"), 1
        )
        self.assertIn(
            "the same mutation carries the exact reviewed head", normalized_execution
        )

        for persistent_queue_anchor in (
            "put /repos/owner/repo/pulls/<pr_number>/merge-async",
            '{"sha":"<head_sha>","merge_action":"merge_queue"}',
            "get /repos/owner/repo/pulls/<pr_number>/merge-async/<uuid>",
            "details.expected_head_sha == merge_expected_head",
            'details.merge_action == "merge_queue"',
            "persist the request's status, response, and uuid",
            "a `409` may identify an older request whose options differ",
            "feature-head change must be observed as cancellation",
            "an `automergeRequest` is not equivalent to this persistent binding",
            "if the async endpoint or an equally persistent server-side expected-head queue primitive is unavailable",
            "never fall back to an unbound auto-merge request",
            "require no active stale `automergeRequest` or queue entry",
        ):
            self.assertIn(persistent_queue_anchor.lower(), normalized_execution)

        queue_example = normalized_execution.split(
            "# the same request through github cli's api transport.", 1
        )[1].split("```", 1)[0]
        self.assertIn("gh api --include --method put", queue_example)
        self.assertIn("x-github-api-version: 2026-03-10", queue_example)
        self.assertIn("merge-async", queue_example)
        self.assertIn('-f sha="<head_sha>"', queue_example)
        self.assertIn('-f merge_action="merge_queue"', queue_example)
        self.assertNotIn("gh pr merge", queue_example)

        for invalidated_gate in (
            "test",
            "review",
            "github",
            "ci",
            "conversation",
            "lifecycle",
            "merge-policy",
            "final reread",
        ):
            self.assertIn(invalidated_gate, normalized_execution)

        for base_race_anchor in (
            "require branches to be up to date before merging",
            "it is not an exact-base comparison",
            "a different base tip that is already an ancestor of the unchanged feature head may still satisfy strict freshness",
            "required checks plus strict",
            "do not by themselves protect the later mutation",
            "a configured merge queue owns only latest-base merge-group freshness by default",
            "it does not reacquire out-of-band local review or conversation gates",
            "if no such hold exists, the queue path is blocked",
            "the only direct-merge alternative is a complete parent proof of monotonic range contraction",
            "the frozen `merge_expected_base_ref` equals the selected repository plus `baserefname`",
            "every update to that same frozen target ref from `merge_expected_base` must be fast-forward",
            "deletion and non-fast-forward updates are forbidden",
            "configured administrator/app/ruleset bypass",
            "trusted external control plane",
            "any observed `baserefname`, applicable-rule, bypass, or actor-inventory change invalidates the proof",
            "does not define a producer implementation or require a nonexistent server-side retarget hold",
        ):
            self.assertIn(base_race_anchor, probes)

        self.assertIn(
            "if the target ref or base tip changes again before the direct merge and the parent observes it, start the full invalidation loop again",
            normalized_execution,
        )
        self.assertIn(
            "when the change leaves the feature branch behind, strict freshness additionally blocks",
            normalized_execution,
        )
        self.assertIn(
            "the queue, rather than a nonexistent expected-base request field, owns base freshness only under a repository-proved required hold",
            normalized_execution,
        )
        for queue_base_change_anchor in (
            "such a change invalidates the existing enrollment, `merge_expected_base`, and every earlier local review",
            "cancel or observe cancellation of that enrollment",
            "complete the full rerun for the new exact base tip",
            "a rebuilt merge group never preserves out-of-band evidence",
            "every invalidated gate is itself a required, non-bypassed check on that new merge group",
            "without either contract, the queue path is blocked",
        ):
            self.assertIn(queue_base_change_anchor, normalized_execution)
        self.assertNotIn(
            "must cancel or rebuild its merge group when the target base changes",
            normalized_execution,
        )

        self.assertIn("direct merge and merge-queue enrollment", skill)
        self.assertIn("--match-head-commit <head_sha>", skill)
        self.assertIn("asynchronous merge request", skill)
        self.assertIn("`merge_action: merge_queue`", skill)
        self.assertIn("a polled `expected_head_sha`", skill)
        self.assertIn("long-lived auto-merge request", skill)
        self.assertIn("the queue path is blocked", skill)
        self.assertIn("a separate head read is not an atomic substitute", skill)
        self.assertIn("a mismatch fails closed", skill)
        self.assertIn("exact-base property is preferred", skill)
        self.assertIn("proven monotonic range contraction", skill)
        self.assertIn("frozen `merge_expected_base_ref`", skill)
        self.assertIn("strict alone", skill)
        self.assertIn("force-push or deletion permission", skill)
        self.assertIn("any configured base-update or merge bypass", skill)
        self.assertIn("trusted external control plane", skill)
        self.assertIn("a separate base read is not an atomic substitute", skill)

        report = _normalize(readiness.split("## Merge-Ready Report", 1)[1])
        self.assertIn("base_ref_name: exact-base-ref-name", report)
        self.assertIn("merge_expected_head: same-as-head-ref-oid", report)
        self.assertIn(
            "merge_expected_base: same-as-base-ref-oid-at-final-reread", report
        )
        self.assertIn("merge_expected_base_ref:", report)
        self.assertIn("repository: same-as-report-repository", report)
        self.assertIn("base_ref_name: exact-base-ref-name-at-final-reread", report)
        self.assertIn(
            "merge_execution_binding: required-server-side-head-and-base-freshness | not-authorized",
            report,
        )
        self.assertIn(
            "protected_base_property: exact-base-equality | monotonic-range-contraction | merge-queue-full-gate-binding | blocked-unproved",
            report,
        )
        self.assertIn(
            "base_freshness_binding: merge-queue-full-gate-binding | expected-base-precondition | repository-exact-base-guard | monotonic-range-contraction | blocked-unbound",
            report,
        )

    def test_monotonic_contraction_direct_merge_alternative_is_closed(self) -> None:
        readiness_raw = _read("references/pr-readiness.md")
        decision = _normalize(
            readiness_raw.split("### Direct Base Protection Decision", 1)[1].split(
                "For a direct merge", 1
            )[0]
        )
        authority = _normalize(_read("references/github-codex-evidence-authority.md"))

        for required_proof in (
            "the frozen `merge_expected_base_ref` equals the final-reread repository plus `baserefname`",
            "the final unique merge base, `merge_expected_base`, and reviewed `base_sha` are equal",
            "strict up-to-date is enforced by the server in the merge transaction",
            "that same frozen target base ref can only move by fast-forward and cannot be deleted or non-fast-forward rewritten",
            "the complete current applicable protection/ruleset and actor inventory",
            "contains no configured base-update or merge bypass",
            "including an administrator, app, or ruleset bypass entry",
            "enumerates actors authorized to retarget the pr",
            "that inventory is complete rather than inferred from one visible rule",
            "`merge_expected_base` is an ancestor of `current_base`",
            "`current_base` is an ancestor of `head_sha`",
            "is a subset of the reviewed `merge_expected_base..head_sha` range",
        ):
            self.assertIn(required_proof, decision)

        for negative_case in (
            "strict up-to-date alone | blocked",
            "force push or another non-fast-forward base update is allowed | blocked",
            "base deletion is allowed | blocked",
            "any configured base-update or merge bypass exists | blocked",
            "applicable protection/ruleset or actor/bypass inventory is incomplete | blocked",
            "base-ref or authorized retarget-actor inventory is incomplete | blocked",
            "an observed `baserefname` retarget, even to the same oid or another `head_sha` ancestor | full invalidation; contraction unavailable",
            "any rule, actor, endpoint, or transactional-enforcement proof is missing or ambiguous | blocked",
        ):
            self.assertIn(negative_case, decision)

        self.assertIn(
            "transactional strict plus frozen target ref, complete fast-forward-only/no-delete/no-configured-bypass proof, and exact reviewed head | eligible through proven monotonic range contraction",
            decision,
        )
        self.assertIn(
            "once the parent observes any `baserefname` or `baserefoid` change, the ordinary full invalidation and rerun rule applies",
            decision,
        )
        self.assertIn(
            "do not infer contraction across two different target ref names",
            decision,
        )
        self.assertIn(
            "a retarget to another `head_sha` ancestor need not make that new tip a descendant of `merge_expected_base`",
            decision,
        )
        self.assertIn(
            "github and authorized repository collaborators or administrators who can retarget the pr or reconfigure rules are the trusted external control plane",
            decision,
        )
        self.assertIn(
            "any observed `baserefname`, applicable-rule, bypass, or actor-inventory change invalidates the contraction proof",
            decision,
        )
        self.assertIn(
            "malicious or concurrent unobserved retargeting or control-plane reconfiguration after the final reread is outside the consumer guarantee",
            decision,
        )
        self.assertIn(
            "only an unobserved movement of the same frozen target ref during the direct merge's atomic window",
            authority,
        )

    def test_change_delivery_reviews_the_exact_final_landing_head(self) -> None:
        delivery_path = POLICY_SCOPE_ROOT / "skills/change-delivery-workflow/SKILL.md"
        delivery = delivery_path.read_text(encoding="utf-8")
        normalized = _normalize(delivery)
        landing_step = normalized.split(
            "5. form the landing shape, freeze, and hand off review.", 1
        )[1].split("6. accept the reviewed landing head.", 1)[0]
        acceptance_step = normalized.split("6. accept the reviewed landing head.", 1)[1]

        self.assertIn(
            "complete every intended squash, amend, or other landing transformation before the final frozen review",
            landing_step,
        )
        self.assertIn(
            "the exact head intended for the next push or pr handoff",
            landing_step,
        )
        self.assertIn("only accept the exact `head_sha`", acceptance_step)
        self.assertIn("invalidates the prior exact-head result", acceptance_step)
        self.assertIn(
            "rerun the full local validation and documentation checks",
            acceptance_step,
        )
        self.assertIn(
            "repeat every requested local review lane",
            acceptance_step,
        )
        self.assertNotIn(
            "review checkpoint commits may be squashed into the final landing shape",
            normalized,
        )

    def test_secret_admission_never_redacts_or_blocks_reviewer_input(self) -> None:
        consent = _normalize(_read("references/egress-consent.md"))
        contracts = _normalize(_read("references/review-lane-contracts.md"))
        self.assertIn("tracked repository secrets may be present", consent)
        self.assertIn("same-repository committed history or extra git objects", consent)
        self.assertIn(
            "do not redact, rewrite, encode, or block reviewer input", consent
        )
        self.assertIn(
            "secret admission controls pr/master acceptance, not reviewer launch",
            consent,
        )
        self.assertIn("secret-delta admission is independent of review", contracts)
        self.assertIn("never supplies a reviewer result", contracts)

    def test_reviewer_role_requests_sol_ultra_and_read_only_findings(self) -> None:
        role_path = POLICY_SCOPE_ROOT / "agents/reviewer.toml"
        with role_path.open("rb") as handle:
            role = tomllib.load(handle)

        self.assertEqual(role["model"], "gpt-5.6-sol")
        self.assertEqual(role["model_reasoning_effort"], "ultra")
        self.assertEqual(role["sandbox_mode"], "read-only")
        instructions = role["developer_instructions"]
        for anchor in (
            "independent code review",
            "validated clean Git workspace",
            "base_sha..head_sha",
            "Never edit files",
            "Return findings only",
            "No findings.",
            "one logical reviewer invocation",
        ):
            self.assertIn(anchor, instructions)
        self.assertIn("do not orchestrate another named review", instructions.lower())

    def test_codex_peer_adapters_share_sanitized_git_prefix_contract(self) -> None:
        contracts = _read("references/review-lane-contracts.md")
        prompts = _read("references/review-prompt-templates.md")
        local = _read("references/local-codex-lane.md")
        workspace = _read("references/review-workspace.md")
        with (POLICY_SCOPE_ROOT / "agents/reviewer.toml").open("rb") as handle:
            role = tomllib.load(handle)["developer_instructions"]

        for document in (contracts, prompts, local, workspace, role):
            self.assertIn("sanitized_git_argv_prefix", document)

        self.assertIn(
            "workspace-helper subprocesses by both the exact\n"
            "  `GIT_NO_LAZY_FETCH=1` environment token and Git's global "
            "`--no-lazy-fetch`",
            workspace,
        )
        self.assertIn(
            "`sanitized-git-argv-prefix-v2` used by a local Codex reviewer\n"
            "  deliberately omits that global option",
            workspace,
        )

        for fixed_token in (
            "/usr/bin/env",
            "-i",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_SYSTEM=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_GRAFT_FILE=/dev/null",
            "GIT_LITERAL_PATHSPECS=1",
            "GIT_NO_LAZY_FETCH=1",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_OPTIONAL_LOCKS=0",
            "GIT_TERMINAL_PROMPT=0",
            "--no-pager",
            "-c core.commitGraph=false",
            "-c core.fsmonitor=false",
            "-c core.hooksPath=/dev/null",
            "-c core.attributesFile=/dev/null",
            "-c diff.external=",
            "<absolute-clean-workspace>",
        ):
            self.assertIn(fixed_token, contracts)

        worktree = pathlib.Path("/review-control/workspace")
        git_executable = pathlib.Path("/usr/bin/git")
        profile_block = (
            contracts.split(
                "The ordered token profile is `sanitized-git-argv-prefix-v2`:", 1
            )[1]
            .split("```text", 1)[1]
            .split("```", 1)[0]
        )
        documented_tokens: list[str] = []
        substitutions = {
            "PATH=<parent-recorded-trusted-path>": f"PATH={named_lane.TRUSTED_PATH}",
            "GIT_CEILING_DIRECTORIES=<absolute-clean-workspace-parent>": (
                f"GIT_CEILING_DIRECTORIES={worktree.parent}"
            ),
            "<fixed-absolute-git-executable>": str(git_executable),
            "<absolute-clean-workspace>": str(worktree),
        }
        for line in profile_block.strip().splitlines():
            token = substitutions.get(line, line)
            if token.startswith("-c "):
                documented_tokens.extend(("-c", token.removeprefix("-c ")))
            else:
                documented_tokens.append(token)
        self.assertEqual(
            tuple(documented_tokens),
            named_lane.build_sanitized_git_argv_prefix(
                worktree=worktree,
                git_executable=git_executable,
            ),
        )
        self.assertNotIn("--no-lazy-fetch", documented_tokens)

        for metadata_field in (
            "prefix_receipt_schema: <sanitized-git-argv-prefix-receipt-v2 | not-applicable>",
            "prefix_receipt: <compact canonical closed composite JSON object | not-applicable>",
            "prefix_receipt_parent_prompt_match: <exact-type-preserving | invalid | not-applicable>",
            "prefix_receipt_cross_field_match: <exact-type-preserving | invalid | not-applicable>",
            "prefix_profile: <sanitized-git-argv-prefix-v2 | not-applicable>",
            "sanitized_git_argv_prefix_conformance: <exact-token-sequence | not-applicable>",
            "sanitized_git_argv_prefix:",
            "sanitized_git_argv_prefix_sha256:",
            "git_executable:",
            "git_executable_identity:",
            "git_version:",
            "git_version_stdout:",
            "workspace_validation_receipt:",
            "workspace_validation_receipt_sha256:",
            "git_prefix_delivery:",
            "git_read_only_boundary:",
            "git_prefix_observation:",
        ):
            self.assertIn(metadata_field, prompts)

        shared_metadata = prompts.split("## Shared Metadata", 1)[1].split(
            "## Local Codex Prompt", 1
        )[0]
        parent_classification = prompts.split("## Parent Classification", 1)[1]
        for required in (
            "prefix_receipt: <compact canonical closed composite JSON object | not-applicable>",
            "executable_identity: <exact closed lexical/target stat identity | not-applicable>",
            "workspace_validation_receipt: <compact canonical closed JSON object | not-applicable>",
        ):
            self.assertIn(required, shared_metadata)
        for required in (
            "sanitized_git_argv_prefix: <exact UTF-8 JSON token array | not-applicable>",
            "codex_git_prefix_receipt: <exact closed composite JSON object | not-applicable>",
            "codex_git_prefix_receipt_parent_prompt_report_match: <exact-type-preserving | invalid | not-applicable>",
            "codex_git_prefix_receipt_cross_field_match: <exact-type-preserving | invalid | not-applicable>",
            "git_executable_identity: <exact closed lexical/target stat identity | not-applicable>",
            "workspace_validation_receipt: <exact closed JSON object | not-applicable>",
            "workspace: <absolute validated lane-private path>",
            "workspace_parent_prompt_report_match: <exact-type-preserving | invalid>",
        ):
            self.assertIn(required, parent_classification)
        self.assertIn(
            "scalar/object/array type drift",
            parent_classification,
        )
        self.assertIn(
            "codex_git_prefix_receipt_schema == codex_git_prefix_receipt.schema_version",
            parent_classification,
        )
        self.assertIn(
            "codex_git_prefix_receipt_sha256 == codex_git_prefix_receipt.receipt_sha256",
            parent_classification,
        )
        for transport_slot in (
            "`codex_git.prefix_receipt`",
            "`codex_git.sanitized_git_argv_prefix`",
            "`codex_git.executable_identity`",
            "`codex_git.workspace_validation_receipt`",
        ):
            self.assertIn(transport_slot, prompts)
        self.assertIn(
            "--base <frozen-base-sha> --head <frozen-head-sha>",
            contracts,
        )
        self.assertIn(
            "sha256-canonical-json-utf8-v1-without-receipt-sha256",
            contracts,
        )
        for document in (contracts, prompts, local):
            self.assertIn("validate-codex-git-prefix-receipt", document)
            self.assertIn("expected-receipt-sha256", document)
        self.assertIn("--receipt-file <absolute-published-receipt-json>", contracts)
        self.assertIn("do not call `codex-git-prefix` a second time", contracts.lower())
        self.assertIn("64 KiB", contracts)
        self.assertIn("exact same closed", contracts)

        subagent = local.split("### Subagent adapter", 1)[1].split(
            "### CLI adapter", 1
        )[0]
        cli = local.split("### CLI adapter", 1)[1].split("## Reviewer Profile", 1)[0]
        for adapter_contract in (subagent, cli):
            self.assertIn("sanitized_git_argv_prefix", adapter_contract)
            self.assertIn("exact", adapter_contract.lower())
            self.assertIn("unobservable", adapter_contract.lower())

        normalized_contracts = _normalize(contracts)
        normalized_prompts = _normalize(prompts)
        normalized_local = _normalize(local)
        normalized_role = _normalize(role)
        for normalized in (
            normalized_contracts,
            normalized_prompts,
            normalized_local,
            normalized_role,
        ):
            self.assertIn("bare", normalized)
            self.assertIn("alternate git", normalized)
            self.assertIn("`-c`", normalized)
            self.assertIn("`--git-dir`", normalized)
            self.assertIn("`--no-ext-diff`", normalized)
            self.assertIn("`--no-textconv`", normalized)
            self.assertIn("inconclusive", normalized)
            self.assertIn("unobservable", normalized)

        self.assertIn("profile, exact-sequence conformance and", contracts)
        self.assertIn("prompt and tool-observation boundary", contracts)
        self.assertIn("not by itself a lane failure", normalized_contracts)
        self.assertIn("not by itself prevent a clean result", normalized_prompts)
        self.assertIn("telemetry limitation is not itself a deviation", role)
        self.assertIn(
            "not an operating-system enforcement claim", _normalize(workspace)
        )

    def test_codex_profile_discovery_and_fallback_are_bounded(self) -> None:
        local = _read("references/local-codex-lane.md")
        normalized = _normalize(local)
        self.assertIn(
            "do not query the network or enumerate model catalogs", normalized
        )
        self.assertIn("parent session's", normalized)
        self.assertIn("effective model family or codex mode", normalized)
        self.assertIn("this is the sole latest-model-lookup trigger", normalized)
        self.assertIn("it never triggers latest-model discovery", normalized)
        self.assertIn("try the peer adapter with the exact same model", normalized)
        self.assertIn("do not silently lower the", normalized)
        self.assertIn("requires explicit user confirmation", normalized)
        self.assertNotIn("highest supported lower mode", normalized)
        self.assertNotIn("cache model discovery for", local.lower())

    def test_workspace_public_commands_and_bound_import_closure(self) -> None:
        guard = SCRIPTS / "named_lane_guard"
        completed = subprocess.run(
            (sys.executable, "-I", "-B", "-S", str(guard), "--help"),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for command in (
            "prepare-workspace",
            "validate-workspace",
            "cleanup-workspace",
            "codex-git-prefix",
            "validate-codex-git-prefix-receipt",
            "run-claude",
        ):
            self.assertIn(command, completed.stdout)
        for retired in (
            "materialize-worktree",
            "validate-worktree",
            "legacy-short-prefix-receipts",
        ):
            self.assertNotIn(retired, completed.stdout)

        guard_source = guard.read_text(encoding="utf-8")
        workspace_entry = (
            '"review_runtime.review_workspace",\n        "review_workspace.py",'
        )
        named_lane_entry = '("review_runtime.named_lane", "named_lane.py", False)'
        self.assertIn(workspace_entry, guard_source)
        self.assertIn(named_lane_entry, guard_source)
        self.assertLess(
            guard_source.index(workspace_entry), guard_source.index(named_lane_entry)
        )
        self.assertIn("_BoundSourceLoader", guard_source)
        self.assertIn("sys.flags.dont_write_bytecode", guard_source)

    def test_workspace_requires_direct_primary_source_and_independent_destination(
        self,
    ) -> None:
        workspace = _read("references/review-workspace.md")
        contracts = _read("references/review-lane-contracts.md")
        claude = _read("references/canonical-claude-lane.md")
        runtime = (RUNTIME / "review_workspace.py").read_text(encoding="utf-8")
        named_runtime = (RUNTIME / "named_lane.py").read_text(encoding="utf-8")
        normalized_workspace = _normalize(workspace)
        normalized_contracts = _normalize(contracts)

        for document in (workspace, contracts):
            normalized = _normalize(document)
            self.assertIn("source", normalized)
            self.assertIn("shallow", normalized)
            self.assertIn("promisor", normalized)
        for document in (workspace, claude):
            normalized = _normalize(document)
            self.assertIn("canonical real `<common", normalized)
            self.assertIn("direct-primary-only", normalized)
            self.assertIn("objects/info/alternates", normalized)
            self.assertIn("objects/info/http-alternates", normalized)
            self.assertIn("dangling symlink", normalized)
            self.assertIn("reflink/cow", normalized)
            self.assertIn("--dissociate", normalized)
            self.assertIn("same-uid aba", normalized)
        self.assertNotIn("backed by alternates", normalized_workspace)
        self.assertNotIn(
            "every local object-store authority",
            normalized_workspace,
        )
        combined = _normalize(workspace + "\n" + contracts)
        self.assertIn("no hardlinks", combined)
        self.assertIn("no source back-pointer", combined)
        self.assertIn("committed objects", combined)
        self.assertIn("history", combined)
        self.assertIn("strategy `exact-pack`", workspace)
        self.assertIn("exactly one matching pack/index pair", workspace)
        self.assertIn(
            "destination shallow receipt binding is empty and `.git/shallow` is absent",
            normalized_workspace,
        )
        self.assertIn(
            "the boundary is never fixed to `base_sha`",
            normalized_workspace,
        )
        self.assertIn("`review-parent-support-objects`", contracts)
        self.assertIn("`parent_support_object_count`", contracts)
        self.assertIn("`parent_support_object_sha256`", contracts)
        self.assertIn("complete imported union", normalized_contracts)
        self.assertIn(
            "`git rev-list --parents --full-history base_sha..head_sha`",
            contracts,
        )
        self.assertIn(
            "Treat the range as the complete Git DAG comparison",
            _read("SKILL.md"),
        )
        self.assertIn("promisor: bool", runtime)
        self.assertIn("promisor = bool(partial_config.strip())", runtime)
        self.assertIn('name.endswith(".promisor")', runtime)
        self.assertIn(
            'PARENT_SUPPORT_OBJECT_MANIFEST = "review-parent-support-objects"',
            runtime,
        )
        self.assertIn('"parent_support_object_count"', runtime)
        self.assertIn('"parent_support_object_sha256"', runtime)
        self.assertIn('"workspace-object-hardlink"', runtime)
        self.assertIn('"workspace-promisor-state"', runtime)
        self.assertIn('objects / "info/alternates"', runtime)
        self.assertIn('objects / "info/http-alternates"', runtime)
        self.assertIn("_validate_direct_primary_object_store", runtime)
        self.assertIn("_revalidate_source_repository", runtime)
        self.assertNotIn("def _discover_object_stores", runtime)
        self.assertIn("_bind_claude_source_read_boundary", named_runtime)
        self.assertIn("_revalidate_claude_source_read_boundary", named_runtime)
        self.assertIn('"source_authority_policy": "direct-primary-only"', named_runtime)
        self.assertIn(
            '"pre-terminal-acceptance"',
            named_runtime,
        )
        self.assertIn('shallow = b"".join(', runtime)
        self.assertIn("if shallow:", runtime)
        self.assertNotIn('shallow = f"{base}\\n".encode("ascii")', runtime)
        self.assertIn(
            "tuple(sorted(set(range_objects).union(support_objects)))",
            runtime,
        )
        self.assertIn(
            '("rev-list", "--parents", "--full-history", f"{base}..{head}")',
            runtime,
        )
        self.assertIn('git_dir / "shallow"', runtime)
        self.assertIn("cleanup-token-mismatch", runtime)
        self.assertNotIn("git worktree add", runtime)

    def test_range_incomplete_is_parent_owned_and_minimally_fetched(self) -> None:
        workspace = _read("references/review-workspace.md")
        runtime = (RUNTIME / "review_workspace.py").read_text(encoding="utf-8")
        for anchor in (
            "status: range-incomplete",
            "The helper never fetches",
            "exact branch/ref refspecs or exact object IDs",
            "--no-tags",
            "smallest useful increment",
            "do not default to `--unshallow`",
        ):
            self.assertIn(anchor, workspace)
        self.assertIn('status="range-incomplete"', runtime)
        self.assertIn("rerun prepare-workspace after the local objects exist", runtime)
        self.assertNotIn('arguments=("fetch"', runtime)

    def test_self_policy_migration_uses_the_prior_trusted_bundle(self) -> None:
        skill = _read("SKILL.md")
        contracts = _read("references/review-lane-contracts.md")
        for document in (skill, contracts):
            normalized = _normalize(document)
            self.assertIn("trusted installed bundle", normalized)
            self.assertIn("outside the candidate range", normalized)
            self.assertIn("candidate", normalized)
            self.assertIn("review subject", normalized)
            self.assertIn("merge and release", normalized)
            self.assertIn("smoke-test", normalized)
        self.assertIn("never execute candidate-head Python, shell", contracts)

    def test_github_lane_passes_on_current_head_clean_without_findings(self) -> None:
        authority = _read("references/github-codex-evidence-authority.md")
        contracts = _read("references/review-lane-contracts.md")
        normalized = _normalize(authority)
        for anchor in (
            "exact current head",
            "terminal clean",
            "no unresolved",
            "provider finding",
            'user.login == "chatgpt-codex-connector[bot]"',
            'user.type == "bot"',
            "complete snapshot",
            "final reread",
            "stable current-head request epoch",
            "head_binding: explicit-commit",
        ):
            self.assertIn(anchor.lower(), normalized)
        self.assertIn(
            "a terminal clean artifact passes only when all of these hold", normalized
        )
        for required_condition in (
            "its actor has the exact provider identity",
            "its accepted head binding resolves to the exact current head",
            "its grammar is a known clean carrier",
            "there is no unresolved applicable github codex finding",
            "scope, lifecycle, raw pages, and selected evidence remain stable on the final reread",
        ):
            self.assertIn(required_condition, normalized)
        self.assertIn("a hashless issue comment is not a terminal carrier", normalized)
        self.assertIn(
            "`stable-request-epoch` is reserved for the reaction-only fallback",
            normalized,
        )
        self.assertIn(
            "A successful service-start check alone is not", _read("SKILL.md")
        )
        self.assertIn(
            "latest head plus no unresolved provider finding passes",
            _normalize(contracts),
        )
        self.assertIn("does not prove which base or merge base", normalized)

    def test_github_lane_prefers_associated_status_and_keeps_small_reaction_fallback(
        self,
    ) -> None:
        authority = _read("references/github-codex-evidence-authority.md")
        probes = _read("references/github-pr-probes.md")
        normalized = _normalize(authority)
        self.assertIn("trustworthy repository merge/status check", normalized)
        self.assertIn("preferred", normalized)
        self.assertIn("association", normalized)
        self.assertIn(
            _normalize(
                "A trustworthy repository merge/status check whose independently "
                "verified producer contract defines successful completion as a "
                "GitHub Codex clean result for its exact declared scope"
            ),
            normalized,
        )
        self.assertIn("does not require a second terminal clean", normalized)
        self.assertIn("github-synthetic-merge", normalized)
        self.assertIn("check_subject_sha", normalized)
        self.assertIn("generic successful check", normalized)
        self.assertIn("trust anchor", normalized)
        self.assertIn("outside the candidate range", normalized)
        self.assertIn("candidate-head contract bytes", normalized)
        self.assertIn("merge_status_candidate_range_exclusion_receipt", authority)
        self.assertIn("non-head candidate commit", normalized)
        self.assertIn("does not provide a production merge-status consumer", normalized)
        self.assertIn(
            "no positive basis bypasses the complete unresolved-finding scan",
            normalized,
        )
        self.assertIn(
            _normalize(
                "prefer it as the positive GitHub-lane basis, while still enumerating "
                "unresolved Codex-provider findings"
            ),
            _normalize(probes),
        )
        self.assertIn("Do not hard-code", probes)
        self.assertIn("A name substring is a hint", probes)
        self.assertIn("Reaction-Only Fallback", authority)
        self.assertIn("requires no historical sampling", authority)
        self.assertIn("no later request", authority)
        self.assertIn("`eyes` is liveness only", authority)
        self.assertNotIn("thumbs-up-clean", normalized)
        self.assertNotIn("3–10", authority)
        self.assertNotIn("three-outcome", normalized)

    def test_github_recovery_is_dynamic_single_flight_and_cost_aware(self) -> None:
        skill = _read("SKILL.md")
        probes = _read("references/github-pr-probes.md")
        normalized = _normalize(skill + "\n" + probes)
        for anchor in (
            "missing or stale",
            "cancelled or skipped",
            "infrastructure",
            "aggregation",
            "retry failed jobs",
            "single-flight",
            "1, 2, 4, 8, 16, 32, 60",
            "four full-run equivalents per 24 hours",
            "status-only hourly",
            "public repositories",
            "same active thread",
            "never create a new conversation",
            "identifiers only",
            "`recovery_operation_preflight`",
            "dependency-edge resolution receipt",
            "idempotent or reentrant",
            "equality identifies a requested repeat",
            "outside the candidate range",
            "candidate-head workflow or contract bytes",
            "total rerun limit is 50",
            "manual dispatch",
            "ordinary producer/status contract",
            "root workflow repository",
        ):
            self.assertIn(anchor, normalized)
        self.assertIn("no time ceiling on status-only monitoring", probes)
        self.assertIn("mutation attempts stop at that cap", _normalize(probes))
        self.assertIn("At 60 minutes, report", probes)
        self.assertIn("For the first 60 minutes", probes)
        self.assertIn(
            "pollable and cancellable active-thread fallback", _normalize(probes)
        )
        self.assertIn(
            "public repositories do not use the private-minute budget",
            _normalize(probes),
        )
        self.assertIn("Never reconcile an explicit review finding", probes)
        self.assertIn("Do not hard-code a workflow filename", probes)
        self.assertIn("cancel pending automation", probes.lower())
        self.assertNotIn(
            "treats repetitions of that same tuple as idempotent", normalized
        )
        self.assertNotIn("no repository-specific idempotency", normalized)

    def test_base_machine_schema_and_old_github_receipt_policy_are_retired(
        self,
    ) -> None:
        retired_json = REFERENCES / "base-only-retarget-state-machine.json"
        self.assertFalse(retired_json.exists())
        active = "\n".join(
            path.read_text(encoding="utf-8") for path in _active_policy_paths()
        )
        normalized = _normalize(active)
        for retired in (
            "base-only-retarget-state-machine.json",
            "parent-recorded-request-scope-v1",
            "pre_request_scope_receipts",
            "post_request_scope_receipts",
            "request_comment_receipt",
            "named-lane-legacy-short-prefix-receipts-v1",
            "thumbs-up-clean",
            "three-outcome history",
        ):
            self.assertNotIn(retired.lower(), normalized)

    def test_public_isolated_review_exposes_only_retained_utilities(self) -> None:
        cli_source = (RUNTIME / "cli.py").read_text(encoding="utf-8")
        completed = subprocess.run(
            (str(SCRIPTS / "isolated_review"), "--help"),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        help_text = _normalize(completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("synthetic-tokens", help_text)
        self.assertIn("secret-admission", help_text)
        self.assertIn("stateful", help_text)
        self.assertNotIn("--reviewer", help_text)
        self.assertNotIn("--base-ref", help_text)
        self.assertIn("RECOVERY_ONLY_STATEFUL_ACTIONS", cli_source)
        self.assertIn('"status", "final", "cleanup"', cli_source)
        self.assertIn('"start", "wait", "admission"', cli_source)
        self.assertIn("RETIRED_REVIEW_MESSAGE", cli_source)

        stateful_help = subprocess.run(
            (str(SCRIPTS / "isolated_review"), "stateful", "--help"),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        normalized_stateful_help = _normalize(stateful_help.stdout)
        self.assertEqual(stateful_help.returncode, 0, stateful_help.stderr)
        self.assertIn("{status,final,cleanup}", normalized_stateful_help)
        for action in ("status", "final", "cleanup"):
            self.assertIn(action, normalized_stateful_help)

        rejected = subprocess.run(
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
            timeout=30,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("supplied-diff foreground", rejected.stderr)
        self.assertIn("clean-workspace helper", rejected.stderr)

    def test_retained_helper_is_ineligible_and_utilities_keep_their_contracts(
        self,
    ) -> None:
        fixtures = _read("references/synthetic-token-fixtures.md")
        self.assertEqual(
            providers.LOW_LEVEL_HELPER_REVIEW_CONTRACT, "supplied-diff-private-git"
        )
        self.assertFalse(providers.NAMED_LANE_ELIGIBLE)
        self.assertIn("head_count <= base_count", fixtures)
        self.assertIn("exact raw bytes only", fixtures)
        self.assertIn("isolated_review synthetic-tokens validate", fixtures)
        self.assertIn(
            "secret-admission result controls only PR/master admission", fixtures
        )
        self.assertTrue((RUNTIME / "synthetic-token-catalog.json").is_file())

    def test_admission_receipt_remains_bound_to_runner_and_launch(self) -> None:
        seal_source = inspect.getsource(state._seal_preflight_receipt)
        admission_source = inspect.getsource(state._admission_status_for_loaded_state)
        read_source = inspect.getsource(state._read_bound_preflight)
        run_source = inspect.getsource(state.run_state)
        self.assertEqual(state.BOUND_STATE_MARKER_SCHEMA_VERSION, 4)
        self.assertEqual(state.STATE_MARKER_SCHEMA_VERSION, 5)
        self.assertEqual(state.PREFLIGHT_RECEIPT_SCHEMA_VERSION, 1)
        self.assertLess(
            seal_source.index("validate_inherited_runner_lock_lease"),
            seal_source.index("_read_modern_bound_state_artifact"),
        )
        self.assertIn("hashlib.sha256(payload).hexdigest()", seal_source)
        self.assertIn("len(payload) != receipt.size", read_source)
        self.assertIn("runner-sealed", read_source)
        self.assertIn("legacy-state-no-preflight-receipt", admission_source)
        self.assertIn("state_reviewer != expected_reviewer", run_source)
        self.assertIn("state_egress_consent != expected_egress_consent", run_source)

    def test_canonical_claude_lane_keeps_runtime_trust_and_auth_boundaries(
        self,
    ) -> None:
        lane = _read("references/canonical-claude-lane.md")
        runtime = _read("references/claude-runtime-trust.md")
        self.assertEqual(
            claude_version_policy.CLAUDE_COMPATIBILITY_SPEC, ">=2.1.211,<3.0.0"
        )
        self.assertTrue(claude_version_policy.is_compatible_release_version("2.1.211"))
        self.assertFalse(claude_version_policy.is_compatible_release_version("3.0.0"))
        for anchor in (
            "actual Claude Code process",
            "different validated workspace",
            "credential-free Claude preflight",
            "ordinary Claude Code local login in trusted real `HOME`",
            "API-key or OAuth-token launch interface",
            "validate-claude-stream",
            "classification: accepted",
            "findings-only",
        ):
            self.assertIn(anchor, lane)
        normalized_lane = _normalize(lane)
        normalized_runtime = _normalize(runtime)
        for contract in (
            "the parent independently rebuilds the expected closed profile",
            "a self-consistent receipt hash without that field-by-field comparison is insufficient",
            "settings_assurance: requested-configuration-only",
            "settings_parser_acceptance_attested: false",
            "managed_policy_residual: true",
            "native_sandbox_effectiveness_attested: false",
            "any missing, differently typed, differently valued, or non-recomputable field is inconclusive and stops before stream validation",
            "`validate-claude-stream` does not consume or authenticate the `run-claude` receipt",
            "parent-owned exact receipt comparison above supplies that link and must finish first",
        ):
            self.assertIn(contract, normalized_lane)
        self.assertLess(
            lane.index("### Launch Receipt Consumption"),
            lane.index("## Stream Validation"),
        )
        self.assertIn(
            "parent receipt consumption and stream validation are distinct mandatory gates",
            normalized_runtime,
        )
        self.assertIn(
            "`claude_code_subprocess_env_scrub` is intentionally absent",
            normalized_lane,
        )
        self.assertIn("allowallunixsockets: false", normalized_lane)
        self.assertIn("allowlocalbinding: false", normalized_lane)
        for contract in (
            "the direct guard rejects `claude-opus-4-7` and every other caller-selected model",
            "retained 4.7 stream schemas or legacy/helper failure classifiers do not authorize a named-direct launch",
            "the named-direct guard remains 4.8-only and is inconclusive until a separately closed fallback bridge exists",
            "retained 4.7 stream-schema recognition supplies validation compatibility rather than launch authority",
        ):
            self.assertIn(contract, normalized_lane + "\n" + normalized_runtime)
        self.assertIn("publisher", runtime.lower())
        self.assertIn("bounded", runtime.lower())

    def test_named_review_consent_is_provider_specific(self) -> None:
        consent = _read("references/egress-consent.md")
        self.assertIn("One fresh-context OpenAI Codex lane", consent)
        self.assertIn("actual Anthropic Claude Code", consent)
        self.assertIn("GitHub Codex on an existing exact-host `github.com` PR", consent)
        self.assertIn("It does not silently opt", consent)
        self.assertIn("into Claude Code, GitHub Copilot", consent)
        self.assertIn("untracked private files", consent)
        self.assertNotIn("double-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertNotIn("triple-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertEqual(
            providers.COPILOT_EGRESS_CONSENTS,
            ("explicit-claude-with-copilot-fallback",),
        )

    def test_retired_independent_supervisor_has_no_public_surface(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        self.assertTrue((tool_root / "review_supervisor").is_dir())
        self.assertFalse((tool_root / "independent-codex-pr-review").exists())
        self.assertFalse((tool_root / "README.md").exists())

    def test_installed_bundle_entrypoints_do_not_create_bytecode(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="review-installed-no-bytecode-"
        ) as temporary:
            copied_skill = pathlib.Path(temporary) / "review-orchestration-playbook"
            shutil.copytree(
                SKILL_ROOT,
                copied_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            copied_scripts = copied_skill / "scripts"
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)
            entrypoints = {
                copied_scripts / "isolated_review": 0,
                copied_scripts / "named_claude_preflight": 2,
                copied_scripts / "validate_claude_stream.py": 3,
            }
            discovered = {
                path
                for path in copied_scripts.rglob("*")
                if path.is_file() and _has_python_shebang(path)
            }
            self.assertEqual(discovered, set(entrypoints))
            for entrypoint, expected in entrypoints.items():
                completed = subprocess.run(
                    (sys.executable, str(entrypoint), "--help"),
                    cwd=copied_skill,
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, expected, completed.stderr)
                bytecode = [
                    path
                    for path in copied_skill.rglob("*")
                    if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
                ]
                self.assertEqual(bytecode, [])

    def test_bare_package_imports_fail_before_writing_usable_bytecode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="review-bare-import-") as temporary:
            copied_skill = pathlib.Path(temporary) / "review-orchestration-playbook"
            shutil.copytree(
                SKILL_ROOT,
                copied_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            copied_scripts = copied_skill / "scripts"
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)
            packages = {
                "review_runtime": copied_scripts,
                "review_supervisor": copied_scripts / "independent_codex_pr_review",
            }
            for package, import_root in packages.items():
                probe = f"import sys;sys.path.insert(0,{str(import_root)!r});import {package}"
                completed = subprocess.run(
                    (sys.executable, "-c", probe),
                    cwd=copied_skill,
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    f"{package} requires bytecode to be disabled", completed.stderr
                )
            bytecode = sorted(copied_skill.rglob("*.pyc"))
            self.assertEqual(len(bytecode), 2)
            self.assertTrue(all(path.name.startswith("__init__.") for path in bytecode))

    def test_python_child_launchers_disable_bytecode(self) -> None:
        launch_vectors: list[tuple[pathlib.Path, int]] = []
        for source_path in sorted(SCRIPTS.rglob("*")):
            if (
                not source_path.is_file()
                or "tests" in source_path.relative_to(SCRIPTS).parts
            ):
                continue
            if source_path.suffix != ".py" and not _has_python_shebang(source_path):
                continue
            tree = ast.parse(
                source_path.read_text(encoding="utf-8"), filename=str(source_path)
            )
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 2:
                    continue
                if "sys.executable" not in ast.unparse(node.elts[0]):
                    continue
                launch_vectors.append((source_path, node.lineno))
                leading_flags: list[str] = []
                for item in node.elts[1:]:
                    if not (
                        isinstance(item, ast.Constant)
                        and isinstance(item.value, str)
                        and item.value.startswith("-")
                    ):
                        break
                    leading_flags.append(item.value)
                self.assertIn("-B", leading_flags, f"{source_path}:{node.lineno}")
        self.assertGreaterEqual(len(launch_vectors), 9)


if __name__ == "__main__":
    unittest.main()
