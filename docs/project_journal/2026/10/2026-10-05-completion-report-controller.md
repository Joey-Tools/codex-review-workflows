---
id: 20261005-crw001
title: Completion Report Controller Routing
status: completed
created: 2026-10-05
updated: 2026-10-05
branch:
pr:
supersedes: []
superseded_by:
---

# Completion Report Controller Routing

## Summary

- The consumer controller follows the canonical v2.1.7 routing for verifier-run completion while preserving the existing opt-in failure-triggered review flow.

## Current State

- The job-level `workflow_run` condition is a pre-run cost filter for the canonical verifier path or its `@refs/pull/.../merge` form. GitHub Actions expression comparisons and `startsWith`/`endsWith` are case-insensitive, so a case-variant path may still allocate this write-permission runner; do not treat the condition as the security boundary.
- Runtime path validation is case-sensitive and rejects uppercase lookalikes before constructing the GitHub API client. For completion reporting, the runtime then refetches the canonical verifier workflow and exact run/attempt, validates workflow identity, PR/head and test-merge binding, and revalidates the diagnostic snapshot before any diagnostic-comment write. If GitHub omits the run's pull-request association, the controller passes the runtime's internal `pr_number: 0` sentinel for exact runtime-side binding.
- Concurrency remains keyed by the associated pull request when available and falls back to the workflow-run ID or GitHub run ID when no association exists, preventing unrelated runs from sharing an empty group.
- Completion uses `report-completion`; it does not scan findings, rerun a workflow, or request a fresh review. The diagnostic snapshot is not review evidence or gate authority.
- `begin-review` and `request_review` remain bound to the existing `CODEX_REVIEW_GATE_AUTO_REQUEST=true`, first-attempt failure, and single-PR association conditions; the runtime refetches and binds the exact verifier run/workflow and PR/head before any review request. Manual dispatch keeps its explicit inputs.
- The unchanged `codex/github-review-gate` verifier CheckRun remains the required gate authority. The verifier and `.github/CODEOWNERS` are unchanged; repository/org variables and rulesets are outside this controller-only update.

## Evidence

- Canonical controller template blob: `c6290c800903303151cbfb34ca706463118b0d09`, from source implementation commit `97268b8a83213300182e9f699eb5cb4dba627670`.
- The case-folding/cost-filter distinction was clarified in source documentation at commit `adbd228729380def987db8619213755c9ce1f94f` / [source PR #105](https://github.com/Joey-Tools/codex-review-gate/pull/105); the frozen Action subtree remains `12ca66f880101208f475f41b3266aad46f249692`.
- Consumer controller matched the canonical template byte-for-byte; `actionlint` passed for the installed verifier and controller.
- Canonical source workflow and security contract tests passed (51 tests) after the controller hardening; the bootstrap `--prepare-worktree` dry run reported no changes for this worktree.
