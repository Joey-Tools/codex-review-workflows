---
id: 20260826-ros002
title: Remove Repository Journal Coupling From Skill Tests
status: completed
created: 2026-08-26
updated: 2026-08-26
branch: codex/review-journal-portability
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/109
supersedes: []
superseded_by:
---

# Remove Repository Journal Coupling From Skill Tests

## Summary

- The first post-release private source-sync run reached the canonical review
  verifier but failed because a synced skill test tried to read this source
  repository's project journal through its computed repository root.
- Remove that repository-specific journal assertion from the distributed skill
  test tree. The same test module continues to assert the effective-profile
  contract directly against the published local-lane and review-lane
  references.
- This follow-up changes no reviewer behavior, role profile, workspace helper,
  GitHub lane authority, or merge-inclusive branch-update policy.

## Decision Rationale

- A project journal is durable repository context, not part of a skill's
  installed interface. Tests shipped with the skill must remain valid when the
  complete skill tree is installed beneath another repository prefix that does
  not carry this source repository's journal.
- Rewriting the journal path during private sync would duplicate repository
  history into the distribution contract and create another source-specific
  replacement rule. Removing the redundant assertion preserves one source of
  truth: the published references that the runtime and reviewers actually
  consume.
- The failed workflow had already passed source-pin refresh, pre/post source
  verification, the private sync tests, and sync-manifest validation. The
  failure is therefore handled as a deterministic source portability defect,
  not as a transient GitHub outage eligible for blind retry.

## Delivery Plan

- Run the focused local Codex lane contract tests, formatting/lint checks,
  project-journal validation, and the repository's proportional delivery gate.
- Complete one fresh-context GPT-5.6 Sol Ultra local Codex review and one exact
  current-head GitHub Codex review, then merge the canonical pull request.
- Re-run the private scheduled source sync, disable generated-PR auto-merge,
  complete the same current-head review and CI gates, merge that PR, verify its
  immutable release, and install the released overlay locally.

## Current State

- The redundant journal assertion is removed; the adjacent published-reference
  assertions still prove that `unknown` and `mismatch` profiles are
  inconclusive for both peer adapters.
- The focused local-lane contract file passes all 14 remaining tests. Ruff
  lint and format checks, `git diff --check`, and project-journal validation
  also pass.
- An independent read-only source-of-truth audit agreed that the assertion
  should be removed rather than moved or replaced: the published reference
  matrix already supplies the complete behavior contract.

## Evidence

- Canonical pull request:
  `https://github.com/Joey-Tools/codex-review-workflows/pull/109`.
- Failed private source-sync workflow:
  `Joey-Tools/codex-private-workflows` run `32923728751`, exact workflow head
  `d6e9583549a2b4395d377e96e1954533aa20b5f6`.
- The only failing test was
  `test_project_journal_records_unknown_profile_as_inconclusive`; its resolved
  private path was
  `personal_codex/docs/project_journal/2026/08/2026-08-22-review-orchestration-simplification-ros001.md`,
  which is intentionally absent from the distributed overlay.
- That workflow executed all 3,217 synced canonical tests in 772.370 seconds;
  the missing source-repository journal was the only error, with 30 conditional
  skips. The candidate removes that one test and changes no remaining test or
  runtime byte.
- The directly published effective-profile assertions remain in
  `skills/review-orchestration-playbook/tests/test_local_codex_lane_contracts.py`.
