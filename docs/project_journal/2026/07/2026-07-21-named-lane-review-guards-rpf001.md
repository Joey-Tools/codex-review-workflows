---
id: 20260721-rpf001
title: Named Lane Review Guards
status: completed
created: 2026-07-21
updated: 2026-07-21
branch: codex/daily-skill-friction-20260721-codex-review-workflows-review-policy-final-review-fixes
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/72
supersedes: []
superseded_by:
---

# Named Lane Review Guards

## Summary

- Close three final-review gaps in the canonical named-lane policy without restoring retired prepared-diff or hidden review gates.

## Current State

- Both local lanes run a parent-owned tracked-symlink containment check before reviewer launch. Stable in-worktree source links remain allowed, while escaping or unstable links and symlinked guidance are rejected.
- GitHub Codex issue-comment evidence must bind to the exact request or head, or be unambiguous across every still-unresolved request; timestamp proximity alone cannot complete triple review.
- The direct Claude lane uses a process-only bounded supervisor with a finite deadline, bounded streams, and process-group cleanup. Partial, over-limit, timed-out, or incompletely cleaned output is inconclusive.
- The guard does not prepare a diff, inspect ordinary file contents, broker authentication, replace the actual reviewer, or add another PR-readiness gate.

## Next Steps

- None after the canonical PR is squash-merged and the private overlay migration is regenerated from the merged source.

## Evidence

- Fresh-context review of `Joey-Tools/codex-private-workflows#128` found the three boundary gaps before merge.
- Eleven focused guard tests cover safe and escaping symlinks, guidance regular-file enforcement, exact frozen-head and clean-worktree checks, bounded Claude process outcomes, and TERM-resistant timeout cleanup.
- Thirty-nine canonical-profile contract tests cover current-request GitHub evidence correlation, the narrow guard boundary, and direct-Claude process limits; private-profile coverage runs again after source sync.
- The 1,071-test review-policy suite completed with one existing loopback-binding test method blocked by the socket-restricted sandbox across three subtests; that exact method passed when rerun with loopback access.
- Both modified skills passed the installed OpenAI quick validator. Python compilation, Ruff lint/format checks, project-journal validation, and `git diff --check` passed.
