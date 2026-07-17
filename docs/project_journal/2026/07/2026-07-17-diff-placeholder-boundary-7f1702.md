---
id: 20260717-7f1702
title: Respect Diff Sides in Secret Assignment Scans
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/diff-placeholder-boundary
pr:
supersedes: []
superseded_by:
---

# Respect Diff Sides in Secret Assignment Scans

## Summary

The synthetic-token preflight parsed raw unified-diff records as one logical
source stream. A complete quoted assignment on one diff side could therefore
be joined to records from the opposite side, producing a false positive when
the opposite-side replacement was longer than the trailing proof budget.

## Current State

- Quoted-assignment proof follows the matched diff side while preserving
  context records shared by both sides.
- Opposite-side records do not consume the logical trailing proof budget, but
  their raw bytes remain covered by the scan's bounded-work accounting.
- Declaration proof reconstructs the matching base or head prefix instead of
  always reconstructing the head side.
- Security regressions keep scanning after opposite-side interleaving and
  continue to reject same-side or shared-context RHS continuations.

## Validation Evidence

- The focused quoted-assignment regressions passed, including opposite-side
  interleaving, same-side and context continuations, base-prefix reconstruction,
  and both per-event and global proof budgets.
- The previously blocked frozen `review.diff` passed the patched scanner in a
  redacted local probe.
- The complete synthetic-token module passed (`85` tests).
- The complete review-orchestration suite passed on the refreshed master
  baseline (`710` tests; `9` skipped).
- Full runtime/test `ruff check` and Python `compileall` passed.
- Synthetic-token catalog validation returned `public-example-v1` as valid.
- Skill validation, project-journal validation, and `git diff --check` passed.
- An independent read-only scanner review returned `No findings.`

## Next Steps

- None after the prerequisite scanner release reaches the installed review
  helper.
