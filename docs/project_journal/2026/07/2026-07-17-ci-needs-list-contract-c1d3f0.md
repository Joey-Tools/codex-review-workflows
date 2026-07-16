---
id: 20260717-c1d3f0
title: Accept List-Form CI Needs in Review Contract
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/ci-direct-dependency-contract
pr:
supersedes: []
superseded_by:
---

# Accept List-Form CI Needs in Review Contract

## Summary

Allow the required `test` status-context contract to recognize both scalar and
list-form GitHub Actions `needs` declarations. This keeps the canonical review
workflow test compatible with private overlays that explicitly gate the same
status context on additional compatibility and platform jobs.

## Current State

- The contract scopes dependency parsing to the required `test` job and still
  requires `platform_tests` to be one of its direct dependencies.
- Scalar `needs: platform_tests` remains accepted for the canonical workflow.
- List-form `needs` declarations containing `platform_tests` are accepted for
  synchronized overlays with additional direct dependencies.
- Quoted dependency names are normalized consistently in scalar, block-list,
  and inline-list forms.
- Every accepted direct dependency must expose its result and be checked for a
  successful outcome by the aggregate `test` job.

## Validation Evidence

- The canonical review-orchestration suite passed (`706` tests; `9` skipped).
- The synchronized private-overlay suite passed (`706` tests; `10` skipped).
- `ruff check` and `git diff --check` passed for both copies.

## Next Steps

- Merge the canonical change before the dependent private-overlay CI update.
