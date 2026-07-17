---
id: 20260717-c1d3f0
title: Accept List-Form CI Needs in Review Contract
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/ci-direct-dependency-contract
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/56
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
- Indentless YAML block sequences under `needs` are accepted when they remain
  within the current job, including comments and the following job boundary.
- Quoted dependency names are normalized consistently in scalar, block-list,
  and inline-list forms; YAML comments, including trailing comments, are
  ignored outside quoted values without truncating later dependencies.
- A UTF-8 BOM is rejected before root-level defaults or job parsing, so it
  cannot hide a custom default shell from the contract.
- The parser structurally anchors the single root `jobs` mapping before locating
  the aggregate job, so job-shaped text inside root block scalars cannot act as
  a decoy; duplicate, inline, or unsupported root mappings fail closed.
- Every accepted direct dependency must expose its result and be checked for a
  successful outcome by the aggregate `test` job.
- Step-scoped result variables count only when the same step checks them;
  job-scoped bindings are rejected because an earlier step can overwrite them
  through `GITHUB_ENV`.
- Success guards count only for unconditional, non-tolerant default-shell steps
  whose non-empty commands are exact dependency-success assertions. The
  aggregate job may contain only such guard steps, preventing earlier steps
  from poisoning the default shell environment. Result bindings must use safe
  shell identifiers ending in `_RESULT`, and every binding must come directly
  from `needs.<job>.result`. The required `always()` condition is scoped to the
  aggregate `test` job, which must run exactly once on `ubuntu-latest` without
  a custom container, services, or matrix strategy. Ordinary, single-quoted,
  and double-quoted control keys share the same semantics; escaped, explicit,
  tagged, anchored, and aliased mapping keys fail closed rather than relying on
  an incomplete YAML decoder. Blank lines and full-line comments cannot
  truncate the parsed job or step scope. Inherited workflow/job custom shells,
  echoed assertions, masked failures, disabled errexit, step custom shells,
  and job-level tolerance are rejected regardless of legal YAML indentation.
  Flow-style collections under `defaults.run` are rejected in workflow and job
  scopes, including quoted-key and multiline flow mappings, because the
  lightweight contract parser supports only ordinary block mappings there.
  Bare sequence-item steps are parsed and validated instead of being skipped,
  and folded `run: >` block scalars are rejected because YAML folding can join
  physical lines into a different shell command. Inline `run:` scalars also
  reject deeper-indented physical continuations, preventing folded commands
  from appending an unvalidated success path after an exact first line.

## Validation Evidence

- The canonical review-orchestration suite passed (`708` tests; `9` skipped).
- The synchronized private-overlay suite passed (`708` tests; `10` skipped).
- `ruff check`, Python compilation, `actionlint`, and `git diff --check` passed
  for both copies.
- The flow-collection regression update passed both focused contract files
  (`17` tests each), Ruff, Python compilation, Actionlint checks for four valid
  workflow/job flow-mapping variants, project-journal validation, and diff
  checks.

## Next Steps

- Merge the canonical change before the dependent private-overlay CI update.
