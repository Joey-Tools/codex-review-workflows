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
  synchronized overlays with additional direct dependencies. Inline sequences
  may use YAML's legal single trailing comma, while empty or repeated-comma
  items still invalidate the complete dependency list.
- Indentless YAML block sequences under `needs` are accepted when they remain
  within the current job, including comments and the following job boundary.
- A sequence item may put one ordinary job-ID scalar on the indented line after
  a bare dash. Any malformed, aliased, tagged, anchored, flow, block-scalar, or
  mapping item invalidates the complete list instead of returning a prefix.
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
- Every accepted direct dependency job must also propagate its own failure.
  Job-level `continue-on-error` accepts only an absent value or the canonical
  unquoted `false` boolean; expressions, tolerant values, duplicate keys, and
  unstructured YAML nodes fail closed.
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
  Workflow/job `defaults.run` accepts only an ordinary block mapping with one
  inline `working-directory` scalar. Custom `shell` keys, aliases, anchors,
  tags, merge keys, flow collections, block scalars, duplicate keys, and other
  unstructured nodes fail closed.
  Bare sequence-item steps are parsed and validated instead of being skipped,
  and the job must expose exactly one structural `steps` block header; ordinary
  quoted, spaced, and commented spellings remain accepted. Mapping-key checks
  skip literal/folded block-scalar payloads. Explicit indentation indicators
  set the minimum payload indent even when the first non-empty line is deeper;
  scalars without an indicator still infer it from that first line. Shell text
  resembling tagged YAML therefore cannot poison an unrelated aggregate-job
  contract.
  Literal `run` body collection uses the same explicit minimum instead of
  locking its boundary to a more-indented first command. A later payload line
  can no longer be hidden from validation to write `BASH_ENV` through
  `GITHUB_ENV` and redefine `test` for a subsequent dependency-check step.
  Folded `run: >` block scalars are rejected because YAML folding can join
  physical lines into a different shell command. Inline `run:` scalars also
  reject deeper-indented physical continuations, preventing folded commands
  from appending an unvalidated success path after an exact first line.
  Multiline single- and double-quoted YAML scalars are outside the accepted
  structural subset, so text resembling step-level `env` or `run` keys inside
  a quoted `name` cannot become a guard decoy. Each accepted guard step must
  expose exactly one real `run` key, exactly one real `env` block, and no
  `uses` key.

## Validation Evidence

- The canonical review-orchestration suite passed (`708` tests; `9` skipped).
- The synchronized private-overlay suite passed (`708` tests; `10` skipped).
- `ruff check`, Python compilation, `actionlint`, and `git diff --check` passed
  for both copies.
- The `defaults.run` regression updates passed both focused contract files
  (`17` tests each), Ruff, Python compilation, Actionlint checks for four valid
  flow-mapping variants and six valid alias/anchor/tag/block-scalar variants,
  project-journal validation, and diff checks.
- The sequence/structure regression update passed both contract files (`17`
  tests each), Ruff, Python compilation, and five Actionlint-valid needs,
  `steps`, alias, and block-scalar-payload fixtures; project-journal validation
  and diff checks also passed. The explicit-indentation payload regression also
  passed focused contract tests, Ruff, and an Actionlint-valid de-indent fixture.
- The explicit-indentation `run` regression passed both focused and complete
  contract files (`17` tests each), Ruff, Python compilation, Actionlint 1.7.12
  coverage for both chomping/indicator orders and quoted/sequence `run` keys,
  project-journal validation, normalized copy comparison, and diff checks.
- The exact-head dependency-propagation, multiline-quoted-scalar, and inline
  trailing-comma regressions passed the focused canonical contract suite (`19`
  tests), Ruff, Python compilation, and Actionlint 1.7.12 checks for the live
  workflow plus an Actionlint-valid combined decoy/trailing-comma fixture.

## Next Steps

- Merge the canonical change before the dependent private-overlay CI update.
