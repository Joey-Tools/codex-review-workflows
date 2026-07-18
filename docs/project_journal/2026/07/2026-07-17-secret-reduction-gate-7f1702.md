---
id: 20260717-7f1702
title: Permit Review of Verified Secret-Reduction Ranges
status: completed
created: 2026-07-17
updated: 2026-07-18
branch: codex/secret-reduction-review
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/60
supersedes: []
superseded_by:
---

# Permit Review of Verified Secret-Reduction Ranges

## Summary

- Treats Codex, Claude Code, and the consent-gated Copilot fallback as trusted processors inside the isolated-review workflow boundary.
- Allows the frozen tracked diff and necessary tracked context to reach the reviewer in their original form, including secret material, only when the range proves a real reduction or an existing catalog rule applies.
- Keeps PR/master protection as the primary control against introducing secrets; the local gate exists to make a remediation range reviewable.

## Decision

For every unregistered dynamic secret candidate, preflight extracts one exact byte value and counts it across every blob and symlink target in the complete base and head trees. Review is eligible only when both conditions hold:

```text
head_raw_count < base_raw_count
head_unembedded_count <= base_unembedded_count
```

An occurrence is unembedded only when no strictly longer candidate completely contains it. This second count prevents a change from deleting a longer secret while leaving or creating its captured substring as a standalone value.

| Range outcome | Decision |
| --- | --- |
| Exact raw count strictly decreases and unembedded count does not increase | Eligible after the rest of preflight passes |
| Residual count is equal | Block |
| Candidate first appears at head | Block |
| Move, rename, or copy without strict global reduction | Block |
| Raw or unembedded count grows | Block |
| Candidate bytes are ambiguous, unsafe to represent, outside budgets, or otherwise uncountable | Block |

Path findings are independent of content counts. A sensitive changed path is eligible only when it is deleted and no sensitive path exists anywhere in the complete head snapshot. A renamed, moved, copied, or retained sensitive path at head blocks review.

## Trust Boundary

The reviewer is a trusted processor for the scoped repository data authorized by the review request. After preflight passes, it receives the frozen tracked diff and necessary tracked context as recorded so it can assess the security-sensitive change accurately. An explicitly supplied `--prompt-file` remains a separate caller-controlled surface: it is sent without rewriting only after an independent secret scan passes, and it does not inherit selected-legacy or dynamic-reduction eligibility from tracked-tree proof. The helper does not automatically discover or collect other untracked private files, unrelated repositories, broad workspace dumps, host-local artifacts, or reviewer/runtime authentication credentials.

Diagnostic and preflight evidence remain bounded audit surfaces. They use stable finding metadata, digests, and counts where applicable; this evidence contract does not require changing the tracked review content sent to the reviewer.

## Catalog Compatibility

- Authoring entries keep their exact catalog-declared scanner-rule acceptance behavior.
- Explicit legacy envelopes keep the existing non-increasing raw and unembedded count policy, including equal-count moves between safe paths when all other legacy checks pass.
- Dynamic reduction does not create catalog entries, select a legacy envelope, weaken catalog validation, or relax sensitive-path checks.
- New fixtures must still use the authoring pool, and master-proven historical fixtures must still use explicit legacy selection.

## Current State

- Runtime preflight exhaustively captures bounded exact candidates across complete base and head trees, performs raw and unembedded counting, and persists range-bound public metadata plus helper-private candidate bytes for stateful head recounting.
- Complete PEM blocks and AWS secret values have stable candidate identities; oversized provider prefixes, oversized assignments/JWTs, incomplete PEM blocks, and other uncountable events remain fail closed.
- Dynamic candidates that do not satisfy the reduction inequalities are rejected during preparation, before a mutable materialized head or reviewer process exists.
- Variable-length provider candidates prove their terminating byte against the provider body alphabet, select the longest actual prefix for the 513-byte fail-closed branch, and retain provider-specific spans across stream commit boundaries.
- Google API-key candidates capture the complete 35-to-512-byte provider body; a 513-byte prefix remains fail closed, so Base64url punctuation cannot truncate distinct longer values into one reduction candidate.
- A generic oversized-assignment event is suppressed only when its 513-byte prefix is proven to be the beginning of one complete provider-specific candidate that exactly fills the quoted or unquoted right-hand side, including across stream commit boundaries; any trailing generic value byte still blocks.
- The oversized-assignment exemption reuses the ordinary quoted or unquoted logical-RHS parser, so whitespace, operators, shell continuations, quote transitions, backslashes, backticks, and unsafe diff continuations remain fail closed after a long provider candidate.
- Exact provider-specific spans still pass through generic quoted or unquoted RHS validation when their short values fall below the generic entropy heuristic. A safe exact RHS is deduplicated only after the parser accepts it; operators, shell continuations, unsafe diff continuations, and other rejected tails remain generic-assignment blockers.
- Complete-catalog legacy raw values and canonical Base64 storage encodings remain forbidden in both frozen base and head paths, including when a marked base path is deleted or renamed away at head.
- Exact unembedded counting uses separate containment domains for each legacy envelope and for dynamic reductions, so a longer dynamic candidate cannot change legacy count semantics while dynamic candidates still contain one another normally.
- Reviewer-visible diff and prompt artifacts are integrity-bound. Text diffs are not secret-egress filters and retain deleted secret bytes in their original form; prompts remain independently secret-scanned and accept only exact authoring-catalog values.
- Deleted sensitive paths are omitted from head-side changed-path findings and are allowed only when the complete materialized head remains free of sensitive paths.
- Catalog authoring and explicitly selected legacy behavior remains unchanged.

## Validation

- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests`: 760 tests passed, 9 skipped.
- `ruff check` on changed runtime and test modules: passed.
- `git diff --check`: passed.
- Fixed-range Codex review and PR readiness evidence are recorded in the delivery thread and PR.

## Evidence

- `AGENTS.md`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/helper-contract.md`
- `skills/review-orchestration-playbook/references/egress-consent.md`
- `skills/review-orchestration-playbook/references/synthetic-token-fixtures.md`
