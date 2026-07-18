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

The reviewer is a trusted processor for the scoped repository data authorized by the review request. After preflight passes, it receives the frozen tracked diff, necessary tracked context, and explicitly supplied review prompt as recorded so it can assess the security-sensitive change accurately. The prompt remains size-, identity-, and integrity-bound but is not a secret-egress filter or part of tracked-tree reduction counting. The helper does not automatically discover or collect other untracked private files, unrelated repositories, broad workspace dumps, host-local artifacts, or reviewer/runtime authentication credentials.

Diagnostic and preflight evidence remain bounded audit surfaces. They use stable finding metadata, digests, and counts where applicable; this evidence contract does not require changing the tracked review content sent to the reviewer. Changed-head paths are published only as ordered SHA-256 commitments, while matching raw records remain helper-private and ephemeral. Changed-blob findings likewise use path digests.

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
- Fixed-length AWS access-key and npm-token candidates use provider-body termination rather than a generic word boundary. A following underscore or other non-body byte therefore preserves both the exact provider span and the complete longer RHS identity.
- Google API-key candidates capture the complete 35-to-512-byte provider body; a 513-byte prefix remains fail closed, so Base64url punctuation cannot truncate distinct longer values into one reduction candidate.
- A generic oversized-assignment event is suppressed only when its 513-byte prefix is proven to be the beginning of one complete provider-specific candidate that exactly fills the quoted or unquoted right-hand side, including across stream commit boundaries; any trailing generic value byte still blocks.
- The oversized-assignment exemption reuses the ordinary quoted or unquoted logical-RHS parser, so whitespace, operators, shell continuations, quote transitions, backslashes, backticks, and unsafe diff continuations remain fail closed after a long provider candidate.
- Exact provider-specific spans still pass through generic quoted or unquoted RHS validation when their short values fall below the generic entropy heuristic. A safe exact RHS is deduplicated only after the parser accepts it; operators, shell continuations, unsafe diff continuations, and other rejected tails remain generic-assignment blockers.
- A complete provider-specific span nested inside a longer low-entropy unquoted assignment retains the complete generic RHS identity, including an attached suffix or nonzero offset. This prevents distinct longer values from being collapsed into one shorter reduction candidate. AWS credential assignments use the same fail-closed complete-RHS treatment.
- Short provider-specific spans inside incomplete, multiline, prefixed, escaped, triple-quoted, adjacent-literal, wrapped, or expression-based assignments retain a generic blocker until the full logical RHS is proven to be that exact candidate. Operators and comments preserve continuation across stream boundaries and blank lines; opposite unified-diff record sides cannot supply a false closing delimiter.
- Wrapped exact-RHS proof uses a type-aware last-in-first-out delimiter stack. Missing, crossed, mismatched, or extra delimiters block when the suffix is complete, while a structurally valid partial wrapper remains deferred at an incomplete stream frontier.
- Exact quoted-RHS proof also validates containers opened before the assignment. A missing external function, array, or object closer blocks at EOF or before a new unseparated statement; comma-delimited sibling assignments remain valid. Mapping-key quotes nested inside a source literal are recognized only when their same-side, unescaped closer is followed by horizontal whitespace and `:` before the assignment value.
- Provider-backed exhaustive assignment discovery skips the secondary RHS walk when no provider span exists, advances line context incrementally, and reserves bounded prefix-proof budget before inspecting a candidate-bearing RHS. Diff-source proof uses a monotonic watermark to avoid charging the same bytes twice while retaining the absolute per-assignment proof cap. Repeated secret-key prefixes therefore remain linear or fail closed within the scanner budget.
- Incomplete stream scans carry separate commit and retention frontiers. Complete assignments before the deferred suffix are committed exactly once, while earlier diff-hunk or PEM proof bytes remain available until the deferred candidate is resolved.
- Exhaustive provenance audit may retain assignment-local evidence for an exact catalog legacy value after an earlier stream window has already committed a blocker and external prefix context is no longer available. This capture-only evidence never suppresses that generic blocker, never applies to authoring or dynamic reduction values, and never broadens ordinary preflight.
- Complete-catalog legacy raw values and canonical Base64 storage encodings remain forbidden in both frozen base and head paths, including when a marked base path is deleted or renamed away at head.
- Exact dynamic reduction raw values and canonical Base64 encodings are forbidden in every frozen and materialized head path. A deleted base-only path remains reviewable through the trusted raw diff and is omitted from changed-head metadata.
- Exact unembedded counting uses separate containment domains for each legacy envelope and for dynamic reductions, so a longer dynamic candidate cannot change legacy count semantics while dynamic candidates still contain one another normally.
- Reviewer-visible diff and prompt artifacts are integrity-bound but are not secret-egress filters. They retain deliberately supplied reviewer input, including deleted or prompt-contained secret bytes, in original form.
- Deleted sensitive paths are omitted from head-side changed-path findings and are allowed only when the complete materialized head remains free of sensitive paths.
- Public changed-path evidence contains ordered SHA-256 commitments only. The helper validates those records lockstep against an owner-only private raw-path stream and checks the commitments and all other audit evidence against catalog and dynamic sensitive values. After preflight consumes the private path stream and Base64 raw-bearing dynamic-reduction manifest, it removes both through owner-, mode-, and identity-checked no-follow parent/container descriptors before publishing preflight evidence or launching a reviewer; failed preflight and later cleanup paths retry that scrub. An explicitly retained or fallback workspace therefore keeps only the frozen workspace and durable bounded evidence. Changed-blob findings identify paths by digest as well.
- Catalog authoring and explicitly selected legacy behavior remains unchanged.

## Validation

- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests`: 807 tests passed, 9 skipped.
- `ruff check` on changed runtime and test modules: passed.
- `git diff --check`: passed.
- Fixed-range Codex review and PR readiness evidence are recorded in the delivery thread and PR.

## Evidence

- `AGENTS.md`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/helper-contract.md`
- `skills/review-orchestration-playbook/references/egress-consent.md`
- `skills/review-orchestration-playbook/references/synthetic-token-fixtures.md`
