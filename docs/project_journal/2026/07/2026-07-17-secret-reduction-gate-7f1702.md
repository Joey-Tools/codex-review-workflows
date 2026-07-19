---
id: 20260717-7f1702
title: Permit Review of Verified Secret-Reduction Ranges
status: completed
created: 2026-07-17
updated: 2026-07-19
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

Counts alone are insufficient. Occurrence provenance (the base location from which a residual head occurrence is allowed to survive) must also prove that every raw and unembedded head occurrence existed at the same raw Git path, normalized surface kind, and absolute byte offset in the base tree. Regular blobs use one surface kind across `100644` and `100755`; symlink targets use a distinct surface kind. A new path, offset, copy, or regular-blob/symlink-target transition therefore blocks even when the global count decreases.

| Range outcome | Decision |
| --- | --- |
| Exact raw count strictly decreases, unembedded count does not increase, and every residual occurrence has matching base provenance | Eligible after the rest of preflight passes |
| Residual count is equal | Block |
| Candidate first appears at head | Block |
| Move, rename, or copy without strict global reduction | Block |
| Raw or unembedded count grows | Block |
| Candidate bytes are ambiguous, unsafe to represent, outside budgets, or otherwise uncountable | Block |

Path findings are independent of content counts. A sensitive changed path is eligible only when it is deleted and no sensitive path exists anywhere in the complete head snapshot. A renamed, moved, copied, or retained sensitive path at head blocks review.

## Trust Boundary

The reviewer is a trusted processor for the scoped repository data authorized by the review request. After preflight passes, it receives the frozen tracked diff, necessary tracked context, and explicitly supplied review prompt as recorded so it can assess the security-sensitive change accurately. Those reviewer inputs remain size-, identity-, and integrity-bound but are intentionally not secret-scanned, redacted, or made subject to an additional prompt-secret authorization gate. The helper does not automatically discover or collect other untracked private files, unrelated repositories, broad workspace dumps, host-local artifacts, or reviewer/runtime authentication credentials. PR/master admission remains the primary secret-introduction control.

Diagnostic and preflight evidence remain bounded audit surfaces. They use stable finding metadata, digests, and counts where applicable; this evidence contract does not require changing the tracked review content sent to the reviewer. Complete changed paths are published only as ordered, side-bound SHA-256 commitments, while matching `H` (head-present) and `B` (base-only) raw records remain helper-private and ephemeral. Changed-blob findings likewise use path digests.

## Catalog Compatibility

- Authoring entries keep their exact catalog-declared scanner-rule acceptance behavior.
- Explicit legacy envelopes keep the existing non-increasing raw and unembedded count policy, including equal-count moves between safe paths when all other legacy checks pass.
- Dynamic reduction does not create catalog entries, select a legacy envelope, weaken catalog validation, or relax sensitive-path checks. A dynamic candidate that equals or contains either a raw value or its canonical Base64 storage encoding from an unselected legacy envelope must use explicit legacy selection and cannot reclassify that catalog value as part of an unregistered deletion.
- New fixtures must still use the authoring pool, and master-proven historical fixtures must still use explicit legacy selection.

## Current State

- Runtime preflight exhaustively captures bounded exact candidates across complete base and head trees, performs raw and unembedded counting, and binds every dynamic occurrence to raw Git path, normalized blob/symlink surface, and absolute byte offset. Public manifest schema version 4 stores only fixed-size base/head provenance commitments; raw paths, offsets, occurrence identities, and candidate bytes are not published. Helper-private state retains only the exact candidate bytes needed for stateful head recounting, and materialized-head validation must reproduce the public head commitment exactly.
- Complete PEM blocks and AWS secret values have stable candidate identities; oversized provider prefixes, oversized assignments/JWTs, incomplete PEM blocks, and other uncountable events remain fail closed. PEM end markers are indexed once by label and matched with bounded binary searches, so dense unmatched begin markers cannot amplify into overlapping 32-KiB scans.
- Dynamic candidates that do not satisfy the reduction inequalities are rejected during preparation, before a mutable materialized head or reviewer process exists.
- Variable-length provider candidates prove their terminating byte against the provider body alphabet, select the longest actual prefix for the 513-byte fail-closed branch, and retain provider-specific spans across stream commit boundaries.
- Fixed-length AWS access-key and npm-token candidates use provider-body termination rather than a generic word boundary. A following underscore or other non-body byte therefore preserves both the exact provider span and the complete longer RHS identity.
- Google API-key candidates capture the complete 35-to-512-byte provider body; a 513-byte prefix remains fail closed, so Base64url punctuation cannot truncate distinct longer values into one reduction candidate.
- Three-part JWT candidates require a stable non-dot boundary, while bounded five-part compact JWE candidates are captured as one complete identity, including empty encrypted-key or ciphertext segments. Four-part, six-or-more-part, and oversized continuations remain fail closed instead of being reduced through a shared three-part prefix. The scanner builds its complete-candidate range index once and resolves each JWE continuation by an O(1) `start -> max_end` lookup, avoiding quadratic work on dense inputs.
- A generic oversized-assignment event is suppressed only when its 513-byte prefix is proven to be the beginning of one complete provider-specific candidate that exactly fills the quoted or unquoted right-hand side, including across stream commit boundaries; any trailing generic value byte still blocks.
- The oversized-assignment exemption reuses the ordinary quoted or unquoted logical-RHS parser, so whitespace, operators, shell continuations, quote transitions, backslashes, backticks, and unsafe diff continuations remain fail closed after a long provider candidate.
- Exact provider-specific spans still pass through generic quoted or unquoted RHS validation when their short values fall below the generic entropy heuristic. A safe exact RHS is deduplicated only after the parser accepts it; operators, shell continuations, unsafe diff continuations, and other rejected tails remain generic-assignment blockers.
- A quoted generic assignment is eligible only when its apparent closing quote is not escaped by an odd backslash run. An escaped quote remains a blocker and cannot supply a dynamic reduction candidate, including across complete-tree counting.
- A complete generic literal RHS remains an exact dynamic candidate when balanced wrappers or triple quotes enclose it, including embedded newlines. Ordinary single- and double-quoted literals may contain the opposite quote and still retain one complete identity; provider-shaped substrings inside those literals do not leave a truncated prefix blocker. This permits strict `1 -> 0` and `2 -> 1` remediation for those forms; unsupported, unclosed, oversized, backtick, or ambiguous forms remain blocking.
- A complete provider-specific span nested inside a longer low-entropy unquoted assignment retains the complete generic RHS identity, including an attached suffix or nonzero offset. This prevents distinct longer values from being collapsed into one shorter reduction candidate. AWS credential assignments use the same fail-closed complete-RHS treatment.
- Short provider-specific spans inside incomplete, multiline, prefixed, escaped, triple-quoted, adjacent-literal, wrapped, or expression-based assignments retain a generic blocker until the full logical RHS is proven to be that exact candidate. Operators and comments preserve continuation across stream boundaries and blank lines; opposite unified-diff record sides cannot supply a false closing delimiter.
- Wrapped exact-RHS proof uses a type-aware last-in-first-out delimiter stack. Missing, crossed, mismatched, or extra delimiters block when the suffix is complete, while a structurally valid partial wrapper remains deferred at an incomplete stream frontier. Any closer consumed before the candidate literal permanently invalidates that wrapper-only prefix, so a completed expression followed by a fresh wrapper cannot regain exact-candidate status.
- Exact quoted-RHS proof also validates containers opened before the assignment. A missing external function, array, or object closer blocks at EOF or before a new unseparated statement; comma-delimited sibling assignments remain valid. Mapping-key quotes nested inside a source literal are recognized only when their same-side, unescaped closer is followed by horizontal whitespace and `:` before the assignment value.
- Secondary RHS discovery retains OPEN (not yet proven complete) and unknown assignments across stream windows even before a provider span is visible, and releases only a CLOSED (proven complete) RHS. The absolute per-assignment proof cap includes the candidate, delimiters, trailing bytes, wrapper state, and external source context inspected for that decision. Line starts and diff-source context advance monotonically, so repeated secret-key prefixes remain linear or fail closed within the scanner budget.
- Incomplete stream scans carry separate commit and retention frontiers. Complete assignments before the deferred suffix are committed exactly once, while earlier diff-hunk or PEM proof bytes remain available until the deferred candidate is resolved.
- Exhaustive provenance audit may retain assignment-local evidence for an exact catalog legacy value after an earlier stream window has already committed a blocker and external prefix context is no longer available. This capture-only evidence never suppresses that generic blocker, never applies to authoring or dynamic reduction values, and never broadens ordinary preflight.
- Complete-catalog legacy raw values and canonical Base64 storage encodings remain forbidden in both frozen base and head paths, including when a marked base path is deleted or renamed away at head.
- Exact dynamic reduction raw values and canonical Base64 encodings are forbidden in every frozen and materialized head path. Candidate discovery and the frozen-head path gate run before materialization, so a case-colliding or overlong secret-bearing path cannot escape through a materialization diagnostic. Validation also repeats the unselected-legacy overlap check against the catalog reloaded immediately before egress. A deleted base-only path remains reviewable through the trusted raw diff and a helper-private `B` record; only the complete-catalog legacy matcher applies to that record, so generic dynamic or sensitive-path deletion does not regress.
- Exact unembedded counting uses separate containment domains for each legacy envelope and for dynamic reductions, so a longer dynamic candidate cannot change legacy count semantics while dynamic candidates still contain one another normally.
- Reviewer-visible diff and prompt artifacts are integrity-bound but are not secret-egress filters. They retain deliberately supplied reviewer input, including deleted or prompt-contained secret bytes, in original form.
- Gitlink changes use metadata-only `--submodule=short` output. Even an initialized source checkout cannot inline nested submodule logs, diffs, or content from a repository outside the authorized review scope.
- Deleted sensitive paths are omitted from head-side changed-path findings and are allowed only when the complete materialized head remains free of sensitive paths.
- Public changed-path evidence contains ordered, domain-separated SHA-256 commitments for every `H` and `B` record. The helper validates those records lockstep against an owner-only private raw-path stream, binds the side tag into each digest, applies the runtime complete catalog to both sides, and checks all public audit evidence against catalog and dynamic sensitive values. After preflight consumes the private path stream and Base64 raw-bearing dynamic-reduction manifest, it removes both through owner-, mode-, and identity-checked no-follow parent/container descriptors before publishing preflight evidence or launching a reviewer; failed preflight and later cleanup paths retry that scrub. An explicitly retained or fallback workspace therefore keeps only the frozen workspace and durable bounded evidence. Changed-blob findings identify paths by digest as well.
- Workspace and container cleanup traverses content only through already-opened verified directory descriptors. Each ordinary file is atomically moved to a fresh quarantine name before unlink, and each generic child or retained-workspace directory is quarantined and identity-checked before recursive traversal; the outer helper-owned container keeps its stable retry path until traversal succeeds. Every head snapshot reserves the helper-owned `.codex-review-cleanup-*` component namespace so tracked content cannot masquerade as retained quarantine state; base-only deleted paths remain permitted in the trusted raw diff. The two helper-private artifacts use a stronger lifecycle binding: preparation captures their container and file identities from creation descriptors before sensitive bytes are written; the review workspace/state marker and control state carry matching immutable copies. Cleanup accepts only those identities, quarantines and revalidates each private file, removes it, and records a monotonic per-file removal receipt through the same container descriptor. A missing preparation-bound container, missing or replacement objects without receipts, and unresolvable corrupted-state layout paths fail closed; a valid independent marker still permits the bounded scrub after a layout-resolution failure. A recorded name that reappears is preserved, and one invalid identity does not skip the other valid scrub. The receipt-bearing control state remains until other tree content is removed so ordinary cleanup errors remain retryable. A crash or forced termination after quarantine begins but before receipt persistence is deliberately ambiguous and fails closed; it may retain a quarantine entry or require manual recovery for a missing-name ambiguity rather than weakening the preparation identity proof. Directory depth and cross-filesystem child traversal are explicitly bounded. As elsewhere in the local helper, malicious current-user processes are part of the host TCB; portable POSIX cannot find an inode moved away before cleanup or provide fd-only unlink/rmdir after the final quarantine identity check.
- Stateful preparation acquires `runner.lock` at the first private-cleanup identity handoff and holds that same descriptor through child launch. Before helper-private secret bytes can be written, it durably records a schema-v3 `preparing` marker bound to a canonical source root, the exact `source_root/.codex-tmp/isolated-review-*` container, and every identity captured so far; the marker advances to `ready` after complete ownership handoff. If `state.json` was never published, either phase can recover and remove the entire identity-bound container once the runner lock is released. Exact historical schema-v1 state and marker layouts remain supported for status, wait, finalization, retention, and cleanup, but the legacy format did not record preparation identities: compatibility cleanup validates the canonical layout and then uses current-object identities under the documented same-user host TCB instead of asserting unavailable provenance.
- The complete prospective retained `preflight.json`, including the final `private_artifacts: removed` field, is assembled through the same shared builder used for publication and checked against every catalog and dynamic value before private-artifact removal or reviewer launch.
- Catalog authoring and explicitly selected legacy behavior remains unchanged.

## Validation

- Post-integration frozen-range review found and fixed scope/scanner gaps: initialized submodule content can no longer enter `review.diff`; wrapped/triple/multiline and opposite-quote generic literals now participate in exact reduction proof; malformed closer prefixes remain blockers instead of disappearing or producing a reduction candidate; provider-specific and PEM events are charged exactly once regardless of later accepted/blocking classification; unselected legacy overlap covers raw and canonical Base64 representations during preparation and runtime catalog reload. `PublicPoolScannerTest`: 96 passed. Synthetic-token module: 217 passed.
- Focused complete-path, catalog-reload, side-binding, quarantine-before-recursion, and failure-regression runs passed. The final lifecycle gate additionally passed 66 state-module tests, 31 cleanup/handoff/durability tests, 12 state-start tests, and the missing-to-concurrent-create durability race regressions.
- Latest `master` (`6dc2050`) was merged without rewriting history. Its Claude authentication, recovery-carrier, and refresh-lock fail-closed policies remain intact; authentication failure is not a Copilot fallback reason.
- Provider tests: 457 passed, 3 platform-conditional skips.
- Python 3.13 full suite: 1211 tests passed, 4 skipped.
- Python 3.10.19 full suite: 1211 tests passed, 4 skipped.
- `ruff check` and `ruff format --check` on all 10 Python files changed from the refreshed `master`: passed.
- `git diff --check`: passed.
- Fixed-range Codex review and PR readiness evidence are recorded in the delivery thread and PR.

## Evidence

- `AGENTS.md`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/helper-contract.md`
- `skills/review-orchestration-playbook/references/egress-consent.md`
- `skills/review-orchestration-playbook/references/synthetic-token-fixtures.md`
