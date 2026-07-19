---
id: 20260717-7f1702
title: Respect Diff Sides in Secret Assignment Scans
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/diff-placeholder-boundary
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/59
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
- Once a hunk side is established, opposite-side records whose source content
  begins with `++ ` or `-- ` remain hunk content instead of being mistaken for
  `+++` or `---` file headers.
- A matched `+++ ` or `--- ` record binds to a diff side only when bounded,
  charged lookbehind proves a hunk after the latest `diff --git` boundary;
  ambiguous file-header and incomplete-prefix cases fail closed.
- Declaration reconstruction anchors hunk proof before the matched assignment,
  even after a long opposite-side record, and subtracts only opposite bytes that
  were already charged while skipping that record.
- Streaming retention carries the latest enclosing hunk across logical chunks
  only while it remains within the proof window plus overlap. That retained
  hunk is a local complete boundary; an arbitrary truncated no-hunk prefix
  cannot fall back to offset zero, and a later `diff --git` invalidates it.
- A non-final streaming window carries the earliest deferred assignment
  boundary forward, commits only the complete prefix before it, and retains the
  match without merging provisional counts.
- Any diff proof that crosses a line boundary and ends at a non-final buffer
  boundary is deferred, including partial same-side and context records.
- Streaming event candidates are filtered to the current commit range before
  consuming event or prefix-proof budget, while in-range candidates still use
  the complete pending buffer as source context.
- Older provider-specific spans remain available to suppress a generic match
  that ends across the commit frontier without charging the provider event
  again.
- Streaming scans spend event and prefix-proof budgets transactionally: a
  complete scan commits its budget, while an incomplete scan discards its
  provisional work and commits only the replayed safe prefix.
- Transport-level short reads are coalesced into bounded logical chunks before
  scanning, so stream fragmentation cannot cause repeated speculative scans;
  negative sizes, early EOF, and oversized reads fail closed.
- Security regressions keep scanning after opposite-side interleaving and
  continue to reject same-side or shared-context RHS continuations.

## Validation Evidence

- The focused quoted-assignment regressions passed, including opposite-side
  interleaving, same-side and context continuations, base-prefix reconstruction,
  symmetric triple-prefix hunk content, and both per-event and global proof
  budgets. The prefix cases include real file headers and a hunk boundary so
  header metadata remains outside the reconstructed source.
- Streaming-boundary regressions failed against the initial candidates and now
  cover both an incomplete record and a record whose newline is the final byte
  of a non-final read; the complete EOF case remains accepted exactly once.
- An eight-assignment segmented-stream regression proves that each complete
  prefix advances the commit frontier and pending input stays bounded. An
  independent 11.54 MiB probe reduced event consumption from `44` to `31` and
  prefix-proof consumption from `36,773,130` to `14,819,754` bytes.
- A bounded-budget red/green regression reproduces the deferred-match double
  charge: the old path consumed `1,412` prefix-proof bytes and failed a valid
  `1,200`-byte budget, while commit-range filtering consumes `1,092` bytes and
  accepts the fixture exactly once.
- Partial-suffix regressions cover base/head marker-only and indented records,
  shared context, direct non-final sentinel reporting, full/stream agreement,
  and safe actual EOF cases. The old stream path accepted these boundary
  payloads; the fixed path blocks the adjacent secret.
- Triple-prefix match regressions cover both hunk sides, real file headers,
  cross-file hunk reset, incomplete prefix context, bounded lookbehind, and an
  exhausted prefix-proof budget.
- A 4 KiB long-opposite-record regression accepts with the exact charged proof
  allowance, leaves zero bytes, and fails when the allowance is one byte short.
- A pattern-order regression places two safe unquoted assignments before one
  deferred quoted assignment; all three logical events are committed exactly
  once, closing the provisional/replay budget bypass.
- A one-byte transport regression coalesces thousands of short reads into three
  logical scanner calls, commits the completed opposite-record proof exactly
  once, and fails when its proof allowance is one byte short.
- Direct/stream equivalence regressions cover the reviewer-reported 4,812-byte
  deferred-hunk payload and an assignment first seen in a later logical chunk;
  both accept exactly once, while the same retained hunk followed by a new
  `diff --git` remains blocked on both paths.
- A three-event provider-specific stream-boundary regression proves that a
  committed provider span is retained for generic suppression without being
  charged again in overlap.
- The previously blocked frozen `review.diff` passed the patched scanner in a
  redacted local probe.
- The complete synthetic-token module passed (`91` tests).
- The complete review-orchestration suite passed on the refreshed master
  baseline (`716` tests; `9` skipped).
- Full runtime/test `ruff check` and Python `compileall` passed.
- Synthetic-token catalog validation returned `public-example-v1` as valid.
- Skill validation, project-journal validation, and `git diff --check` passed.
- Independent read-only follow-up reviews of the partial-suffix, hunk-proof,
  event-accounting, transactional-budget, short-read, EOF, raw-occurrence, and
  bounded hunk-retention changes returned `No findings.`

## Next Steps

- None after the prerequisite scanner release reaches the installed review
  helper.
