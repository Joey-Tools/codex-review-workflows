---
id: 20260722-pfb001
title: Union Overlapping Secret Prefix Proof Ranges
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/secret-prefix-proof-budget
pr:
supersedes: []
superseded_by:
---

# Union Overlapping Secret Prefix Proof Ranges

## Summary

- Exact-secret admission keeps the 4 MiB per-proof limit and 64 MiB aggregate
  proof budget, but overlapping physical proof ranges within one streamed path
  or blob value are charged only once.
- Speculative streaming scans clone the proof-range ledger together with the
  logical scan budget and publish both only when that scan prefix commits.
- A separate 512 MiB cumulative proof-work budget charges repeated parser work
  even when the underlying bytes already have coverage credit or the scan is
  speculative and later discarded.
- A separate 100,000-range metadata cap preserves bounded memory and fails
  closed for genuinely excessive distinct proof work.

## Current State

- Dense credential-shaped test fixtures can request thousands of assignment
  context proofs over the same tracked source bytes without turning a small
  blob into an artificial aggregate-budget failure.
- Distinct newly inspected bytes still consume the aggregate budget. A single
  logical proof above 4 MiB, aggregate new coverage above 64 MiB, cumulative
  proof work above 512 MiB, or more than 100,000 disjoint proof ranges remains
  inconclusive and blocks admission.
- Proof ranges are scoped to one path or blob scan. Equal offsets in distinct
  Git values do not share credit.
- This accounting correction does not change exact raw secret counters,
  addition-location reporting, encoded-form limitations, reviewer launch, or
  reviewer egress policy.

## Root Cause

The quoted-assignment prepass repeatedly reconstructed wrapper context from an
earlier prefix for many candidates in the same source blob. Each reconstruction
charged its complete prefix to the aggregate proof budget even when almost all
of those bytes had already been covered by an earlier candidate. A 1,200,559
byte unchanged Webex test blob therefore attempted 67,325,162 proof bytes and
exhausted the 64 MiB budget after consuming 66,420,932 bytes.

## Validation Evidence

- Bounded instrumentation of the original failing blob completes with
  1,169,608 newly covered proof bytes after the fix; the aggregate limit remains
  unchanged.
- Focused regressions cover dense accepted assignments, rejected assignments
  nested in source fixtures, true new-byte exhaustion, range-ledger metadata
  exhaustion, diff-side proof accounting, and transactional incomplete-suffix
  replay.
- Python 3.13 passes the complete review-orchestration suite: 1,937 tests run,
  5 skipped. The focused synthetic-token module passes 177 tests, and the
  helper-contract suite passes 55 tests.
- Ruff lint and format checks, Actionlint, C launcher syntax checks, skill
  validation, project-journal validation, and `git diff --check` pass.
- An independent implementation audit found no remaining blocking issue after
  verifying transactional coverage reconciliation, monotonic proof-work
  charging, and atomic exhaustion behavior.
- The source-tree helper accepts
  `25be8931876a133ac510e10917681a99022b066c..db709507b83e7650d8fcc59697c8bb8ee979bffd`
  with exit `0`, `operation=exact-secret-admission`,
  `source=direct-git-tree-scan`,
  `review_contract=admission-only-no-reviewer`, `reviewer_started=false`,
  `secret_delta.status=clean`, and `temporary_cleanup_status=complete`.

## Next Steps

- No canonical implementation work remains after the reviewed change is merged
  and propagated through the private overlay release.
