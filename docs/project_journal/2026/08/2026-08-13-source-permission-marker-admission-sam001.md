---
id: 20260813-sam001
title: Source Permission Marker Admission
status: completed
created: 2026-08-13
updated: 2026-08-13
branch: wip/secret-admission-marker-fix
pr:
supersedes: []
superseded_by:
---

# Source Permission Marker Admission

## Summary

- Secret admission now recognizes the exact plain-string workflow OIDC write
  permission marker as source metadata instead of an opaque credential.
- The exception is closed to one bounded source record. Bytes, raw, formatted,
  escaped, concatenated, triple-quoted, unclosed, and overlong forms continue
  to fail closed.
- Credential values that share the permission-key prefix remain subject to the
  existing exact-secret rules.

## Current State

- The runtime and regression fixtures assemble the permission marker from
  adjacent byte fragments, so the compatibility scanner can evaluate this
  parser change without encountering the marker as a tracked raw literal.
- Direct and streamed scanner paths share the same record classification and
  proof-budget accounting.
- An exact marker without a trailing comma is accepted only at a proved final
  line ending. Later source bytes fail closed, preventing C adjacent literals,
  Python implicit concatenation, and next-line operators from extending it.
- Marker candidates outside the bounded record window or inside recognized
  non-plain source literals remain opaque and fail closed instead of falling
  through as unrelated text.
- Marker classification runs before the provider-specific fast path, so a
  later unchanged provider candidate remains counted without reclassifying the
  exact marker as a generic secret.
- The marker exception now requires the marker to begin at the recognized
  quoted literal's content boundary. Ordinary prose that mentions the marker
  later in the same literal remains ordinary source text.
- Rust raw hash-delimited literals remain marker near-misses and fail closed;
  the exception stays limited to plain single- or double-quoted literals.
- Same-line assignments, adjacent literals, language-ambiguous quote contexts,
  and unproved literal boundaries remain near-misses; ordinary containing
  prose is excluded only after a bounded plain-literal proof.
- Exact standalone list entries may carry a conservative ASCII `#` or `//`
  line comment after their comma. Directives, block comments, lookalikes,
  alternate line separators, and incomplete records remain near-misses.
- Whitespace-separated Rust outer and inner attribute tokens after `#` remain
  directives rather than comments and therefore fail closed.

## Evidence

- Twelve focused parser/admission regressions passed on Python 3.13.0.
- `PublicPoolScannerTest`: 119 tests passed.
- `WorkspaceTest`: 308 tests passed with one expected skip.
- Ruff checks passed for the runtime and both changed test modules.
- Fresh review identified the cross-line continuation boundary; the follow-up
  regressions cover C and Python forms plus a logical stream-read boundary.
- Whole-range re-review identified long-leading-context and C/C++ literal-prefix
  gaps; direct, streamed, and repository admission regressions cover both.
- The next whole-range review identified a later-provider fast-path gap;
  direct/stream parity and an unchanged-provider admission range cover it.
- GitHub Codex identified an ordinary-prose false positive; direct, streamed,
  classifier, and Git-tree admission regressions now cover the exact literal
  start boundary without weakening the existing fail-closed cases.
- A current-head GitHub Codex pass identified same-line literal-boundary,
  cumulative malformed-fixture, and inline-comment gaps. Each malformed
  Git-tree case now compares one fixture against its own immediate clean base;
  direct, streamed, and admission regressions cover the repaired boundaries.
- Formal whole-range review identified a second cumulative Git-tree fixture in
  the permission-suffix matrix. Every suffix case now compares against its own
  immediate clean base, binds all reported additions to that case's path, and
  commits fixture removal before the next case.
- The next formal review identified whitespace-separated Rust attributes that
  the generic `#` comment grammar still admitted. Classifier, direct/stream,
  and Git-tree regressions now reject both outer and inner attribute forms.
