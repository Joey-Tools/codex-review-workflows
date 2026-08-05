---
id: 20260805-ca401f
title: Claude Numeric API Error Status Authentication
status: completed
created: 2026-08-05
updated: 2026-08-05
branch: codex/claude-api-status-auth
pr:
supersedes: []
superseded_by:
---

# Claude Numeric API Error Status Authentication

## Summary

- Accept a true integer `api_error_status` from `100` through `599` as bounded error metadata on Claude failure envelopes.
- Classify numeric `401` authentication evidence as `blocked-authentication` through the canonical direct lane while keeping successful envelopes with numeric status fail closed.

## Current State

- The provider compatibility classifier accepts exact login text plus numeric `401` only when the failure envelope and requested-model `modelUsage` binding are otherwise verified; `_record_attempt` records `auth` with `structured-authentication`.
- The canonical stream validator maps bounded integer status metadata into the existing strict failure classifier. Numeric `401` produces `terminal.authentication-error`; other bounded statuses remain classified evidence, while booleans, non-integer numbers, objects, and values outside `100..599` are malformed.
- Success still accepts only absent, `null`, or whitespace-only `api_error_status`; a numeric status contributes `terminal.success-with-error` and yields `inconclusive`.
- The aggregate runtime profile and its validator mirror use `null_or_whitespace_string_or_http_status_integer`. The audited Claude Code 2.1.212 baseline remains unchanged.

## Decision Rationale

- HTTP status is transport metadata, not a competing error payload, so a verified bounded integer may coexist with the exact authentication result on a failure envelope.
- Exact `type(value) is int` checks exclude JSON booleans even though Python booleans are integer subclasses; inclusive `100..599` bounds preserve the HTTP status domain and reject unreviewed numeric shapes.
- Numeric metadata is admitted only into failure classification. Success retains its stronger empty-error invariant, preventing a contradictory success envelope from supplying findings.

## Review Finding Provenance

- A named single review of `Joey-Tools/codex-private-workflows` PR 146 reported that generated overlay `providers.py` downgraded exact login text plus numeric `401` to `unverified-auth-failure-envelope`.
- Canonical-source adjudication assigned the fix to `Joey-Tools/codex-review-workflows` and identified the direct stream validator as a second independent rejection point; fixing only the provider compatibility layer would not have changed the complete named Claude lane outcome.

## Next Steps

- Downstream private-overlay sync and release consume the canonical squash merge.

## Evidence

- Focused provider regression: 2 tests passed in 0.986 seconds.
- Complete stream-validator suite: 109 tests passed in 6.584 seconds.
- Focused stream schema/authentication/bounds regression, including float, object, and blank-string cases: 3 tests passed in 0.329 seconds.
- Canonical documentation contract anchor: 1 test passed in 0.008 seconds.
- Floating aggregate schema contract case: 1 test passed in 0.003 seconds.
- Complete review-orchestration suite outside the restricted sandbox: 2,840 tests passed in 1,564.537 seconds with 6 platform-gated skips.
- Ruff lint, aggregate-schema JSON parsing, skill validation, project-journal validation, independent read-only audit, and `git diff --check` passed.
