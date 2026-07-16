---
id: 20260716-662f2c
title: Claude OAuth Per-Model-Attempt Freshness
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: wip/claude-oauth-per-attempt-freshness
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/49
supersedes: []
superseded_by:
---

# Claude OAuth Per-Model-Attempt Freshness

## Summary

Claude local-login preflight previously required one OAuth credential to cover
both candidate models: `2 * (1800 + 120) = 3840` seconds. A newly refreshed
credential with an approximately one-hour lifetime therefore could not satisfy
the gate even though it safely covered the current bounded model attempt.

This workstream replaces only that aggregate-lifetime rule. It preserves the
runtime and isolation design established by the Claude local-login and platform
capabilities workstreams.

## Current State

- Credential freshness is defined once as the current model-attempt timeout plus
  its safety margin: `1800 + 120 = 1920` seconds.
- On macOS, each local-login model attempt independently performs the existing
  fixed-input, no-tools, no-workspace-read warmup when needed and then re-reads
  and validates the Keychain credential. The final one-shot broker performs a
  second read and fail-closed validation for the same attempt window.
- On Linux/WSL2, each model attempt independently stages and validates a fresh
  read-only credential snapshot for the 1920-second window. The runtime never
  refreshes or persists the host credential.
- API-key attempts skip local-login warmup and local credential staging.
- A warmup supervision or explicit transient failure is recorded as
  authentication-preflight inconclusive and returns Outcome 75 while preserving
  earlier model-attempt evidence. This remains true if the warmup happened to
  refresh the credential before returning a transient result, and it never
  enters Copilot fallback.
- Explicit authentication unavailability and model entitlement keep the
  existing fallback policy: only prior `double-review` or `triple-review`
  consent may authorize Copilot.
- The trusted executable snapshot remains reusable across the model chain;
  credential freshness is the per-attempt boundary that is re-evaluated.

## Validation Evidence

- Python compile checks passed for the helper scripts and complete runtime/test
  trees.
- Full runtime/test `ruff check` passed.
- Focused provider and contract suite: 251 tests run; 6 skipped and the suite
  passed. The final transient-after-refresh regression and its adjacent warmup
  cases also passed separately.
- Full helper suite on current `master`: 682 tests run; 9 skipped and the suite
  passed.
- Strict Clang syntax checks passed for the unchanged Keychain broker and Linux
  launcher, including the production POSIX feature macro for the launcher.
- Both workflow actionlint checks, the isolated PyYAML skill validator,
  synthetic-token catalog validation, project-journal validation, and
  `git diff --check` passed.

No live Claude or Copilot review, repository-content egress to those providers,
private overlay synchronization, release, or live OAuth retry was performed.

## Next Steps

- None for this local delivery workstream.
