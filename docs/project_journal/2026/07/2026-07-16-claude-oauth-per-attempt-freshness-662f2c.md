---
id: 20260716-662f2c
title: Claude OAuth Per-Model-Attempt Freshness
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: wip/claude-oauth-per-attempt-freshness
pr:
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
- A warmup supervision failure is recorded as authentication-preflight
  inconclusive and returns Outcome 75 while preserving earlier model-attempt
  evidence. It never enters Copilot fallback.
- Explicit authentication unavailability and model entitlement keep the
  existing fallback policy: only prior `double-review` or `triple-review`
  consent may authorize Copilot.
- The trusted executable snapshot remains reusable across the model chain;
  credential freshness is the per-attempt boundary that is re-evaluated.

## Validation Evidence

- `python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py`
- `ruff check` for the modified provider, Linux runtime, provider tests, and
  contract tests
- Focused provider tests: 15 passed
- Full helper suite: 612 tests run; 4 skipped and the suite passed
- The broker fixture's sandbox loopback denial reproduced on the unchanged
  canonical mirror; the same fixture passed outside that sandbox, and the full
  suite then passed outside it.
- CI-equivalent Linux launcher syntax check with `cc -std=c11 -O2 -Wall
  -Wextra -Werror -D_POSIX_C_SOURCE=200809L -fsyntax-only`

No live Claude or Copilot review, repository-content egress to those providers,
private overlay synchronization, release, or live OAuth retry was performed.

## Next Steps

- None for this local delivery workstream.

## Deferred Follow-Up

1. Merge the reviewed public change after explicit authorization.
2. Force the private source sync and confirm its sync PR and Private Overlay
   Release.
3. Update the private overlay on the local machine and
   `BL-mac-mini-m4-hoteng`, then verify the deployed helper contains the
   per-attempt behavior.
4. Retry the original live Claude review only after those deployment gates.
