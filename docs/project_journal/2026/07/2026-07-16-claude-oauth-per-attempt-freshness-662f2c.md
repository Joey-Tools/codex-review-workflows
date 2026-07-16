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
- A fixed-input warmup's explicit entitlement becomes model-chain evidence only
  when strict structured output verifies the exact requested effective model.
  It has no final text, does not start the final broker or repository-review
  sandbox, and leaves credential freshness unvalidated. Missing or mismatched
  model metadata stops the lane without fallback, while the next entitled model
  still repeats its own credential-boundary refresh and validation. Its complete
  bounded stdout/stderr is copied into the persistent formal attempt logs, and
  an explicit authentication failure stays unavailable even if refresh produced
  a structurally fresh credential. Entitlement also requires a strict top-level
  error result and structured error evidence; success plus entitlement-shaped
  stderr never enters fallback. A later successful preflight overwrites the
  prior entitlement model in runtime evidence.
- The trusted executable snapshot remains reusable across the model chain;
  credential freshness is the per-attempt boundary that is re-evaluated.

## Validation Evidence

- Python compile checks passed for the helper scripts and complete runtime/test
  trees.
- Full runtime/test `ruff check` passed.
- Focused provider and contract suite: 267 tests run; 6 skipped and the suite
  passed. The entitlement-preflight routing, exact-model verification,
  next-model revalidation, no-final-broker path, and final
  transient-after-refresh regressions also passed separately.
- Full helper suite after the final `master` refresh at `4d40df7`: 702 tests
  run; 9 skipped and the suite passed.
- The final helper-backed review found that Keychain freshness-read supervision
  failures could bypass the authentication-preflight classification. Both the
  initial and post-warmup reads now convert timeout, output-limit, drain, and
  process-leak failures to `ClaudeAuthWarmupInconclusive`, preserving existing
  attempt evidence without fabricating an unstarted model attempt.
- The follow-up review found that `run_review()` and each model attempt both
  prepared TLS CA copies. Whole-chain TLS preparation was removed; each attempt
  now performs exactly one preparation before warmup/final runtime, avoiding
  duplicate CA directories while preserving the attempt-boundary ordering.
- The next follow-up found that an attempt-local restricted Keychain broker
  failure was not included in the inner unavailable branch. It now records
  `authentication-preflight-unavailable`, preserves earlier attempts, and uses
  the same consent-gated fallback policy as an unavailable credential.
- A focused exception audit then closed the remaining pre-launch boundaries:
  transient warmup evidence takes precedence over a post-warmup broker failure;
  final credential-read supervision becomes credential-read inconclusive with
  no attempt; and final broker/loopback failure resets the runtime report to
  unavailable before any Claude CLI launch.
- Strict Clang syntax checks passed for the unchanged Keychain broker and Linux
  launcher, including the production POSIX feature macro for the launcher.
- Both workflow actionlint checks, the isolated PyYAML skill validator,
  synthetic-token catalog validation, project-journal validation, and
  `git diff --check` passed.

The pre-merge implementation gates did not run a live Claude or Copilot review,
send repository content to those providers, or perform a live OAuth retry.

## Next Steps

- None for this local delivery workstream.
