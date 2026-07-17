---
id: 20260717-c17a11
title: Trust Claude Authentication Carriers
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/claude-auth-carriers
pr:
supersedes:
  - 20260703-b4e9d1
  - 20260715-7c1501
  - 20260716-662f2c
superseded_by:
---

# Trust Claude Authentication Carriers

## Summary

- Claude authentication now trusts the publisher-verified current CLI's credential-store coordination and refresh behavior instead of enforcing a helper-defined OAuth access-token freshness window.
- The supported signed-manifest and capability range starts at `2.1.211` and remains bounded below `3.0.0`; API-key reviews keep that range, while local-login writeback is enabled only for exact signed artifacts whose refresh-lock protocol has been audited.

## Current State

- Provenance, capability, outer-sandbox, file-tool, escaping-symlink, sensitive-content, bounded-output, effective-model, and terminal-artifact gates remain mandatory before a result can count as review evidence.
- The helper performs no fixed-input authentication warmup and does not require an access token to cover a 30-minute attempt. Access-token expiry alone is not login expiry when a usable refresh token remains.
- On macOS, the parent safely reads the current-account Keychain item and the credential file under the account home returned by `pwd`; it never trusts caller-controlled `HOME`. The file is an empirically verified compatibility source for current Claude Code releases, not an officially guaranteed macOS storage location. The structurally valid candidate with the later access-token expiry is loaded into the restricted temporary broker regardless of whether that access token has already expired. Carriers with the same refresh-token fingerprint are one logical login, and every broker rotation is persisted and verified before acknowledgement while advancing the complete carrier baseline. If a file-first dual write gets an ambiguous Keychain result, the parent readbacks both carriers, accepts an already-complete commit, retries one exact partial state once, and otherwise preserves the rotated file credential while pausing as inspection-inconclusive rather than rolling back to a potentially invalid old refresh token. If Keychain-only persistence or the first required file write fails, the parent copies the newest structurally valid broker rotation into a helper-private recovery carrier before the broker clears its buffer. Later valid updates atomically replace that same recovery credential; only the private path is reported, and the lane pauses as inspection-inconclusive without a login prompt or Copilot fallback.
- On Linux and WSL2, the current-user exact-mode-`0600` host credential is copied into a helper-owned writable `/auth` carrier with config at `/auth/config`. The original host file is never mounted and `/auth` remains denied to model-visible file tools. A bounded watcher persists multiple stable rotations during the attempt; after an ordinary stop, a synchronous final drain runs before cleanup. If a normally reaped Claude process leaves helper-owned staged locks after rotating its token, the parent uses the supervisor's process-group-quiescence handoff plus the stopped watcher to preflight and remove only the exact empty private staged locks, then retries the final drain once. Timeout, process-leak, unsafe-lock, retry, or guarded host-write uncertainty instead retains the private recovery carrier under the review container and reports its path without credential contents. A watcher join timeout is inspection-inconclusive and retains the carrier immediately, without concurrent final drain, cleanup, or an unbounded wait.
- The restricted final runtime may refresh only inside its temporary carrier. For local login, the helper requires an exact version/platform/SHA-256 match in its signed-artifact lock catalog before reading host credentials. At each commit point, the parent acquires the audited CLI's primary `.oauth_refresh.lock` and legacy sibling lock, renews both leases every five seconds, rechecks the complete macOS Keychain-plus-file snapshot or the Linux/WSL2 file snapshot, and performs guarded writeback only while the observed host state still matches the current baseline. This serializes supported Claude Code login/refresh writers, normally preserves refresh-token rotation, and refuses observed concurrent changes, but is not an atomic compare-and-swap guarantee against unrelated external writers that bypass both locks. Stale shared locks are never reclaimed automatically and instead pause for controlled cleanup after confirming that no writer remains.
- Refresh-lock shutdown retries one transient heartbeat join timeout once. Two timeouts, or an interruption after cleanup starts, permanently mark that lease cleanup-inconclusive: exact helper-owned paths remain visible through combined operation errors and forwarded signals, later release calls cannot silently delete them, and only controlled operator cleanup after writer-quiescence proof is allowed.
- Missing, malformed, unsafe, refresh-token-less, `Login expired`, HTTP 401, or refresh failure is terminal `blocked-authentication`. The workflow pauses and instructs the operator to run `claude auth login` for local login, or unset/replace an explicit `ANTHROPIC_API_KEY`, as applicable; authentication never authorizes Copilot fallback.
- Only stderr and structured primary errors are classified. Partial result text is repository-controlled and can never authorize authentication, model, or Copilot fallback, so a partial review cannot forge a backend switch.
- With existing `double-review` or `triple-review` consent, Copilot fallback remains limited to deterministic secure-runtime absence/unavailability or a strictly verified Claude model-entitlement path.
- The Keychain update transport-size limit is enforced only when the selected source or same-login synchronization will write Keychain; a distinct, unselected Keychain login remains validated and snapshotted but cannot block an independently usable file login on that transport-only limit.

## Next Steps

- None for this workstream.

## Evidence

- Policy and implementation contract: `skills/review-orchestration-playbook/SKILL.md`, `references/helper-contract.md`, and `references/claude-runtime-trust.md`.
- Repository contract coverage: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- macOS Claude Code `2.1.211` carrier smoke: isolated `claude auth status --json` probes reported `loggedIn: true` with only a pwd-home credential file and, separately, with only the restricted `security` carrier.
- Python compile checks passed for the helper scripts and complete runtime tree.
- The complete helper suite passed after review fixes and integration with the latest `master`: 822 tests run, 9 skipped.
- Strict C syntax checks passed for the Linux launcher with its production POSIX feature macro and for the Keychain broker with its production clang flags.
- Fixed-range review and follow-up concurrency audits found and closed credential classification, deeply nested malformed-JSON handling, repository-controlled partial-result fallback, lock-coordination, heartbeat, whole-snapshot, exact-artifact, descriptor-cleanup, partial dual-write reconciliation, delayed-persistence, staged-lock crash recovery, stale shared-lock isolation, watcher-start ownership, forwarded-signal, and watcher-shutdown/process-exit defects. Credential inspection now has a distinct inconclusive path with no Copilot fallback, missing or actually rejected credentials remain blocking, exact audited artifacts share a heartbeat-backed writeback commit lock, and refresh rotations are persisted during the attempt. A macOS writeback failure no longer loses the only new refresh credential when the broker buffer is cleared; the newest verified rotation is retained in a reported private carrier. An unpersisted Linux/WSL2 rotation is either recovered after proven writer quiescence or retained the same way.
- `project_journal.py validate` passed for the repository journal set.
- The isolated `uv --with pyyaml` fallback reported `Skill is valid!` for `review-orchestration-playbook`; the preferred wrapper could not import local PyYAML.
