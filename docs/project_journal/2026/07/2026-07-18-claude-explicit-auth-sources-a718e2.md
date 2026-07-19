---
id: 20260718-a718e2
title: Claude Explicit Authentication Sources
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/claude-explicit-auth-sources-pr
pr:
supersedes: []
superseded_by:
---

# Claude Explicit Authentication Sources

## Summary

- Claude authentication now has one deterministic precedence order: `ANTHROPIC_API_KEY` over `CLAUDE_CODE_OAUTH_TOKEN` over pwd-resolved local login.
- Explicit authentication and macOS local-login Keychain access have separate trust paths. An explicit winner bypasses every local credential facility, while local login uses descriptor-bound Security.framework access without weakening the existing refresh-lock and recovery protocol.

## Current State

- Empty explicit values are absent. When one or both explicit variables are nonempty, only the winner enters the final Claude runtime. Both nonempty startup values—including the loser—are frozen for artifact, exception, and output redaction.
- Explicit authentication short-circuits the temporary broker, host Keychain and credential-file reads, certified refresh locks, credential staging, recovery-root and journal creation, broker refresh handling, and host writeback before any of those facilities are touched. API-key rejection names `ANTHROPIC_API_KEY`; OAuth-token rejection names `CLAUDE_CODE_OAUTH_TOKEN`; neither is treated as a local-login refresh carrier.
- With no explicit winner, macOS local login resolves the current account through `pwd`, reads the real login Keychain through Security.framework by exact item reference, and independently inspects the compatible credential file under that account home. The Keychain operation binds the complete `/`-to-leaf descriptor identity, requires local APFS, accepts DENY-only ACL metadata, and fails closed on unexpected kqueue vnode events.
- Each complete Keychain read or guarded replacement runs in a dedicated supervised helper process. The worker disables Keychain user interaction before access, restores the prior setting after native cleanup on normal exit, exchanges credentials only through an anonymous bounded socket, and is killed and reaped at a monotonic hard timeout.
- The caller retains the certified writer lease across the expected-payload check, exact-item replacement, worker termination, and readback. An ordinary cleanly exited guard failure may use at most two Keychain replacement attempts: the initial replacement plus one exact file-new/Keychain-old retry. A replacement timeout has a write outcome unknown, receives one bounded readback and no second replacement, and preserves the rotated credential and recovery carrier unless exact completion is proven. A worker that cannot be proven reaped receives neither readback nor retry, and its shared refresh locks remain for controlled operator cleanup.
- A forwarded signal or other control-flow interruption after replacement dispatch is classified as write-outcome-unknown, reconciled once under the retained writer lease, and then restored as the original exception object. Cleanup blocks and consumes forwarded signals around transport shutdown and worker termination, persists spawned/proven state across the complete `finally` boundary, and classifies any uncertain `poll`, kill, wait, or reaper result as worker-termination-inconclusive. The provider blocks forwarded signals before the guarded write begins and publishes retained-lock ownership for that typed result before any later lease assertion, readback, or signal restoration. If worker reap cannot be proven, the shared lock state is retained before restoring the original control flow from the typed error's cause chain.
- Explicit credential redaction of JSON artifacts now walks only string values before serialization. Fixed mapping keys, JSON syntax tokens, `null`, booleans, and numeric values preserve their schema and types, while state metadata still fails closed before writing any string value that contains a frozen explicit credential.
- Broker `W` acknowledgement continues to prove durable private recovery staging rather than host persistence. Only the post-quiescence owner performs host writeback, and no explicit-auth path enters staging, recovery, or writeback.

## Next Steps

- None for this workstream.

## Evidence

- Policy surfaces: `AGENTS.md`, `README.md`, `skills/review-orchestration-playbook/SKILL.md`, `references/helper-contract.md`, and `references/claude-runtime-trust.md`.
- Repository contract coverage: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Python 3.13 full suite: 1,121 tests passed with four expected skips.
- Focused Python 3.13 coverage: provider 462/462, Keychain 44/44, refresh lock 44/44, Linux runtime 155/155, common/state 127/127, and repository contracts 19/19.
- System Python 3.9 compiled the complete supported runtime successfully; Python 3.10 was not installed on the integration host.
- Ruff check, targeted Ruff format checks for the newly formatted explicit-auth and Keychain files, C launcher syntax, `git diff --check`, skill validation, and project-journal validation passed. The existing refresh-lock files and the protected Claude Linux changes carried from the concurrent review-hardening work retain their formatter drift and were not mechanically rewritten.
- Independent security/correctness reviews of the descriptor-bound Keychain and first-write redaction state machine returned no findings after the first two redaction blockers were fixed and retested. Pinned whole-range reviews then found that recursive redaction could rewrite fixed status keys, synchronous Security.framework calls had no hard deadline, a post-dispatch forwarded signal could bypass locked write-outcome reconciliation, Keychain cleanup could lose an unreaped-worker result behind `KeyboardInterrupt`, serialized-text redaction could corrupt valid JSON tokens, and provider-side lease reassertion could run before unreaped-worker lock retention. The status schema and JSON types are now preserved through value-only structural redaction; the Keychain path uses a UI-disabled supervised worker with timeout, reap, strict transport, and buffer-scrubbing; and every post-dispatch control-flow path now reaches one locked readback or signal-masked retained-lock terminal handling before the original interruption is restored.
