---
id: 20261007-fg1911
title: Fast Git Exit Session Binding
status: completed
created: 2026-10-07
updated: 2026-10-07
branch: codex/daily-skill-friction-2026-10-07-codex-review-workflows-preserve-private-191-fast-git-exit-repair
pr:
supersedes: []
superseded_by:
---

# Fast Git Exit Session Binding

## Summary
- Port the already landed private #191 fast-exit behavior into the canonical review supervisor so source regeneration retains the same process and output guarantees.

## Current State
- `run_bounded` treats a session-binding `ProcessLookupError` as a completed command only after `terminal_status` confirms the direct child is terminal without reaping it. A live or unprovable lookup failure remains fatal.
- Process identity is protected by the unreaped direct child: its PID and fresh-session process group are used for cleanup only while that child proves the numeric identity has not been reused. Cleanup verifies that no other group member remains before reaping the leader.
- The fast-exit path reads stdout and stderr only after group cleanup and leader reap. It drains both pipes nonblocking to EOF under a deadline and enforces each stream's existing byte cap; overflow or incomplete closure remains an error.
- The regression tests cover nonzero terminal output on both streams, per-stream overflow, and fatal live lookup failure with child cleanup.

## Next Steps
- Carry these canonical source, test, inventory-guard, trusted-source-manifest, and journal changes through the planned source promotion. Re-run the full deterministic suite with process permissions that allow the phase-helper cases before claiming the suite passes.

## Evidence
- Private fix landed in `codex-private-workflows` as `397ac8b90fa558a859e309e3d74878314dda6688` (#191).
- Canonical candidate starts at `7a8ed7562f006c10a32806d4416db1e83186fb88`.
- `tests.test_runtime_process.BoundedGitProcessTests`: 3 tests passed in 1.632 seconds; the output-limit test covers stdout and stderr separately.
- Full `tests.test_runtime_process` module: 15 tests passed in 3.605 seconds, no skips. Execution had a 180-second deadline and a 65,536-byte retained-output ceiling.
- Project-journal validation and `git diff --check` passed. No local code-review lane was started; current-head PR Codex review and CI remain the delivery gates recorded in the PR rather than this completed implementation record.
- Inventory guard audit against base `1ec1e86`: the base has 861 discovered identities and 848 selected identities after the unchanged 13 required exclusions; this candidate has 864 discovered and 851 selected. The complete identity delta is exactly the three new `test_runtime_process.py` regressions, with no removed or newly skipped identities. The base selected-set digest remains `6c7be4c1f1fe9a69c5e0af931f9f9c404bd5a7d8c9b7c0b856d5085616a02f18`; the updated selected-set digest is `02495486bd9e6d0cd7a3f1e82ecc0825b72570024036fe27edd07430f0324caf`.
- Updated `EXPECTED_TEST_COUNT` to 851 and its identity digest from that audit. Regenerated `trusted_mac_gate_sources.index` with `python3 skills/review-orchestration-playbook/tests/test_trusted_mac_gate_manifest.py --regenerate`; the manifest contract test passed all 4 tests. Only the bindings for `gitraw.py`, `run_required_deterministic_supervisor.py`, and `test_runtime_process.py` changed.
- Re-ran the complete `tests.test_runtime_process` module on this candidate: 15 passed, no skips (13.645 seconds; retained log `/private/tmp/codex-fast-git-runtime-pr130.Iw0M1c/test_runtime_process.log`).
- Bounded deterministic runner executed all 851 selected tests in 339.328 seconds, with no skips, but exited 1: one failure and one error both report `PermissionError: [Errno 1] Operation not permitted` from phase-helper operations (`CliLifecycleTests.test_final_revalidates_the_sealed_artifact` and `FinalAuthorizationTests.test_publish_binds_the_direct_predecessor_and_exact_allocation`). This sandbox run is not a pass; retained log `/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/policy-pr-20261005/resume-20261007/canonical130-deterministic-runner-851.txt` (154,062 bytes, SHA-256 `84ca87cfe4fa958b44b3401416df245f3fd3a9e8cbe2026ee8eec4c7a133115c`).
- Native non-sandbox Python 3.13.0 re-ran those exact two cases and reproduced both failures (11.685 seconds). An independently clean baseline checkout at `7a8ed7562f006c10a32806d4416db1e83186fb88`, whose runtime matches the subsequent CI-inventory-only base update, reproduced the same two failures under the same native interpreter (10.400 seconds) and remained clean. This is baseline-local permission behavior, not evidence of a passing local full runner. Keep the actual failed records; do not change exclusions, weaken phase-helper checks, or expand this repair into legacy-helper diagnostics. The unchanged required hosted runner must execute all 851 selected tests without failures or skips before landing.
