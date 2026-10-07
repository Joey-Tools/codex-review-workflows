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
- Carry these canonical source, test, and journal changes through the planned source promotion, then confirm regeneration preserves the same behavior.

## Evidence
- Private fix landed in `codex-private-workflows` as `397ac8b90fa558a859e309e3d74878314dda6688` (#191).
- Canonical candidate starts at `7a8ed7562f006c10a32806d4416db1e83186fb88`.
- `tests.test_runtime_process.BoundedGitProcessTests`: 3 tests passed in 1.632 seconds; the output-limit test covers stdout and stderr separately.
- Full `tests.test_runtime_process` module: 15 tests passed in 3.605 seconds, no skips. Execution had a 180-second deadline and a 65,536-byte retained-output ceiling.
- Project-journal validation and `git diff --check` passed. No local code-review lane was started; current-head PR Codex review and CI remain the delivery gates recorded in the PR rather than this completed implementation record.
