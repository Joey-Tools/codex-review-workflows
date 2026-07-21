---
id: 20260721-rpf001
title: Named Lane Review Guards
status: completed
created: 2026-07-21
updated: 2026-07-21
branch: codex/daily-skill-friction-20260721-codex-review-workflows-review-policy-final-review-fixes
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/72
supersedes: []
superseded_by:
---

# Named Lane Review Guards

## Summary

- Close three final-review gaps in the canonical named-lane policy without restoring retired prepared-diff or hidden review gates.

## Current State

- Both local lanes run a parent-owned tracked-symlink containment check before reviewer launch. Stable in-worktree source links remain allowed, while escaping or unstable links and symlinked guidance are rejected.
- GitHub Codex issue-comment evidence must bind to the exact request or head, or be unambiguous across every still-unresolved request; timestamp proximity alone cannot complete triple review.
- The direct Claude lane uses a process-only bounded supervisor with a finite deadline, bounded streams, and process-group cleanup. Partial, over-limit, timed-out, or incompletely cleaned output is inconclusive.
- Worktree validation accepts safe system symlinks in path ancestors while still rejecting a symlink leaf, so canonical paths such as macOS `/tmp` do not become false safety failures.
- Claude process supervision is explicitly limited to the initial supervisor process group and inherited streams. It does not overclaim containment of descendants that deliberately escape with `setsid()` or `setpgid()` and close those streams.
- Claude output publication stays anchored to prevalidated parent-directory descriptors across process launch, rejects parent identity drift without treating content-derived directory metadata as identity, and rolls back through the retained descriptors.
- Ambient `NODE_EXTRA_CA_CERTS` remains excluded by default. A value-free explicit opt-in validates the configured absolute non-symlink regular file without exposing its path in the guard argv; the direct lane deliberately does not claim the helper's copied/attested CA guarantees.
- The guard does not prepare a diff, inspect ordinary file contents, broker authentication, replace the actual reviewer, or add another PR-readiness gate.

## Next Steps

- None after the canonical PR is squash-merged and the private overlay migration is regenerated from the merged source.

## Evidence

- Fresh-context review of `Joey-Tools/codex-private-workflows#128` found the three boundary gaps before merge.
- Twenty-nine focused named-lane guard tests passed. They cover hidden index bits, ignored artifacts, bytecode-free entrypoint launch, absent, empty, init-only, populated, empty-`.gitmodules`, and malformed-`.gitmodules` gitlink boundaries, default-denied and explicitly opted-in Node CA configuration, descriptor-anchored output publication under parent replacement, the complete bounded-failure classification matrix including I/O thread-start failure, and the daemonized-descendant contract.
- The detached-boundary regression atomically publishes its child PID before a pipe handshake permits the child to detach; its `finally` path recovers that PID from the file after either normal return or an exception.
- Forty-three canonical-profile contract tests passed, covering current-request GitHub evidence correlation, the narrow guard boundary, and direct-Claude process limits; private-profile coverage runs again after source sync.
- The final loopback-enabled full review-policy suite passed all 1,093 tests with four skips. During an earlier repair iteration, one unchanged concurrent-cleanup test hit a transient identity race; it passed five consecutive exact reruns and did not recur in either final full-suite run.
- Both modified skills passed the installed OpenAI quick validator. Python compilation, Ruff lint/format checks, project-journal validation, and `git diff --check` passed.
