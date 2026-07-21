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
- The direct Claude lane uses a process-only bounded supervisor with a finite deadline, bounded streams, and process-group cleanup. Linux cleanup also reaps a direct child after its process group contains only zombies. Partial, over-limit, timed-out, or incompletely cleaned output is inconclusive.
- Worktree validation accepts safe system symlinks in path ancestors while still rejecting a symlink leaf, so canonical paths such as macOS `/tmp` do not become false safety failures.
- Claude process supervision is explicitly limited to the initial supervisor process group and inherited streams. It does not overclaim containment of descendants that deliberately escape with `setsid()` or `setpgid()` and close those streams.
- Claude output publication stays anchored to prevalidated parent-directory descriptors across process launch, rejects parent identity drift without treating content-derived directory metadata as identity, and rolls back through the retained descriptors.
- Tracked symlink targets are read in one aggregate 30-second Git batch with explicit entry, per-target, and total-output limits instead of one process deadline per symlink.
- Materialized gitlinks are rejected before the guard invokes `git status`, preventing a pre-existing gitfile from redirecting that query into external repository metadata.
- Effective local, per-worktree, and included Git configuration is checked before status. Tracked submodules follow Git's per-name active-boolean precedence and repeated `submodule.active` pathspec semantics, while only status-executable clean/process filters are rejected; unrelated invalid booleans, explicit per-name false, smudge-only filters, and required-only settings do not become false findings.
- Ambient `NODE_EXTRA_CA_CERTS` remains excluded by default. A value-free explicit opt-in validates the configured absolute non-symlink regular file without exposing its path in the guard argv; the direct lane deliberately does not claim the helper's copied/attested CA guarantees.
- Claude output publication uses a lane-unique current-user-owned mode-`0700` directory, temporary signal handlers, and an explicit commit point. A signal observed before commit rolls back the complete pair, while final and temporary cleanup preserve identity drift already observed before unlink. The contract explicitly excludes the non-portable stat-to-unlink race from non-cooperative same-UID writers instead of claiming an impossible conditional unlink.
- The guard does not prepare a diff, inspect ordinary file contents, broker authentication, replace the actual reviewer, or add another PR-readiness gate.

## Next Steps

- None after the canonical PR is squash-merged and the private overlay migration is regenerated from the merged source.

## Evidence

- Fresh-context review of `Joey-Tools/codex-private-workflows#128` found the three boundary gaps before merge.
- Forty-six focused named-lane guard tests passed. They cover hidden index bits, ignored artifacts, bytecode-free entrypoint launch, absent, empty, init-only, populated, external-gitdir, empty-`.gitmodules`, malformed-`.gitmodules`, effective worktree/include config, per-name active booleans, and global active pathspecs; a binary-safe aggregate symlink batch and its count limit; default-denied and explicitly opted-in Node CA configuration; private-parent and mode-drift checks; descriptor-anchored publication, signal-window and cleanup-failure rollback; the complete bounded-failure classification matrix including I/O thread-start failure; and the daemonized-descendant contract.
- The detached-boundary regression atomically publishes its child PID before a pipe handshake permits the child to detach; its `finally` path recovers that PID from the file after either normal return or an exception.
- Forty-three canonical-profile contract tests passed, covering current-request GitHub evidence correlation, the narrow guard boundary, and direct-Claude process limits; private-profile coverage runs again after source sync.
- The final loopback-enabled full review-policy suite passed all 1,111 tests with four skips in 259.020 seconds. During an earlier repair iteration, one unchanged concurrent-cleanup test hit a transient identity race; it passed five consecutive exact reruns and did not recur in any final full-suite run.
- Both modified skills passed the installed OpenAI quick validator. Python compilation, Ruff lint/format checks, project-journal validation, and `git diff --check` passed.
