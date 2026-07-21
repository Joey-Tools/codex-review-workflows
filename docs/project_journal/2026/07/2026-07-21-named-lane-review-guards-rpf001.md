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

- Close the final named-lane safety and evidence-correlation gaps without restoring retired prepared-diff or hidden review gates.

## Current State

- Both local lanes run a parent-owned tracked-symlink containment check before reviewer launch. Stable in-worktree source links remain allowed, while escaping or unstable links and symlinked guidance are rejected.
- GitHub Codex completion evidence may bind to the exact request/run or current head, while a no-start rejection must bind to the exact request/dispatch or satisfy the sole-unresolved fallback. A full SHA does not select between multiple unresolved requests on the same head, and timestamp proximity alone cannot complete or downgrade triple review.
- The direct Claude lane uses a process-only bounded supervisor with a finite deadline, bounded streams, and process-group cleanup. Linux cleanup also reaps a direct child after its process group contains only zombies. Partial, over-limit, timed-out, or incompletely cleaned output is inconclusive.
- The same absolute monotonic deadline now begins before the CLI reads the control prompt through EOF and can only tighten the duration bound. A writer that sends a short prompt but withholds EOF becomes an inconclusive deadline result without launching the reviewer, while termination signals during that wait become structured `inconclusive` / `forwarded-signal` evidence.
- Worktree validation accepts safe system symlinks in path ancestors while still rejecting a symlink leaf, so canonical paths such as macOS `/tmp` do not become false safety failures.
- Claude process supervision is explicitly limited to the initial supervisor process group and inherited streams. It does not overclaim containment of descendants that deliberately escape with `setsid()` or `setpgid()` and close those streams.
- Claude output publication stays anchored to prevalidated parent-directory descriptors across process launch, rejects parent identity drift without treating content-derived directory metadata as identity, and rolls back through the retained descriptors.
- Tracked symlink targets are read in one aggregate 30-second Git batch with explicit entry, per-target, and total-output limits instead of one process deadline per symlink.
- Materialized gitlinks are rejected before the guard invokes `git status`, preventing a pre-existing gitfile from redirecting that query into external repository metadata.
- Repository-visible `include.path` and `includeIf.*.path` keys are blocked before status or reviewer execution, including inactive conditions and benign or malformed targets. Included values are not accepted as safety configuration; initial bounded repository-identity probes may still parse the target and fail closed, so the guard does not claim a no-read boundary. Other safety-relevant configuration is evaluated only from direct local/per-worktree values with includes disabled. Raw gitlinks without `.gitmodules` or name/path mappings still participate in repeated global `submodule.active` pathspec matching, alongside direct path mapping, per-name active-boolean precedence, and URL registration evidence. Status is forced to honor executable-bit drift even when `core.fileMode=false`. Every direct Git alias and direct executable clean/process filter plus `diff.external`, driver command, and textconv settings are rejected, while unrelated invalid booleans, explicit per-name false, smudge-only filters, required-only settings, and non-command diff metadata do not become false findings. Any parent- or reviewer-owned diff rendering must disable both external diff and textconv.
- Direct `core.fsmonitor` is validated before any status or reviewer Git command. Unset and Git-false values are allowed; built-in daemon, no-value, and path hook values are rejected without execution. Direct local/per-worktree precedence remains supported, so a worktree `false` can safely override a local path.
- Self-policy migration now keeps candidate-head Markdown available as review subject and scoped guidance while pinning the reviewer profile, prompt, guard, launcher, and transitive in-repo runtime dependency to an independently trusted external bundle. Its absolute source and publisher release/frozen-commit version accompany a deterministic control-file manifest digest verified before each launch/spawn and after each lane. Candidate-head scripts cannot bootstrap their own formal review; an incompatible new guard activates only after the prior trusted policy reviews, merges, and releases it.
- The Codex reviewer receives one exact sanitized Git argv prefix and cannot use bare Git, alternate wrappers, extra environment state, changed safe flags, or another worktree. Every diff-producing invocation explicitly disables external diff and textconv.
- The canonical direct Claude lane is local-login-only in trusted real `HOME`. It has no API-key or OAuth-token interface, reports forbidden refresh or non-local-only credentials as `blocked-authentication`, rejects npm/NVM shebang shims under canonical provenance, and does not expand trusted `PATH` to accommodate them.
- Test-oriented `run-claude` CLI overrides can equal or tighten, but never raise, the 1,800-second timeout, 64 MiB per-stream, and 256 KiB prompt production caps. Direct Python API callers are bound by the same ceilings.
- Ambient `NODE_EXTRA_CA_CERTS` remains excluded by default. A value-free explicit opt-in validates the configured absolute non-symlink regular file without exposing its path in the guard argv; the direct lane deliberately does not claim the helper's copied/attested CA guarantees.
- Claude output publication uses a lane-unique current-user-owned mode-`0700` directory, temporary signal handlers, and an explicit commit point. A signal observed before commit rolls back the complete pair, while final and temporary cleanup preserve identity drift already observed before unlink. The contract explicitly excludes the non-portable stat-to-unlink race from non-cooperative same-UID writers instead of claiming an impossible conditional unlink.
- The guard does not prepare a diff, inspect ordinary file contents, broker authentication, replace the actual reviewer, or add another PR-readiness gate.

## Next Steps

- None after the canonical PR is squash-merged and the private overlay migration is regenerated from the merged source.

## Evidence

- Fresh-context review of `Joey-Tools/codex-private-workflows#128` found the three boundary gaps before merge.
- The final independent formal review identified four remaining control-boundary gaps: self-policy bootstrap trusted candidate code, repo-visible Git includes, unsanitized reviewer Git, and non-local direct-Claude credential interfaces. A supplemental frozen-diff review then found a fifth: repo-visible Git aliases could still execute commands through the allowed Git prefix. The policy and contract updates close all five without turning candidate-head scripts into trusted review control.
- All sixty-six focused named-lane guard tests passed after the final review repairs. They cover hidden index bits, ignored artifacts, file-mode drift hidden by local config, bytecode-free entrypoint launch, absent, empty, init-only, populated, external-gitdir, raw-gitlink, empty-`.gitmodules`, malformed-`.gitmodules`, blocked local/worktree/inactive-conditional include directives, fail-closed malformed include targets, direct local/per-worktree Git aliases, direct per-name active booleans, and global active pathspecs even without raw-gitlink name/path mappings; direct `core.fsmonitor` false/active/no-value/path-hook and local/worktree-precedence boundaries; executable and non-command diff config boundaries; a binary-safe aggregate symlink batch and its count limit; default-denied and explicitly opted-in Node CA configuration; a prompt writer that withholds EOF, structured prompt-stage forwarded signals, shared remaining-budget propagation, an absolute deadline that cannot extend the duration limit, and CLI/Python resource-cap enforcement; private-parent and mode-drift checks; descriptor-anchored publication, signal-window and cleanup-failure rollback; the complete bounded-failure classification matrix including I/O thread-start failure; and the daemonized-descendant contract.
- The detached-boundary regression atomically publishes its child PID before a pipe handshake permits the child to detach; its `finally` path recovers that PID from the file after either normal return or an exception.
- Fifty-four canonical-profile contract tests passed after the final policy anchors were added, and forty-one common-runtime tests passed after merging the latest target branch. They cover current-request GitHub evidence correlation, the narrow guard boundary, effective `core.fsmonitor`, immutable production resource ceilings, direct-Claude process limits, current-head admission, and descriptor-based logging; private-profile coverage runs again after source sync.
- The final loopback-enabled full review-policy suite passed all 1,447 tests with five skips in 414.276 seconds after the supplemental alias repair. The preceding formal-review run passed all 1,446 tests with five skips in 407.983 seconds, and earlier repair runs passed all 1,437 and 1,431 then-current tests with five skips. A pre-merge sandboxed run reached its then-current 1,121-test inventory but could not bind three loopback fixtures; the identical pre-merge command passed outside that loopback restriction before the newer target-branch tests were integrated. During an earlier repair iteration, one unchanged concurrent-cleanup test hit a transient identity race; it passed five consecutive exact reruns and did not recur in any completed full-suite run.
- Both modified skills passed the installed OpenAI quick validator. Python compilation, Ruff lint/format checks, project-journal validation, and `git diff --check` passed.
