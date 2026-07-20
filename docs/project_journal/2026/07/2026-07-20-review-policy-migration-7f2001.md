---
id: 20260720-7f2001
title: Review Policy Migration
status: completed
created: 2026-07-20
updated: 2026-07-21
branch: codex/review-policy-migration
pr:
supersedes:
  - 20260717-c17a11
  - 20260719-7f1901
superseded_by:
---

# Review Policy Migration

## Summary

- The review policy migration removes the former extra Codex PR-review and frozen-diff gates from PR readiness.
- Single, double, and triple review now share one progressive lane model instead of combining unrelated mandatory gates.
- The canonical Claude lane now records the accepted real-`HOME` selected-deny trust boundary without overstating native host-read isolation.

## Current State

- Single review is a fresh or otherwise clear-context Codex review in a clean Git workspace, with no prepared diff supplied to the reviewer.
- Double review adds an actual Claude Code review in a separate read-only workspace.
- Triple review adds exact `@codex review` on a supported GitHub Cloud PR plus a trustworthy terminal GitHub Codex result bound to the current PR head; the request comment does not complete the lane by itself.
- Directly known no-PR/unsupported-host/unsupported-identity evidence or an authenticated provider no-start rejection can make a requested triple an effective double. Missing response or generic failure is inconclusive; untrustworthy evidence after service start is triple-inconclusive instead of fallback.
- Former mandatory extra local PR-review gates are retired and no longer define the policy; their historical helper implementations do not satisfy a named lane.
- Named single review uses a dedicated fresh-context Codex reviewer in a clean Git worktree. Named double adds a directly launched actual Claude Code process in a second clean worktree. Neither lane receives a prepared diff.
- The low-level supplied-diff helper is explicitly ineligible for named-lane counting. Its stateful surface records `review_contract: supplied-diff-no-git` and `named_lane_eligible: false`; raw foreground or `stateful final` output is never a named-lane envelope.
- Claude launch requests global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary. Outside-workspace read exclusion remains a prompt/model rule because selected `allowRead` is not a global host-read whitelist and sandboxed Bash can technically read an un-denied host path.
- Claude Code 2.1.212 init/capability output is not evidence of the final merged sandbox, managed permission arrays, runtime path evaluation, or effective enforcement of the requested controls.
- A bare named-review request is report-only. Bare triple may request GitHub Codex only on an already-existing supported PR; branch creation, push, PR creation, and PR branch/metadata changes require separate authorization.
- Named local lanes deliberately use executable clean-worktree and behavioral read-only contracts. They do not require an unimplemented raw-object materializer, endpoint-only object store, immutable instruction snapshot system, or unique Git wrapper.

## Evidence

- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/canonical-claude-lane.md`
- `skills/review-orchestration-playbook/references/pr-readiness.md`
- `skills/review-orchestration-playbook/tests/test_contracts.py`
- Fresh-context semantic checks independently reconstructed the single, double, and triple contracts without a competing active definition.
- Skill validation passed for `review-orchestration-playbook` and `change-delivery-workflow`; project-journal validation passed.
- A late fixed-range review correctly found that an intermediate hardening draft made the default review gate depend on an unimplemented raw-object/sanitized-Git runtime. The final migration removed that overreach and returned the named lanes to clean worktrees, behavioral read-only enforcement, normal instruction loading, and reviewer-derived diffs.
