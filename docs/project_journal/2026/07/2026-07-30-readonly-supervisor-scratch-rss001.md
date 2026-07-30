---
id: 20260730-rss001
title: Read-Only Supervisor Scratch
status: completed
created: 2026-07-30
updated: 2026-07-30
branch: wip/broker-codesign-pin-refresh
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/85
supersedes: []
superseded_by:
---

# Read-Only Supervisor Scratch

## Summary

- Move every no-child-profile test scratch directory out of the source or
  installed release tree and into the validated owner-private test runtime.
- Add a fail-closed explicit runtime-parent binding for isolated test runners.
- Exercise the complete deterministic supervisor suite from a read-only copy
  below `/private/tmp`, while keeping scratch under an independently validated
  owner-private root.
- Make the descriptor-reuse injection explicitly duplicate onto the protected
  descriptor number instead of relying on incidental kernel allocation order.

## Current State

- The deterministic suite contains no source-tree `TemporaryDirectory`
  allocation in the no-child tests or hosted fail-closed probe.
- The read-only runner verifies the sticky/world-writable source ancestor,
  immutable installed tree, empty runtime residue, and all 605 deterministic
  supervisor tests.
- CI runs both the ordinary deterministic suite and the read-only installed
  regression on macOS with Python 3.13.

## Next Steps

- None in this repository. The private overlay sync publishes the same runner,
  test support, and workflow gate.

## Evidence

- A fresh-context reviewer of the private overlay identified source-local
  scratch allocation as incompatible with read-only installed releases and
  untrusted `01777` ancestors.
- Focused no-child regressions passed 6/6.
- The ordinary deterministic suite passed 605/605 in 219.242 seconds.
- The first read-only run preserved the release tree and cleaned all runtime
  residue while exposing one fd-allocation-order assumption; the exact focused
  test passed after replacing that assumption with an explicit `dup2`.
- The final read-only run returned
  `{"install_parent_is_sticky_world_writable":true,"release_tree_immutable":true,"returncode":0,"runtime_residue":[]}`.
- The complete playbook discovery ran 2,822 tests with 2,821 passes and six
  platform skips inside Codex; its only failure was the expected nested
  Seatbelt denial. That exact broker test passed 1/1 outside the parent sandbox.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
