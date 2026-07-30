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
  object identity, content or link targets, owner/group/mode, file flags,
  ACLs, and xattr values across the installed tree, plus empty runtime residue
  and all deterministic supervisor tests. Timestamp, link-count, directory-size,
  and completed child-entry churn are outside the declared protected property
  and do not create false mutation findings.
- Cleanup completes before success output. Every ordinary primary exception is
  reported in the structured summary; a concurrent cleanup error returns
  nonzero, preserves the primary failure and child return code, and reports the
  exact retained path as secondary evidence.
- CI runs the ordinary deterministic suite and the read-only installed
  regression in separate macOS Python 3.13 jobs. The read-only job has a
  20-minute outer budget around the runner's 10-minute child timeout so GitHub
  cannot normally preempt its structured cleanup path.

## Next Steps

- None in this repository. The private overlay sync publishes the same runner,
  test support, and workflow gate.

## Evidence

- A fresh-context reviewer of the private overlay identified source-local
  scratch allocation as incompatible with read-only installed releases and
  untrusted `01777` ancestors.
- Focused no-child regressions passed 6/6.
- The ordinary deterministic suite passed 611/611 in 261.917 seconds with
  selected-identity SHA-256
  `2154c3cd7c983d56a5d7a8f8d8e6478f207bbd04fe489b0fbd4f4bda533bf541`.
- The first read-only run preserved the release tree and cleaned all runtime
  residue while exposing one fd-allocation-order assumption; the exact focused
  test passed after replacing that assumption with an explicit `dup2`.
- The final read-only run returned
  `{"cleanup_failures":[],"cleanup_status":"complete","install_parent_is_sticky_world_writable":true,"primary_failure":null,"primary_status":"complete","release_tree_immutable":true,"release_tree_property":"object-identity-content-access-policy","retained_paths":[],"returncode":0,"runtime_residue":[],"timed_out":false}`.
- The complete playbook discovery ran 2,822 tests in 1051.356 seconds with
  2,815 passes, six platform skips, and one expected nested Seatbelt denial.
  That exact broker test passed 1/1 outside the parent sandbox in 3.056
  seconds.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
