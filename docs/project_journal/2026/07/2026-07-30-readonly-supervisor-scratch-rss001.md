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
- Run that nested suite through the existing bounded process-group supervisor,
  with explicit output caps, signal deferral, descendant settlement, and
  fail-closed retention when process closure cannot be proved.
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
- The child suite runs in a fresh process group with 8 MiB caps for stdout and
  stderr. Normal leader exit, output overflow, timeout, and SIGTERM settle the
  leader and same-group descendants before cleanup. Unproven process closure
  retains both exact trees and reports `closure-unproven`.
- CI runs the ordinary deterministic suite and the read-only installed
  regression in separate macOS Python 3.13 jobs. The read-only job has a
  20-minute emergency outer budget around the runner's 10-minute child timeout.
  CI success requires the terminal structured closure and cleanup proof; a host
  cancellation or missing terminal summary cannot count as a clean gate.
- Linux sandbox-command unit tests use a synthetic trusted runtime mount instead
  of assuming `/usr` ownership on a hosted image. A separate policy test still
  accepts a system path only when every resolved component is root-owned and
  not group- or world-writable.

## Next Steps

- None in this repository. The private overlay sync publishes the same runner,
  test support, and workflow gate.

## Evidence

- A fresh-context reviewer of the private overlay identified source-local
  scratch allocation as incompatible with read-only installed releases and
  untrusted `01777` ancestors.
- Focused no-child regressions passed 6/6.
- The ordinary deterministic suite passed 615/615 in 242.046 seconds with
  selected-identity SHA-256
  `eff105b9684821650adaa25232152b09088f32e51f8d00cb4709fa444fbf4389`.
- A fresh-context Codex reviewer found that the prior `subprocess.run` timeout
  path did not prove descendant closure before deleting the trees. The bounded
  replacement has live regressions for a lingering same-group descendant,
  output overflow, SIGTERM, and closure-unproven retention.
- GitHub Ubuntu image `20260726.254.1` exposed `/usr` as non-root-owned and
  correctly triggered the production trust policy. The host-independent
  fixture preserves that policy instead of weakening it.
- The first read-only run preserved the release tree and cleaned all runtime
  residue while exposing one fd-allocation-order assumption; the exact focused
  test passed after replacing that assumption with an explicit `dup2`.
- The final read-only run returned
  `{"child_process_closure":"proven","cleanup_failures":[],"cleanup_status":"complete","install_parent_is_sticky_world_writable":true,"primary_failure":null,"primary_status":"complete","release_tree_immutable":true,"release_tree_property":"object-identity-content-access-policy","retained_paths":[],"returncode":0,"runtime_residue":[],"signal_number":null,"timed_out":false}`.
- The complete playbook discovery ran 2,822 tests in 1111.726 seconds with
  2,815 passes, six platform skips, and one expected nested Seatbelt denial.
  That exact broker test passed 1/1 outside the parent sandbox in 2.681
  seconds.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
