---
id: 20260730-rss001
title: Read-Only Supervisor Scratch
status: completed
created: 2026-07-30
updated: 2026-07-31
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
- Bind every runtime-parent component through no-follow descriptors, reject
  unsafe ACL/xattr policy, and revalidate each newly created private directory.
- Reject group- or world-writable components anywhere in an explicit
  owner-private runtime-parent chain, including sticky ancestors, while keeping
  the sticky `/private/tmp` exception scoped to the read-only install container.
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
  and all deterministic supervisor tests. Every regular file must retain exactly
  one link; timestamps, directory link-count and size, and completed child-entry
  churn are outside the declared protected property and do not create false
  mutation findings.
- Runtime-parent selection and child creation use the existing secure-I/O
  descriptor chain. The held parent and its path must retain object identity,
  owner/mode, flags, ACL, and xattr policy. Initial open, path reopen, and child
  path reopen walk the complete owner-private chain and reject every group- or
  world-writable ancestor, including sticky directories; every new `0700` child
  is opened no-follow and compared with a fresh path-bound descriptor before
  use. The install container remains a separate explicit sticky-parent case.
- Cleanup completes before success output. Every ordinary primary exception is
  reported in the structured summary; a concurrent cleanup error returns
  nonzero, preserves the primary failure and child return code, and reports the
  exact retained path as secondary evidence.
- The child suite runs in a fresh process group with 8 MiB caps for stdout and
  stderr. Normal leader exit, output overflow, timeout, and SIGTERM settle the
  leader and same-group descendants before cleanup. Unproven process closure
  retains both exact trees and reports `closure-unproven`.
- Signal-guard teardown cannot replace an already raised
  `GitProcessClosureUnproven`. Deactivation and handler-restoration failures are
  retained as ordered secondary diagnostics, while cleanup is authorized only
  by an explicit process-closure proof; a still-pending or unproven child keeps
  both the installed and runtime trees.
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
- The ordinary deterministic suite passed 619/619 in 278.468 seconds with
  selected-identity SHA-256
  `346a50ba8b68780fb7afee2e71c9c2caa9f1805d6bb7d4da96ed71cbc1401787`.
- A replacement-head Fresh Codex review found that the prior runtime-parent
  selector ignored macOS ACL inheritance and that the read-only tree snapshot
  did not reject a regular file with an external hardlink alias. New regressions
  cover an ACL-bearing ancestor, an ACL attached between child creation and
  validation, and a tree-external hardlink while retaining benign directory
  link-count churn.
- A fresh-context Codex reviewer found that the prior `subprocess.run` timeout
  path did not prove descendant closure before deleting the trees. The bounded
  replacement has live regressions for a lingering same-group descendant,
  output overflow, SIGTERM, and closure-unproven retention.
- A later fresh-context Codex reviewer found that signal teardown in
  `_bound_child_signals()` could overwrite `GitProcessClosureUnproven`, causing
  the pending fallback to claim closure and delete both recovery trees. The
  focused runner suite now passes 14/14, including compound closure plus
  deactivation/restoration failures and a pre-supervision proof-negative case.
- GitHub Codex review on head `705fefb7d4df3bb687f911a59f101fbdeeade6b6`
  found that an explicit
  `CODEX_REVIEW_TEST_RUNTIME_PARENT` could be an owner-private leaf below a
  sticky world-writable ancestor, unintentionally inheriting the
  `/private/tmp` install-container exception. The strict runtime-parent opener
  now performs a complete descriptor walk on initial validation and every path
  revalidation. Focused secure-I/O and read-only-runner regressions pass 46/46,
  including safe-chain acceptance, sticky-ancestor rejection, and rejection
  after ancestor access-policy drift.
- The updated ordinary deterministic gate passes 621/621 with selected-identity
  SHA-256
  `0203bf84f76bfe4fcb49362ac3137474753af30c4aea0a0a31c47774a6929f4d`.
  The real read-only installed runner also completed with explicit proven child
  closure, complete cleanup, an immutable release tree, no retained paths, no
  runtime residue, and no secondary failure. All 102 repository contract tests
  passed, and an independent state-machine audit returned `No findings.`.
  Ruff lint/format, source compilation, actionlint, skill validation, project
  journal validation, and `git diff --check` passed on the final files.
- GitHub Ubuntu image `20260726.254.1` exposed `/usr` as non-root-owned and
  correctly triggered the production trust policy. The host-independent
  fixture preserves that policy instead of weakening it.
- The first read-only run preserved the release tree and cleaned all runtime
  residue while exposing one fd-allocation-order assumption; the exact focused
  test passed after replacing that assumption with an explicit `dup2`.
- The final read-only run returned
  `{"child_process_closure":"proven","cleanup_failures":[],"cleanup_status":"complete","install_parent_is_sticky_world_writable":true,"primary_failure":null,"primary_status":"complete","release_tree_immutable":true,"release_tree_property":"object-identity-content-access-policy","retained_paths":[],"returncode":0,"runtime_residue":[],"signal_number":null,"timed_out":false}`.
- The complete playbook discovery ran 2,822 tests in 1171.121 seconds with
  2,815 passes, six platform skips, and one expected nested Seatbelt denial.
  That exact broker test passed 1/1 outside the parent sandbox in 2.601
  seconds.
- The sticky-ancestor fix reran the same 2,822-test discovery in 1238.657
  seconds with 2,815 passes, six platform skips, and only the expected nested
  Seatbelt denial. The exact broker regression passed 1/1 outside the parent
  sandbox in 2.314 seconds, and the production-equivalent live no-child suite
  passed 9/9 in 7.585 seconds.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
