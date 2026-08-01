---
id: 20260730-rss001
title: Read-Only Supervisor Scratch
status: completed
created: 2026-07-30
updated: 2026-08-01
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
  world-writable ancestor, including sticky directories. A newly created child
  is normalized to `0700` through the held parent descriptor with no symlink
  following, then must retain device, inode, type, generation, owner, group, and
  flags across that expected mode transition. The child is opened no-follow and
  compared with a fresh path-bound descriptor before use, independent of the
  process umask. The install container remains a separate explicit sticky-parent
  case.
- The read-only runner keeps parent and child descriptors plus an identity and
  policy receipt for the exact runtime directory before the child starts.
  Residue is enumerated from that descriptor between full path revalidations;
  cleanup is attempted only after proven child-process closure and only while
  the receipt still maps to the held object. Persistent replacement is a primary
  failure plus an explicit cleanup gap, while completed child-entry churn
  remains benign. The machine-visible contract explicitly records the macOS
  same-UID host-TCB boundary for the non-atomic mkdir-to-first-open and final
  path-unlink windows.
- Cleanup completes before success output. Every ordinary primary exception is
  reported in the structured summary; a concurrent cleanup error returns
  nonzero, preserves the primary failure and child return code, and reports a
  descriptor-verified retained path or descriptor-object locator as secondary
  evidence. Terminal JSON bytes and the process exit consume one sealed signal
  decision; late lifecycle signals remain blocked through actual process exit,
  and an optional newline failure cannot contradict an already complete JSON
  record.
- The child suite runs in a fresh process group with 8 MiB caps for stdout and
  stderr. Normal leader exit, output overflow, timeout, and SIGTERM settle the
  leader and same-group descendants before cleanup. Unproven process closure
  retains both exact trees and reports `closure-unproven`.
- Signal-guard teardown cannot replace an already raised
  `GitProcessClosureUnproven`. Deactivation and handler-restoration failures are
  retained as ordered secondary diagnostics, while cleanup is authorized only
  by an explicit process-closure proof; a still-pending or unproven child keeps
  both the installed and runtime trees.
- Hosted CI runs the ordinary deterministic suite and the reviewed
  blocker-signature probe. It does not run the positive read-only installed
  regression because separate rolling `macos-26` jobs can receive different
  images and the hosted outer Seatbelt is not production-equivalent.
- The positive read-only installed regression runs immediately after the live
  isolation suite as one operator-enforced Trusted Mac exact-head gate. Success
  requires the documented complete structured predicate, including proven
  closure, complete cleanup, immutable release content and access policy, the
  `production-current` runtime profile, zero child return code, and no retained
  paths, runtime residue, or secondary failures.
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
- GitHub Codex review `4821503396` on head
  `d66244b550f06f69395c04878d45d0d2ed6fb721` found two remaining installed-test
  gaps: restrictive umasks could remove owner permissions before child
  validation, and lexical residue/cleanup checks could observe an empty
  replacement instead of the child-exposed runtime object. Descriptor-relative
  no-follow mode normalization and a command-lifetime runtime-directory binding
  close both gaps. Five new regressions cover umasks `0177` and `0777`, benign
  child churn, residue-path replacement, cleanup-path replacement, and the
  complete runner failure result.
- The focused secure-I/O and read-only-runner suite passed 51/51 in 3.515
  seconds. The reviewed deterministic selection passed 626/626 in 243.743
  seconds with identity SHA-256
  `135686bbf5d166fe7a050c739ea88a4d6080cd2019298762650e3372fee9fe76`.
  The real read-only installed runner then proved child closure, immutable
  release-tree identity/content/access policy, complete cleanup, no retained
  paths, no runtime residue, and no secondary failures.
- The complete playbook discovery ran 2,822 tests in 1310.748 seconds with six
  platform skips. Its only failure was the expected parent-sandbox denial of
  nested `sandbox-exec`; that exact broker regression passed 1/1 outside the
  parent sandbox in 2.363 seconds, and the production-equivalent live no-child
  suite passed 9/9 in 9.351 seconds. All 102 repository contract tests passed
  in 7.999 seconds. Ruff lint and changed-file formatting, source-only
  compilation of 107 Python/entrypoint files, actionlint, Bash syntax,
  ShellCheck, skill validation, project-journal validation, zero-bytecode
  inventory, and `git diff --check` passed.
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
- A final Fresh Codex review identified four distinct retained-state risks:
  the read-only job did not select the legacy hosted runtime pin, signals during
  profile preparation could be recorded without stopping launch, settled
  timeout/output/signal exceptions discarded their no-child closure evidence,
  and path revalidation failures reported the stale lexical name instead of the
  held directory object. The repair keeps these protected properties separate:
  exact hosted runtime compatibility, launch cancellation, authenticated
  process settlement, and retained-object identity.
- The runner now enters its child-signal guard before runtime selection and
  profile preparation, records whether launch was attempted, and checks the
  lifecycle fence again immediately before launch. A prelaunch interruption is
  therefore `not-started` and permits ordinary cleanup; an attempted launch must
  still prove authenticated leader settlement.
- `run_bounded_command()` attaches its authenticated no-child settlement to
  timeout, output-limit, and signal exceptions after terminating and reaping the
  leader. The installed runner accepts only the typed evidence with a reaped
  leader, proven permitted closure, and no process-group-emptiness substitute.
- The authenticated sandbox now applies a global `file-write*` denial to the
  installed-test process and grants one exception only for the independently
  FD-attested runtime root. Parent and child revalidation bind that root's
  object identity and exact owner-private access policy through launch. The
  installed tree and its container remain outside the writable authority.
- Signal deferral now spans leader reap, closure-evidence publication,
  descriptor cleanup, and caller proof publication. A pending signal is
  delivered only after the caller records a proven closure; an unproven launch
  keeps its original retention failure primary.
- Retained cleanup locations now come from a descriptor path reopened through
  the applicable ancestor policy and compared to the held object identity.
  When no path can be verified, the report uses a `descriptor-object://`
  locator; it never attributes retained custody to a stale or replacement
  lexical path.
- Focused runner and closure regressions passed 35/35. The full
  `test_codex_executable` module passed 87 tests with two intentional live skips,
  and the deterministic suite passed 638/638 in 298.666 seconds with
  selected-identity SHA-256
  `7785fd61ddd001a6423783efbf28defa1d050956d51a357e1074845cd365c1f8`.
- The reviewed read-only selection now contains 274/274 no-child-safe tests with
  identity SHA-256
  `8a7732243d8f3eeedda6fd14aab612913407b608b168dffcf18b226e0fca1ede`.
  Its real installed run returned proven closure, complete cleanup, immutable
  release-tree identity/content/access policy, no retained paths, no runtime
  residue, and runtime profile `production-current`. Repository contracts passed
  102/102 in 12.947 seconds, the live no-child/Seatbelt gate passed 9/9 in
  11.567 seconds, and the complete Python 3.13 platform discovery passed 2,822
  tests with six skips in 1308.684 seconds.
- A subsequent Fresh Codex review found two final gaps: mode-only read-only
  installation could be undone by the same-UID child, and signals could arrive
  after reap or after bounded-command return but before closure proof was
  published. The repair adds live kernel-policy probes for root/file chmod,
  file write-open, install-parent creation, and runtime-root creation, plus
  deterministic post-reap and caller-proof signal regressions.
- The final ordinary deterministic gate passed 642/642 in 246.962 seconds with
  selected-identity SHA-256
  `4688e2cdafda8f42c650a75ddfddd9f8b64c1b07afcdb00c46bc98444615f455`.
  The no-child-safe selection passed 275/275 with identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`.
  The real read-only installed gate returned proven child closure, complete
  cleanup, immutable release-tree identity/content/access policy, no retained
  paths, no runtime residue, and runtime profile `production-current`.
- Final Python 3.13 validation passed the focused no-child profile 58/58,
  read-only runner 33/33, and Codex executable 90/90 modules, with the two
  expected live skips in the last module. Repository contracts passed 102/102
  in 9.471 seconds, and the production-equivalent live no-child/Seatbelt gate
  passed 9/9 in 7.633 seconds with zero skips.
- The first package-aware 651-test discovery exposed one pre-existing test
  publication race: the parent observed an evidence file after creation but
  before the child had written its six fields. The exact live process-group
  test then passed three consecutive same-condition retries, and the complete
  package discovery reran clean with 651 tests and two expected skips in
  264.201 seconds. No production file involved in that race is changed here.
- Ruff lint/format, actionlint for canonical and private CI profiles,
  source-only syntax checks, skill validation, project-journal validation,
  `git diff --check`, and the zero-bytecode inventory passed after removing the
  validator's ignored task-local dependency cache.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
- A later Fresh Codex review showed that two independent jobs on the rolling
  `macos-26` label could accidentally satisfy conflicting positive and
  fail-closed expectations by receiving different images. The hosted positive
  job is therefore superseded by the paired Trusted Mac exact-head procedure;
  hosted CI retains only the reviewed blocker-signature gate.
- Follow-up read-only review moved the two real-fork stream-overflow
  regressions into the live isolation set, replaced text-matched overflow
  handling with typed stream/limit evidence, and made regular-file content plus
  access policy one repeated combined sample. Timestamp-only churn remains
  benign, while same-inode same-length content mutation fails closed.
- The repaired ordinary deterministic selection passed 647/647 in 226.329
  seconds with identity SHA-256
  `086d84524704e97791e47ed9b9e3e0a7bab1c99a63ba9bee27e58db3725dbadb`.
  The deny-child selection passed 275/275 in 20.480 seconds with identity
  SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`.
- Package-aware discovery passed 658 tests with six expected outer-sandbox or
  platform skips in 219.658 seconds. The complete Python 3.13 playbook
  discovery ran 2,822 tests in 983.661 seconds with six skips; only the known
  nested-Seatbelt broker regression failed under the parent sandbox, and that
  exact test passed 1/1 outside it in 2.469 seconds. Repository contracts passed
  102/102 in 7.404 seconds.
- The current receipt-bound cleanup and terminal-publication implementation
  passed the focused read-only runner module 40/40 in 4.795 seconds and the
  ordinary deterministic gate 648/648 in 196.449 seconds on Python 3.13. The
  reviewed 648-test selected identity is SHA-256
  `5956350e0995ae84ad17dfee413a6cde547d2649b06e51d7d6b98e757a20d69d`.
  The added real-process matrix covers SIGHUP, SIGINT, SIGQUIT, and SIGTERM at
  the pre-seal, serialization, write, stdout-flush, stderr-flush, and pending
  restore boundaries, and requires the sole JSON record and OS return code to
  reflect the same sealed outcome.
- Fresh frozen-range Codex review found two launch-authority gaps. A custom
  runtime pin could pass behavior probes and reach a real launch despite being
  non-production, and the read-only child used `-B -c`, allowing ambient
  `sitecustomize` or `.pth` startup code to run before the selected suite.
  Custom pins are now probe-only, preparation rejects them before probe or
  executable authentication, and launch requires exact production-capable
  evidence. The child uses and self-checks `-I -S -B`; a live real-process test
  injects both startup mechanisms and proves neither marker is created.
- The affected Python 3.13 modules passed 106/106. The reviewed deterministic
  selection passed 649/649 in 205.965 seconds with identity SHA-256
  `7be8915dfd39ff943aa782c73ea2e259c6a9c6a8a68bdd305227d85a1e712e56`.
- The next frozen-range Fresh Codex review found two remaining proof gaps. Exit
  zero lacked a parent-verified record proving all 275 selected tests completed,
  and writable-root ancestry retained device/inode identity without retaining
  owner, mode, ACL, or xattr policy. A side-effect-free shared contract now owns
  the selected count, identity digest, and canonical success JSON; the suite
  emits it only after complete success and the parent requires exact stdout.
  Writable-root authority now carries a descriptor-walked component receipt,
  accepts only root/current-user-owned safe or sticky ancestors, and compares
  object identity plus access policy on every revalidation before launch.
- A subsequent frozen-range Fresh Codex review found that the runner copied its
  live source subtree without binding those bytes to the recorded commit. The
  runner now requires an explicit full HEAD, rejects dirty, untracked, and
  subtree-ignored input, rebinds the checkout after copying, and requires one
  stable content/access-policy manifest across the source before and after the
  copy and the installed tree. Its terminal summary exposes the exact bound
  HEAD and manifest digest.
- Post-fix Python 3.13 validation passed the affected tests 103/103 in 11.082
  seconds and the reviewed deterministic selection 652/652 in 284.796 seconds
  with the reviewed 652-test selected identity and SHA-256
  `ae05fcb1dac9077c4d3a477413c762664c8d9046e467d8286a4f302fa9d52b39`.
  Repository contracts passed 102/102 in 7.218 seconds.
- The first exact-head installed run failed closed before child launch because
  `/private/tmp` assigned a different group to the copied tree. Git does not
  bind ambient checkout UID/GID, so the cross-container manifest now covers
  content and portable access policy while the installed before/after snapshot
  still binds actual UID/GID. The held install container is group-aligned and
  policy-revalidated before copying so Darwin inheritance is deterministic.
  Focused source-binding and runner tests passed 44/44 in 11.018 seconds.
- The portable-ownership relaxation was superseded before final freeze. Once
  the descriptor-bound install container is group-aligned, the copied tree can
  and must match the source UID/GID as part of the exact access-policy
  manifest. Final Python 3.13 validation passed the affected modules 109/109,
  the deterministic selection 652/652 in 237.512 seconds with identity SHA-256
  `ae05fcb1dac9077c4d3a477413c762664c8d9046e467d8286a4f302fa9d52b39`,
  and repository contracts 102/102 in 9.312 seconds.
