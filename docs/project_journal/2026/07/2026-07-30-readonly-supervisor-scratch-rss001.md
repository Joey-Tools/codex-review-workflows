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
- Bind both the installed copy and runtime directory for the command lifetime,
  keep object-identity proof distinct from access-policy proof, and delete only
  the descriptor-custodied object recorded in a private cleanup manifest.
- Keep descriptor-bound retention unknown when its current namespace path
  cannot be recovered; only an identity-matched held directory with zero links
  proves that exact object is absent from the namespace.
- Run the nested suite through the bounded process-group supervisor and a full
  same-UID process-identity census from an isolated non-admin account, with
  fail-closed retention whenever system-wide child-process closure is unproved.
- Inherit a Seatbelt profile that denies launchd `job-creation` and execution
  of every set-user-ID or set-group-ID file by mode rather than by path, and
  require kernel-visible denial before the nested child starts.
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
- The read-only runner keeps descriptor and policy bindings for the exact
  installed copy and runtime directory before the child starts. Original-path
  identity, held-object identity, and access policy are reported separately:
  replacement, unreadable revalidation, policy drift, and benign child-entry
  churn cannot be collapsed into one generic mutation result.
- Cleanup requires proven process closure, creates a custodied manifest in a
  private cleanup-control directory, quarantines the exact descriptor-bound
  root relative to its held parent, revalidates the quarantined identity, and
  then performs descriptor-relative recursive deletion. A missing cleanup
  control root, pathname replacement, policy drift, or check-to-delete swap
  retains the affected object instead of deleting an unproved target.
- Cleanup completes before success output. Every ordinary primary exception is
  reported in the structured summary; a concurrent cleanup error returns
  nonzero, preserves the primary failure and child return code, and reports the
  exact retained path as secondary evidence.
- The child suite runs in a fresh process group with 8 MiB caps for stdout and
  stderr. Normal leader exit, output overflow, timeout, and SIGTERM settle the
  leader and same-group descendants. A Darwin `libproc` census binds every
  same-real-or-effective-UID PID, including zombies, to its start time before
  the child and after process-group settlement; any new identity, including a
  `setsid()` and double-fork escape, prevents cleanup. Each census phase has an
  independent five-second monotonic deadline. Enumeration errors, disappearing
  identities, and incomplete identities fail closed. A pre-start account or
  census failure is reported as `child_process_closure:not-started`, never as
  an unproved child.
- Signal-guard teardown cannot replace an already raised
  `GitProcessClosureUnproven`. Deactivation and handler-restoration failures are
  retained as ordered secondary diagnostics, while cleanup is authorized only
  by an explicit process-closure proof; a still-pending or unproven child keeps
  both the installed and runtime trees.
- CI runs the ordinary deterministic suite and the read-only installed
  regression in separate macOS Python 3.13 jobs. The read-only job copies the
  tracked source into an owner-private `/Users` root and executes the runner as
  `nobody` with an empty environment inside an inherited Seatbelt profile.
  Before starting the child, the runner proves real/effective UID equality,
  non-root and non-admin membership, kernel-visible `job-creation` denial,
  generic set-ID exec filtering through a direct `sudo` EPERM probe, and a
  same-UID baseline containing only the supervisor. The job has a 20-minute
  emergency outer budget around the
  runner's 10-minute child timeout. CI success requires the terminal structured
  closure and cleanup proof; a host cancellation or missing terminal summary
  cannot count as a clean gate. The root-owned outer isolation container is
  removed only after that proof and otherwise remains at the reported recovery
  path. The Seatbelt profile is copied into that root-owned outer container,
  byte- and identity-bound there without changing checkout metadata, and
  revalidated before and after launch. The outer summary parser runs with
  isolated, site-disabled Python imports and accepts only the exact terminal
  schema; its identity-bound path is reported whenever failure retains it.
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
- The final process-census and descriptor-custody regressions pass 40/40 on the
  uv-managed CPython 3.13 runtime. Coverage includes a `setsid()` double-fork
  escape with standard descriptors closed, zombie handoff visibility, bounded
  `libproc` enumeration with the SDK-declared `sysctl(KERN_PROC_PID)`
  start-time identity and safe prelaunch churn union, inherited Seatbelt
  enforcement, install/runtime pathname replacement, access-policy-only drift, and a
  quarantine-rename race that preserves machine-visible recovery identities
  for both objects. Unlike `proc_pid_rusage`, the read-only sysctl path is
  expected to remain available for protected same-UID hosted-runner processes;
  empty or vanished records restart the complete bounded census, while every other incomplete or
  malformed identity fails closed.
- The final deterministic independent-supervisor gate passed 646/646 in
  91.255 seconds on the host-level uv-managed CPython 3.13.13 runtime, with
  selected-identity SHA-256
  `cc1b2204ad8af6de52668bf83779aac60ec5bab00b20578e20419b5b6fe8f57e`.
  The selected suite includes the unresolved-retention and safe prelaunch
  same-UID churn regressions.
  All 104 repository contract tests passed under the same uv-managed runtime.
  The hosted read-only job now installs that one exact CPython through pinned
  setup-uv v8.1.0 and uv 0.11.18 into a root-private staging tree, relocates and
  seals one physical version root, and revalidates its content, object identity,
  access policy, loader metadata, symlinks, and code signature before and after
  the isolated run.
  The enclosing parent sandbox makes Apple Git emit a `confstr()` temporary-root
  diagnostic that the strict raw-Git tests correctly reject; the four affected
  tests pass 4/4 when rerun at their required host level.
  A local production-shaped invocation correctly rejected the interactive
  admin account before starting a child and still reported complete cleanup
  with no retained paths. The hosted isolated-account success path remains a
  required CI result rather than a locally claimed success.
- A host-level Seatbelt probe for the path-independent set-ID filter allowed
  ordinary `/usr/bin/true`, while both root-setuid `/usr/bin/sudo` and setgid
  `/usr/bin/write` were rejected at `exec` with `EPERM` (sandbox exit 71). The
  hosted runner still must prove the same inherited policy before CI can pass.
- The final async cleanup-boundary and recovery directory-FD custody
  hardening passed 776/776 deterministic independent-supervisor tests in 90.357
  seconds on the uv-managed CPython 3.13.13 runtime, with reviewed
  selected-identity SHA-256
  `e7a7ac91c591d27a82b26f6e7a412364c171ee5832913aed5d8fcef05f70fc02`.
  Caller-owned runtime-root and child-descriptor settlement now survives the
  remaining call/return interruption windows without retrying an ambiguous
  close. Recovery admission also rejects multiply linked non-directory objects
  before manifest publication. These checks protect exact object identity and
  the selected access policy; benign child-entry churn remains distinct from
  replacement, content mutation, or an access-policy change.
- Hosted setup-uv paths are now resolved through physical parent ancestry to a
  regular non-symlink executable leaf before identity and digest binding. Exact
  version admission uses `uv self version --short`, while a regression accepts
  a benign ancestor alias and rejects a symlink executable leaf.
