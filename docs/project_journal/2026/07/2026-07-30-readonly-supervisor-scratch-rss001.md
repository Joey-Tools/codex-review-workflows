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
- A returned bounded-child outcome is published into a separate caller-owned
  receipt before the same-UID closure census. The receipt preserves only the
  already bounded return code, stdout, and stderr for failure diagnosis; it is
  not process-closure evidence and cannot authorize destructive cleanup. A
  later closure failure therefore remains primary and retains both protected
  trees while the terminal summary and stderr still expose the inner suite's
  bounded outcome.
- CI runs the ordinary deterministic suite and the read-only installed
  regression in separate macOS Python 3.13 jobs. The read-only job copies the
  tracked source from the checkout into a root-owned, read-only
  `/private/codex-review-readonly.*` isolation tree and executes the runner as
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
- The final async cleanup-boundary, recovery directory-FD custody, and delayed
  Darwin process-visibility hardening passed 785/785 deterministic
  independent-supervisor tests in 101.433 seconds on the uv-managed CPython
  3.13.13 runtime, with reviewed selected-identity SHA-256
  `d5c05be333956ec17a9190f79044d730eab639328d1ec4e5aec5a74c903b05ef`.
  Caller-owned runtime-root and child-descriptor settlement now survives the
  remaining call/return interruption windows without retrying an ambiguous
  close. Recovery admission also rejects multiply linked non-directory objects
  before manifest publication. These checks protect exact object identity and
  the selected access policy; benign child-entry churn remains distinct from
  replacement, content mutation, or an access-policy change.
- The remote failure after `f4f3198` exposed delayed same-group and terminal
  child visibility after output-overflow settlement. Process-group emptiness
  now requires stable observations, and the unfiltered same-UID closure census
  requires 250 milliseconds of stable exact-identity absence within its
  existing five-second deadline. It opportunistically reaps only terminal
  direct children and never treats process state as identity: PID plus start
  seconds and microseconds remain the protected process-table object. After
  `waitid(WNOWAIT)` exposes a terminal direct child, a fresh bounded census must
  bind that exact start-time identity before `waitpid`; missing, unreadable, or
  reused PID identity evidence fails closed. Every identity and reap operation
  shares the original five-second absolute deadline. Zombies, live descendants,
  unreadable census results, and identities that reappear before the stability
  window still fail closed.
- The live double-fork regression ignores `SIGHUP`, settles its escaped marker
  PID to stable exact absence after cleanup, and uses real Darwin start identity
  for only the supervisor and fixture process on an ordinary developer account.
  This test-only scope avoids unrelated account process churn; the hosted
  isolated-account gate continues to run the complete production census without
  filtering. The read-only runner module passed 108/108 in 8.661 seconds, and
  ten ordered output-overflow/double-fork stress rounds passed 20/20 in 58.9
  seconds under the same uv-managed CPython 3.13.13 runtime. The complete
  repository contract module passed 105/105 with every helper
  subprocess resolving that same uv-managed interpreter.
- Hosted setup-uv paths are now resolved through physical parent ancestry to a
  regular non-symlink executable leaf before identity and digest binding. Exact
  version admission uses `uv self version --short`, while a regression accepts
  a benign ancestor alias and rejects a symlink executable leaf. The pinned uv
  0.11.18 managed-Python staging inventory also validates its one architecture
  alias as a symlink to the exact versioned runtime before unlinking that alias.
- The root-owned hosted isolation tree is allocated directly below `/private`
  and has inherited ACLs removed before any child is created, so the
  explicit nobody-owned mode-`0700` runtime parent has a root-owned,
  non-group/world-writable ancestor chain. This preserves the runtime-parent
  trust policy instead of weakening it for runner-specific `/Users` metadata.
- The outer root remains root-owned mode `0700` while uv and source custody are
  prepared, then transitions to exact root-owned mode `0755` for the sandboxed
  nobody run. Full descriptor-based ACL/xattr policy validation requires read
  and search access on every ancestor; the outer root remains non-writable and
  the nobody-owned payload and runtime parent remain exact mode `0700`.
- The installed child suite receives `TMPDIR` bound to its already validated
  private runtime parent. The outer runner still creates the read-only install
  container below sticky `/private/tmp`, while nested unittest temporary roots
  no longer fall back to that intentionally rejected ancestor.
- The complete host-level deterministic gate now passes 799/799 in 102.251
  seconds on the uv-managed CPython 3.13.13 runtime, with selected-identity
  SHA-256
  `306ce4d6bcdacd57b555f5e1eecefe59c4033c853e7e8c939a527dce05c10377`.
  Recovery manifests bind complete bounded leaf access-policy evidence,
  including ACL state and canonical xattr names and values, plus exact bounded
  regular-file bytes through a domain-separated double-observed digest. Raw
  content is read with one fixed cleared buffer and never enters manifest
  state; non-regular leaves are never stream-read. The final leaf unlink starts
  only while the original absolute cleanup deadline remains live. Policy or
  content drift, unreadable evidence, and deadline expiry retain the
  descriptor-bound quarantine instead of weakening cleanup admission.
- Hosted read-only job `91367316563` failed closed on one long-lived post-baseline
  same-UID process while retaining both protected trees; an unchanged-head
  failed-job rerun passed the complete gate. The first summary could not report
  whether the already bounded inner suite had passed or failed because closure
  failure interrupted `CompletedProcess` publication. The outcome receipt now
  keeps that diagnostic evidence independent of the still mandatory process
  closure proof. Timing makes the read-only runner's live double-fork fixture
  the highest-probability source, not a proven attribution. Its normal cleanup
  now publishes and revalidates the exact PID/start-time identity before
  writing a task-private cooperative stop marker and proves stable absence even
  when the assertion path exits unexpectedly. If marker publication fails, the
  still-unreaped direct-child relationship prevents PID reuse while the parent
  sends SIGKILL and reaps that child; a separate custody receipt and
  exact-identity absence proof verify that failure path before another fixture
  process starts.
- The final exact working tree passed 802/802 deterministic tests in 103.447
  seconds with selected-identity SHA-256
  `d937a349ec87ffbd440be7e73734f5ea7533331c7212d5977c7661481b0a3516`.
  The complete read-only runner module passed 111/111 in 10.548 seconds, and ten
  ordered normal/failure-injection double-fork rounds passed 20/20 in 67.488
  seconds. The repository contracts passed 105/105 under the same uv-managed
  CPython 3.13.13 runtime.
- The exact follow-up working tree passed 825/825 deterministic tests in
  397.034 seconds on host-level Homebrew CPython 3.13.12. The reviewed
  825-test selected identity has SHA-256
  `44716a7919f53dc79897cb7426ccca293c8f4a0a3d879003cc3b346cf17eb3cd`.
  The read-only no-child subset independently passed 275/275 in 28.783 seconds
  with selected-identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`.
  The fixed `/usr/bin/git` checkout module passed 43/43 at host level. Inside
  the Codex outer sandbox, Apple Git 2.53 emitted a `confstr()` diagnostic while
  resolving `DARWIN_USER_TEMP_DIR`; the unchanged stderr-empty contract rejected
  all four affected reachability paths. Setting `TMPDIR` inside the private Git
  control was rejected because `xcrun` created an unmanifested `xcrun_db`; no
  such workaround or stderr relaxation entered the source.
- The positive thirteen-test production no-child gate remains blocked in this
  Codex Desktop context because the process inherits an outer Seatbelt. The
  required-mode run failed closed with one failure and two errors rather than
  skipping. A no-outer-Seatbelt Trusted Mac must rerun all 13 tests and the
  exact-head read-only installed runner after the final signed commit; neither
  the hosted blocker-signature probe nor the deterministic result
  substitutes for that evidence.
- Fresh prior-bundle Codex review of the signed source-binding merge found that
  `file-link` remained independently available inside writable-root Seatbelt
  profiles and that index-aware status could hide exact-head source divergence.
  Writable profiles now globally deny `file-link`, with a real hard-link alias
  attack in the child suite. Source custody rejects repository-visible include,
  filter/diff, fsmonitor, `core.fileMode=false`, assume-unchanged, and
  skip-worktree state, then compares a descriptor-based double snapshot with
  raw HEAD tree/blob/mode evidence from an isolated object-control view.
- The corrected host-level deterministic gate passed 827/827 in 236.142 seconds
  on Homebrew CPython 3.13.12. The reviewed 827-test selected identity has
  SHA-256
  `759eaa93eb1903347f2160532617154b5c54d910ce964cc4c77794767dfc0ba0`.
  The read-only no-child subset remained 275/275 in 26.676 seconds with
  selected-identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`;
  the complete affected modules passed 198/198 in 48.776 seconds with three
  platform skips, and the fixed `/usr/bin/git` checkout module passed 43/43 at
  host level. The sandboxed deterministic attempt retained the known four raw
  Git non-passing outcomes and is not successful evidence.
- BL's prior-bundle Claude 2.1.220 attempt passed credential-free preflight and
  clean child supervision, but strict validation remained inconclusive with
  `init.capabilities.mismatch`, `init.unknown-field`, and
  `terminal.unknown-field`. No findings were accepted or classified. The
  result records the prior-policy bootstrap need for this exact closed schema;
  it does not complete a Claude lane or authorize candidate control execution.
- The final host-level Python 3.13.12 full discovery passed 2,833/2,833 tests in
  1080.124 seconds with six platform skips. Actionlint passed for the canonical
  workflow and both generated CI fixtures; full Ruff lint, changed-file Ruff
  formatting, source-only compilation, skill validation, project-journal
  validation, `git diff --check`, and the zero-bytecode inventory also passed.
- The Trusted Mac outer gate now executes only source bytes streamed from the
  exact frozen HEAD blob or from one manifest-bound, no-follow descriptor read.
  The installed-release producer validates a closed 131072-byte cap, a singly
  linked regular file, stable object identity and selected access policy, and
  the exact manifest SHA-256 before writing the same in-memory bytes to the
  isolated Python consumer. Size and digest predicates exit explicitly on
  failure. Regressions execute the documented producer and prove that digest
  mismatch, oversize content, a symlink, a hard link, and a FIFO produce no gate
  bytes. Git size and digest producer failures are checked independently before
  any frozen gate blob is consumed.
- Exact source custody now shares bounded entry, path, source-byte, depth, and
  per-snapshot deadline accounting across raw HEAD expansion, descriptor
  snapshots, and copy revalidation. The hosted no-HEAD path uses the same
  bounded descriptor manifest and copy owner; neither production path calls
  `shutil.copytree`. Opened gate files are charged from descriptor size plus a
  growth probe before reading, while immutable content is the compared
  property and timestamp-only churn remains benign.
- The replacement host-level deterministic gate passed 837/837 in 253.934
  seconds on Homebrew CPython 3.13.12. The reviewed selected-identity SHA-256 is
  `100e6bfa5e93c72f61c20d45cfe69a1d945ae55908b3fc4e6943564886fed434`.
  The complete read-only runner module passed 143/143 in 55.021 seconds, the
  source-binding/bootstrap focus passed 18/18 in 20.851 seconds, the read-only
  no-child subset passed 275/275 in 19.809 seconds with selected-identity
  SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`,
  and the fixed `/usr/bin/git` checkout module passed 43/43 in 29.644 seconds.
- A direct real read-only wrapper attempt in the current Desktop host failed
  closed before child launch because the configured read-only child account is
  a member of the admin group. Process closure remained `not-started`, and the
  runner retained two descriptor-bound roots with explicit incomplete-cleanup
  evidence. This host-configuration result is not counted as the 275-test
  deterministic gate or as Trusted Mac exact-head evidence; no retained path
  was silently deleted or reported as clean.
- The frozen final host-level Python 3.13.12 full discovery passed
  2,833/2,833 in 941.136 seconds with six existing platform skips. Final
  contracts passed 105/105, both bounded precommit audits returned
  `No findings.`, and canonical/fixture Actionlint plus canonical fixture byte
  equality passed. Changed Python files passed Ruff 0.13.2 lint and formatting,
  source-only compilation, skill validation, project-journal validation,
  `git diff --check`, and the zero-bytecode inventory.
- A diagnostic repository-wide `uvx ruff check .` used a newer unpinned Ruff
  ruleset and surfaced 3,033 pre-existing all-rule baseline findings. It made no
  source change and is not counted as this diff's lint gate; the repository's
  installed Ruff 0.13.2 changed-file gate is the applicable passing evidence.
- Canonical PR #86 hosted job `91434745317` then failed closed at
  `install-copy`: the root-owned staged source receipt was incorrectly reused as
  the expected owner of the nobody-owned installed tree. Cleanup completed, no
  child started, and no path was retained. The replacement binds source
  identity/access policy and destination execution ownership independently,
  projects only the source UID when deriving the expected installed manifest,
  and rejects any destination owner other than the frozen execution UID. The
  affected read-only runner module passed 144/144, and the host-level
  deterministic gate passed 838/838 in 243.890 seconds with selected-identity
  SHA-256
  `76dedc279ab17a3033d3f87dcdbb1b6534bae68bde8837568e5bb913507e66f3`.
- The matching hosted summary contract now treats that manifest as a required
  exact lowercase SHA-256 rather than a null field. The runner summary is never
  printed before validation; successful validation emits a canonical JSON
  object, while malformed input reports only bounded metadata and never echoes
  injected content. Canonical and fixture workflows remain byte-identical. The
  final read-only audit returned `No findings.`, contracts passed 105/105, the
  affected runner passed 144/144 in 61.905 seconds, and the final host-level
  Python 3.13.12 full discovery passed 2,833/2,833 in 1008.735 seconds with six
  platform skips.
