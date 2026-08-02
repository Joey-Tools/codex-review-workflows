---
id: 20260727-rsr001
title: Review Runtime State Root
status: completed
created: 2026-07-27
updated: 2026-08-01
branch: wip/review-runtime-state-no-bytecode
pr:
supersedes: []
superseded_by:
---

# Review Runtime State Root

## Summary

- Keep independent-review retention and checkout state outside immutable installed release trees.
- Replace workflow `py_compile` and `compileall` calls with source-only syntax checks.
- Require every Python-bearing CI job to finish with no repository bytecode artifacts.

## Current State

- Default state resolves from the current POSIX account database to
  `~/.codex/review-runtime/independent-codex-pr-review/`, without trusting
  ambient `$HOME`.
- Every explicit retention root resolves and proves stable equivalence against
  the account-local default inside the CLI failure boundary. Proven distinct
  roots skip the migration gate, equivalent aliases use it, and unavailable
  proof fails closed. Each public command resolves the POSIX account state root
  once, then derives default retention and checkout paths from that one
  snapshot; an explicit checkout parent avoids an unnecessary second helper
  call.
- The CLI retains the selected/default path snapshots through command
  completion. Every exact selected-root open binds the object identity and
  private access policy to that classification before a retention lock or
  durable state can be written, and finalization revalidates both paths plus
  their equivalence. A missing selected root is opened and materialized
  relative to the originally held deepest-prefix descriptor, so a concurrent
  pathname replacement cannot redirect state into a different parent object.
  Expected missing-leaf materialization, restoration of the same bound parent,
  and directory child-entry churn are accepted; persistent selected/default
  object replacement or an equivalence transition fails closed.
- Installed overlays fail closed when any sibling release still has a
  release-local retained attempt. Operators must explicitly select that old
  retention root and drain it before using the account-local default.
- The scanner always fences the currently executing helper's own
  `runtime/retention` root before optionally enumerating a standard installed
  overlay catalog. Self-contained and other nonstandard layouts with an
  existing root retain the same migration protection; if that root is absent,
  they fail closed before the public command because no immutable catalog
  marker can prove that an older writer will not create it after a final
  pathname check. Documented self-contained commands therefore select explicit
  release-local retention and checkout roots; account-local defaults are for
  standard installed-overlay catalogs. The current standard release also
  passes the catalog
  capability and directory-identity checks while reusing the already-held
  current-root fence instead of acquiring its lock twice.
- Releases that use account-local retention carry a source-controlled
  `ACCOUNT_LOCAL_RETENTION_V1` capability marker. The scanner validates its
  exact bytes, owner, mode, link count, ACL/xattr policy, and object identity,
  then rereads the held descriptor in full and requires identical bytes.
  Same-inode same-size writes are rejected even when the path is restored;
  benign timestamp drift is ignored. The currently executing installed release
  receives the same capability, catalog, and directory-identity checks while
  reusing its already-held current-root fence. An unmarked installed helper
  without an existing legacy lock is blocked before the public command can
  run, rather than treating one absent-path observation as proof that an old
  version cannot start later.
- Shared descriptor-relative and absolute regular-file openers request
  nonblocking, no-follow descriptors before regular-file validation. This
  prevents FIFO peer-rendezvous blocking. Device nodes are rejected after
  `open()` returns, but the openers do not bound arbitrary device-driver open
  latency.
- The legacy scan walks from an ACL/xattr-validated releases-root descriptor
  through `O_NOFOLLOW` child descriptors. It binds object identity and access
  policy with device, inode, type, generation, owner, group, mode, flags, and
  normalized ACL/xattr evidence while deliberately ignoring timestamps,
  directory size, and link count. Catalog discovery retains the releases-root,
  current-release, and current-helper descriptors plus their policy bindings
  through the public command; the scan consumes those held objects directly
  and revalidates both descriptors and pathname mappings before and after the
  command. For current or sibling helpers without a
  legacy root, the initial component bindings and deepest existing descriptor
  remain held through the command; a final fresh probe must match that initial
  custody. Nested helper replacement fails closed, while ordinary child-entry
  churn remains benign.
- The scanner acquires every existing legacy `retention.lock` with a
  nonblocking exclusive flock, enumerates attempts while holding that fence,
  and retains it through the default-root command plus final path/catalog
  revalidation, including when the command itself fails. Active old writers,
  empty unfenced roots, newly appeared roots, an initially empty root gaining
  an attempt, ACL drift, and ancestor replacement all fail closed.
- When a public command and fence finalization or resource cleanup both fail,
  the command exception remains primary with its original type and structured
  `SupervisorError` fields. Finalization and cleanup failures are attached as
  secondary exception evidence and surfaced through an optional
  `secondary_errors` field bounded to four 512-character entries. A secondary
  failure remains fail closed when the command itself succeeded.
- Explicit default paths bind every existing prefix to the secure descriptor
  walk's device/inode identity and use a conservative case-insensitive key for
  a missing suffix. Darwin root aliases, double-root spelling, and
  case-insensitive filesystem aliases therefore cannot select different
  migration behavior. Existing distinct objects remain distinct. The held
  prefix descriptors are revalidated for object identity and access policy
  after both snapshots are opened; target replacement or missing-suffix
  creation observed between the initial snapshots and final revalidation
  raises `ESTALE` before the public command is entered. Migration
  setup/finalization errors remain fail closed, while `OSError` and
  `ValueError` raised by the public command retain their original type and
  diagnostic.
- Installed-symlink preflight coverage proves the release tree inventory and
  bytes remain unchanged while runtime directories are created externally.
- Test-runtime directories are normalized to `0700` relative to a held parent
  descriptor and revalidated for the same object before use, so restrictive
  process umasks cannot make valid scratch allocation fail. The read-only
  installed runner retains the exact runtime-directory descriptor through child
  closure, enumerates residue from that object, and revalidates the pathname
  before cleanup; a replacement cannot be mistaken for an empty clean tree.
- Canonical and private reviewed CI fixtures use in-memory `compile(...)`
  syntax validation and explicit zero-cache guards. Their Python 3.13
  workflows run the installed-release immutability regression in a dedicated
  20-minute job, separate from the ordinary deterministic supervisor job.
- Trusted Mac gate bootstrap object reads no longer load the candidate
  repository's Git configuration. The hosted gate binds a detached exact-SHA
  checkout, its Git object directory, and its `HEAD` file before creating an
  owner-private empty bare control repository outside the candidate source. A
  fixed direct Git executable reads the source objects only as an alternate,
  with lazy fetch, prompts, credentials, replacement objects, optional writes,
  and every transport protocol disabled. Control/source identities and the
  control config digest are revalidated before and after the bounded object
  reads. The documented operator gate uses the same isolated-control model.

## Next Steps

- Sync the canonical change into the private overlay and publish a trusted release.

## Evidence

- A fresh private-overlay Codex review identified the release-local runtime
  state and explicit-bytecode workflow gaps on the synced canonical control plane.
- Fresh-context Codex review found that moving the defaults alone hid retained
  attempts in older installed releases and that the README still documented the
  obsolete release-local default. The explicit drain gate, cross-version
  regression, and corrected README close both findings.
- The final platform suite ran 2,822 tests with 6 skips in 1051.356 seconds.
  Its only failure was the known parent-sandbox denial of nested
  `sandbox-exec`; that exact broker test passed 1/1 outside the parent sandbox
  in 3.056 seconds. The required live no-child/Seatbelt suite passed 9/9
  outside the parent sandbox in 7.866 seconds.
- The complete 100-test contract module passed in 8.001 seconds.
- Focused installed-symlink immutability, default state-root, CI snapshot, and
  no-bytecode entrypoint regressions passed. The new cross-version tests also
  prove explicit old-root visibility and fail-closed release replacement.
- Fresh-context Codex review found eager account-home resolution outside the
  JSON failure boundary. The follow-up makes defaults lazy and covers both
  lookup failure and explicit-root bypass.
- Exact-head Fresh Codex review found that documented explicit default paths
  bypassed the migration gate, a concurrent old writer could create an attempt
  after enumeration, and pathname scans did not bind ACL or descriptor
  identity. Default examples now delegate root selection to the CLI, while
  focused CLI and secure-I/O tests cover explicit-default gating, held flock
  fencing, active writers, roots appearing during a command, ACL rejection, and
  directory replacement.
- The next exact-head Fresh Codex review found that an unmarked old helper
  without a retention root could start after the final absent-path probe, that
  Darwin root aliases could bypass explicit-default detection, and that the
  context manager rewrote command-body `OSError`/`ValueError` diagnostics.
  Capability-marker admission, shared path normalization, and separated
  setup/body/finalization exception scopes close those findings.
- A later exact-head Fresh Codex review found that self-contained installations
  were omitted from the sibling-only catalog and that lexical path equality
  still let equivalent aliases bypass the explicit-default gate. The current
  helper is now fenced unconditionally, while explicit-default classification
  uses descriptor/object identity plus the documented missing-suffix policy.
- The following exact-head Fresh Codex review found that sequential path
  snapshots could interpret a concurrent target creation or replacement as a
  stable custom retention root. Held descriptor revalidation and deterministic
  creation/replacement race tests close that bypass.
- The next trusted-release Fresh Codex review found that a same-inode,
  same-length capability-marker rewrite could retain stale first-read bytes,
  and that a lexical suffix prefilter could skip equivalence for filesystem
  aliases. The marker is now reread from the held descriptor after complete
  path/access-policy revalidation, with primary and cleanup errors separated.
  Every explicit retention root now performs stable equivalence; unavailable
  proof fails closed and only a proven distinct root skips migration.
- The replacement-head Fresh Codex review found that the current release
  bypassed its own capability/catalog identity checks and that a simultaneous
  fence finalization or cleanup failure could replace the public command's
  primary diagnostic. Current-release probes now run before and after the
  command without duplicating its lock, and dual-failure handling preserves
  the exact primary exception while retaining secondary evidence in an
  optional, bounded `secondary_errors` response field.
- The next exact-head Fresh Codex review found that root equivalence snapshots
  were closed before the public command opened its actual root and that final
  legacy scans ignored an attempt appearing during the command. Command-scoped
  root bindings now guard every exact selected-root open and finalization, while
  each legacy fence records and enforces its initial attempt state.
- The following exact-head Fresh Codex review found that regular-file opens
  could block on a FIFO and that device nodes reach driver-specific `open()`
  paths before file-type validation. The shared openers now add `O_NONBLOCK`;
  bounded descriptor-relative and absolute FIFO regressions verify rejection
  without waiting for a FIFO peer. The `/dev/null` smoke check does not bound
  arbitrary device-driver open latency.
- The next exact-head Fresh Codex review found that differently cased aliases
  of the same installed helper could bypass the sibling-release catalog and
  that the journal's deterministic count was not bound to the runner. Catalog
  detection now proves directory-object equivalence and resolves the release
  name from the held catalog, while a canonical contract test binds the
  journal count and digest to the runner's reviewed constants.
- The following exact-head Fresh Codex review found a final absent-path
  check-to-return race for non-catalog helpers and a stale repo recovery
  pointer. Non-catalog helpers without an existing legacy root now block before
  the public command, and the contract-bound recovery pointer names this
  workstream journal.
- The next exact-head Fresh Codex review found that directory policy bindings
  discarded group and normalized ACL/xattr evidence, and that the documentation
  overclaimed device-node open latency. Account-local root equivalence and
  legacy release custody now retain complete in-process directory policy
  bindings across held descriptors and path reopens; allowed-to-allowed ACL
  drift and group drift fail closed. FIFO coverage and device-driver limits are
  now stated separately.
- The following exact-head Fresh Codex review found that initial current and
  no-root sibling helper bindings were discarded before the migration-fenced
  command, that retention and checkout defaults could query two different
  account homes, and that the installed-release immutability regression was
  skipped by hosted Python 3.13 CI. Command-lifetime catalog probes now retain
  component policies and held descriptors, public defaults share one state-root
  snapshot, and both canonical/private Python 3.13 jobs run the regression.
- The next exact-head Fresh Codex review found that an initially missing
  retention root could be opened through a replacement pathname after the
  binding's pre-open check, so the final root no longer had to descend from the
  originally held parent object. Selected-root traversal now starts from a
  duplicate of that held descriptor and processes only the missing suffix.
  Persistent parent replacement fails closed before lock or durable-state
  creation, while replacement followed by restoration of the same bound parent
  remains safe and supported.
- The replacement-head Fresh Codex review found that a double-leading-slash
  root alias retained a different lexical root marker than the descriptor-bound
  prefix and therefore failed when the selected root was actually opened.
  Missing-suffix traversal now uses the bound snapshot prefix directly, and the
  alias regression exercises the real public `status` command through lock
  creation.
- The next exact-head Fresh Codex review found that installed catalog discovery
  closed its releases/current-release/helper descriptors before the migration
  fence reopened the catalog, and that self-contained README examples omitted
  the explicit roots required by the fail-closed non-catalog policy. Catalog
  custody now survives discovery through finalization, with a regression that
  replaces the complete catalog after discovery but before scan. The
  self-contained examples again pin distinct release-local runtime roots
  without weakening the account-local migration gate.
- A two-agent internal review then found descriptor-transfer cleanup gaps,
  incomplete multi-descriptor cleanup, a possible cleanup override of a
  catalog-mismatch error, missing standard-overlay examples, and tests coupled
  to a private revalidation call count. New regressions prove every acquired
  descriptor is attempted, preserve the primary mismatch, parse both public
  command matrices, and induce real catalog replacement during finalization.
- The deterministic independent-supervisor gate passed 619/619 in 278.468
  seconds with the reviewed 619-test selected identity and SHA-256
  `346a50ba8b68780fb7afee2e71c9c2caa9f1805d6bb7d4da96ed71cbc1401787`.
- The current hardened runtime-parent suite passed 621/621 in 225.264 seconds
  with the reviewed 621-test selected identity and SHA-256
  `0203bf84f76bfe4fcb49362ac3137474753af30c4aea0a0a31c47774a6929f4d`.
- The post-GitHub-review runtime binding and umask hardening passed 626/626 in
  243.743 seconds with the reviewed 626-test selected identity and SHA-256
  `135686bbf5d166fe7a050c739ea88a4d6080cd2019298762650e3372fee9fe76`.
  The real read-only installed runner also returned proven child closure,
  complete cleanup, an immutable release tree, no retained paths, no runtime
  residue, and no secondary failures.
- The post-fix CLI module passed 53/53 tests in 43.543 seconds on Python 3.13.
- The focused post-fix CLI and secure-I/O modules passed 78/78 tests in 45.435
  seconds on Python 3.13.
- Ruff lint/format, actionlint for canonical and private CI profiles,
  source-only syntax checks, project-journal validation, `git diff --check`,
  and the zero-bytecode inventory passed.
- No local Python 3.10 run is required for this delivery; local validation uses
  Python 3.13 only.
- The process-census, inherited Seatbelt, and descriptor-custody hardening
  passed 646/646 in 91.255 seconds on the host-level uv-managed CPython 3.13.13
  runtime, with the reviewed 646-test selected identity and SHA-256
  `cc1b2204ad8af6de52668bf83779aac60ec5bab00b20578e20419b5b6fe8f57e`.
  The Darwin object identity is the exact `(PID, start seconds, start
  microseconds)` returned by the SDK-declared `sysctl(KERN_PROC_PID)` interface:
  PID detects the process-table slot, the start timeval distinguishes slot
  reuse, and mutable state or credential fields are intentionally not identity
  signals.
- The final runtime-root reentry, parent-publication, recovery-admission,
  child-FD settlement, recovery directory-FD custody, and delayed Darwin
  process-visibility changes passed 785/785 deterministic tests in 101.433
  seconds on the same uv-managed CPython 3.13.13 runtime. The
  reviewed 785-test selected identity has SHA-256
  `d5c05be333956ec17a9190f79044d730eab639328d1ec4e5aec5a74c903b05ef`.
  Runtime-root custody continues to bind object identity independently from
  access-policy evidence: directory child churn is benign, while pathname
  replacement, content mutation, unreadable revalidation, and policy drift
  remain distinct fail-closed outcomes. Process closure likewise retains exact
  `(PID, start seconds, start microseconds)` identity; the numeric Darwin state
  is diagnostic only. Empty process-group and exact-identity absence results
  must remain stable across bounded observation windows, and terminal direct
  children are reaped before closure can be proven. Zombies and persistent live
  identities continue to block cleanup until exact absence is observed. A
  terminal child remains unreaped with `WNOWAIT` while a fresh Darwin census
  proves the complete start-time identity still occupies its PID; missing,
  unreadable, or mismatched rebinding fails closed, and every reap step shares
  the original five-second absolute deadline.
- The post-CI correction rejects non-3.13 interpreters before importing the
  supervisor package, so unsupported runtimes cannot replace the stable version
  diagnostic with an import failure. The current complete contract module
  passed 105/105 on the uv-managed CPython 3.13.13 runtime.
- The final leaf-cleanup and child-outcome diagnostic hardening passed 802/802
  deterministic tests in 103.447 seconds on the host-level uv-managed CPython
  3.13.13 runtime. The reviewed 802-test selected identity has SHA-256
  `d937a349ec87ffbd440be7e73734f5ea7533331c7212d5977c7661481b0a3516`.
  Manifest v3 now binds each leaf's object identity, owner, group, mode, flags,
  generation, normalized ACL state, and every canonical xattr name plus its
  complete bounded value. It also binds the exact bytes of each readable
  regular leaf with a domain-separated SHA-256 digest. Regular content is read
  twice from the same descriptor through a fixed, cleared 64 KiB buffer under
  one absolute deadline and a dedicated 512 MiB per-leaf cap; FIFO, symlink,
  and other non-regular leaves use domain-separated canonical states without
  consuming stream or target data. Raw content and xattr values never enter the
  manifest. Oversized, unreadable, unstable, or equal-length rewritten content
  fails closed, while the destructive unlink boundary rechecks the original
  absolute deadline and retains the quarantined leaf when it has expired. The
  focused recovery and secure-I/O modules passed 76/76 and 30/30,
  respectively, under the same runtime. A separate caller-owned receipt now
  preserves an already bounded child return code and output before same-UID
  closure without authorizing cleanup. On the live double-fork fixture's normal
  path, a custody receipt binds the exact PID/start-time identity before marker
  publication, cleanup rebinds that identity before writing a task-private
  cooperative stop, and one deadline covers stable absence proof. If marker
  publication fails, the unreaped direct-child relationship prevents PID reuse
  while the parent sends SIGKILL and then reaps that child; an independent
  custody receipt and exact-identity absence proof exercise that failure path.
- The source-binding and terminal-publication follow-up passed 825/825
  deterministic tests in 397.034 seconds on host-level Homebrew CPython 3.13.12.
  The reviewed 825-test selected identity has SHA-256
  `44716a7919f53dc79897cb7426ccca293c8f4a0a3d879003cc3b346cf17eb3cd`.
  Its read-only no-child subset passed 275/275 with selected-identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`,
  and the fixed `/usr/bin/git` checkout module passed 43/43 at host level.
  The same Git tests fail closed inside the Codex outer sandbox when Apple Git
  2.53 emits a `DARWIN_USER_TEMP_DIR` diagnostic; the source retains the strict
  empty-stderr requirement and does not set `TMPDIR` inside private Git control.
- Claude Code 2.1.220 compatibility is exact-version and closed-schema only.
  The reviewed profile admits only the ordered additional
  `interrupt_cancel_queued_v1` capability and the exact
  `fast_mode_disabled_reason == "sdk_opt_in_required"` field where the audited
  init and terminal records permit it. Adjacent versions, unknown fields,
  reordered or extra capabilities, and stale aggregate evidence remain
  rejected. The complete validator module passed 109/109 on Python 3.13.
- The required thirteen-test positive no-child profile is still
  `sandbox-blocked` in Codex Desktop because the inherited outer Seatbelt makes
  nested Seatbelt evidence unavailable. This is an explicit merge-readiness
  gap: a no-outer-Seatbelt Trusted Mac must run 13/13 and the exact-head
  read-only installed runner on the final signed commit.
- Fresh prior-bundle Codex review of the signed source-binding merge found two
  remaining protected-property gaps. The production Seatbelt profile denied
  writes but still allowed an independent `file-link` operation to create a
  writable hard-link alias, and the exact-head source check trusted index-aware
  status semantics that could hide bytes or executable-mode drift. Writable
  profiles now globally deny `file-link` and the real child suite attempts the
  alias attack. Exact-head binding now rejects repository-visible includes,
  executable filters/diffs, fsmonitor, `core.fileMode=false`, assume-unchanged,
  and skip-worktree state, then compares a descriptor-based double snapshot
  against raw HEAD tree/blob/mode data from an isolated object-control view.
- The hardened selection passed 827/827 deterministic tests in 236.142 seconds
  on host-level Homebrew CPython 3.13.12. The reviewed 827-test selected identity
  has SHA-256
  `759eaa93eb1903347f2160532617154b5c54d910ce964cc4c77794767dfc0ba0`.
  The read-only no-child subset remained 275/275 in 26.676 seconds with
  selected-identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`,
  the complete no-child/read-only focused modules passed 198/198 in 48.776
  seconds with three platform skips, and the fixed `/usr/bin/git` checkout
  module passed 43/43 at host level. The sandboxed deterministic attempt
  produced the known four raw Git non-passing outcomes and is not counted as a
  successful gate.
- BL's prior-bundle Claude 2.1.220 bootstrap attempt passed credential-free
  preflight and the supervised child exited zero with complete cleanup, but the
  trusted prior validator correctly returned inconclusive with exact reasons
  `init.capabilities.mismatch`, `init.unknown-field`, and
  `terminal.unknown-field`. No Claude findings were accepted or classified.
  This is compatibility-gap evidence for the exact-version closed schema in
  this change, not a completed Claude lane; candidate review control remains
  inactive until a new trusted release exists.
- The final host-level Python 3.13.12 full discovery passed 2,833/2,833 tests in
  1080.124 seconds with six platform skips. Actionlint passed for the canonical
  workflow and both generated CI fixtures; full Ruff lint, changed-file Ruff
  formatting, source-only compilation, skill validation, project-journal
  validation, `git diff --check`, and the zero-bytecode inventory also passed.
- The bounded-source follow-up passed 837/837 deterministic tests in 253.934
  seconds on host-level Homebrew CPython 3.13.12.
  The reviewed 837-test selected identity has SHA-256
  `100e6bfa5e93c72f61c20d45cfe69a1d945ae55908b3fc4e6943564886fed434`.
  The read-only no-child subset independently passed 275/275 in 19.809 seconds
  with selected-identity SHA-256
  `c860d5d56346ea3069a57da7310a5a96611b93d05f557b28d3772c741b4aab6b`,
  and the fixed `/usr/bin/git` checkout module passed 43/43 in 29.644 seconds.
  Source and installed-tree resource counters are shared across exact raw HEAD
  expansion, descriptor snapshots, bounded copy, and revalidation; each
  snapshot retains its own absolute deadline so a legitimate long child run
  cannot expire post-run verification in advance.
- Trusted Mac bootstrap content is now an explicit protected property. Frozen
  repository mode streams the exact HEAD blob, while installed-release mode
  performs one bounded no-follow descriptor read, validates object identity,
  selected access policy, and the manifest digest, then writes that same
  in-memory byte sequence to isolated Python. The producer never executes the
  candidate path and emits no bytes for oversized, linked, FIFO, replaced, or
  digest-mismatched input. The frozen Git producer's command status is part of
  admission rather than being inferred from a digest-shaped string.
- The final host-level Python 3.13.12 full discovery passed 2,833/2,833 in
  941.136 seconds with six existing platform skips. Repository contracts passed
  105/105 after the journal identity update. Both bounded source/bootstrap
  audits returned `No findings.`, and every applicable workflow, changed-file
  lint/format, source-only syntax, skill, journal, diff, and bytecode gate passed.
- Hosted read-only execution exposed that the bounded copy receipt incorrectly
  required a root-owned source and its nobody-owned execution copy to share one
  owner. Source object identity and access policy now retain the original owner,
  while the destination independently binds the exact execution UID and checks
  an owner-projected expected manifest; a third owner remains rejected. The
  corrected host-level deterministic gate passed 838/838 in 243.890 seconds on
  Homebrew CPython 3.13.12. The reviewed 838-test selected identity has SHA-256
  `76dedc279ab17a3033d3f87dcdbb1b6534bae68bde8837568e5bb913507e66f3`.
- The hosted summary consumer now requires the source manifest to be an exact
  lowercase 64-character SHA-256 and binds that value into the closed expected
  summary before comparison. Raw runner output remains suppressed; only a
  validated canonical JSON object reaches the workflow log, and invalid input
  exposes bounded type/length diagnostics rather than attacker-controlled
  bytes. The final precommit audit returned `No findings.` after both hosted
  regressions were closed. Contracts passed 105/105, the affected read-only
  runner passed 144/144 in 61.905 seconds, and the final host-level Python
  3.13.12 full discovery passed 2,833/2,833 tests in 1008.735 seconds with six
  platform skips.
- Fresh prior-bundle Codex review of signed head
  `7fd02b0ec52f0e60f5fd221cbf12ae40f44e70d0` found that the Trusted Mac gate
  compiled mutable local modules without proving exact committed content and
  that destination copies projected the execution UID but retained the source
  GID. That head and all head-bound review or CI evidence are stale. The
  replacement binds a complete checked source inventory to an externally
  supplied exact-HEAD or release-publication digest before compilation, and it
  projects both the execution UID and GID from the held install-container
  policy while retaining source identity and access policy separately.
- The corrected host-level deterministic gate passed 839/839 in 241.339
  seconds on Homebrew CPython 3.13.12. The reviewed 839-test selected identity
  has SHA-256
  `7eae7f29771b98d6ddef11365c2896b25f8a216b80d168464ffe5dec8e0b73fd`.
- The same P1-corrected tree passed the complete host-level Python 3.13.12
  discovery, 2,833/2,833 tests in 941.501 seconds with six existing platform
  skips. Repository contracts passed 105/105 in 8.167 seconds after the journal
  identity update.
- PR #86 run `30736565697`, job `91466273221`, exposed a raw fixture
  `subprocess.run` timeout that left descendant closure unproven. All five raw
  process launches in `test_git_checkout.py` now use the existing bounded
  process-group owner without extending their deadlines. A real fake-Git
  timeout regression proves leader, TERM-ignoring same-group descendant, and
  process-group absence before return. After synchronizing the exact Trusted
  Mac source manifest, the final host-level Python 3.13.12 deterministic gate
  passed 840/840 in 269.450 seconds. The reviewed 840-test selected identity
  has SHA-256
  `6d40334cf49865b44402c49233a9f820b722eb9cb5f35de646f42194b6345fa0`.
  The earlier manifest-mismatch run is non-counting.
- The next hosted run proved that `/usr/bin/git` is an Xcode-selection shim,
  not the Git implementation the gate intended to trust. The hosted gate now
  constructs the Git executable and `git-core` exec path directly below one
  fixed `DEVELOPER_DIR`; it rejects the shim and symlink/escape cases, binds
  executable content, code-signing and loader evidence, inventories and hashes
  the bounded helper closure including resolved symlink targets, and compares
  one canonical closed-schema JSON receipt before launch and after return. It
  never calls `xcrun`, and every Git argv uses the measured executable with the
  exact exec path.
- The dedicated account receives only the validated owner-private runtime
  `TMPDIR`; fixture sanitization carries that value explicitly rather than
  inheriting or discarding an ambient path. The sandboxed gate consumes the
  previously measured version hash instead of launching Git inside its
  no-child boundary. Receipt mode itself runs under isolated Python with a
  ten-second Git deadline and fixed output cap. Closed-schema, helper-escape,
  target-content mutation, environment completeness, and canonical-payload
  regressions passed. The regenerated Trusted Mac source manifest binds these
  exact source bytes, and the final deterministic gate passed 846/846 in
  292.588 seconds. The reviewed 846-test selected identity has SHA-256
  `cf927546fed88325300574c2c802f42b63a2038ac0a22322e0fa773a48e317b8`.
- PR #86 run `30741504176`, job `91479663871`, found that the source-binding
  live integration fixture still bypassed the receipt-bound Git toolchain for
  its raw `/usr/bin/git init`. The `assume-unchanged` case hit the unchanged
  ten-second deadline and left the 846-test hosted suite with one error after
  254.968 seconds. The integration owner now derives argv from the selected
  direct Git executable and derives the exact exec path and owner-private
  `TMPDIR` from the bound Git environment before launching through the bounded
  process owner; stderr remains a hard failure.
- The exact failing case and launch-contract regression passed 2/2, the whole
  source-binding integration class passed 14/14, and the affected read-only
  runner module passed 151/151. The regenerated trusted source manifest and
  deterministic selection passed 847/847 in 356.893 seconds on host-level
  Python 3.13.12. The reviewed 847-test selected identity has SHA-256
  `93cbe4c702f25d1cf3c5fdc1170f55df5217f6dad4ba170085b4aae63621a897`.
- The `acb1182dbcab61ab6076e661c35088719dac2f35` local named-single preparation
  is zero-start and non-counting: materialization and validation completed, no
  reviewer agent or model started, no output or findings were produced, and the
  independent task root was cleaned before any superseding-head work.
- The first 2,834-test full discovery was intentionally non-counting because the
  Desktop sandbox denied Unix and loopback socket binds, yielding 7 failures
  and 11 errors after 1203.084 seconds. Repeating the exact frozen tree on the
  same Python 3.13.12 runtime outside that sandbox passed 2,834/2,834 in
  1036.788 seconds with six existing platform skips.
- The prior-bundle fresh Codex retry for exact head
  `e8a0080de284711893c416f7ca546182e748c9fa` returned one P1: the Trusted Mac
  bootstrap still ran its first `cat-file` through candidate-local Git config,
  so a missing promisor blob could trigger lazy fetch, credential or remote
  helpers, object-store writes, and external commands before isolated Python
  started. The independent reviewer workspace was safely cleaned, and the
  prior-b4ca control manifest remained
  `b383222c430ab57779a750d137d509db885b235ca5bdb5ace2845ccdb7d3c71b`.
  That finding makes all e8a admission, CI, Claude, and review evidence stale.
- The replacement bootstrap uses an empty owner-private control repository and
  the candidate object directory only as a read-only alternate. A real
  malicious-promisor regression proves that the unsafe source-local query
  starts an `ext::` helper, while the isolated query fails with no stdout,
  helper start, or object materialization. Two bounded precommit audits then
  required a positive alternate read before the missing-object failure, full
  source/control object-store inventory comparison, recursive source/control
  ACL rejection, rejection of local/HTTP alternate metadata and promisor pack
  markers, and a final operator-side Git executable/digest/exec-path custody
  check after both streamed gate executions. All five findings were fixed.
  Final repository contracts passed 107/107 in 8.982 seconds. Extracted
  workflow and operator shell passed `bash -n` and ShellCheck 0.11.0; Ruby
  Psych parsed the workflow and canonical/private fixture parity remained
  enforced. One exact 120-second actionlint run timed out with empty output and
  is tooling-inconclusive rather than a lint result.
- A Desktop-sandbox deterministic run was non-counting after Git emitted
  `DARWIN_USER_TEMP_DIR` fallback warnings to stderr, causing 22 failures and 2
  errors. The affected source-binding class passed 14/14 in 20.942 seconds at
  host level. After all precommit findings were fixed, the same Python 3.13.12
  host runtime passed the complete deterministic selection 847/847 in 283.459
  seconds with unchanged identity
  `93cbe4c702f25d1cf3c5fdc1170f55df5217f6dad4ba170085b4aae63621a897`,
  followed by full discovery 2,835/2,835 in 1058.164 seconds with six existing
  platform skips.
