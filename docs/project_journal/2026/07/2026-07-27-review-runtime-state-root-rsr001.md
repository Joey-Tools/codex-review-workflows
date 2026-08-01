---
id: 20260727-rsr001
title: Review Runtime State Root
status: completed
created: 2026-07-27
updated: 2026-07-31
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
  child-FD settlement, and recovery directory-FD custody changes passed 776/776
  deterministic tests in 90.357 seconds on the same uv-managed
  CPython 3.13.13 runtime. The reviewed 776-test selected identity has
  SHA-256
  `e7a7ac91c591d27a82b26f6e7a412364c171ee5832913aed5d8fcef05f70fc02`.
  Runtime-root custody continues to bind object identity independently from
  access-policy evidence: directory child churn is benign, while pathname
  replacement, content mutation, unreadable revalidation, and policy drift
  remain distinct fail-closed outcomes.
- The post-CI correction rejects non-3.13 interpreters before importing the
  supervisor package, so unsupported runtimes cannot replace the stable version
  diagnostic with an import failure. The complete contract module passed
  105/105 on the uv-managed CPython 3.13.13 runtime.
