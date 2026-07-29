---
id: 20260727-rsr001
title: Review Runtime State Root
status: completed
created: 2026-07-27
updated: 2026-07-29
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
  proof fails closed. Explicit checkout-parent lookup remains independent and
  lazy.
- Installed overlays fail closed when any sibling release still has a
  release-local retained attempt. Operators must explicitly select that old
  retention root and drain it before using the account-local default.
- The scanner always fences the currently executing helper's own
  `runtime/retention` root before optionally enumerating a standard installed
  overlay catalog. Self-contained and other nonstandard layouts therefore
  retain the same migration protection, while the current standard release is
  skipped only in the sibling pass to avoid duplicate locking.
- Releases that use account-local retention carry a source-controlled
  `ACCOUNT_LOCAL_RETENTION_V1` capability marker. The scanner validates its
  exact bytes, owner, mode, link count, ACL/xattr policy, and object identity,
  then rereads the held descriptor in full and requires identical bytes.
  Same-inode same-size writes are rejected even when the path is restored;
  benign timestamp drift is ignored. An unmarked installed helper without an
  existing legacy lock is blocked before the public command can run, rather
  than treating one absent-path observation as proof that an old version
  cannot start later.
- The legacy scan walks from an ACL/xattr-validated releases-root descriptor
  through `O_NOFOLLOW` child descriptors. It binds object identity and access
  policy with device, inode, type, owner, and mode while deliberately ignoring
  timestamps, directory size, and link count.
- The scanner acquires every existing legacy `retention.lock` with a
  nonblocking exclusive flock, enumerates attempts while holding that fence,
  and retains it through the default-root command plus final path/catalog
  revalidation, including when the command itself fails. Active old writers,
  empty unfenced roots, newly appeared roots, ACL drift, and ancestor
  replacement all fail closed.
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
- Canonical and private reviewed CI fixtures use in-memory `compile(...)`
  syntax validation and explicit zero-cache guards.

## Next Steps

- Sync the canonical change into the private overlay and publish a trusted release.

## Evidence

- A fresh private-overlay Codex review identified the release-local runtime
  state and explicit-bytecode workflow gaps on the synced canonical control plane.
- Fresh-context Codex review found that moving the defaults alone hid retained
  attempts in older installed releases and that the README still documented the
  obsolete release-local default. The explicit drain gate, cross-version
  regression, and corrected README close both findings.
- The final deterministic independent-supervisor gate passed 582/582 in
  176.726 seconds with the reviewed 591-test discovery identity and SHA-256
  `bf7a3f7476d7e08d51f2b20354bb074034ec92f5a97c6e81cf43e98abb1c4967`.
- The final platform suite ran 2,819 tests with 6 skips in 1,041.337 seconds.
  Its only failure was the known parent-sandbox denial of nested
  `sandbox-exec`; that exact broker test passed 1/1 outside the parent sandbox
  in 2.363 seconds.
- The complete 99-test contract module passed in 6.930 seconds.
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
- The focused post-fix CLI and secure-I/O modules passed 61/61 tests in 19.690
  seconds on Python 3.13.
- Ruff lint/format, actionlint for canonical and private CI profiles,
  source-only syntax checks, project-journal validation, `git diff --check`,
  and the zero-bytecode inventory passed.
- No local Python 3.10 run is required for this delivery; local validation uses
  Python 3.13 only.
