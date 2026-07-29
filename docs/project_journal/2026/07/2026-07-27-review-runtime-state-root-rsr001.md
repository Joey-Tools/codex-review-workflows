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
- Default account lookup is lazy, remains inside the CLI failure boundary, and
  is skipped when both task-scoped roots are supplied explicitly.
- Installed overlays fail closed when any sibling release still has a
  release-local retained attempt. Operators must explicitly select that old
  retention root and drain it before using the account-local default.
- The legacy scan binds directory object identity and access policy with
  device, inode, type, owner, and mode. It deliberately ignores timestamps,
  directory size, and link count, then revalidates the release catalog and
  retention path after enumeration.
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
- The deterministic independent-supervisor gate passed 555/555 in 228.570
  seconds with the reviewed 564-test discovery identity and SHA-256
  `1f5dbc7f624832d8dd3b16870238a35180030675684ddcc61e6057f8b90b778d`.
- The post-fix platform suite ran 2,819 tests with 6 skips in 1,372.989 seconds.
  Its only failure was the known parent-sandbox denial of nested
  `sandbox-exec`; that exact broker test passed 1/1 outside the parent sandbox
  in 2.922 seconds.
- The complete 99-test contract module passed in 7.680 seconds.
- Focused installed-symlink immutability, default state-root, CI snapshot, and
  no-bytecode entrypoint regressions passed. The new cross-version tests also
  prove explicit old-root visibility and fail-closed release replacement.
- Fresh-context Codex review found eager account-home resolution outside the
  JSON failure boundary. The follow-up makes defaults lazy and covers both
  lookup failure and explicit-root bypass.
- Ruff lint/format, actionlint for canonical and private CI profiles,
  source-only syntax checks, project-journal validation, `git diff --check`,
  and the zero-bytecode inventory passed.
- No local Python 3.10 run is required for this delivery; local validation uses
  Python 3.13 only.
