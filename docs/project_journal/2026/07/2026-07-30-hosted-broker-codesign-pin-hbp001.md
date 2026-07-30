---
id: 20260730-hbp001
title: Hosted Broker Codesign Pin
status: completed
created: 2026-07-30
updated: 2026-07-30
branch: wip/broker-codesign-pin-refresh
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/85
supersedes: []
superseded_by:
---

# Hosted Broker Codesign Pin

## Summary

- Keep broker reproducibility fail closed while GitHub rolls macOS runners from
  macOS 26.4 to 26.5.2.
- Select the reviewed host `codesign` digest by exact OS version and build.
- Emit the observed SHA-256 for every verified broker build input so future
  runner drift is directly auditable.

## Current State

- Hosted macOS 26.4 build `25E246` accepts only
  `06eacc36d43376972d3bca0a2137ea4efd6d0fe27de8a7af0e6b11d599e8f337`.
- Hosted macOS 26.5.2 build `25F84` accepts only
  `214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7`.
- Any other hosted OS version/build remains blocked before the broker is built.
- Source, artifact, Xcode, SDK, clang, linker, lipo, vtool, and
  `codesign_allocate` pins are unchanged.

## Next Steps

- None in this repository. The private overlay sync publishes this catalog with
  the rest of the reviewed control plane.

## Evidence

- Private overlay PR #139 job `90795685398` ran on image
  `20260728.0273.1` and isolated the drift to `/usr/bin/codesign`; every earlier
  fixed input passed.
- Canonical PR #85 job `90798189131` passed on image `20260720.0258.1`,
  proving the legacy OS build and digest remain active during rollout.
- Canonical PR #85 rerun job `90800935103` ran on image
  `20260728.0273.1` and reported the exact new digest before failing closed.
- Local `--developer-check` reproduced the pinned broker artifact exactly with
  the unchanged source, toolchain, signing identity, and CDHashes.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
