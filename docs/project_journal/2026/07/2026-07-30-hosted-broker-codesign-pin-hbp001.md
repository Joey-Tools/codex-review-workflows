---
id: 20260730-hbp001
title: Hosted Broker Codesign Pin
status: completed
created: 2026-07-30
updated: 2026-08-01
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
- Select the hosted no-child blocker profile from the exact reviewed
  OS/build/Darwin/Python catalog instead of pinning the workflow to one runner
  generation.

## Current State

- Hosted macOS 26.4 build `25E246` accepts only
  `06eacc36d43376972d3bca0a2137ea4efd6d0fe27de8a7af0e6b11d599e8f337`.
- Hosted macOS 26.5.2 build `25F84` accepts only
  `214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7`.
- Any other hosted OS version/build remains blocked before the broker is built.
- Hosted no-child fail-closed probing accepts only the exact reviewed
  macOS 26.4 build `25E246` or macOS 26.5.2 build `25F84` runtime fingerprint;
  an unknown runtime fails before the probe.
- Source, artifact, Xcode, SDK, clang, linker, lipo, vtool, and
  `codesign_allocate` pins are unchanged.
- Hosted read-only execution enters the source-only gate through bounded stdin
  under `-I -B -S`; the candidate path is never the Python entrypoint. Its
  root-owned staged source uses a bounded descriptor manifest and copy rather
  than an unbounded recursive copy.

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
- Fresh Codex review found that the independent-supervisor job still selected
  only the legacy 26.4 no-child profile while the broker job had admitted
  26.5.2.
- Canonical PR #85 rerun job `90814780194` then ran on macOS 26.5.2 build
  `25F84`, Darwin `25.5.0`, with `/usr/bin/sandbox-exec` SHA-256
  `8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16`,
  proving the legacy-only workflow failed closed on the new runner generation.
- Local `--developer-check` reproduced the pinned broker artifact exactly with
  the unchanged source, toolchain, signing identity, and CDHashes.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
- A fresh control review found that shell size/digest predicates could fall
  through and that installed-release validation reopened the gate path for
  execution. The corrected runbook exits explicitly on every predicate failure
  and uses parent-validated Python to read one no-follow descriptor, validate
  the manifest digest over those exact bytes, and stream that same memory image
  to the isolated gate. The executable regression accepts the bound input and
  rejects digest mismatch, oversize, symlink, hard-link, and FIFO inputs before
  any candidate byte reaches the consumer. Frozen Git size and digest producer
  failures also terminate before the gate pipeline.
- The canonical/fixture hosted workflows remain byte-for-byte aligned after
  moving the outer gate to stdin. Private overlay synchronization and release
  are owned by the separate BL workstream; this canonical follow-up does not
  modify or trigger private PR #139 or #140.
