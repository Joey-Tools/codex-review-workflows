---
id: 20261010-prb001
title: Bound the Private Reconciliation CI Budget
status: completed
created: 2026-10-10
updated: 2026-10-10
branch: codex/private-reconciliation-ci-budget-20261010
pr:
supersedes: []
superseded_by:
---

# Bound the Private Reconciliation CI Budget

## Outcome

The canonical private CI fixture gives the complete latest-Python reconciliation
safety module a ten-minute step budget and verbose per-test progress. The
twenty-minute parent job cap, all test cases, the independent supervisor,
hosted-runner fail-closed check, byte reproduction, and required aggregate remain
unchanged. A regression contract preserves the bounded step, setup-success
condition, full module invocation, and progress output.

## Evidence and Decision

Private source-promotion PR221 at `05545303ad3b46f5f1b4398d388bc44928a58bec`
failed job `114076606574` in run `38006569481`. Its 851 deterministic supervisor
tests passed in 275.150 seconds. The subsequent CPython 3.14.7 reconciliation
step reached its existing two-minute deadline; this was a real CI failure, not
a review-provider or quota error.

An independent native CPython 3.14.2 run of the unchanged complete module passed
all 326 tests in 175.256 seconds (bounded supervisor: exit zero, 176.406 seconds,
no incomplete result; raw log SHA-256
`eb50e39a2be59afd0ec9abdcb73ae8bd5f66e8cb808357ffeed89a00afbd11c6`).
This demonstrates an insufficient 120-second budget without claiming the local
runtime reproduces the hosted runtime exactly. The ten-minute limit leaves
finite hosted-runner headroom; verbose output identifies the active case if a
later execution stalls.

The fixture is the canonical source of the private workflow and its embedded
skill snapshot. Downstream byte-equality and provenance guards must stay intact:
promote the merged canonical source through the normal source-lock refresh and
generator, then update the consumer-owned budget assertion. Do not hand-edit
generated copies or treat the failed old-head CI as infrastructure recovery.

## Delivery Boundary

Focused canonical repository contracts passed: 43 tests in 3.996 seconds,
one private-layout-only skip, bounded supervisor exit zero and no incomplete
result (log SHA-256
`ecc7a78a5b8a4fa6bbbc30e85d05f5fbead0536c97bfea83ac28ede2b47fe06c`).
Skill validation, journal validation, and whitespace checks also passed.

This focused source fix does not claim PR221 review, merge, release, installation,
or PR190 cleanup is complete. Those outcomes retain their own exact-head gates.
