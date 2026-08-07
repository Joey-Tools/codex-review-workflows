---
id: 20260807-wme001
title: Large-Repository Exact-Range Materialization
status: completed
created: 2026-08-07
updated: 2026-08-07
branch: wip/wme-range-materialization
pr:
supersedes: []
superseded_by:
---

# Large-Repository Exact-Range Materialization

## Summary

- The canonical named-lane materializer now keeps the source repository full
  while importing only the exact commit scope
  `{base_sha} ∪ (base_sha..head_sha)` and every scoped commit's complete
  recursive tree/blob snapshot closure.
- The private destination has exactly one materializer-owned shallow boundary
  at `base_sha`; graph shapes that cannot be represented by that single
  boundary fail closed.
- The WME large-repository fixture's exact inclusive-range union produced a
  629,546,021-byte pack. The bounded exact-range pack ceiling is therefore
  768 MiB, while the 250,000-object, 2 GiB logical-object, checkout, path, and
  legacy-prefix budgets remain unchanged. A separate 250,000 parent-edge
  occurrence budget now closes materialization and validation over the same
  bounded parent traversal.

## Current State

- Source shallow, promisor/partial-clone, alternate, bitmap, incomplete, and
  unsafe states remain rejected. The exact unique-merge-base result proves
  `base_sha` is an ancestor of `head_sha` before scope derivation.
- Under the exact base boundary, the destination-visible commit closure must
  equal the source scope. The total destination object inventory must then
  equal the range snapshot manifest before `fsck`, local completeness checks,
  and detached checkout.
- Materialization counts every parent token before object import under a
  format-aware output ceiling; validation independently repeats the same graph
  count. Their success receipts bind equal `commit_count` and
  `parent_edge_count` values.
- The full source `base_sha..head_sha` set must equal its `--ancestry-path`
  projection; off-corridor side history is rejected so materialization and the
  source-independent formal validator bind the same topology.
- The new `validate-worktree` interface requires the same frozen `--base` and `--head`
  as materialization. Before its first status, it revalidates both lane refs,
  exact `BASE+LF` shallow state, endpoint commits, the unique merge base, and
  exact range topology.
- Arbitrary, pre-existing, missing, additional, malformed, replaced, or
  content/access-policy-drifted destination shallow state is rejected.
  Timestamp-only churn is not treated as range mutation.
- The captured pack remains one bounded in-memory bytearray. Cleanup overwrites
  it with fixed 64 KiB chunks and clears it, avoiding a second pack-sized wipe
  allocation. Forwarded signals remain blocked across capture ownership
  publication and the complete erase/clear operation, then propagate without
  replacing an already-recorded primary failure.
- This tracked state describes the canonical target branch after its squash
  merge. Because this changes the review control plane, candidate-head code
  does not bootstrap formal review; the independently trusted prior release
  controls review, and the new materializer activates only after release.

## Downstream Deployment

- The canonical repository workstream is complete in this squash candidate.
  Sync and release the canonical squash through the private overlay.
- Reinstall the resulting public/private layers for uid 501 and uid 502.
- Complete exact WME `materialize-worktree --base ... --head ...` →
  `validate-worktree --base ... --head ...` HDR
  installed-state acceptance. Until those downstream steps pass, the larger
  overlay/install/HDR workstream remains active and final deployment is not
  claimed.

## Evidence

- WME exact inclusive-range union: 16,689 objects, 1,528,979,578 logical
  bytes, and a 629,546,021-byte pack; source base was the unique merge base of
  the seven-commit range head.
- Canonical contract:
  `skills/review-orchestration-playbook/references/review-lane-contracts.md`.
- Runtime and focused regressions:
  `skills/review-orchestration-playbook/scripts/review_runtime/named_lane.py`
  and `skills/review-orchestration-playbook/tests/test_named_lane.py`.
