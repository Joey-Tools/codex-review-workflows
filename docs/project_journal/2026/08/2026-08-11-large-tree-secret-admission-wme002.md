---
id: 20260811-wme002
title: Large-Tree Secret Admission Streaming
status: active
created: 2026-08-11
updated: 2026-08-11
branch: wip/private-catalog-exact-scan-budget
pr:
supersedes: []
superseded_by:
---

# Large-Tree Secret Admission Streaming

## Summary

- Required PR/master secret admission now scans complete frozen endpoint trees
  without first buffering the endpoint's entire blob payload under the helper's
  512 MiB materialization budget.
- The endpoint scanner retains the 64 MiB per-blob bound and charges every
  tree-entry blob occurrence against a 2 GiB total matching the named-lane
  checkout contract. Duplicate OIDs remain separate occurrences for exact and
  opaque multiplicity.
- Sized tree metadata drives bounded `cat-file --batch` groups. Every response
  is bound to its expected OID, type, size, delimiter, and exact output ceiling.
- The installed private overlay exposed a second large-tree boundary that the
  public catalog could not exercise: 17 exact legacy values require more than
  the generic 16 GiB occurrence-search budget across the real WME endpoint.

## Current State

- Endpoint metadata, blob batches, and per-blob parsing share one 900-second
  deadline that is rechecked at every blob boundary. A scan
  is also capped at 64 blob-batch invocations, 128 MiB payload and 8,192 entries
  per batch, 100,000 tree entries, and 128 MiB of tree metadata.
- The batch payload bound is asserted to be at least the existing 64 MiB
  per-blob limit, so batching cannot silently introduce a second per-file cap.
- The canonical `cat-file` header parser reads at most 128 bytes and does not
  include untrusted header bytes in errors. Frozen-tree size mismatches fail
  before any payload scan.
- Each frozen-tree blob uses one complete context already bounded to 64 MiB;
  the endpoint itself remains streamed. This avoids quadratic prefix replay
  when arbitrary binary chunk boundaries expose overlapping incomplete
  assignment shapes. The generic streaming scanner separately permits at most
  1,024 monotonic retreats under its unchanged shared proof-work budget.
- Event, exact-value, legacy-occurrence, reduction-provenance, and opaque
  container budgets persist across batches. Per-blob streaming state resets at
  each object boundary, and path-sensitive reduction identities are derived
  before offsets are discarded.
- Frozen endpoint exact counting now has a distinct 68 GiB search-work budget,
  equivalent to 32 complete fixed-pattern passes over both the 2 GiB blob
  envelope and the conservatively bounded 128 MiB path-metadata envelope.
  Generic workspace scanning retains the existing 16 GiB bound.
- Changed-location scanning remains separately capped at 512 MiB. A location
  failure cannot erase an exact-value growth violation proved by the complete
  endpoint count.

## Evidence

- Focused regression coverage exercises decreasing shared timeouts, batch
  invocation exhaustion, exact batch-output ceilings, bounded non-disclosing
  headers, pre-payload size mismatch rejection, missing delimiters, duplicate
  OID exact counts, duplicate opaque multiplicity, occurrence-based total
  boundaries, and independent changed-location failure. Multi-retreat
  streaming coverage also consumes real proof ranges: discarded speculative
  coverage may temporarily overdraft, the final complete replay must fit the
  committed coverage budget, and all speculative proof work remains charged.
- The 2 GiB endpoint limit is contract-tested against
  `MATERIALIZER_CHECKOUT_BLOB_BYTES_LIMIT` rather than copied without a drift
  detector.
- The real WME range completed all four internal count passes against its full
  local object store. Base/head discovery took 550.318 and 552.406 seconds;
  base/head exact-only counting took 3.149 and 3.217 seconds. The earlier
  35,388,008-byte Mach-O regression object completes in 11.3 seconds with the
  size-bound complete-context path instead of exhausting prefix-proof work.
- Python 3.10 validation completed 300 `test_workspace.py` tests with one
  expected skip and 228 `test_named_lane.py` tests with no failures. Full
  discovery ran 2,924 tests with 15 expected skips; its only failure was the
  macOS nested-sandbox probe rejected by the outer Codex sandbox with
  `sandbox_apply: Operation not permitted`, and that exact test passed when
  rerun outside the outer sandbox.
- The public `isolated_review secret-admission` command completed for WME range
  `982b02b6d29ad6b26b2e8aa0fbb306e78a1f20aa..e66e22604d60b9525fa6501613a508ec4cf0bca2`
  with exit code 0, `status: clean`, `location_status: complete`,
  `temporary_cleanup_status: complete`, and `reviewer_started: false`.
- The first installed private release attempts returned exit code 75 with
  `failure_class: exact-value-scan-incomplete` and complete temporary cleanup
  against both the shallow implementation worktree and the full non-shallow
  WME source. Both endpoint trees had zero missing objects with lazy fetching
  disabled, so this is not an object-completeness failure.
- A direct installed-runtime diagnostic completed base/head discovery in
  540.107/555.368 seconds, found one dynamic exact candidate, and entered the
  count pass with 18 patterns. The base count then failed in 4.303 seconds with
  `external review content exceeds the legacy synthetic search limit`; the
  failing blob had 2,089,920 bytes while only 3,526,144 search bytes remained.
  This isolates the old 16 GiB search-work budget rather than the endpoint
  deadline, object store, or batch parser.
- A 17-pattern regression forces the generic search budget below one scan and
  proves direct frozen endpoint admission uses the catalog-scale budget while
  remaining clean and reviewer-free.
- The candidate runtime then loaded the installed private catalog and completed
  direct admission for the real full WME range with exit code 0, `status:
  clean`, complete location mapping and temporary cleanup, zero violations,
  and `reviewer_started: false`.
- Fresh Codex review found that the initial 64 GiB derivation covered 32 full
  blob passes but omitted raw-path search work charged to the same monotonic
  budget. The corrected derivation adds one bounded tree-metadata envelope per
  pass, and the unit test consumes all 32 maximum blob and path surfaces without
  allocating endpoint-sized fixtures before proving the next byte fails closed.
- Focused validation is clean on Python 3.14.6: all 113 public-pool scanner
  tests, all 190 synthetic-token tests, and 302 workspace tests passed; the
  workspace class retained one expected skip. The separate frozen-budget
  exhaustion case also passed and remained reviewer-free with complete cleanup.
- After the review fix, the complete local suite passed outside the outer Codex
  sandbox with a PATH that resolves executable Python shebangs to the supported
  Homebrew runtime: 2,927 tests passed in 631.777 seconds with seven expected
  skips. Three earlier inherited-PATH failures had selected macOS Python 3.9 for
  a `>=3.10` entrypoint; the fourth was the outer sandbox rejecting the suite's
  nested `sandbox-exec`.
- The corrected candidate runtime re-ran real WME admission against the installed
  private catalog and completed with exit code 0, `status: clean`, complete
  location mapping and temporary cleanup, zero violations, and
  `reviewer_started: false`.
- Runtime implementation:
  `skills/review-orchestration-playbook/scripts/review_runtime/workspace.py`.
- Regression coverage:
  `skills/review-orchestration-playbook/tests/test_workspace.py`.

## Remaining Gates

- Complete focused and full canonical tests, fresh review, exact-secret
  admission, PR/CI, merge, and immutable public/private release publication.
- Install the resulting private overlay and re-run required admission for WME
  range
  `982b02b6d29ad6b26b2e8aa0fbb306e78a1f20aa..e66e22604d60b9525fa6501613a508ec4cf0bca2`
  with the installed trusted release. A clean result with complete temporary
  cleanup is the downstream acceptance gate.
