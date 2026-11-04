---
id: 20261104-cir001
title: Private CI Runtime Reduction
status: completed
created: 2026-11-04
updated: 2026-11-04
branch: codex/ci-reduction-review-20261104
pr:
supersedes: []
superseded_by:
---

# Private CI Runtime Reduction

## Summary

- Reduce repeated macOS CI work while retaining full Linux coverage and the existing aggregate required gate.
- This entry records the intended stable code state after merge. Runner deployment and live end-to-end acceptance remain separate and incomplete.

## Current State

- The six selected modules (`claude_provenance`, `claude_refresh_lock`, `state`, `synthetic_tokens`, `validate_claude_stream`, and `workspace`) retain full Linux execution. macOS runs 11 existing cases selected for native Darwin behavior; `claude_provenance` has no selected macOS case because its Darwin-facing cases mock `otool` rather than exercise native behavior.
- The macOS selection covers refresh-lock heartbeat and identity checks; state lock-path replacement and nonblocking FIFO/path-swap probes; secure synthetic-token file loading; Claude stream FIFO, workspace-boundary, and stream-binding checks; and workspace raw-path batching/round-tripping.
- Project-journal tests and the standalone private-overlay-sync test job are Linux-only. The 202 regular-overlay-uninstall status-regression cases run in four deterministic shards, with the shard job's module coverage unioned into the aggregate required result.
- Runtime reduction is admitted only when trusted-base proof establishes that the only changed file is the source lock, only source commit SHAs changed, and each old/new source commit has the same verified tree. The classifier and source-admission gate apply across pull-request CI, private-overlay release, and scheduled sync. Ambiguous or failed classification retains the full runtime path.
- Native CI uses a fail-closed probe and does not change the production pin. A disposable macOS runner slot is implemented with a fixed-root helper and lease; this records implementation only, not host activation.
- A bounded manual run of the 202 uninstall cases passed in four shards (51, 51, 50, and 50 cases) in 30:35.548 total. This measured the same-source-tree test subset, not the complete CI workflow; the historical comparison was not a controlled-load benchmark.
- The self-hosted host remains paused. No live end-to-end run on an activated disposable macOS slot has established deployment acceptance.

## Next Steps

- Keep the host paused until its separate readiness and activation conditions are met.
- After activation, run and record live end-to-end CI evidence for the disposable macOS slot; do not infer deployment success from fixture tests or the targeted shard measurement.

## Evidence

- Canonical workflow fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Canonical workflow contracts and source admission: `skills/review-orchestration-playbook/tests/test_contracts.py` and the private CI source-admission tests.
- The four-shard timing is a targeted manual measurement of the 202-case uninstall subset, not whole-workflow runtime evidence.
