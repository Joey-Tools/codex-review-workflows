---
id: 20260721-rbh001
title: Private Overlay Release Blocker Hotfixes
status: completed
created: 2026-07-21
updated: 2026-07-21
branch: codex/release-blocker-hotfix
pr:
supersedes: []
superseded_by:
---

# Private Overlay Release Blocker Hotfixes

## Summary

- Removed a cleanup race in which concurrent observer probes could impersonate a live runner and concurrent first-use `cleanup.lock` initialization could fail identity validation.
- Made the secret source-proof watermark regression independent of the active synthetic-token catalog's first value length.

## Current State

- The runner keeps its exclusive lifetime lease while `status`, `wait`, and cleanup use compatible shared liveness probes.
- Cleanup acquires the bound container directory lock before creating or validating `cleanup.lock`, then acquires the compatibility lock and preserves that descriptor order for worker handoff.
- Legacy lock migration, no-follow identity validation, path-replacement rejection, and independent-open-file-description lease checks remain fail-closed.
- The watermark regression uses a fixed local accepted descriptor and therefore exercises the same per-assignment proof limit under public and private catalogs.

## Next Steps

- None.

## Evidence

- https://github.com/Joey-Tools/codex-private-workflows/actions/runs/29822399814
- The full Python 3.13 review-workflow suite passed 1,367 tests in 353.208 seconds with 5 skips.
- The concurrent cleanup regression passed 30 consecutive Python 3.13 iterations.
- `test_state` passed 167 Python 3.13 tests.
- `PublicPoolScannerTest` passed 100 Python 3.13 tests.
- Ruff lint and format checks, Python bytecode compilation, the skill validator, the project-journal validator, and `git diff --check` passed.
