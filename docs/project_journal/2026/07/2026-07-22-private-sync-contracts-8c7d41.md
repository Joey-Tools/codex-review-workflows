---
id: 20260722-8c7d41
title: Repair Private Sync Contracts
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: wip/private-sync-contracts
pr:
supersedes: []
superseded_by:
---

# Repair Private Sync Contracts

## Summary

- Refresh the reviewed private CI profile to match the private repository's current workflow.
- Make the no-legacy-exemptions source-WIP regression independent of the installed private synthetic-token catalog.

## Current State

- The private profile includes the current Linux isolation dependencies, user-namespace setup, launcher C syntax check, and real isolation integration test.
- The source-WIP regression explicitly uses one catalog with no legacy exemptions for both workspace preparation and validation.
- The changed fixture and synthetic-token test do not overlap the files changed by public PR #72.

## Next Steps

- None for this workstream.

## Evidence

- Triggering private-overlay sync run: https://github.com/Joey-Tools/codex-private-workflows/actions/runs/29915138504
- Import-boundary follow-up: https://github.com/Joey-Tools/codex-review-workflows/pull/77
