---
id: 20261115-local-review-snapshots
title: Review Explicit Uncommitted Local Snapshots
status: completed
created: 2026-11-15
updated: 2026-11-15
branch: wip/local-review-snapshots
pr:
supersedes: []
superseded_by:
---

# Review Explicit Uncommitted Local Snapshots

## Summary

Routine local review can inspect an explicitly requested uncommitted snapshot
without creating a project commit or changing the source refs and index.

## Current State

- Parent-selected final files and deletions form a content-bound packet beside the independent clean committed baseline.
- Capture checks content and executable mode; benign timestamps, directory churn, and same-content replacement do not invalidate the protected property.
- Untracked files require explicit selection, and failed reads and unsupported filesystem objects remain incomplete.
- Snapshot disposition has its own identity and cannot claim a reviewed commit head or merge approval.
- Delivery guidance checks known consumer export and installation compatibility before source landing.

## Evidence

- Snapshot/disposition and repository contract tests cover staged and unstaged content, binary and executable files, deletions, retained identity, source Git preservation, benign metadata changes, true content changes, and unsafe file types.
- Real CLI capture/validation and consumer compatibility preflight run without source mutation.
