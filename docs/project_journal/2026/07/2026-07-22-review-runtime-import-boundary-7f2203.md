---
id: 20260722-7f2203
title: Decouple Review Runtime Package Imports
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: wip/review-runtime-lazy-import
pr:
supersedes: []
superseded_by:
---

# Decouple Review Runtime Package Imports

## Summary

- The low-level helper loads the sibling Claude stream validator only when stream validation or runtime binding actually needs it.
- Package consumers can load `review_runtime` and `synthetic_tokens` without adding the scripts directory to `sys.path`, matching the private-overlay sync contract.

## Current State

- The provider keeps the existing validator implementation and runtime behavior while removing its import-time dependency on a top-level sibling module.
- An isolated-Python regression loads the package, provider, and synthetic-token parser through package metadata alone and proves that the sibling validator remains unloaded.
- The change deliberately avoids `review_runtime/__init__.py`, which is concurrently modified by PR #72.

## Next Steps

- None for this workstream.

## Evidence

- Triggering private-overlay sync failure: https://github.com/Joey-Tools/codex-private-workflows/actions/runs/29905797329
- Upstream authentication/runtime change: https://github.com/Joey-Tools/codex-review-workflows/pull/63
- Non-overlapping concurrent work: https://github.com/Joey-Tools/codex-review-workflows/pull/72
