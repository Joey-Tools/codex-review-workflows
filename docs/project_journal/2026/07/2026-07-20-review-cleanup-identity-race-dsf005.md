---
id: 20260720-dsf005
title: Review Cleanup Identity Race
status: completed
created: 2026-07-20
updated: 2026-07-20
branch: codex/daily-skill-friction-20260720-codex-review-workflows-review-cleanup-identity-upstream
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/66
supersedes: []
superseded_by:
---

# Review Cleanup Identity Race

## Summary

- Prevented concurrent cleanup waiters from treating legitimate state-directory child-entry changes as directory replacement.

## Current State

- State-directory identity uses stable device, inode, mode, and owner metadata.
- Content-derived link counts and timestamps no longer invalidate an otherwise unchanged directory.
- Descriptor-to-path replacement detection and directory ownership and mode checks remain enforced.
- The canonical public workflow records the invariant first delivered through the private overlay repair.

## Next Steps

- None.

## Evidence

- https://github.com/Joey-Tools/codex-review-workflows/pull/66
- https://github.com/Joey-Tools/codex-private-workflows/pull/125
- `python3.14 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py'` passed 1,061 tests with 4 skips.
- `python3.14 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py` passed.
- The concurrent cleanup regression passed 20 consecutive iterations.
