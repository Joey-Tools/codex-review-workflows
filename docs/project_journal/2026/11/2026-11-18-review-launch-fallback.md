---
id: 20261118-review-launch-fallback
title: Make Routine Review Startup Explicit
status: completed
created: 2026-11-18
updated: 2026-11-18
branch: codex/review-launch-fallback
pr:
supersedes: []
superseded_by:
---

# Make Routine Review Startup Explicit

## Summary

- Keep GPT-6.1 Sol with Daybreak off as the default; retain GPT-6 Sol with Daybreak on when the user authorizes that fallback.
- Select model, reasoning, Daybreak, and adapter together, preserving explicit user choices and the frozen read-only review scope.
- Recover from the actual startup error, and reuse a working configuration within the task across later heads.
- Route startup guidance through one existing reference. No launcher, model probe, runtime guard, or test matrix is added.

## Validation

- Skill metadata, existing policy contracts, relative links, and private-consumer export compatibility are checked before landing.
- The user-requested fresh-context Sol and Luna rereads assess clarity, redundancy, and decision traces; their results remain in the task and PR records.
