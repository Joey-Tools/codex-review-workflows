---
id: 20260717-7f1701
title: Preserve Review Wait Continuity
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-review-workflows-healthy-review-wait-continuity
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/57
supersedes: []
superseded_by:
---

# Preserve Review Wait Continuity

## Summary

- Clarified that a healthy reviewer's bounded wait expiry is an intermediate poll rather than task completion.

## Current State

- Parent workflows stay active through bounded status/wait polling until `stateful final` is terminal or a real blocked/inconclusive decision point is reached.
- Contract coverage protects the task-continuity wording in the canonical review skill.

## Next Steps

- Watch for fresh review tasks that still require a manual continuation while the reviewer is healthy.

## Evidence

- Daily Skill Friction sessions `019f615b-2f9b-7073-a804-f21a7d6f0f34` and `019f62a6-a37a-7d21-b8e9-10df10aab9eb` ended a parent task while their reviewers were still healthy.
- Five real main sessions required nine manual `please continue` messages during nonterminal review/test waits.
- https://github.com/Joey-Tools/codex-review-workflows/pull/57
