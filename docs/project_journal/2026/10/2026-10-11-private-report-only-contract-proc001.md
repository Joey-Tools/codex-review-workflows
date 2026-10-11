---
id: 20261011-proc001
title: Private Layout Report-Only Contract Compatibility
status: completed
created: 2026-10-11
updated: 2026-10-11
branch: wip/private-layout-report-only-contract-20261011
pr:
supersedes: []
superseded_by:
---

# Private Layout Report-Only Contract Compatibility

## Outcome

The report-only contract test inspects the denial clause in the exact bare
named-review AGENTS rule. It requires branch creation, commits, push,
PR creation/update, and merge to remain prohibited without requiring the
canonical sentence's exact conjunctions. The private policy's additional
mutation, metadata, Actions, and transport restrictions remain unchanged.

A regression accepts both canonical and private wording. Removing any one of
the five operations from either denial remains detectable even when a later,
unrelated rule mentions that operation. No existing test method is removed.
Production controls, generated private policy, CI, and authorization rules
are unchanged.

## Validation

Python 3.13.0 passed 134 relevant canonical contract, carrier, recovery,
local-lane, and trusted-manifest tests (one private-layout-only skip).
The stock private text replacement function was independently checked against
the existing generated test, then used in memory to project this successor.
All 48 repository contracts passed against the real private layout, including
its CI matrix; no generated file was edited for this proof.
Selected Ruff, skill metadata, journal frontmatter, and whitespace checks pass.
These results do not claim remote review, platform CI, or private release
completion; PR lifecycle evidence remains in the PR body.

## Evidence

- Canonical source: review-workflows PR135, merge
  `8e29e9f50c967d5943565117384c3e5ef4920d9c`.
- The private source-sync repair exposed the sentence mismatch after the two
  newly routed documents passed its updated exact inventory and full generator.
  This canonical test fix must land before the private source pin advances.
