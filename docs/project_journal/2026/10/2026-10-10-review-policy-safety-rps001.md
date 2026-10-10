---
id: 20261010-rps001
title: Review Request and Clean Carrier Safety
status: completed
created: 2026-10-10
updated: 2026-10-10
branch: codex/review-policy-safety-20261010
pr:
supersedes: []
superseded_by:
---

# Review Request and Clean Carrier Safety

## Outcome

Request preflight reads the complete exact-head request set and retained
transport evidence under one mutation owner. A visible request is reused.
Only independently proved non-delivery leaves an unused POST budget; empty
GET, timeout, EOF or lost response never supplies that proof.

The named `clean-issue-v2` branch accepts only the exact observed official
disclosure. Existing v1 presentation and disclosure remain unchanged.
Provider identity, exact head or stable scoped short-head resolution,
terminal lifecycle, complete pages and zero applicable unresolved findings
remain mandatory. Generic, partial and mixed disclosure prose fails closed.

## Validation

Python 3.13.0 passed 64 GitHub carrier/recovery tests and 43 repository
contracts, with one private-layout-only skip. Selected Ruff, skill validation,
whitespace and source-only checks passed. These are contract/reference-consumer
checks, not production Actions or remote reviewer pass evidence.

## Boundary

Instruction relocation and slimming are excluded. The original combined local
commit remains preserved for that later work. The private companion fixes
consumer-owned personal AGENTS text and its exact migration; generated private
skill bytes, source pins, releases and native installations are not changed by
this canonical PR.
