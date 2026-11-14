---
id: 20261114-routine-local-review
title: Make Routine Local Review Proportionate
status: completed
created: 2026-11-14
updated: 2026-11-14
branch: wip/review-policy-relaxation
pr:
supersedes: []
superseded_by:
---

# Make Routine Local Review Proportionate

## Summary

- Routine local review is the default for local/named lanes. The exact-projection audited profile and its dedicated role remain explicit opt-ins.
- Keep machine receipts in the parent, use a compact semantic reviewer task, and distinguish recoverable diagnostics from missing necessary evidence or a broken read-only boundary.
- Review final differences and necessary interfaces; inspect intermediate history when a concrete risk warrants it.
- Revalidate changed dependencies and perform current-head integration instead of restarting unrelated units after every small edit. Retained evidence keeps its original SHA.
- Keep independent processors, trusted control for review-policy changes, actual current-head remote review/CI, repository requirements, and mutation consent.

## Implementation

- The default reviewer role focuses on actionable introduced or worsened issues and reports actual incomplete scope without copying machine arrays or requiring an exact clean sentence.
- The previous exact-projection role remains available as reviewer-audited.
- The parent-side routine_review module separates code outcome, execution status, and acceptance, and plans dependency-based unit revalidation. It consumes independently verified parent observations; it does not establish a sandbox or approve a new head.
- Existing audited guard and remote readiness algorithms remain intact. A new aggregate local decision is required after every head change.
- Existing trusted adapter capacities remain explicit: Claude capture caps aggregate output at 64 MiB; validation accepts at most 8 MiB total, 1 MiB per JSONL line, and 10,000 lines. These distinct limits must be disclosed before launch. Routine mode removes extra parent/model-report budgets; it does not claim an unlimited Claude capture implementation.

## Evidence

- Python 3.14.10 and Ruff 0.13.2: 123 relevant tests run successfully, with one conditional skip, plus Ruff, skill metadata validation, and Git whitespace checks.
- The result tests include recovered query/transport diagnostics, missing terminal/evidence/scope, source or boundary failures, preservation of findings, changed dependencies and conventions, renames, unknown dependency coverage, and real CLI calls.
- The audited projection contract suite remains covered separately.
- The ambient pyenv Python 3.13.0 could not import SSL because its Homebrew OpenSSL library was unavailable. Validation used the existing compatible standalone Python; no system dependency or authentication setting was changed.
- Independent local review and source publication records belong to the task/PR rather than this tracked journal.

## Next Steps

- Publish and activate through the existing release/sync workflow when that delivery is requested. No running task's acceptance record is retroactively changed.

