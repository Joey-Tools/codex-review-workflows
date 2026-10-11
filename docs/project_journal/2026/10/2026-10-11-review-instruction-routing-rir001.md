---
id: 20261011-rir001
title: Review Instruction Routing and Progressive References
status: completed
created: 2026-10-11
updated: 2026-10-11
branch: codex/review-instruction-routing-20261011
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/135
supersedes: []
superseded_by:
---

# Review Instruction Routing and Progressive References

## Outcome

The approved fourth improvement is a separate documentation-routing change.
The playbook entrypoint routes default provider selection to
`default-review-routing.md` and conditional GitHub producer/status and Actions
recovery details to `github-codex-producer-and-recovery.md`.

The entrypoint is reduced from 423 to 130 lines. Default routing is preserved
in its dedicated reference; six obsolete shared-contract redirects are removed
and every current repository caller points directly to the new reference.
Duplicated URL/path, canonical-JSON and repository-field details in the
producer reference are replaced by links to the owning evidence authority and
versioned machine contract.

Shared scope, independence, full-DAG coverage, consent, self-policy isolation,
exact merge bindings, and current-head readiness remain required. The shorter
GitHub entry still requires read-only request discovery, independent
non-delivery proof, and no ambiguous-delivery duplicate POST. Producer trust,
immutable closure, dependency edges, Actions transactions, retry/cost limits,
and status-only uncertainty remain in the routed detailed contract.

## Validation

Repository contract tests cover conditional routing, direct links, removed
redirects, unchanged provider decisions, and producer/recovery boundaries.
Detailed assertions target their owning references rather than requiring the
same prose in the entrypoint. Read-only byte comparisons verify unchanged
machine contracts, executable controls, routing decisions, shared scope, and
the remaining producer/readiness contracts.

Python 3.13.0 passed all 47 repository contracts (one private-layout-only skip)
and all 68 GitHub carrier/recovery tests. Selected Ruff, source-only syntax,
skill metadata, journal frontmatter, and whitespace validation passed.
Initial documentation tests exposed old entrypoint-specific assertions. Their
inputs now include the owning references, while typed finding resolution,
new-head invalidation and the no-empty-commit rule remain checked. Complete
reruns pass; initial failures are not counted as successful validation.
These checks validate the documentation/reference contracts, not a production
Actions result or formal remote review.

## Boundary

This change does not modify the terminal grammar, reference consumer,
production guard, CI workflows, personal AGENTS migration, source locks,
installed policy, native homes, or any authorization rule. It preserves the
three safety fixes delivered by canonical PR134. PR review and CI lifecycle
state belongs in the PR body; this journal describes the post-merge outcome.
