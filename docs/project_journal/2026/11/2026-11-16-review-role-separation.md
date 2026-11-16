---
id: 20261116-review-role-separation
title: Separate Reviewer And Review Recipient Instructions
status: completed
created: 2026-11-16
updated: 2026-11-16
branch: codex/review-role-separation
pr:
supersedes: []
superseded_by:
---

# Separate Reviewer And Review Recipient Instructions

## Summary

Reviewers receive an independent, read-only assessment task. Implementation
agents receive a separate workflow for verifying and addressing findings.

## Current State

- `code-review` owns source inspection and findings, without repair, CI, or reviewer-orchestration duties.
- `review-response` owns evidence-based acceptance or rebuttal, proportionate authorized repairs, and current-status updates.
- `review-orchestration-playbook` retains provider selection, machine proofs, lane acceptance, and PR-readiness contracts.
- Real triggers and applicable convention exceptions are checked before adopting a fix; existing repository test-policy exceptions and warning severities remain authoritative.
- The routine profile routes each role to its own instructions; audited adapters and GitHub evidence contracts remain unchanged.

## Validation

- Existing repository policy contracts include both new role instructions.
- Skill metadata, relative links, and private-consumer export compatibility are checked before landing.
