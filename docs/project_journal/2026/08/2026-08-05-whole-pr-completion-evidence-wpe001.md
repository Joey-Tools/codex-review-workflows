---
id: 20260805-wpe001
title: Whole-PR Completion Evidence Binding
status: completed
created: 2026-08-05
updated: 2026-08-05
branch: wip/whole-pr-evidence-binding-master
pr:
supersedes: [20260730-gea001]
superseded_by:
---

# Whole-PR Completion Evidence Binding

## Summary

- Terminal GitHub Codex payloads now supply artifact-level clean/findings
  classification only; they do not prove the provider's whole-PR input base.
- Terminal findings remain blocking negative evidence, while positive lane
  completion requires a complete `thumbs-up-clean` reaction basis.

## Current State

- Every terminal basis records
  `scope_assurance: artifact-publication-only`.
- Publication-only clean evidence is audit-only for merge readiness.
- The current accepted provider-authenticated input-base and
  request/run/artifact binding schema sets are empty.
- Base-only retarget state-machine version 3 preserves terminal
  classification and negative evidence without treating either as whole-PR
  completion.

## Next Steps

- No canonical follow-up remains after this change lands; downstream private
  overlay synchronization is handled in its own repository.

## Evidence

- Regression source: `Joey-Tools/codex-private-workflows#149`.
- Contract coverage: `skills/review-orchestration-playbook/tests/test_contracts.py`.
