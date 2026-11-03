---
id: 20261103-srr001
title: Private CI Self-Hosted Runner Routing
status: completed
created: 2026-11-03
updated: 2026-11-03
branch: wip/self-hosted-routing
pr:
supersedes: []
superseded_by:
---

# Private CI Self-Hosted Runner Routing

## Summary

- Add opt-in JSON label routing for private CI Linux and macOS jobs while preserving the hosted defaults and existing test coverage.

## Current State

- The canonical private workflow fixture and contract tests describe the routing variables and retain the original job and matrix structure.
- `docs/private-ci-runners.md` records the repository-variable contract, intended runner pools, and platform-specific checks.
- The routing implementation slice is complete for the post-merge target state. Runner provisioning is not complete; no live self-hosted execution is claimed.

## Next Steps

- Complete repository-only runner provisioning before claiming live self-hosted validation.
- Keep CI timing and optimization work in a separate follow-up PR.

## Evidence

- Canonical fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Canonical contract tests: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Runner configuration and validation limits: `docs/private-ci-runners.md`.
