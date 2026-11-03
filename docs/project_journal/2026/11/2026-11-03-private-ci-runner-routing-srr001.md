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

- Add opt-in JSON label routing for eligible private CI Linux and macOS jobs while preserving hosted defaults and existing test coverage.

## Current State

- The canonical private workflow fixture and contract tests describe the routing variables and retain the original job and matrix structure.
- Independent supervisor checks, read-only macOS installation, and Linux isolation retain hosted runners for hosted evidence or disposal-dependent side effects.
- The shared Python setup fixture preserves `setup-python` on hosted runners and uses pinned uv-managed CPython plus an empty-environment smoke test on self-hosted runners.
- `docs/private-ci-runners.md` records the repository-variable contract, provisioned runner pools, and platform-specific checks.
- Four Linux and two macOS runners are registered and have accepted jobs. The routing implementation slice is complete for the post-merge target state; full CI validation of its portable Python setup remains a separate gate.

## Next Steps

- Verify full CI execution with the portable Python setup.
- Keep CI timing, optimization, and removal of the three hosted dependencies in a separate follow-up PR.

## Evidence

- Canonical fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Canonical private Python setup fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/setup-private-python/action.yml`.
- Canonical contract tests: `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Runner configuration and validation limits: `docs/private-ci-runners.md`.
