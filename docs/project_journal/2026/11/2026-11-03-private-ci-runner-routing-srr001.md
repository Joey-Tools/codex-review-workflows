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

- Add opt-in JSON label routing for eligible Linux and macOS jobs while preserving existing hosted defaults and test coverage.

## Current State

- `CODEX_PRIVATE_LINUX_RUNNER_LABELS` and `CODEX_PRIVATE_MACOS_RUNNER_LABELS` route eligible jobs through JSON label arrays; empty values retain the existing per-job hosted labels.
- Python jobs keep their existing `actions/setup-python@v5` steps and requested versions. Matrix contents and test coverage are unchanged.
- The contract tests preserve the workflow fixture, routing variables, and hosted fallbacks.

## Next Steps

- Keep test-matrix reduction and CI timing optimization in a separate change.

## Evidence

- Workflow fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Contract tests: `skills/review-orchestration-playbook/tests/test_contracts.py`.
