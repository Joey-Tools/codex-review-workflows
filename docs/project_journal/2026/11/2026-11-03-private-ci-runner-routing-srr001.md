---
id: 20261103-srr001
title: Private CI Self-Hosted Runner Routing
status: completed
created: 2026-11-03
updated: 2026-11-04
branch: wip/self-hosted-routing
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/148
supersedes: []
superseded_by:
---

# Private CI Self-Hosted Runner Routing

## Summary

- Add opt-in JSON label routing for eligible Linux and macOS jobs while preserving existing hosted defaults and test coverage.

## Current State

- `CODEX_PRIVATE_LINUX_RUNNER_LABELS` and `CODEX_PRIVATE_MACOS_RUNNER_LABELS` route eligible jobs through JSON label arrays; empty values retain the existing per-job hosted labels.
- Python jobs keep their existing `actions/setup-python@v5` steps and requested versions. Matrix contents and test coverage are unchanged.
- Existing contract tests remain; runner routing is validated by actual CI execution. Cleanup of existing tests that only inspect YAML text is deferred.

## Next Steps

- Keep test-matrix reduction and CI timing optimization in a separate change.

## Evidence

- Workflow fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`.
- Contract tests: `skills/review-orchestration-playbook/tests/test_contracts.py`.
