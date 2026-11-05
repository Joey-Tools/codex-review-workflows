---
id: 20261104-cir001
title: Public CI Read-Only Gate Removal
status: completed
created: 2026-11-04
updated: 2026-11-05
branch: codex/ci-reduction-review-20261104
pr:
supersedes: []
superseded_by:
---

# Public CI Read-Only Gate Removal

## Summary

- Remove the public `readonly_install_supervisor_tests` job and its aggregate requirement.
- Keep the public Ubuntu/macOS platform matrix, the macOS independent-supervisor tests, and the existing no-argument hosted no-child probe.
- This change narrows public CI qualification only; it does not change runtime code, private CI, private preferences, AGENTS policy, or runner deployment.

## Current State

- The public CI source is `.github/workflows/ci.yml`; `canonical.yml` is its byte-identical fixture. `private.yml` is retained as reference and contract data. The private repository's actual CI workflow is maintained independently and is not materialized from this public fixture.
- The hosted no-child probe keeps its base no-argument invocation, and the runtime catalog is unchanged. Normal Linux/macOS platform tests and deterministic reviewer tests remain required.
- The removed read-only-install qualification job was the public workflow's root/cross-UID fixture gate. No private workflow or preference policy changed in this workstream.

## Evidence

- Public workflow and snapshot contract: `.github/workflows/ci.yml`, `skills/review-orchestration-playbook/tests/fixtures/ci/canonical.yml`, and `skills/review-orchestration-playbook/tests/test_contracts.py`.
- Private workflow fixture contracts remain reference-only in this public repository.
