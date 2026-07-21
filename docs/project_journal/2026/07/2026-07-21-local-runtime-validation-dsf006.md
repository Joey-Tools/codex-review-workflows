---
id: 20260721-dsf006
title: Local Runtime Validation Guardrail
status: completed
created: 2026-07-21
updated: 2026-07-21
branch: codex/daily-skill-friction-20260721-codex-review-workflows-local-runtime-validation-guardrail
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/70
supersedes: []
superseded_by:
---

# Local Runtime Validation Guardrail

## Summary

- Resolved one deterministic version per required local runtime or toolchain instead of expanding minimum-version or CI declarations into a local matrix.
- Required serial execution or isolated mutable state when a necessary multi-version suite cannot prove same-checkout concurrency is safe.

## Current State

- Local validation keeps every required runtime or toolchain in scope, while selecting one version for each by default.
- Each toolchain first uses an explicit user or repository version, then a repository-pinned or runner-resolved version, then the tool default, and finally the newest installed compatible version.
- Each selected toolchain version stays fixed for the validation pass and is recorded in the evidence.
- Minimum supported versions and CI matrices do not imply an unrequested local runtime matrix.
- Cross-version compatibility changes may still validate multiple runtimes locally.
- Multi-version validation that shares checkout output, caches, fixed ports, or mutable state runs serially or with isolated worktrees, caches, and state.

## Next Steps

- None.

## Evidence

- https://github.com/Joey-Tools/codex-review-workflows/pull/70
- Daily Skill Friction found two independent tasks where an unrequested concurrent two-version Python matrix interfered through shared checkout state and required user correction.
- A repository contract test preserves the per-toolchain version resolution order, matrix scope, and isolation requirements.
- `uv run --isolated --with pyyaml python3 .../quick_validate.py skills/change-delivery-workflow` passed.
- `project_journal.py validate --repo ...` passed.
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -q` passed 1,062 tests with 4 skips under the single resolved Python 3.13.0 runtime; loopback-binding tests ran outside the sandbox.
- `git diff --check` passed.
