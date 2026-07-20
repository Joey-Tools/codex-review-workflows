---
id: 20260721-dsf006
title: Local Runtime Validation Guardrail
status: completed
created: 2026-07-21
updated: 2026-07-21
branch: codex/daily-skill-friction-20260721-codex-review-workflows-local-runtime-validation-guardrail
pr:
supersedes: []
superseded_by:
---

# Local Runtime Validation Guardrail

## Summary

- Kept local runtime validation scoped to versions explicitly required by the user or repository policy.
- Required serial execution or isolated mutable state when a necessary multi-version suite cannot prove same-checkout concurrency is safe.

## Current State

- Minimum supported versions and CI matrices no longer imply an unrequested local runtime matrix.
- Cross-version compatibility changes may still validate multiple runtimes locally.
- Declared versions outside the local scope remain covered by CI.
- Multi-version validation that shares checkout output, caches, fixed ports, or mutable state runs serially or with isolated worktrees, caches, and state.

## Next Steps

- None.

## Evidence

- Daily Skill Friction found two independent tasks where unrequested concurrent Python 3.10 and 3.13 suites interfered through shared checkout state and required user correction.
- A repository contract test preserves both the runtime-scope and isolation requirements.
- `uv run --isolated --with pyyaml python3 .../quick_validate.py skills/change-delivery-workflow` passed.
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -q` passed 1,062 tests with 4 skips under Python 3.13 after rerunning outside the sandbox for loopback-bind permission.
- `git diff --check` passed.
