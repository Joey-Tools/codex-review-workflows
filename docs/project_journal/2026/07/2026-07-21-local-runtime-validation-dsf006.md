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
- Allowed same-checkout serial reuse only when it is proven safe; otherwise version-sensitive state must be isolated or explicitly cleaned and rebuilt.

## Current State

- Local validation keeps every required runtime or toolchain in scope and decides its validation shape before resolving versions. Only an explicit user or repository multi-version requirement, or a cross-version compatibility goal, selects the multi-version path; minimum versions and CI matrices alone do not.
- On the single-version path, each toolchain uses the first source that exists, in strict order: explicit user version, explicit repository policy, repository version pin, normal repository runner or tool default, then the newest installed compatible version. Only a missing source permits checking the next one.
- The selected single-version source must resolve to exactly one compatible version; ambiguity, conflict, or incompatibility stops as a blocker instead of silently falling through. The selected version and source stay fixed for the validation pass and are recorded in the evidence.
- Multi-version validation uses same-checkout serial reuse only when the suite proves it safe. Version-sensitive checkout output, caches, and mutable state use isolated worktrees, caches, and state, or are explicitly cleaned and rebuilt between versions.

## Next Steps

- None.

## Evidence

- https://github.com/Joey-Tools/codex-review-workflows/pull/70
- Daily Skill Friction found two independent tasks where an unrequested concurrent two-version Python matrix interfered through shared checkout state and required user correction.
- A repository contract test preserves the per-toolchain version resolution order, matrix scope, and isolation requirements.
- `uv run --isolated --with pyyaml python3 .../quick_validate.py skills/change-delivery-workflow` passed.
- `project_journal.py validate --repo ...` passed.
- `python3 -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -q` passed 1,057 tests with 4 skips under the single resolved Python 3.13.0 runtime; loopback-binding tests ran outside the sandbox.
- `git diff --check` passed.
