---
id: 20261013-routine-merge-readiness
title: Routine Merge Readiness and Base-Impact Revalidation
status: completed
created: 2026-10-13
updated: 2026-10-13
branch: wip/routine-merge-readiness-20261013
pr:
supersedes: []
superseded_by:
---

# Routine Merge Readiness and Base-Impact Revalidation

## Outcome

Routine readiness uses exact server-side reviewed-head binding and the
documented GitHub control-plane trust boundary, without demanding strict
atomic base proof or a complete bypass/actor inventory. Strict base proof
remains explicit opt-in or mandatory under a stronger user/project policy.
A read-only planner applies parent-owned evidence
dependencies to observed base changes; head-bound provider evidence remains
invalidated on head change. Read-only protection, ruleset, bypass-list, and
effective-permission inspection is authorized within the selected repository
and PR scope; unreadable state remains unknown. The planner is not a readiness
verdict and cannot approve this migration.

## Validation

Python 3.10.19: `test_readiness_plan.py` passed 10 tests; `test_contracts.py`
passed 52 tests with 2 private-layout skips. Commands used:

The parent also ran the planner CLI with a hypothetical base-tip-only change:
it preserved the head-only review, invalidated the base-sensitive test, and
reported `readiness_verdict: not-evaluated`. Native `gh 2.100.0` accepted
`gh pr merge --match-head-commit <40-character SHA> --help` without a network
mutation; this flag binds the feature head, not the base.

Retained focused log SHA-256 values:
- Planner: `87143b7f6b6aac4e475de83518421aa155c3d8ef1a7467867356f17418515aa8`.
- Contracts: `bd8ba45800c2c39f2f4dcf7d2a91ff1e5ce64516055d3810dc250466f3a1c1e4`.

```text
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 --version
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_readiness_plan.py' -v
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_contracts.py' -v
git diff --check
```

## Boundary

This change defines the prospective default and preserves strict opt-in
proofs. It does not change provider clean grammar, credential admission,
review request/retry budgets, repository protection, or external GitHub state.
Candidate approval remains subject to the previously installed trusted
review policy.
