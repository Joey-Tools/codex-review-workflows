---
id: 20261013-routine-merge-readiness
title: Routine Merge Readiness and Base-Impact Revalidation
status: completed
created: 2026-10-13
updated: 2026-10-13
branch: wip/routine-merge-readiness-20261013
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/137
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

Follow-up consistency repairs scope every direct-merge base-proof requirement
to strict mode and clarify that routine base-only changes reuse only
parent-classified invariant evidence. The planner distinguishes `direct` from
`merge_queue` and rejects mismatched/missing head-binding inputs. For an
unchanged head and same target ref, routine queue base-tip/merge-base changes
preserve the persistent `merge-async` SHA enrollment across a merge-group
rebuild while reacquiring current merge-group checks; target-ref retargets and
head changes cancel it. Strict base changes cancel/re-enroll after full base
revalidation. Strict queue proof is separately classified and cannot be
confused with direct expected-base/exact-base/monotonic proof.

## Validation

Initial-scope validation passed 10 planner tests and 52 contract tests with 2
private-layout skips; it predates the current-head consistency repairs and is
not their validation evidence.

Current-head repairs: Python 3.10.19 `test_readiness_plan.py` passed 13 tests
in 0.064 seconds; `test_contracts.py` passed 52 tests with 2 private-layout
skips in 5.043 seconds. Ruff, source compile, and whitespace checks passed.
The parent independently checked both final logs and ran the actual direct
and queue CLI with a same-target base-tip-only change. Both preserved only
the head-only review, invalidated the base-sensitive test, and remained
`planning_only: true` / `readiness_verdict: not-evaluated`; the queue plan
retained its exact-head enrollment while requiring current merge-group checks.
Skill and journal validation also passed.
Final test log paths and SHA-256:

- Planner log `/private/tmp/pr137-readiness-fixes.ME9JQc/planner-final.log`:
  `a914909069a6e54a9eac50e0c333624a9f3f96528af7bf05c04c18c0eeb02007`.
- Contracts log `/private/tmp/pr137-readiness-fixes.ME9JQc/contracts-final.log`:
  `71aba193d43c43a4150f8bdf6f0c4ffca335db547b9fd8d62ae59ac64fcbaef2`.

Initial-scope supporting checks only: the parent ran the planner CLI with a
hypothetical base-tip-only change and verified native `gh 2.100.0` accepted
`gh pr merge --match-head-commit <40-character SHA> --help`. Earlier log hashes
are historical initial-scope evidence, not validation for the current-head
repairs.

```text
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 --version
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_readiness_plan.py' -v
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_contracts.py' -v
ruff check skills/review-orchestration-playbook/scripts/readiness_plan.py skills/review-orchestration-playbook/tests/test_readiness_plan.py skills/review-orchestration-playbook/tests/test_contracts.py
/Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -c 'import pathlib,sys; [compile(pathlib.Path(p).read_bytes(),p,"exec") for p in sys.argv[1:]]' skills/review-orchestration-playbook/scripts/readiness_plan.py skills/review-orchestration-playbook/tests/test_readiness_plan.py skills/review-orchestration-playbook/tests/test_contracts.py
git diff --check
```

No current-head remote review, CI, or merge pass is claimed here.

## Boundary

This change defines the prospective default and preserves strict opt-in
proofs. It does not change provider clean grammar, credential admission,
review request/retry budgets, repository protection, or external GitHub state.
Candidate approval remains subject to the previously installed trusted
review policy.
