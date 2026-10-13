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
dependencies to observed base and queue merge-group changes; head-bound provider evidence remains
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

First successor-round repairs: Python 3.10.19 `test_readiness_plan.py` passed 13 tests
in 0.064 seconds; `test_contracts.py` passed 52 tests with 2 private-layout
skips in 5.043 seconds. Ruff, source compile, and whitespace checks passed.
The parent independently checked both first-round logs and ran actual direct
and queue CLI examples before successor review a6. Those examples and results
predate the out-of-band queue coverage repair below and are not validation for
the current successor candidate. Skill and journal validation passed for that
earlier candidate.
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

Successor observation a6 repairs: a queue request must explicitly set and
prove `bypass_rules: false` before reuse; an unproved/true flag blocks. Routine
same-ref base changes retain an enrollment only when no positive out-of-band
gate was invalidated or all such gates are covered by the required merge group
or a non-bypassed hold; otherwise re-enroll after reacquisition. The planner's
evidence array is restricted to positive/pass/clean artifacts, while applicable
negative findings remain independent blockers. Strict retargets now use the
full strict rerun action, with head change retaining precedence. No remote
review, CI, or merge pass is claimed by this journal update.

Worker validation before final parent documentation/test refinements: Python 3.10.19 `test_readiness_plan.py` passed 17
tests in 0.066 seconds; `test_contracts.py` passed 52 tests with 2 expected
private-layout skips in 4.008 seconds. Ruff, source compile, whitespace, and
project-journal validation passed. Final log paths and SHA-256:

- Planner `/private/tmp/pr137-readiness-fixes.ME9JQc/successor-planner-final.log`:
  `b6cf55a0ae2ff72e1f18d89299bb4889f545372ba8ca3b968f2bd36fbd9cc6bb`.
- Contracts `/private/tmp/pr137-readiness-fixes.ME9JQc/successor-contracts-final2.log`:
  `3812d68e9bc91f46943fbcb4f3fbc9f5b12c2fdcea9e75df83d7fff2422b7e6b`.

The parent then clarified own acknowledged async requests versus reuse of a
pre-existing UUID, made the retention condition explicit in every queue
execution clause, and strengthened wrong-binding/strict-retarget tests.
Final actual parent Python 3.10.19 validation passed 17 planner tests in
0.065 seconds and 52 contract tests in 4.582 seconds, with 2 expected skips;
both bounded supervisors exited 0 with no incomplete output. Log SHA-256:

- Planner `80c9ca59c0f637ee915445a8099a69842a9d7bfc7c17c9a4e2fe2570ed5a752f`.
- Contracts `11e3ca4cc31b31f8a8a36ba50cb43a3b48a2e223880c4bf4b4e13a094470bdd0`.

Actual direct plus three queue CLI cases retained the head-only positive
artifact but invalidated the base-sensitive test. The unprotected case
canceled/re-enrolled after revalidation, covered evidence retained the entry,
and unknown bypass state blocked it. Every output stayed planning-only and
`readiness_verdict: not-evaluated`, never full readiness or merge authority.

Third repair adds the independent `merge_group` dimension: queue reordering or
removal can change the synthetic SHA while all four PR/base coordinates stay
unchanged. Group-dependent artifacts and current group checks are invalidated;
unprotected out-of-band artifacts require cancellation/reacquisition, while a
required group gate or non-bypassed hold permits retention. Direct plans reject
queue-only group changes/dependencies. This does not alter runtime closure or
provider clean authority.

Final parent Python 3.10.19 validation passed 20 planner tests in 0.056 seconds
and 52 contracts in 3.528 seconds with 2 expected private-layout skips; both
supervisors exited 0 with incomplete-null. SHA-256:

- Planner `0b5cb16e7b9440680d76a742aed17e5b45a66e166ebf6eb8620e9365f64d1299`.
- Contracts `13e01b52b8057fb5101de8abfe144296b069435f39d957accfe8ce37f63cb3e7`.

The parent also ran actual direct, group-only/uncovered, and group-only/held
CLI cases. They respectively kept the direct path, canceled/reacquired group
artifacts, and retained a held queue entry; head-only provider evidence stayed
invariant. All outputs remained planning-only, not readiness approval.

Fourth repair preserves the explicit HTTP 200 already-queued boundary: an
unchanged head or generic queue reread does not prove request options. Only the
same still-current owned enrollment with its exact submitted head/action,
false bypass option and acknowledged UUID/scope can be reused; canceled or
replaced entries do not carry that proof forward. Every active queue entry
with blocked merge constraints is canceled pending reacquisition, even when
all five change flags are false. Existing head/base-specific cancellation
precedence and the direct-path action are preserved.

Final parent Python 3.10.19 validation passed 21 planner tests in 0.056 seconds
and 52 contracts in 3.443 seconds with 2 expected skips, supervisor0 and
incomplete-null. Planner log SHA-256
`5ff5d78376b4e12f828a6c4e7f15cf456e9ed6eb698959274c4b935d2b3fbe4e`;
contracts log
`a9a3470ed05180f8d8262dc155ab68d6fdba6282a0f6b809bfe0abe1a703b3a6`.
The actual unchanged-coordinate strict/blocked CLI case canceled an entry
rather than returning retention, while keeping its invariant head artifact.
This is planning-only evidence, not permission to merge or proof of current
remote review/CI. Runtime security remains unchanged.

```text
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 --version
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_readiness_plan.py' -v
PYTHONPATH=/private/tmp/readiness-plan-python-deps /Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_contracts.py' -v
ruff check skills/review-orchestration-playbook/scripts/readiness_plan.py skills/review-orchestration-playbook/tests/test_readiness_plan.py skills/review-orchestration-playbook/tests/test_contracts.py
/Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 -B -c 'import pathlib,sys; [compile(pathlib.Path(p).read_bytes(),p,"exec") for p in sys.argv[1:]]' skills/review-orchestration-playbook/scripts/readiness_plan.py skills/review-orchestration-playbook/tests/test_readiness_plan.py skills/review-orchestration-playbook/tests/test_contracts.py
git diff --check
/Users/hoteng/.local/share/uv/python/cpython-3.10-macos-aarch64-none/bin/python3.10 /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .
```

No current-head remote review, CI, or merge pass is claimed here.

## Boundary

This change defines the prospective default and preserves strict opt-in
proofs. It does not change provider clean grammar, credential admission,
review request/retry budgets, repository protection, or external GitHub state.
Candidate approval remains subject to the previously installed trusted
review policy.
