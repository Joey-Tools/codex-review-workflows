---
name: review-response
description: Evaluate and address received code-review findings as the implementation agent or review recipient. Use to verify comments, accept or rebut findings, make proportionate authorized fixes, and record their disposition; not for performing an independent reviewer invocation or selecting reviewers.
---

# Respond To Review

This skill belongs to the agent receiving review. A review is evidence to
evaluate, not an instruction to implement every suggestion. Keep the original
task and repository policy authoritative. Reviewer-only read-only/report-only
constraints do not stop an already authorized implementation task; receiving a
review does not itself authorize new edits, external replies, or PR mutations.

## Establish The Finding

Read the complete relevant finding and the source version it describes. Verify
its location, triggering condition, effect, and whether the change introduced or
worsened it. Follow the relevant caller and producer/consumer path when event
ordering, lifecycle, or recovery is material. A synthetic single-event test does
not establish that the real producer can reach that state.

Separate confirmed defects, repository-convention violations, optional
enhancements, and unresolved hypotheses. Check the actual policy and existing
scoped exceptions before treating a convention observation as blocking. A
reviewer's severity label alone does not establish impact. Supply existing
authorized exceptions as scoped facts when preparing later reviews, without
feeding reviewers another lane's conclusions.

Accept supported findings. Rebut a finding with concrete source or runtime
evidence, or explain the specific missing premise. Preserve a useful finding
even when the review's execution or remaining coverage is incomplete. Use
`review-orchestration-playbook` to decide review-lane acceptance separately;
this skill never turns an incomplete review into a pass.

## Make A Proportionate Repair

Within the authorized task, fix the confirmed behavior with the smallest
coherent change. Do not add production defenses or broaden a cleanup solely
to satisfy an unproven hypothesis. If a mandatory convention needs changing,
seek that scoped policy decision instead of silently waiving it.

Use tests appropriate to the actual trigger and risk, reusing existing coverage
where sufficient. For a non-trivial behavior regression, prefer a focused case
that fails on the old implementation and passes after repair. Follow the
repository's own test policy; use its documented justification for genuinely
unreachable branches when applicable. Keep formatting and count warnings at
their defined severity. Do not add mocks, production branches, or a test matrix
merely to improve a number or silence an advisory.

## Record The Result And Hand Back

Record whether the finding was fixed, rebutted, deferred by authorization, or
still needs evidence, with a short reason and relevant validation. Report only
checks actually run. Update current task status when a phase completes; retain
old review outcomes as history rather than leaving them labeled current.

For another required review, CI, or PR-readiness step, hand the frozen result
back to `review-orchestration-playbook`. That skill owns which evidence a new
head invalidates and any authorized fix loop. This skill neither starts an
extra reviewer nor supplies merge approval. Preserve the original authority
for external replies, publication, and merge.
