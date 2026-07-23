---
name: change-delivery-workflow
description: "Deliver repository changes through one explicit profile: a focused signed checkpoint for MVP/early-usable/agile/scout requests, a full signed local gate for non-trivial work, or a PR-readiness handoff after the local gate. Use when creating a local checkpoint or commit, probing local gate readiness, wrapping up implementation, or continuing a full workflow toward merge-ready."
---

# Change Delivery Workflow

## Purpose

Use this skill as the only active delivery entrypoint. Select and record exactly
one profile before implementation:

- `focused-checkpoint`
- `local-gate`
- `pr-readiness-handoff`

Keep the selected profile stable. Do not downgrade it because a gate is slow,
and do not silently promote a local checkpoint into PR, CI, release, or merge
work. Record a new profile only when the user changes the requested outcome.

## Resolve Commit Mode First

Resolve commit mode before selecting a profile. An explicit `report-only`,
`probe-only`, or `no-commit` request is a hard constraint for the whole run:
apply it before any review checkpoint, anchor, or landing commit. A delivery
profile never overrides it.

When the hard constraint applies, run only the requested inspection or gate
work and leave Git history unchanged. A formal review may use a pre-existing
exact committed range only when it already represents the result under review.
Otherwise skip the formal lane and report that the missing committed range is a
blocker; do not create an implicit checkpoint to satisfy the reviewer.

## Choose The Profile

Choose by the requested terminal outcome, using this precedence:

1. An explicit PR, PR-readiness, full-workflow, or merge-ready outcome selects
   `pr-readiness-handoff`.
2. Otherwise, an explicit full local gate or local landing outcome selects
   `local-gate`.
3. Otherwise, an explicit early usable slice selects `focused-checkpoint`.
4. Otherwise, a non-trivial delivery request selects `local-gate`.

A combined MVP-plus-PR request therefore selects `pr-readiness-handoff`. Treat
the focused slice as an intermediate feedback point, continue through the full
local gate, and then hand off; do not stop at the intermediate slice. A combined
MVP-plus-full-local-gate request similarly selects `local-gate`. If the user
instead says that remote or full-gate work must wait for a later request, select
`focused-checkpoint` and stop locally.

| Representative request | Selected profile | Transition |
| --- | --- | --- |
| `Deliver a quick MVP and stop at a local checkpoint.` | `focused-checkpoint` | focused checkpoint, then stop |
| `Deliver an MVP, then open a PR for feedback.` | `pr-readiness-handoff` | focused slice, full local gate, then PR handoff |
| `Start with an MVP but complete the full local gate now.` | `local-gate` | focused slice, full local gate, then stop |
| `Complete this non-trivial implementation locally.` | `local-gate` | full local gate, then stop |
| `Take the implementation to merge-ready and stop before merge.` | `pr-readiness-handoff` | full local gate, then PR handoff |
| `Probe local gate readiness, but do not commit.` | `local-gate` | gate-only report under `no-commit` |

### `focused-checkpoint`

Choose this only for an explicit MVP, early usable product, quick iteration,
agile delivery, scout, `先可用`, `快速迭代`, or similar first-slice request.

- Define the smallest user-visible behavior, artifact, command, or diagnostic
  that makes the slice useful.
- Run focused checks and the conditional journal gate.
- When commit mode allows, create a signed local checkpoint automatically.
- Stop at the checkpoint unless the user asks to continue.

The checkpoint is a product-feedback point, not merge-ready. Do not
automatically push, open a PR, wait for CI, start external review, release, or
merge.

### `local-gate`

Choose this for ordinary non-trivial delivery, local gate readiness, or a
pre-commit workflow when no narrower or remote outcome was requested.

- Complete the implementation and reasonable local validation.
- Update required documentation and apply the conditional journal gate.
- Complete the required local/internal review.
- When commit mode allows, create a signed landing commit automatically.
- Stop locally unless the user separately authorizes remote work.

### `pr-readiness-handoff`

Choose this when the user requests a full workflow, PR readiness, merge-ready,
`在合并前停止`, `stop before merge`, or explicit continuation after the local
gate.

- Complete the full `local-gate` first.
- Create the signed landing commit when commit mode allows.
- Hand off to the authoritative `$review-orchestration-playbook`.

The review skill owns target authorization, PR selection and lifecycle, named
review shapes, CI and conversation handling, and the merge-ready decision.
This profile does not authorize merge.

When a non-trivial delivery request is otherwise ambiguous, use `local-gate`.
Stop for input when the missing choice would materially change scope or remote
authorization.

## Run The Shared Workflow

1. Confirm scope.
- Read the applicable repository policy and preserve unrelated user changes.
- Record the selected profile, intended local outcome, and any requested remote
  handoff.
- Fix only blockers that are necessary for that outcome.

2. Implement.
- Read the relevant code, tests, and documentation before editing.
- Keep the diff focused and correct low-level mistakes introduced by the task.
- Under `focused-checkpoint`, defer polish, broad refactors, extra platforms,
  release wiring, and full gates that are not required for the first slice.

3. Validate.
- `focused-checkpoint` uses the narrowest checks that prove the slice builds,
  runs, or can be inspected, and reports broader checks that were skipped.
- `local-gate` and `pr-readiness-handoff` use the repository's broadest
  reasonable local build, unit, integration, and end-to-end checks.
- Resolve each runtime or toolchain from the user's instruction, then repository
  policy and an authoritative repository runner or version pin. If the selected
  authority is missing, internally contradictory, ambiguous, or incompatible,
  fail closed instead of guessing or silently falling back.
- When the repository supports more than one runtime or toolchain version, or
  the changed behavior can depend on version-sensitive checkout, cache, or
  state, read
  [validation-environments.md](references/validation-environments.md) before
  choosing or running checks. That reference owns deterministic environment
  selection and isolation; this workflow only consumes its results.
- After a failure, return to the earliest affected step and rerun the affected
  checks. Never claim a gate that was not run.

4. Apply the journal automation gate.
- Update automatically when the repository already adopted the convention
  through `docs/project_journal/`, stable entrypoints, or an explicit manifest.
- Update automatically when repository policy requires it.
- Update automatically when the task truly crosses a session or PR handoff and
  an existing tracking product is needed for durable recovery.
- Do not introduce tracking into an unadopted repository merely because one
  turn has ordinary implementation, test, and review phases.
- A short `focused-checkpoint` does not require first-time journal adoption.
  First-time setup still needs an explicit product or recovery need.
- When the gate applies, update the smallest relevant workstream journal.
  Change stable top-level entrypoints only for repository-wide state, recovery,
  or backlog changes.

5. Review the exact result.
- Use risk-proportionate local diff/self-review for `focused-checkpoint`; start a
  formal lane only when the user or repository policy requires it.
- Apply the resolved commit mode before creating anything for review. Under
  `report-only`, `probe-only`, or `no-commit`, do not create a checkpoint or
  anchor. Use a pre-existing exact committed range only when it already
  represents the result; otherwise report the formal lane blocked.
- When a formal review is required and commits are allowed, create a signed
  review checkpoint after implementation, validation, and the journal gate,
  then hand the exact frozen range to the authoritative
  `$review-orchestration-playbook`.
- Do not copy the review skill's materialization, provider, PR-state, or evidence
  rules into this skill.
- Any fix after review creates a new head and immediately invalidates every
  review result bound to the old range. Rerun affected validation and journal
  work, create a new signed review checkpoint, and review the new exact range.
- Continue only when the latest reviewed head is clean or a crisp blocker
  remains.
- The latest clean reviewed checkpoint is the profile's landing commit. When
  review produces no fixes, do not create an empty commit or amend, squash, or
  rewrite history merely to relabel that checkpoint as the landing.

6. Create the signed checkpoint or landing commit.
- When commit mode allows it, selecting a delivery profile authorizes its
  corresponding local commit after the gates pass; do not ask again merely to
  commit.
- Reuse the latest clean signed review checkpoint when it already represents
  the current tree. Otherwise create exactly one profile checkpoint or landing
  commit. Never manufacture an empty commit or perform an implicit history
  rewrite to create a second landing.
- Sign every checkpoint, review anchor, and landing commit. Use repository
  policy, or `git commit -S` when no stronger local convention exists, and add
  any required `Co-authored-by` footer.
- Keep the commit scope focused and exclude unrelated user changes.
- Treat a signing failure as a blocker. Never silently create an unsigned
  fallback commit.
- Report the commit SHA, delivered behavior, checks actually run, skipped gates,
  and remaining gaps.

7. Stop or hand off.
- `focused-checkpoint` stops at the signed local checkpoint, or at the requested
  report when commit mode forbids a checkpoint.
- `local-gate` stops at the signed local landing commit, or at the requested
  report or formal-review blocker when commit mode forbids a commit. It does not
  push without separate authorization.
- `pr-readiness-handoff` continues through `$review-orchestration-playbook` and
  stops at merge-ready or a clear blocker, including a missing committed range,
  never at merge.

## Compatibility And Guardrails

- `$agile-delivery-workflow` is a retired compatibility alias that maps to
  `focused-checkpoint`; do not run a second agile workflow.
- Do not treat a focused checkpoint as a quality waiver or claim full validation
  from focused checks.
- Do not treat a local handoff record as authorization for an arbitrary PR
  target.
- If a required credential, login, TCC grant, device action, or human approval
  is unavailable, stop at a precise handoff point.
