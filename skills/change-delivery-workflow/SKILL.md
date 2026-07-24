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

Keep the selected profile and its scope constraints stable. Do not downgrade it
because a gate is slow, do not silently promote a local checkpoint into
PR, CI, release, or merge work, and do not discard a limiting constraint
because the same request also says `full workflow` or mentions a PR. Record a
new profile or remove a constraint only when the user changes the requested
outcome.

## Resolve Hard Constraints First

Resolve explicit scope and commit constraints before selecting a profile:

- `local-only`: the requested terminal scope is explicitly local, such as
  `locally and stop` or `only work locally`. A mere reference to the local-gate
  phase inside an otherwise explicit PR request is not this constraint.
- `report-only` or `probe-only`: inspect or evaluate without delivery mutation.
- `read-only`: do not mutate the working result or any remote state.
- `no-remote`: do not push, create or update a PR, comment, start a remote
  readiness wait, release, or perform another remote mutation.
- `no-commit`: leave Git history unchanged.

These constraints are subtractive and take precedence over `full workflow`,
PR-ish, merge-ready, or similar expansion signals in the same request. Any of
`local-only`, `report-only`, `probe-only`, `read-only`, or `no-remote` forbids
`pr-readiness-handoff` and every remote mutation. Select the appropriate
remaining local profile and stop locally. A later explicit user request may
remove the constraint; a downstream workflow may not reinterpret it.

An explicit `report-only`, `probe-only`, `read-only`, or `no-commit` request
also sets commit mode to `forbidden` for the whole run. Apply it before any
review checkpoint, anchor, or landing commit. A delivery profile never
overrides it.

When commit mode is `forbidden`, run only the requested inspection or gate work
and leave Git history unchanged. A formal review may use a pre-existing exact
committed range only when it already represents the result under review.
Otherwise skip the formal lane and report that the missing committed range is a
blocker; do not create an implicit checkpoint to satisfy the reviewer.

## Choose The Profile

After applying hard constraints, choose by the remaining requested terminal
outcome, using this precedence:

1. An explicit PR, PR-readiness, full-workflow, or merge-ready outcome selects
   `pr-readiness-handoff` only when no hard constraint forbids that handoff.
   When the handoff is forbidden, the same full-workflow signal selects
   `local-gate` and stops there.
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
| `Run the full workflow locally, report-only.` | `local-gate` | gate-only report under local/report constraints |
| `Run the full workflow with no remote work.` | `local-gate` | full local gate, then stop under `no-remote` |
| `Review full-workflow readiness read-only.` | `local-gate` | read-only gate report with no handoff |
| `Probe full workflow and PR readiness; do not make remote changes.` | `local-gate` | probe-only local report with no handoff |
| `Run the full workflow and open a PR.` | `pr-readiness-handoff` | full local gate, then PR handoff |

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
- Record the selected profile, every canonical hard-constraint token, resolved
  commit mode, intended local outcome, and any permitted remote handoff.
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
  `report-only`, `probe-only`, `read-only`, or `no-commit`, do not create a
  checkpoint or anchor. Use a pre-existing exact committed range only when it
  already represents the result; otherwise report the formal lane blocked.
- When a formal review is required and commits are allowed, create a signed
  review checkpoint after implementation, validation, and the journal gate,
  then hand the exact frozen range to the authoritative
  `$review-orchestration-playbook`.
- Do not copy the review skill's materialization, provider, PR-state, or evidence
  rules into this skill.
- When formal review returns findings, branch on the resolved `commit_mode`
  before applying fixes:
  - If commit mode is `allowed`, apply the fixes, rerun affected validation and
    journal work, and create a new signed review checkpoint. That checkpoint
    creates a new head and invalidates every review result bound to the old
    range; review the new exact range.
  - If commit mode is `forbidden`, do not apply fixes or create or require a new
    head, checkpoint, anchor, or commit. Preserve the exact existing committed
    range, report the unresolved findings as a blocker, and stop. Only a later
    authorization may begin a new mutation-capable run.
- Resolve every required formal-review terminal state with this matrix:

| Commit mode | Exact committed range | Formal review result | Required terminal action |
| --- | --- | --- | --- |
| `allowed` | available | `clean` | Continue to the signed-commit step, reusing the clean checkpoint when it already is the landing commit. |
| `allowed` | available | `findings` | Apply fixes and repeat the affected gates on a new exact range. |
| `forbidden` | missing | not started | Report `missing-committed-range` as a blocker and stop. Do not create or require a checkpoint, anchor, or commit to start review. |
| `forbidden` | available | `findings` | Report `review-findings` as a blocker and stop on the preserved range without mutation. |
| `forbidden` | available | `clean` | Report the exact clean range, bypass the signed-commit step, and continue directly to the profile terminal step. Do not create, require, amend, or relabel a commit. |

- Continue to the signed-commit step only when the latest reviewed head is clean
  under an allowed commit mode.
- A clean review under forbidden commit mode is complete evidence for the
  pre-existing exact range. It does not turn commit mode back to `allowed`.
- A missing exact range or review findings under forbidden commit mode is a
  terminal blocker. Do not continue to a profile handoff from either blocker.
- The latest clean reviewed checkpoint is the profile's landing commit. When
  review produces no fixes, do not create an empty commit or amend, squash, or
  rewrite history merely to relabel that checkpoint as the landing.

6. Create the signed checkpoint or landing commit.
- Enter this step only when commit mode is `allowed`. When commit mode is
  `forbidden` and the pre-existing exact range reviewed cleanly, bypass this
  step without asking for or implying commit authorization.
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
  report when commit mode forbids a checkpoint. A clean pre-existing reviewed
  range is reported directly; no additional commit is required.
- `local-gate` stops at the signed local landing commit, or at the requested
  report when a pre-existing exact range reviewed cleanly, or at the
  `missing-committed-range` / `review-findings` blocker when commit mode forbids
  a commit. It does not push without separate authorization.
- `pr-readiness-handoff` continues through `$review-orchestration-playbook` and
  stops at merge-ready or a clear blocker, never at merge. Under forbidden
  commit mode, it may hand off the clean pre-existing exact range only when no
  hard constraint forbids remote work; a missing range or findings stop before
  handoff.
- A hard constraint that forbids PR handoff always wins at this step. Do not
  invoke the review skill's PR-readiness path, push, create or update a PR,
  comment, start a remote wait, or release.

## Emit The Result And Handoff Record

Every terminal report and permitted handoff must include the JSON-compatible
record defined by
[delivery-result.schema.json](references/delivery-result.schema.json). Preserve
these fields unchanged across any handoff:

- `profile`
- every explicit canonical token in `constraints`
- resolved `commit_mode`
- resolved `remote_mutation`
- `handoff`

For `local-only`, `report-only`, `probe-only`, `read-only`, or `no-remote`,
`remote_mutation` must be `forbidden`, `handoff` must be `none`, and `profile`
must not be `pr-readiness-handoff`. For `report-only`, `probe-only`,
`read-only`, or `no-commit`, `commit_mode` must be `forbidden`.

Only a `pr-readiness-handoff` record without a remote-limiting constraint may
set `handoff` to `review-orchestration-playbook` and `remote_mutation` to
`review-authorization-required`. That value is not remote authorization; it
means the review skill must perform its own target and lifecycle preflight.
Receivers must fail closed on a missing constraint, an unknown field, or an
internally contradictory record instead of inferring a broader scope from prose.

## Compatibility And Guardrails

- `$agile-delivery-workflow` is a retired compatibility alias that maps to
  `focused-checkpoint`; do not run a second agile workflow.
- Do not treat a focused checkpoint as a quality waiver or claim full validation
  from focused checks.
- Do not treat a local handoff record as authorization for an arbitrary PR
  target.
- If a required credential, login, TCC grant, device action, or human approval
  is unavailable, stop at a precise handoff point.
