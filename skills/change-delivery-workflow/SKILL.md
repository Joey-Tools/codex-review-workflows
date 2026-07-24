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
- `report-only` or `probe-only`: inspect or evaluate without mutating the
  working result.
- `read-only`: do not mutate the working result or any remote state.
- `no-remote`: do not push, create or update a PR, comment, start a remote
  readiness wait, release, or perform another remote mutation.
- `no-commit`: leave Git history unchanged.

Resolve two independent mutation dimensions:

- `local_mutation` is `forbidden` for `report-only`, `probe-only`, or
  `read-only`; otherwise it is `allowed`.
- `remote_mutation` is `forbidden` for `local-only`, `report-only`,
  `probe-only`, `read-only`, or `no-remote`; otherwise a selected
  `pr-readiness-handoff` records `review-authorization-required`.

These constraints are subtractive and take precedence over `full workflow`,
PR-ish, merge-ready, or similar expansion signals in the same request. Any
remote-mutation-limiting constraint forbids `pr-readiness-handoff` and every
remote mutation. Select the appropriate remaining local profile. A later
explicit user request may remove the constraint; a downstream workflow may not
reinterpret it.

Remote mutation being forbidden does not erase an explicitly requested
read-only PR-readiness probe. Unless `local-only` or an explicit no-network/no
remote-access instruction also forbids remote reads, route that request to
`$review-orchestration-playbook` with handoff profile
`pr-readiness-read-only-probe`. This handoff may collect only PR selection,
lifecycle, CI, conversation, base, and head evidence. It never authorizes a
comment, `@codex review` request, state-changing wait, branch or PR metadata
change, fix, commit, push, release, or merge.

An explicit `report-only`, `probe-only`, `read-only`, or `no-commit` request
also sets commit mode to `forbidden` for the whole run. Apply it before any
review checkpoint, anchor, or landing commit. A delivery profile never
overrides it.

When commit mode is `forbidden`, run only the requested inspection or gate work
and leave Git history unchanged. A formal review may use a pre-existing exact
committed range only when it already represents the result under review.
Otherwise skip the formal lane and report that the missing committed range is a
blocker only when formal review is required; do not create an implicit
checkpoint to satisfy the reviewer. When formal review is not required, report
the uncommitted checked result and exact validations directly without inventing
a missing-range blocker or review handoff.

When `local_mutation` is `forbidden`, short-circuit the implementation and
journal steps. Do not edit source or documentation, write a journal, create a
commit, generate working-result artifacts, update an index or ref, or run a
validation known to create output, caches, or persistent state. Run only the
read-only validation subset defined below. Unknown mutation behavior is not
read-only.

## Choose The Profile

After applying hard constraints, choose by the remaining requested terminal
outcome, using this precedence:

1. An explicit PR, PR-readiness, full-workflow, or merge-ready outcome selects
   `pr-readiness-handoff` only when no hard constraint forbids that handoff.
   When the handoff is forbidden, the same full-workflow signal selects
   `local-gate`. It stops locally unless the request also explicitly asks for
   PR-readiness evidence and remote reads remain allowed; that combination uses
   the read-only PR probe handoff.
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
| `Implement and validate this locally, but do not commit.` | `local-gate` | mutable local gate, then uncommitted report |
| `Run the full workflow locally, report-only.` | `local-gate` | gate-only report under local/report constraints |
| `Run the full workflow with no remote work.` | `local-gate` | full local gate, then stop under `no-remote` |
| `Review full-workflow readiness read-only.` | `local-gate` | read-only gate report with no handoff |
| `Probe full workflow and PR readiness; do not make remote changes.` | `local-gate` | read-only local report, then read-only PR probe |
| `Complete the full local workflow, then report PR readiness without remote mutations.` | `local-gate` | full local gate, formal review, then read-only PR probe |
| `Run the full workflow and open a PR.` | `pr-readiness-handoff` | full local gate, then PR handoff |

### `focused-checkpoint`

Choose this only for an explicit MVP, early usable product, quick iteration,
agile delivery, scout, `先可用`, `快速迭代`, or similar first-slice request.

- Define the smallest user-visible behavior, artifact, command, or diagnostic
  that makes the slice useful.
- When `local_mutation` is `forbidden`, inspect that slice without creating or
  changing it and report only read-only evidence.
- Run focused checks and, when local mutation is allowed, the conditional
  journal gate.
- When commit mode allows, create a signed local checkpoint automatically.
- Stop at the checkpoint unless the user asks to continue.

The checkpoint is a product-feedback point, not merge-ready. Do not
automatically push, open a PR, wait for CI, start external review, release, or
merge.

### `local-gate`

Choose this for ordinary non-trivial delivery, local gate readiness, or a
pre-commit workflow when no narrower or remote outcome was requested.

- Complete the implementation and reasonable local validation when
  `local_mutation` is `allowed`; otherwise perform only the read-only validation
  subset and report the existing result.
- When local mutation is allowed, update required documentation and apply the
  conditional journal gate.
- Complete the required local/internal review.
- When commit mode allows, create a signed landing commit automatically.
- Stop locally unless the user separately authorizes remote work.

### `pr-readiness-handoff`

Choose this when the user requests a full workflow, PR readiness, merge-ready,
`在合并前停止`, `stop before merge`, or explicit continuation after the local
gate.

- Complete the full `local-gate` first.
- Create the signed landing commit when commit mode allows.
- Hand off to the authoritative `$review-orchestration-playbook` only after the
  local gate succeeded, an exact committed range exists, required formal review
  is clean, the landing signature is verified, and required authorization and
  input are satisfied.

The selected profile records the requested terminal outcome; it is not proof
that the handoff became ready. Preserve `profile: pr-readiness-handoff` on a
blocked run, but set `handoff: none` and `handoff_profile: none`. Missing
committed range, review findings, signing failure, blocked authorization, or
blocked input always stop before handoff.

The review skill owns target authorization, PR selection and lifecycle, named
review shapes, CI and conversation handling, and the merge-ready decision.
This profile does not authorize merge.

### `pr-readiness-read-only-probe` handoff

This is a handoff mode from `local-gate`, not a fourth delivery profile. Select
it only when the request explicitly asks for PR-readiness evidence while remote
mutation is forbidden and remote reads remain allowed.

- Hand the closed delivery record to `$review-orchestration-playbook`.
- Allow only selection of an existing PR and read-only snapshots of lifecycle,
  CI status, conversation state, and exact base/head evidence.
- A bounded refresh may reread that evidence. It must not start CI, a reviewer,
  a check, or another remote action and must not persist an authentication
  refresh or cache. If the required read cannot remain non-mutating, report it
  blocked.
- Forbid comments, `@codex review`, state-changing waits, branch/ref or PR
  metadata changes, fixes, commits, pushes, releases, and merge.
- Return terminal `pr-readiness-read-only-report`, conforming to its
  [closed receiver schema](../review-orchestration-playbook/references/pr-readiness-read-only-report.schema.json),
  and let the receiver choose its staged terminal target. Selection failure
  must remain a real pre-target report with no invented PR/base, while
  preserving the exact current query head; a selected PR whose base lookup
  fails must retain that selected PR and current head while omitting the
  unresolved base.
  Every report uses fresh instance IDs, and every `observed` evidence kind
  must contain its one closed kind-specific record and repeat the exact report,
  target, and snapshot bindings. Unavailable or blocked kinds contain no
  observation record. Never call this merge-ready and never promote the
  handoff to the mutation-capable `pr-readiness` profile.

When a non-trivial delivery request is otherwise ambiguous, use `local-gate`.
Stop for input when the missing choice would materially change scope or remote
authorization.

## Run The Shared Workflow

1. Confirm scope.
- Read the applicable repository policy and preserve unrelated user changes.
- Record the selected profile, every canonical hard-constraint token, resolved
  local-mutation mode, commit mode, intended local outcome, and any permitted
  remote handoff.
- When `local_mutation` is `allowed`, fix only blockers that are necessary for
  that outcome. Otherwise report them without modification.

2. Implement.
- Skip this entire step when `local_mutation` is `forbidden`; inspection cannot
  become an implementation pass.
- Read the relevant code, tests, and documentation before editing.
- Keep the diff focused and correct low-level mistakes introduced by the task.
- Under `focused-checkpoint`, defer polish, broad refactors, extra platforms,
  release wiring, and full gates that are not required for the first slice.

3. Validate.
- When `local_mutation` is `forbidden`, first classify each candidate check by
  its documented side effects. Run only commands proven not to write the
  worktree, Git index or refs, generated output, caches, journals, user
  configuration, or persistent host state. Disable optional caches and lock
  refreshes where the tool provides an authoritative no-write mode. Treat an
  unknown or merely hoped-for no-write behavior as mutating: skip it and report
  the unavailable gate. Source/object inspection, already-produced result
  parsing, and explicitly no-cache/no-output validators form the read-only
  subset; builds, tests, formatters, code generators, dependency resolution,
  and validators that may populate caches do not.
- Do not create a generated artifact merely to make a read-only check possible.
  A formal review of a pre-existing range may use the review skill's own
  isolated ephemeral evidence lane only when formal review is required; that
  lane must not change the delivery worktree or become a delivered artifact.
- When local mutation is allowed, `focused-checkpoint` uses the narrowest checks
  that prove the slice builds, runs, or can be inspected, and reports broader
  checks that were skipped.
- When local mutation is allowed, `local-gate` and `pr-readiness-handoff` use
  the repository's broadest reasonable local build, unit, integration, and
  end-to-end checks.
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
  checks only when `local_mutation` allows the needed fix. Otherwise report the
  failure without changing the result. Never claim a gate that was not run.

4. Apply the journal automation gate.
- Skip this entire step when `local_mutation` is `forbidden`; an adopted journal
  is still part of the working result and cannot be updated by a read-only run.
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
- Resolve `formal_review_required` once after the profile and hard constraints,
  before creating any review checkpoint:
  - `pr-readiness-handoff` always resolves to `true`.
  - An ordinary mutation-capable `local-gate` with commit mode `allowed`
    resolves to `true`.
  - A constrained `local-gate` with commit mode `forbidden` resolves to `false`
    unless the user or repository policy independently requires formal review.
  - `focused-checkpoint` resolves to `false` by default and uses
    risk-proportionate local diff/self-review. It resolves to `true` only when
    the user, repository policy, or authoritative risk policy requires a formal
    lane.
  - An independent formal-review requirement may promote a default `false` to
    `true`; it may not downgrade either profile-mandated `true`.
- Record the resolved boolean in the delivery result before review starts and
  preserve it unchanged across every handoff. Do not let a downstream receiver
  reinterpret the profile, constraints, or risk prose into a different value.
- Apply the resolved commit mode before creating anything for review. Under
  `report-only`, `probe-only`, `read-only`, or `no-commit`, do not create a
  checkpoint or anchor. When formal review is required, use a pre-existing
  exact committed range only when it already represents the result; otherwise
  report the formal lane blocked. When formal review is not required, report
  the checked result and exact validations without requiring a range.
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
    range; review the new exact range. This branch has no terminal delivery
    record until a later exact range is clean or another independent blocker
    occurs. In particular, it may never emit `review-findings`.
  - If commit mode is `forbidden`, do not apply fixes or create or require a new
    head, checkpoint, anchor, or commit. Preserve the exact existing committed
    range, report the unresolved findings as a blocker, and stop. Only a later
    authorization may begin a new mutation-capable run.
- Resolve every required formal-review terminal state with this matrix:

| Formal review required | Commit mode | Exact committed range | Formal review result | Required terminal action |
| --- | --- | --- | --- | --- |
| `true` | `allowed` | available | `clean` | Continue to the signed-commit step, reusing the clean checkpoint when it already is the landing commit. |
| `true` | `allowed` | available | `findings` | Apply fixes and repeat the affected gates on a new exact range. |
| `true` | `forbidden` | missing | not started | Report `missing-committed-range` as a blocker and stop. Do not create or require a checkpoint, anchor, or commit to start review. |
| `true` | `forbidden` | available | `findings` | Report `review-findings` as a blocker and stop on the preserved range without mutation. |
| `true` | `forbidden` | available | `clean` | Report the exact clean range, bypass the signed-commit step, and continue directly to the profile terminal step. Do not create, require, amend, or relabel a commit. |
| `false` | `forbidden` | missing | not required | Report the uncommitted checked result and exact validations. Do not invent a missing-range blocker, start formal review, create a commit, or hand off solely for review. |

- Continue to the signed-commit step only when the latest reviewed head is clean
  under an allowed commit mode.
- A clean review under forbidden commit mode is complete evidence for the
  pre-existing exact range. It does not turn commit mode back to `allowed`.
- Before a clean pre-existing range may enter either PR-readiness handoff,
  perform read-only signature verification on the exact frozen head. Record
  `signature: verified` together with `signature_verified_head_oid` equal to
  that exact frozen head. This read-only signature verification authorizes no
  commit, amendment, ref update, fetch, or key import. An unsigned or
  unverifiable frozen head cannot hand off: preserve the range, record
  `signature: failed` with a null verified-head binding, and stop with
  `signing-failed`. A local-only clean-range report that does not hand off may
  continue to use `signature: not-required`.
- A missing exact range or review findings under forbidden commit mode is a
  terminal blocker only when formal review is required. Do not continue to a
  profile handoff from either blocker.
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
- `local-gate` stops at the signed local landing commit, at the requested
  uncommitted checked-result report when formal review is not required, at the
  report when a pre-existing exact range reviewed cleanly, or at the
  `missing-committed-range` / `review-findings` blocker when formal review is
  required and commit mode forbids a commit. It does not push without separate
  authorization.
- `pr-readiness-handoff` continues through `$review-orchestration-playbook` and
  stops at merge-ready or a clear blocker, never at merge, only when its
  terminal record proves the complete ready gate. Under forbidden commit mode,
  it may hand off the clean pre-existing exact range only when no hard
  constraint forbids remote work and all remaining evidence is satisfied; a
  missing range, findings, signing failure, authorization blocker, or input
  blocker stops before handoff.
- A hard constraint that forbids remote mutation always wins at this step. Do
  not invoke the review skill's mutation-capable PR-readiness path, push, create
  or update a PR, comment, request `@codex review`, start a state-changing wait,
  or release. An explicitly requested read-only PR probe may still use the
  `pr-readiness-read-only-probe` handoff unless remote reads are also forbidden.

## Emit The Result And Handoff Record

Every terminal report and permitted handoff must include the JSON-compatible
record defined by
[delivery-result.schema.json](references/delivery-result.schema.json). Preserve
these fields unchanged across any handoff:

- `profile`
- every explicit canonical token in `constraints`
- resolved `local_mutation`
- resolved `commit_mode`
- resolved `formal_review_required`
- resolved `remote_mutation`
- closed `terminal_outcome`, `terminal_reason`, and `terminal_evidence`
- `handoff`
- `handoff_profile`

The v3 schema's `$defs.successTerminalMatrix` is the machine authority for every
successful reason. One reason fixes one exact profile, local-mutation mode,
commit mode, formal-review requirement, remote-mutation mode, handoff,
handoff profile, and complete evidence object. The evidence object separately
records local gate, build, tests, docs, journal, committed range, formal
review, signature, signature-bound exact head, authorization, and input.
`signature_verified_head_oid` is a full SHA-1 or SHA-256 object ID exactly when
`signature` is `verified`; it is null for `failed` and `not-required`.
Mutation-capable success uses
`satisfied` for each build/tests/docs/journal gate; a no-mutation observation
uses `read-only-observed` and never implies that a mutating gate ran. No
successful matrix row may contain `blocked`, `failed`, `findings`, or
`not-started`.

The closed reason families are:

- focused checkpoint: signed, reviewed-signed, mutable uncommitted,
  read-only uncommitted, mutable clean-range, or read-only clean-range;
- local gate: signed complete, mutable uncommitted, read-only uncommitted,
  mutable clean-range, or read-only clean-range;
- mutation-capable PR handoff: signed ready or clean existing-range ready;
- read-only PR handoff: read-only unreviewed, read-only reviewed,
  signed local-gate, mutable uncommitted, or mutable existing-range probe.

Do not reuse a reason across two rows or infer a missing row from prose. A
receiver must reject a reason/profile/mode/evidence cross-product even when
every individual value is otherwise in its enum.

For `report-only`, `probe-only`, or `read-only`, `local_mutation` must be
`forbidden`. For `local-only`, `report-only`, `probe-only`, `read-only`, or
`no-remote`, `remote_mutation` must be `forbidden` and `profile` must not be
`pr-readiness-handoff`. For `report-only`, `probe-only`, `read-only`, or
`no-commit`, `commit_mode` must be `forbidden`.

Only a successful `pr-readiness-handoff` record without a remote-limiting
constraint and with exact ready evidence may set `handoff` to
`review-orchestration-playbook`, `handoff_profile` to `pr-readiness`, and
`remote_mutation` to `review-authorization-required`. Exact ready evidence is:
local gate `succeeded`, build/tests/docs/journal all `satisfied`, committed
range `present`, formal review `clean`, signature `verified`, authorization
`satisfied`, and input `satisfied`. A forbidden-commit PR handoff instead uses
the distinct existing-range reason, local gate `checked`, the same four
`satisfied` phase records, a present clean range, and a read-only verified
signature whose `signature_verified_head_oid` equals the exact frozen head.
The remote-mutation value is not itself remote authorization;
it means the review skill must perform its own target and lifecycle preflight.

Every blocker uses `terminal_outcome: blocked`, one closed reason, and one row
from `$defs.blockedTerminalMatrix`. The matrix closes implementation,
earliest-failing validation stage, journal, formal-review, missing-range,
findings, signing, authorization, and input evidence and forces both handoff
fields to `none`; contradictory later-stage evidence is invalid. Preserve
the requested profile so the report states what was attempted without
misrepresenting the blocked terminal as a ready transition.
`review-findings` is valid only when formal review is required and commit mode
is `forbidden`, with a present range, findings, and signature
`not-required`. Findings under commit mode `allowed` are never terminal: they
must return to repair, validation, journal, signed-head, and exact-range review.

A `local-gate` record with an explicit PR-readiness probe and no
remote-read-limiting constraint may instead set `handoff` to
`review-orchestration-playbook`, `handoff_profile` to
`pr-readiness-read-only-probe`, and `remote_mutation` to `forbidden`. Preserve
the already resolved `formal_review_required` value: a `local-gate` whose commit
mode is `allowed` keeps `true` and completes its formal review before the probe;
a commit-forbidden gate may keep its default `false` or an independent
policy-required `true`. The exact reason distinguishes those states:
`pr-readiness-read-only-probe-ready`,
`pr-readiness-read-only-reviewed-probe-ready`,
`pr-readiness-read-only-gate-ready`,
`pr-readiness-read-only-uncommitted-probe-ready`, or
`pr-readiness-read-only-existing-range-probe-ready`. The handoff never changes
that value. The receiver must preserve that read-only capability ceiling and
return only the selection/lifecycle/CI/conversation/base/head evidence report.
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
