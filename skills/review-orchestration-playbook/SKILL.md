---
name: review-orchestration-playbook
description: Orchestrate remote-first PR review and merge readiness using GitHub Codex @codex review or native GitHub Copilot code review. Use for explicitly requested fresh local Codex review, opt-in Claude Code review, named single/double/triple shapes, or an authorized review, CI, and conversation fix loop.
---

# Review Orchestration Playbook

Use this skill as the only entrypoint for review selection and PR readiness.
Count independent judgments, not processes, retries, helper/admission calls, or internal delegation.

## Keep The Roles Separate

- Reviewer: `$code-review`, concrete frozen scope, then report and stop.
- Implementation agent: `$review-response`, verify findings and make authorized repairs.
- Parent: this playbook owns review selection, machine proofs, lane acceptance, and PR readiness.
Give each role only its instructions. Named single/double/triple requests still enter this playbook.

## Choose The Shape

For unnamed PR-bound delivery, use the repository-configured eligible GitHub
Codex or native GitHub Copilot provider, without adding local review.
For local-only delivery, use one fresh local Codex lane. Unknown or unavailable
remote support requires the user's session choice, not a silent fallback.
Pending or inconclusive remote evidence never supplies a local-only pass.
An explicit local or named request remains required.

| Requested shape | Required reviewer lanes |
| --- | --- |
| `single` / `single review` / `单重 review` | One fresh-context local Codex lane. |
| `double` / `double review` / `双重 review` | Single plus one actual Claude Code lane. |
| `triple` / `triple review` / `三重 review` | Double plus current-head GitHub Codex evidence on an existing supported GitHub.com PR. |

Read [Default Review Routing](references/default-review-routing.md) before selecting
a provider or session choice: it owns availability, model consent, and native
Copilot rules. Claude requires explicit opt-in; generic delivery adds no double/triple.
Record the selected provider and requested/effective lanes.

## Freeze Scope Before Review

Use [Routine Local Review](references/routine-local-review.md) by default:
compact prompts, parent-owned proofs, recoverable diagnostics, and dependency-based revalidation.
Exact audited projections/commands/reports require explicit selection; named shapes select processors only.
For commit or PR review, freeze a committed `base_sha..head_sha`; preserve the caller's range and parent-owned origin.
Explicit uncommitted local review uses the routine reference's frozen snapshot; it cannot satisfy PR readiness or a remote lane.
Keep the complete Git DAG, including merges and side history, available.
A new head requires a new local aggregate from affected-unit and integration review;
retain only dependency-checked supporting evidence under its original SHA.
Required remote review still binds the actual current head.
For whole-PR coverage, read
[PR Range And Invalidation](references/pr-readiness.md#freeze-the-whole-pr-range)
and bind exact head, target ref, base tip, and unique merge base.
Recheck scope after base changes and revalidate affected evidence. Track queue
synthetic SHAs separately. Audited shared scope is in
[Shared Scope](references/review-lane-contracts.md#frozen-range).
Report-only authority never creates commits. Explicit uncommitted review permits tracked snapshots; untracked files require separate user selection.

## Run Local Lanes

Use separate clean, detached, read-only workspaces with committed tracked state
and independent Git storage. Routine snapshots add a validated packet beside
the unchanged clean baseline, without live-source access or a head claim.
Give reviewers frozen scope and applicable guidance, not another reviewer's conclusions.
Commit review uses direct frozen Git objects; snapshot review follows the routine reference.
Prepare committed state through the trusted [workspace helper](references/review-workspace.md),
including candidate-guidance selection. Keep receipts in the parent without reviewer echo.
Clean up terminal workspaces unless retained with explicit user authorization.

- Local Codex: read [Local Codex](references/local-codex-lane.md) and
  [Prompt Templates](references/review-prompt-templates.md) only for an explicitly
  audited profile. Otherwise use Routine Local Review and the compact
  `reviewer` role; audited adapters use the packaged
  `agents/reviewer-audited.toml` template. Prefer a clean-context,
  read-only subagent; otherwise use a fresh non-resumed CLI for unsuppressed candidate controls or external write tools.
  Follow [Local Model and Reasoning Consent](references/default-review-routing.md#local-model-and-reasoning-consent)
  and, for routine review, [Startup And Recovery](references/default-review-routing.md#routine-local-startup-and-recovery).
  The default is `gpt-6.1-sol` / `high`, not the parent's effort. A generic
  subagent with the same boundaries is also eligible. Other model/effort
  selections require explicit opt-in; worker allocation alone is insufficient.
- Claude: read [Claude Code](references/canonical-claude-lane.md) only after
  explicit opt-in. Default to Opus 5.5 at `high` effort. Use an actual
  fresh independent Claude process; another Codex process, Copilot or a
  simulation never satisfies this lane. Preserve the preparation-to-launch
  source-authority handoff.

## Run The GitHub Lane

Read [Evidence Authority](references/github-codex-evidence-authority.md) for
provider identity, terminal selection, finding precedence and evidence
validation. Read [Authenticated Probes](references/github-pr-probes.md)
before acquisition or an authorized request. Read-only request discovery
and independent non-delivery proof are required before a first POST.
An ambiguous response never authorizes a duplicate comment POST.

A trustworthy current-head terminal clean comment or review plus zero
applicable unresolved provider findings completes the Codex lane, not CI
or merge readiness. Provider reactions are only the authority's fallback;
judge completion and findings from the full provider body, not an exact prose
template. Formatting changes alone do not invalidate a result. Identity,
current-head binding, complete findings, and final reread remain mandatory;
generic successful checks, service-start markers, and ambiguous meaning do not pass.

For a user-directed CI retry or an authorized diagnostic fix loop, follow
[Ordinary Diagnostic Reruns](references/github-codex-producer-and-recovery.md#ordinary-diagnostic-reruns).
Do not apply the automatic-recovery proof contract to that operation.
When evaluating a producer/status pass basis or authoritative automatic recovery,
read [Producer And Recovery](references/github-codex-producer-and-recovery.md).
Its outside-candidate trust, immutable closure, exact scope, transaction,
single-flight and cost requirements remain mandatory. A dispatch alone is
status-only. Never reconcile code, test or policy failures as infrastructure.

## Drive PR Readiness

Read [PR Readiness](references/pr-readiness.md) before claiming merge-ready or an authorized merge.
The routine profile is the default; strict base proof is opt-in. Handle findings,
add proportionate tests, freeze new heads, and repeat invalidated required lanes.
Acquire complete CI/conversations, merge policy, and a final stable reread. Omitted local lanes remain omitted.

Use `$review-response` to assess findings before
repair; this playbook retains the evidence, invalidation, and readiness gates.

A merge requires its own authorization. Bind the reviewed head in the
state-changing server request itself, using `--match-head-commit <head_sha>`
for direct merge; queue enrollment uses the separate persistent `merge-async`
SHA binding. Do not request administrator or other bypass. Routine mode does
not require an exact-base or atomic base-contraction proof; report its
GitHub control-plane trust boundary and residual race. Strict mode retains the
readiness reference's complete base proof. Preserve persistent queue head
binding with `bypass_rules: false`; verify the exact head, queue action, and
false bypass option before reusing a pending request. If required strict
freshness requires a base update, use a signed
merge and rerun evidence invalidated by the resulting new head, not rebase or
force-push.

Within authorized repo/PR scope, reading protection, rulesets, bypass lists, and
permissions needs no extra verbal confirmation. Unavailable reads stay unknown.
This grants no policy changes, bypass, auth switching, Actions mutations, or
other external writes; follow the environment's execution permissions.

## Preserve Authorization Boundaries

Read [Egress Consent](references/egress-consent.md) before external review.
A bare named request is report-only except the one scoped GitHub Codex
request allowed by bare triple. It never authorizes branch/PR metadata
mutation, extra repositories, Actions recovery or merge. Keep one mutation
owner and the exact-request write budget; uncertainty is not authorization.

## Self-Policy Migration

Candidate review policy/executables are subjects, not their own approval control.
Use independently trusted installed/released control outside the candidate range.
Routine review follows its compact boundary; for an explicitly audited profile,
read [Self-Policy Trust](references/review-lane-contracts.md#self-policy-migration-trust-boundary)
before preparing or admitting candidate guidance. Use a clean-context read-only
subagent or neutral CLI root; unsuppressible candidate-control injection requires
the neutral-root CLI fallback and cannot pass. Trusted personal guidance remains
allowed; fresh conversation context does not prove full host instruction isolation.
Do not execute candidate control code to approve itself. Use semantic judgment for
prose. Fixed receipt fields, digests, modes and states use their owning helper or
versioned contract; keep machine proofs out of routine model reports.
