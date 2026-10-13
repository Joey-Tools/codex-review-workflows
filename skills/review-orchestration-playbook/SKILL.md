---
name: review-orchestration-playbook
description: Orchestrate remote-first PR review and merge readiness using GitHub Codex @codex review or native GitHub Copilot code review. Use for explicitly requested fresh local Codex review, opt-in Claude Code review, named single/double/triple shapes, or an authorized review, CI, and conversation fix loop.
---

# Review Orchestration Playbook

Use this skill as the only entrypoint for review selection and PR readiness.
Count independent reviewer judgments, not processes, retries, helper calls,
admission checks, or a reviewer's internal delegation.

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

Read [Default Review Routing](references/default-review-routing.md) before
selecting a provider or applying a session choice. Use its read-only
availability probe, model consent and native Copilot rules. Claude requires
explicit opt-in; generic review or delivery does not add double/triple.
Record the selected provider and requested/effective lanes.

## Freeze Scope Before Review

Freeze one committed `base_sha..head_sha` range for local lanes. Preserve the
caller's supplied range and its parent-owned origin; do not silently replace
it with a PR-derived range. Compare the complete Git DAG, including merge
commits and side history, not a linear or first-parent projection.
For whole-PR coverage, bind the selected PR's exact current head, target ref,
base tip and unique merge base. A new head invalidates old-head positive
evidence. An observed base change requires a fresh scope and final reread;
revalidate only evidence whose recorded dependencies include the changed base
dimension. The routine merge profile binds the exact reviewed head in the
server mutation and accepts the documented GitHub control-plane trust boundary.

Read [Shared Scope](references/review-lane-contracts.md#frozen-range) for
scope, independence and outcomes, and
[PR Range And Invalidation](references/pr-readiness.md#freeze-the-whole-pr-range)
when the range must count as whole-PR coverage. Do not create a review commit
or include dirty/untracked state under report-only authorization.

## Run Local Lanes

Use separate clean, detached, read-only workspaces with committed tracked
state and independent Git storage. Give reviewers the frozen endpoints and
applicable guidance, not a prepared diff or another reviewer's conclusions.
Prepare and validate through the trusted
[workspace helper](references/review-workspace.md), including ordinary
candidate-guidance admission. Clean up terminal workspaces unless retained
with explicit user authorization.

- Local Codex: read [Local Codex](references/local-codex-lane.md) and
  [Prompt Templates](references/review-prompt-templates.md). A fresh-context
  subagent and non-resumed CLI are peer adapters for one logical lane. Default to `gpt-6.1-sol`
  at model-default reasoning, currently `medium`, not the parent's effort.
  Another model/effort requires explicit opt-in; worker allocation alone
  does not authorize a reviewer override. Record requested and effective
  adapter, model and reasoning.
- Claude: read [Claude Code](references/canonical-claude-lane.md) only after
  explicit opt-in. Default to Opus 5.5 at model-default effort. Use an actual
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
generic successful checks, service-start markers and unknown prose do not pass.

When evaluating a producer/status pass basis or any Actions recovery, also
read [Producer And Recovery](references/github-codex-producer-and-recovery.md).
Its outside-candidate trust, immutable closure, exact scope, transaction,
single-flight and cost requirements remain mandatory. A dispatch alone is
status-only. Never reconcile code, test or policy failures as infrastructure.

## Drive PR Readiness

Read [PR Readiness](references/pr-readiness.md) before claiming merge-ready
or executing an authorized merge. The routine profile is the default; strict
base proof is opt-in. Handle applicable findings, add proportionate tests for
fixes, freeze any new head, and repeat every invalidated required lane. Acquire
complete CI and conversation evidence, repository merge policy and a final
stable reread. Omitted local lanes remain omitted.

A merge requires its own authorization. Bind the reviewed head in the
state-changing server request itself, using `--match-head-commit <head_sha>`
for direct merge; queue enrollment uses the separate persistent `merge-async`
SHA binding. Do not request administrator or other bypass. Routine mode does
not require an exact-base or atomic base-contraction proof; report its
GitHub control-plane trust boundary and residual race. Strict mode retains the
readiness reference's complete base proof. Preserve persistent queue head
binding. If required strict freshness requires a base update, use a signed
merge and rerun evidence invalidated by the resulting new head, not rebase or
force-push.

Within the authorized repository/PR scope, read-only inspection of branch
protection, rulesets, bypass lists, and effective permissions needs no extra
verbal confirmation. An unavailable read is unknown, not a pass. This does not
authorize policy changes, bypass use, auth switching, workflow dispatch/rerun,
or other external writes; follow the environment's execution permissions.

## Preserve Authorization Boundaries

Read [Egress Consent](references/egress-consent.md) before external review.
A bare named request is report-only except the one scoped GitHub Codex
request allowed by bare triple. It never authorizes branch/PR metadata
mutation, extra repositories, Actions recovery or merge. Keep one mutation
owner and the exact-request write budget; uncertainty is not authorization.

## Self-Policy Migration

Candidate review policy and executables are review subjects, not their own
approval control. Use an independently trusted installed/released bundle
outside the candidate range. Read
[Self-Policy Trust](references/review-lane-contracts.md#self-policy-migration-trust-boundary)
before preparing or admitting candidate guidance. Use only an adapter with
proved instruction isolation; otherwise report the lane inconclusive.
Do not execute candidate control code to approve itself.

Use semantic judgment for design relevance and prose. Fixed receipt fields,
digests, modes and enumerated states are machine interfaces, not optional
writing conventions: use the owning helper or versioned contract instead of
inventing, paraphrasing or accepting an approximate record.
