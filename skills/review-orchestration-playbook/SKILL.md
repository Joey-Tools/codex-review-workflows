---
name: review-orchestration-playbook
description: Orchestrate Joey's named single, double, and triple code-review shapes plus PR and merge readiness. Use for a fresh local Codex review, a direct Claude Code review, GitHub Cloud `@codex review`, or an authorized review, CI, and conversation fix loop. Single is one logical fresh Codex lane; double adds actual Claude Code; triple adds current-head GitHub Codex.
---

# Review Orchestration Playbook

Use this skill as the only entrypoint for named review shapes and PR-readiness orchestration. Count logical reviewer lanes, not processes, retries, helper calls, or a model's internal delegation.

## Choose The Shape

| Requested shape | Required reviewer lanes |
| --- | --- |
| `single` / `single review` / `单重 review` | One fresh-context local Codex lane. |
| `double` / `double review` / `双重 review` | Single plus one actual Claude Code lane. |
| `triple` / `triple review` / `三重 review` | Double plus current-head GitHub Codex evidence on an existing supported GitHub.com PR. |

PR readiness is the effective review shape plus current-head CI, conversation, branch/base, and repository merge-policy gates. It does not add another reviewer.

The seven Joey-Tools skill repositories may route an unnamed PR-bound request to `skill-repo-codex-gate`: one local Codex lane plus GitHub Codex. That is a separate repository default, not an alias for single, double, or triple. An explicitly named shape wins.

## Freeze Scope Before Review

Freeze one committed `base_sha..head_sha` range for all local lanes. Resolve a PR selector separately.

- A caller-supplied range stays authoritative. Do not silently replace it with a PR range.
- At the first freeze, persist a parent-owned immutable `range_origin` lineage
  header and first record. The header fixes a stable `lineage_id` and `kind`;
  every record has a stable `record_id`, exact endpoints, and the parent binds
  exactly one `active_record_id`. Missing or unknown origin blocks a local lane
  that would count as PR-wide coverage.
- A successor record must keep the same lineage and kind, name the previously
  active record as its predecessor, and be created together with the parent's
  active-record advancement as one parent-owned transition. Appending a record
  alone never activates it; never replace a caller-supplied lineage with a
  PR-derived lineage.
- If the PR merge base changes while its head stays fixed, a `pr-derived` range
  may be rederived automatically. Preserve a `caller-supplied` range until the
  caller explicitly supplies or confirms the exact current endpoints; that
  confirmation authorizes a new parent-owned successor record rather than
  rewriting the old one.
- Treat the range as the complete Git DAG comparison. Merge commits and in-range side history are valid; never project it to linear, first-parent, or ancestry-path history.
- When PR-wide coverage matters, require one unique current merge base, `base_sha` to equal it and be an ancestor of `head_sha`, and `head_sha` to equal the selected PR's current head.
- A report-only review request does not authorize a branch, commit, push, PR creation, PR retarget, or metadata change.
- Do not review intended uncommitted or untracked changes as a named lane. Ask for an existing committed range or separate authorization to create a review commit.
- A fix creates a new head. Freeze the new range and rerun every lane required by the requested shape.

Read [review-lane-contracts.md](references/review-lane-contracts.md) for shared scope, outcome, self-policy, and rerun rules. For PR selection and readiness, also read [pr-readiness.md](references/pr-readiness.md) and [github-pr-probes.md](references/github-pr-probes.md).

## Run Local Lanes

Each local lane gets its own independent, clean, detached, read-only Git workspace. The workspace contains committed repository state only; it must not share Git administrative state or mutable object dependencies with the source or another lane. The reviewer receives the workspace, frozen endpoints, applicable guidance order, and output contract—not a prebuilt diff—and inspects the range itself with bounded commands.

Prepare and validate each workspace through the active trusted helper contract in [review-workspace.md](references/review-workspace.md). Always clean it up after a terminal lane result unless the user explicitly asks to retain it for diagnosis.

### Local Codex

Read [local-codex-lane.md](references/local-codex-lane.md) and [review-prompt-templates.md](references/review-prompt-templates.md).

A fresh zero-inherited-context `reviewer` subagent and a fresh non-resumed Codex CLI review process are peer adapters for the same one logical lane. Neither is the default winner. Select the adapter that can most directly realize the intended effective reviewer profile with the least orchestration and context overhead.

The intended installed profile is `gpt-5.6-sol` with Codex mode `ultra`. Ultra may internally delegate; that remains one logical lane. Record the requested and effective adapter, model, and mode. Do not describe `ultra` as an OpenAI API `reasoning.effort` enum value.

### Claude Code

Double and triple add one actual Claude Code process in a second independent workspace. It starts fresh, receives no Codex findings, and returns its own findings-only result. Another Codex process, GitHub Copilot, or a Claude simulation never satisfies this lane. Read [canonical-claude-lane.md](references/canonical-claude-lane.md) before launching it.

## Run The GitHub Lane

Before any GitHub-lane action, read [github-codex-evidence-authority.md](references/github-codex-evidence-authority.md). It is the field-level authority for producer identity, complete pagination, lifecycle, terminal selection, unresolved findings, fallback reactions, and machine-readable reporting.

The intended current policy is:

- Use exact `@codex review` on an existing supported `github.com` PR at the frozen current head. Do not infer provider coverage of the local merge base; base and merge-base coverage remain local PR-readiness facts.
- A trustworthy provider terminal clean comment or review on the latest head, together with no unresolved provider finding in the PR, passes the lane. Prefer a trustworthy associated merge-commit or provider status check when the repository exposes one, while still checking unresolved provider findings.
- A complete provider `+1` reaction basis is a fallback when no stronger terminal artifact is available.
- Only applicable unresolved provider findings block. On the same head, an exact
  typed GraphQL thread resolution or a later trustworthy provider correction
  accepted by the evidence authority can clear a finding without inventing a
  code change. If addressing a finding actually changes code, the resulting
  new head invalidates old-head evidence and requires fresh review.
  A successful service-start check alone is not a clean review.

Only a machine-decidable retryable pending or infrastructure reason enters
automatic recovery. A stable malformed snapshot, scope contradiction, or
other non-retryable inconclusive result terminates recovery and is reported
immediately. For a retryable reason, prefer the smallest associated recovery,
but rerun or dispatch a GitHub Action automatically only when the repository
predeclares that exact operation as idempotent or reentrant for the frozen
scope and the current mutation is authorized. Otherwise poll read-only state
and report the missing contract or authorization. Never reconcile an explicit
code finding, test failure, or policy failure as infrastructure.

While that exact reason remains machine-decidably retryable, use one
single-flight recovery schedule: 1, 2, 4, 8, 16, 32, then 60 minutes, followed
by hourly retries without a fixed attempt limit. Report to the user when the
delay first reaches 60 minutes and keep recovery pending. Apply the
repository's private-run cost budget; when it is exhausted, poll status only
until a low-frequency retry is allowed. Public repositories may retry more
freely within the same authorization boundary. Prefer an Automation that
wakes the same active thread; when that capability is unavailable, keep a
cancellable hourly wait in the active thread. Remove the wake-up when the
result becomes terminal or the PR closes, merges, or is superseded.

## Drive PR Readiness

When the user authorizes implementation or PR repair, loop on the same explicit PR and current head:

1. Classify all local and GitHub reviewer findings.
2. Resolve valid findings. When resolution changes code, add proportionate
   tests and create a new committed head; a typed thread resolution or
   trustworthy same-head provider correction alone does not require a commit.
3. Rerun every invalidated lane. A code-changing new head requires fresh local
   and GitHub review; a resolution-only same-head transition requires the
   authority's complete stable reread instead.
4. Wait for required CI and read all review conversations with complete pagination.
5. Confirm no unresolved blocking finding, the intended base/head relationship, open lifecycle, merge policy, and a final stable reread.

If merge is authorized, bind both a direct merge and merge-queue enrollment to
the exact reviewed `head_sha` in the state-changing server request itself. For
a direct merge, select the exact repository and PR and pass
`--match-head-commit <head_sha>` to `gh pr merge`. For a queue, use GitHub's
documented asynchronous merge request with exact `sha`,
`merge_action: merge_queue`, and a polled `expected_head_sha`; do not accept a
CLI path that merely enables a long-lived auto-merge request. If that queue API
or an equally persistent server-side expected-head binding is unavailable,
the queue path is blocked. A separate head read is not an atomic substitute.
A mismatch fails closed: reread scope and rerun every gate invalidated by the
resulting current state before any new merge attempt.

GitHub's `Require branches to be up to date before merging` policy is distinct from `Require linear history`. If strict freshness is the blocker and no merge queue owns freshness, merge the current base branch into the feature branch with a signed merge commit instead of rebasing, force-pushing, or linearizing it. The merge creates a new head, invalidates all old-head evidence, and requires a newly frozen whole-PR range plus the entire pre-merge verification loop.

Use [pr-readiness.md](references/pr-readiness.md) for the detailed gate. Transport errors and provider outages stay `pending` while the recovery policy can make progress; malformed or contradictory stable evidence is `inconclusive`. Do not turn uncertainty into a pass.

## Preserve Authorization Boundaries

Named review consent authorizes only the processors in that named shape and their scoped review input. Read [egress-consent.md](references/egress-consent.md) before exposing repository data to an external processor.

A bare triple request authorizes the scoped exact `@codex review` producer operation on an already-existing supported PR, including only the evidence authority's single-flight recovery after ambiguous delivery. It does not authorize PR creation, branch mutation, empty commits, merge, or unrelated repository actions. PR repair, delivery, and merge require their own authorization.

## Self-Policy Migration

When this skill, its role, prompt, workspace helper, launcher, or validator is itself in the reviewed range, candidate-head policy is review subject—not the review control plane. The trusted parent may enumerate and digest-bind candidate Markdown only as `review-subject`; it is never activated as repository guidance.

Use the previously trusted installed bundle outside the candidate range to prepare and validate workspaces and launch the formal review. Record its absolute path, release identity, and digest. Never execute candidate-head review-control code to approve itself. A subagent adapter may count only when the host supplies a parent-verifiable instruction-surface receipt proving that no candidate or user guidance was injected automatically; role digest, zero inherited context, and host acceptance are insufficient. If that isolation cannot be proved, do not use the subagent adapter for this migration; use an eligible CLI adapter or report the lane inconclusive. If the prior bundle cannot use the new interface, complete the migration review under the prior trusted policy, merge and release it, then activate and smoke-test the new interface from that release.

## Reference Router

- Always read [review-lane-contracts.md](references/review-lane-contracts.md).
- For a local Codex lane, read [local-codex-lane.md](references/local-codex-lane.md), [review-workspace.md](references/review-workspace.md), and [review-prompt-templates.md](references/review-prompt-templates.md).
- For Claude Code, additionally read [canonical-claude-lane.md](references/canonical-claude-lane.md). Read [claude-runtime-trust.md](references/claude-runtime-trust.md) only when changing or diagnosing its runtime provenance, authentication, process, or stream validator.
- For GitHub Codex, read [github-codex-evidence-authority.md](references/github-codex-evidence-authority.md). Read [github-pr-probes.md](references/github-pr-probes.md) for authenticated probes.
- For PR or merge readiness, read [pr-readiness.md](references/pr-readiness.md).
- For review-data authorization, read [egress-consent.md](references/egress-consent.md).
