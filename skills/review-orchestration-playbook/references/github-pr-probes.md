# GitHub PR Probes And Recovery

## Scope

Use these probes to acquire current PR, GitHub Codex, CI, conversation, and
workflow evidence. Interpretation of GitHub Codex results belongs to
[github-codex-evidence-authority.md](github-codex-evidence-authority.md).
Merge readiness belongs to [pr-readiness.md](pr-readiness.md).

Prefer typed `gh` output and exact REST or GraphQL fields. Keep large raw page
sets in a task-scoped bounded artifact and surface only IDs, URLs, times,
states, and decisive findings.

This probe layer owns acquisition, not interpretation. Preserve every complete
raw REST and GraphQL page used by a finding decision so the parent can freeze a
current-scope `finding_page_receipt`. Independently provide the exact full-DAG
range input for the parent's `finding_range_receipt`; only then may the parent
freeze the `finding_carrier_snapshot` selected from the complete observation
under the evidence authority's precedence and supersession rules. Freeze and
pass all three inputs before report validation and again for the final reread.
The evidence authority alone defines carrier validity, applicability, thread
resolution, terminal selection, and report classification.

## Select The Exact PR

An explicitly named PR wins. Otherwise accept only one authenticated open PR
whose head repository and branch exactly match the intended branch. Multiple
candidates require caller selection; a local diff range is not a PR selector.

Start with:

```bash
gh pr view <number-or-url> --repo <owner/repo> \
  --json url,number,state,isDraft,mergedAt,mergeable,mergeStateStatus,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,headRepositoryOwner,statusCheckRollup,reviewDecision
```

Record exact repository, PR number, `baseRefName`, `baseRefOid`, and
`headRefOid`. Use commit OIDs rather than mutable branch names for range
comparisons, but keep exact repository plus `baseRefName` as the target-ref
identity. Keep the exact `baseRefOid` as another independent readiness binding
rather than collapsing it into the unique merge base.

## Fetch Complete Provider Evidence

Fetch every page; do not rely on `gh pr view` summaries for authority.

```bash
gh api --paginate repos/<owner>/<repo>/issues/<pr>/comments
gh api --paginate repos/<owner>/<repo>/pulls/<pr>/reviews
gh api --paginate repos/<owner>/<repo>/pulls/<pr>/comments
gh api --paginate repos/<owner>/<repo>/commits/<head>/check-runs
gh api --paginate repos/<owner>/<repo>/commits/<head>/status
```

Always retain the exact feature head independently. If a dynamically verified
producer contract declares GitHub's synthetic merge commit as the check
subject, also read the PR REST resource's exact `merge_commit_sha`, verify that
the associated check suite/run reports that same subject, and fetch the complete
check-run and status collections for that exact SHA. Never substitute the
synthetic subject for `headRefOid`, and never infer it from a name or local
merge.

For each candidate request comment, fetch its individual reactions with the
GitHub reactions media type and full pagination. Aggregate reaction counts do
not include the actor identity required by the authority.

Fetch GraphQL `reviewThreads` from a null cursor. Retain each thread's `id`,
typed `isResolved`, typed `isOutdated`, `comments` connection, stable comment
IDs, URLs, parent review IDs, and both outer and nested `pageInfo`. Continue
each connection only when typed `hasNextPage` is true and require a non-empty
opaque `endCursor` for the next request. A terminal page is one with typed
`hasNextPage == false`.

Bind every GraphQL response back to raw `repository.nameWithOwner` and
`pullRequest.number`. Normalize IDs only for comparison; preserve the raw
records. Never synthesize `thread_resolved` on REST comments.

Derive the parent-owned `finding_range_receipt` independently from the exact
range's complete reachable DAG rather than treating ancestry embedded in a
carrier or snapshot as sole authority. Preserve merge commits and every
in-range side-history commit; do not acquire a `--first-parent`,
`--ancestry-path`, single-parent, or linear-history projection as a substitute.

Immediately before accepting a result, repeat the PR detail, all provider
evidence pages used by the decision, finding-thread state, exact feature-head
checks/statuses, and selected check subject plus its complete checks/statuses.
Require type-preserving equality with the initial closed scope and selection.
A changed head restarts the head-bound lane; a changed base ref/tip, merge base,
or synthetic subject invalidates a synthetic-merge basis.

An observed `baseRefName` change, even with the same OID, or a changed
`baseRefOid` invalidates all previously counted local reviews, local validation
and tests, CI/status results, conversation decisions, readiness decisions, and
the final reread, even when the head and unique merge base remain unchanged. A
trustworthy terminal artifact, reaction, or feature-head-only producer result
is the only exception: retain it only after this complete repeat proves its
exact head is still current and no applicable provider finding remains
unresolved. It supplies no base, merge-base, or target-ref coverage. A
synthetic-merge producer basis is base-sensitive and must be reacquired for the
new exact scope and check subject.

## Request The Review

Post the exact body:

```text
@codex review
```

Define one comment-mutation epoch by the exact repository, PR, and feature
head. In each epoch, permit at most one possibly delivered create-comment
POST. Before that POST, reread the unchanged PR head and completely enumerate
every page of the visible exact-request set for the current epoch. If an exact
request already exists, bind the selected visible request under the evidence
authority and do not POST. Keep one mutation owner and never run concurrent
comment POSTs. After a successful response, store its stable comment ID, URL,
actor, body, and server time.

Comment creation is not an idempotent operation. Once the create-comment call
could have reached GitHub, it consumes the epoch's comment-mutation budget
regardless of whether the client receives success, failure, or an ambiguous
transport outcome. An ambiguous outcome never authorizes a repeat. Reread the
unchanged head and the complete visible exact-request set. If the closed
before/after observations unambiguously prove which request that single call
created, bind its stable identity and continue. Otherwise set
`request_policy.status: unknown` and keep only read-only observation pending
while delayed visibility or typed retryable service state makes another read
meaningful. If no independently accepted terminal basis appears and delivery
remains unproved after that observation is exhausted, terminate the lane as
`inconclusive` with `last_reason: request-delivery-unproven`. Never repeat the
comment POST in that epoch.

Any visible duplicate remains part of the same logical review lane and is
recorded as an audit warning. An observed duplicate does not restore the
comment-mutation budget, never authorizes another comment write, and never
counts as an additional lane. Only a new feature head creates a new
comment-mutation epoch.

A base-only retarget, including one whose new ref has the same OID, or
target-base-tip advance on the same head does not authorize or require another
request. Reuse qualifying head-bound provider
evidence only after the exact-current-head and complete unresolved-finding
reread above. Rerun every invalidated local review, validation/test, CI/status,
conversation, readiness, and final-reread gate; when the merge base changed,
first require the parent-owned `range_origin` gate in
[pr-readiness.md](pr-readiness.md) to authorize the exact local PR-wide range.
Reconcile a related merge/status check when its contract is base-sensitive.
This probe layer never selects or rewrites that range. Never claim the provider
inspected the changed base tip or retargeted base.

## Discover Related Checks Dynamically

Do not hard-code a workflow filename, workflow display name, job name, or
check name. Start from the exact current feature head, then select the check
subject only through the verified producer contract:

1. Read `statusCheckRollup` plus the complete feature-head check-run and status
   collections. Preserve `headRefOid` even if no selected check is attached to
   it.
2. Select a candidate only when its App identity, `details_url`, check suite,
   external ID, or documented repository contract associates it with the
   GitHub Codex review or merge aggregation, and the contract has a closed
   parent-owned source trust anchor outside the candidate range. Candidate-head
   workflow or contract bytes cannot supply that anchor. Join the anchor to a
   separate parent-owned receipt containing the complete byte-sorted
   `merge_base..head` commit set, exact count, and digest; reject a
   same-repository source commit found anywhere in that set.
3. If that contract declares `github-synthetic-merge`, independently read the
   current base ref/tip, locally proved unique merge base, PR
   `merge_commit_sha`, and complete check/status collections for that subject.
   If it declares `feature-head`, require the subject SHA to equal
   `headRefOid` and make no base-coverage claim.
4. Follow the associated run URL or API identity to the exact workflow run and
   jobs.
5. Preserve the App ID/slug, workflow ID, run ID/attempt, check-suite ID, check
   ID/name/URL, feature head, base ref/tip, merge base, subject kind/SHA,
   status, conclusion, server time, producer-contract descriptor, and its
   candidate-range-external trust anchor and candidate-range exclusion receipt.

A name substring is a hint for discovery, not proof. A check attached to an
older head, a generic App success, or a run found only by static name guessing
is not a valid basis.

When a trustworthy related merge/status check exists, prefer it as the
positive GitHub-lane basis, while still enumerating unresolved Codex-provider
findings. Its independently verified contract and candidate-range-external
source anchor must define successful completion as
`github-codex-provider-clean`, require zero unresolved applicable findings,
and declare either `latest-feature-head` or `current-merge-scope`. The former
does not prove the PR base. The latter additionally requires the exact synthetic
subject and current base/merge bindings above. Ordinary readiness still
validates base and merge base locally. A generic successful check or
service-start marker cannot use this basis.

Before an authorized merge, acquire complete applicable branch-protection or
ruleset evidence for the exact base branch. A direct merge's base binding is
proved only by a documented server-side expected-base mutation precondition or
a repository-proved exact-base guard that rejects every
`baseRefOid != merge_expected_base` mutation without bypass. The strict setting
for **Require branches to be up to date before merging** is useful when a
branch is behind, but it is not an exact-base comparison: a different base tip
that is already an ancestor of the unchanged feature head may still satisfy
strict freshness. Required checks plus strict, `mergeStateStatus`, a
mergeability snapshot, or another `baseRefOid` read therefore do not by
themselves protect the later mutation.

The only direct-merge alternative is a complete parent proof of monotonic range
contraction. Require all of these from the complete applicable protection and
ruleset snapshot: the frozen `merge_expected_base_ref` equals the selected
repository plus `baseRefName`; the final unique merge base and
`merge_expected_base` both equal reviewed `base_sha`; the mutation carries
exact reviewed head; strict up-to-date is enforced in that merge transaction;
every update to that same frozen target ref from `merge_expected_base` must be
fast-forward; deletion and non-fast-forward updates are forbidden; and the
complete current protection/ruleset and actor inventory contains no configured
base-update or merge bypass and enumerates actors authorized to retarget the
PR. An allowed force push, allowed deletion, configured
administrator/App/ruleset bypass, incomplete ruleset or bypass page,
incomplete base-ref or retarget-actor inventory, or merely point-read strict
state makes the alternative unproved and blocks direct merge. GitHub and
authorized repository collaborators or administrators who can retarget the PR
or reconfigure rules are the trusted external control plane. Any observed
`baseRefName`, applicable-rule, bypass, or actor-inventory change invalidates
the proof. Malicious or concurrent unobserved retargeting or control-plane
reconfiguration is outside this consumer guarantee; never claim that the
proof excludes it. These are consumer-side proof requirements only; this
playbook does not define a producer implementation or require a nonexistent
server-side retarget hold.

A configured merge queue owns only latest-base merge-group freshness by
default; it does not reacquire
out-of-band local review or conversation gates. Before enrollment, require a
repository-proved, non-bypassed merge-group hold that prevents completion after
any target-base change until every invalidated gate is reacquired for the new
exact base tip.
If no such hold exists, the queue path is blocked. A narrowly equivalent
contract may instead prove that every invalidated gate is itself a required,
non-bypassed check on the rebuilt merge group. See
[pr-readiness.md](pr-readiness.md).

## Reconcile Only Recoverable States

Enter automatic recovery only when typed GitHub state or a documented
repository contract supplies a stable, machine-decidable retryable reason.
Eligible reasons are:

- missing or stale provider/check evidence whose exact producer contract
  classifies that condition as recoverable;
- a typed pending provider/check state whose associated metadata classifies
  the wait as recoverable;
- a cancelled or skipped job whose typed conclusion and associated metadata
  distinguish retryable infrastructure from an intentional condition or
  policy decision;
- a typed GitHub, service, or runner infrastructure failure; and
- an aggregation mismatch where complete child-job state proves success but
  the documented related aggregate is absent or stale.

The label `inconclusive` is not itself a retry reason. A stable malformed
snapshot, identity or scope contradiction, unsupported operation, permission
denial, or any other non-retryable inconclusive state terminates recovery and
must be reported immediately. Unknown free-form prose cannot supply the
machine-decidable retryable classification.

Never reconcile an explicit review finding that is applicable and unresolved,
a test failure, lint failure, policy failure, or other substantive negative
result. Those require resolution, a fix, or an explicit policy decision.

Before an Actions mutation, obtain one closed parent-owned
`recovery_operation_contract` from a source independently anchored outside the
candidate range. The contract must bind the exact repository, PR, head,
dynamically identified Action or workflow, ref, operation, and exact inputs,
and must explicitly classify that exact operation as idempotent or reentrant.
Accepted source relationships are the exact target-branch baseline, an
installed trusted release, or another parent-pinned source proved outside the
candidate range. Candidate-head workflow or contract bytes cannot grant repeat
authority.

Only after that proof, freeze the exact recovery tuple and join it
type-preservingly to the contract. Tuple equality identifies a requested
repeat; it does not make an operation idempotent or reentrant. The current task
must still authorize the external mutation. When the trusted contract, exact
join, or authorization is absent, keep the recovery owner in status-only mode,
poll the scoped evidence on the schedule below, and report the missing gate
instead of triggering the workflow. This repeat authority never applies to
GitHub comment creation; the one-shot comment-mutation budget above remains
consumed after any possibly delivered create-comment call.

After the tuple and authorization are established, choose the smallest
operation that can recover the machine-decidable retryable state:

1. Retry failed jobs when the associated run exists and only jobs failed.
2. Rerun the full associated run for a run-level infrastructure failure or a
   broken aggregate that cannot be repaired by failed-job rerun.
3. Dispatch a new run only for missing, stale, or aggregation-only state, and
   only after dynamic discovery proves the exact workflow and required inputs.

Illustrative commands for an already authorized, trusted-contract-bound exact
operation are:

```bash
gh run rerun <run-id> --failed --repo <owner/repo>
gh run rerun <run-id> --repo <owner/repo>
gh workflow run <workflow-id> --repo <owner/repo> --ref <current-head-branch>
```

Repository-specific inputs come from the trusted recovery contract. Never
invent input names. Single-flight still applies: wait until the current attempt
is terminal or proved lost before repeating the same contract-bound tuple. A
different repository/PR/head scope, Action, workflow, ref, operation, or input
set is not a retry of that tuple; stop and obtain ordinary confirmation before
mutating it.

## Retry Schedule And Cost Control

Persistent monitoring is an explicit product requirement for states with a
machine-decidable retryable pending or infrastructure reason. It is
caller-owned, single-flight, and cancellable; it is not an independent review
lane or a detached best-effort task. Monitoring continues only while that
classification remains true, until the expected head or PR is superseded, or
until the user cancels it. A stable malformed snapshot, scope contradiction,
or non-retryable inconclusive state stops the schedule immediately and is
reported as terminal for this recovery owner.

Use exponential backoff in minutes:

```text
1, 2, 4, 8, 16, 32, 60, 60, 60, ...
```

There is no retry-count ceiling while the same reason remains
machine-decidably retryable. At 60 minutes, report the continuing delay to the
user and then retry hourly without a terminal time ceiling. Reset the schedule
only after meaningful progress, such as a new run, new provider artifact,
changed check conclusion, or new head. Crossing an hour is a reporting and
cadence transition, not a reason to stop or declare the lane inconclusive;
losing the retryable classification is.

For private repositories, default to a rolling budget of four full-run
equivalents per 24 hours unless repository policy defines another budget.
Count a full rerun or new dispatch as one equivalent; count failed-job reruns
proportionally when reliable job-cost data exists, otherwise conservatively as
one. When the budget is exhausted, perform status-only hourly checks until the
window recovers. Do not spend private Action minutes on repeated runs during a
known service degradation. This budget throttles Action-consuming mutations;
it never terminates status-only monitoring or imposes a retry-count ceiling.

Public repositories do not use the private-minute budget and may retry more
frequently within the same backoff, single-flight, repository-contract, and
authorization rules.

Keep recovery visibly pending:

```yaml
recovery:
  status: pending
  phase: observe | rerun-failed | rerun-full | dispatch | status-only
  attempt: 1
  next_retry_at: RFC3339
  reason_class: retryable-pending | retryable-infrastructure
  last_reason: stable-machine-readable-reason
  mutation_gate: authorized-contract-bound-repeat | status-only
  rolling_full_run_equivalents: 0
```

Do not convert a retryable recovery into `pass` or `inconclusive` merely because
the active wait crossed an hour.

Persistent monitoring does not expand authorization. A wake may always reread
scoped evidence; it may repeat an Actions mutation only when the frozen
recovery tuple is type-preservingly unchanged, its candidate-range-external
trusted recovery contract still matches and explicitly declares the exact
operation idempotent or reentrant, and the current mutation remains authorized.
A new scope, Action, workflow, ref, operation, input set, branch or PR mutation,
destination, or other materially different action requires ordinary
confirmation.

The schedule may repeat read-only probes and an authorized exact Actions
operation only through its still-valid trusted recovery contract. It never
repeats a create-comment POST.

## Active Thread And Automation

For the first 60 minutes, keep recovery in the active Codex thread with bounded
polls and progress updates. After 60 minutes:

- if the Automation tool is visible, schedule the next wakeup to deliver into
  this same active thread; never create a new conversation;
- if Automation is unavailable, keep a pollable and cancellable active-thread
  fallback, such as a cancellable `sleep 3600`, that waits until the hourly
  retry; and
- keep enough local recovery state that either mechanism can resume without
  relying on stale prompt text.

An Automation wake payload contains identifiers only: repository, PR number,
expected head SHA, recovery-state location or ID, and reason. It must reread
GitHub on every wakeup rather than carrying comments, logs, or verdicts in the
payload.

Cancel pending automation and local waits when the lane becomes terminal, the
PR closes or merges, the head is superseded, or the user cancels the task.
Repeated automation delivery must target this same active thread and resume
the same recovery owner; it must not open or hand off to a new conversation.

## Bounded Logs

Read job metadata before logs. If logs are required, fetch only the failing job
or a bounded relevant section, retain it in a task-scoped capped artifact, and
surface the decisive lines. Spinner output and whole-run archives are not the
default evidence source.

## Probe Failures

Classify transport, authentication, and rate-limit errors separately from an
empty result. Retry typed `429`, retryable `5xx`, service degradation, and
transient network failures under the schedule above while their
machine-decidable classification remains retryable. Permission denial,
unsupported host, malformed stable response, irreconcilable scope mismatch,
or another non-retryable inconclusive result terminates recovery immediately;
report the exact failed endpoint and scope.

The generic transport retry rule applies to reads and eligible Actions
mutations only. An ambiguous create-comment result follows the one-shot
comment-mutation rule and is never POSTed again for the same repository, PR,
and head.
