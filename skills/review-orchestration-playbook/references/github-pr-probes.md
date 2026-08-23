# GitHub PR Probes And Recovery

## Scope

Use these probes to acquire current PR, GitHub Codex, CI, conversation, and
workflow evidence. Interpretation of GitHub Codex results belongs to
[github-codex-evidence-authority.md](github-codex-evidence-authority.md).
Merge readiness belongs to [pr-readiness.md](pr-readiness.md).

Prefer typed `gh` output and exact REST or GraphQL fields. Keep large raw page
sets in a task-scoped bounded artifact and surface only IDs, URLs, times,
states, and decisive findings.

## Select The Exact PR

An explicitly named PR wins. Otherwise accept only one authenticated open PR
whose head repository and branch exactly match the intended branch. Multiple
candidates require caller selection; a local diff range is not a PR selector.

Start with:

```bash
gh pr view <number-or-url> --repo <owner/repo> \
  --json url,number,state,isDraft,mergedAt,mergeable,mergeStateStatus,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,headRepositoryOwner,statusCheckRollup,reviewDecision
```

Record exact repository, PR number, `baseRefOid`, and `headRefOid`. Use commit
OIDs rather than mutable branch names for every later comparison.

## Fetch Complete Provider Evidence

Fetch every page; do not rely on `gh pr view` summaries for authority.

```bash
gh api --paginate repos/<owner>/<repo>/issues/<pr>/comments
gh api --paginate repos/<owner>/<repo>/pulls/<pr>/reviews
gh api --paginate repos/<owner>/<repo>/pulls/<pr>/comments
gh api --paginate repos/<owner>/<repo>/commits/<head>/check-runs
gh api --paginate repos/<owner>/<repo>/commits/<head>/status
```

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

Immediately before accepting a result, repeat the PR detail, all provider
evidence pages used by the decision, finding-thread state, and selected
check/status. A changed head restarts the head-bound lane.

## Request The Review

Post the exact body:

```text
@codex review
```

Before posting, reread the PR head and enumerate visible exact requests for the
current head epoch. Keep one recovery owner and one POST in flight. After a
successful response, store its stable comment ID, URL, actor, body, and server
time.

If the POST returns an ambiguous transport result, first reread comments to
look for the request. If no result can be proved, the same exact POST may be
repeated after backoff only under the named lane's authorized ambiguous-delivery
recovery. A duplicate still counts as the same logical review lane, but the
GitHub write is not intrinsically idempotent. Do not run two POSTs
concurrently, and do not treat multiple visible requests as multiple review
lanes.

A base-only retarget on the same head does not authorize or require another
request. Reuse qualifying head-bound provider evidence, rerun the base-sensitive
local/readiness gates only after the parent-owned `range_origin` gate in
[pr-readiness.md](pr-readiness.md) authorizes their exact local PR-wide range,
and reconcile a related merge/status check when its contract is base-sensitive.
This probe layer never selects or rewrites that range. Never claim the provider
inspected the retargeted base.

## Discover Related Checks Dynamically

Do not hard-code a workflow filename, workflow display name, job name, or
check name. Start from checks and statuses attached to the exact current head:

1. Read `statusCheckRollup` plus the complete current-head check-run and status
   collections.
2. Select a candidate only when its App identity, `details_url`, check suite,
   external ID, or documented repository contract associates it with the
   GitHub Codex review or merge aggregation.
3. Follow the associated run URL or API identity to the workflow run and jobs.
4. Preserve the check ID, suite/run ID, workflow ID, attempt, head SHA,
   conclusion, and details URL.

A name substring is a hint for discovery, not proof. A check attached to an
older head, a generic App success, or a run found only by static name guessing
is not a valid basis.

When a trustworthy related merge/status check exists, prefer it as the
positive GitHub-lane basis, while still enumerating unresolved Codex-provider
findings. The check does not prove the PR base unless its documented contract
does so; ordinary readiness still validates base and merge base locally.

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

An Actions mutation has two independent gates:

1. The repository's documented producer contract predeclares the exact rerun
   or dispatch operation as idempotent or reentrant for the frozen head and
   exact inputs.
2. The current task authorizes that external mutation.

The existence of a run, workflow ID, or `gh` subcommand proves neither gate.
When either gate is absent, keep the recovery owner in status-only mode, poll
the scoped evidence on the schedule below, and report the missing contract or
authorization instead of triggering the workflow.

After both mutation gates pass, choose the smallest operation that can recover
the machine-decidable retryable state:

1. Retry failed jobs when the associated run exists and only jobs failed.
2. Rerun the full associated run for a run-level infrastructure failure or a
   broken aggregate that cannot be repaired by failed-job rerun.
3. Dispatch a new run only for missing, stale, or aggregation-only state, and
   only after dynamic discovery proves the exact workflow and required inputs.

Illustrative commands for an already authorized, repository-declared recovery
are:

```bash
gh run rerun <run-id> --failed --repo <owner/repo>
gh run rerun <run-id> --repo <owner/repo>
gh workflow run <workflow-id> --repo <owner/repo> --ref <current-head-branch>
```

Repository-specific inputs come from the discovered workflow contract. Never
invent input names or assume that a rerun or dispatch is idempotent. Even when
the repository contract declares the operation idempotent or reentrant,
single-flight still applies: wait until the current attempt is terminal or
proved lost before starting another.

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
  mutation_gate: authorized-predeclared-reentrant | status-only
  rolling_full_run_equivalents: 0
```

Do not convert a retryable recovery into `pass` or `inconclusive` merely because
the active wait crossed an hour.

Persistent monitoring does not expand authorization. A wake may always reread
scoped evidence; it may repeat an Actions mutation only when the exact
repository contract still predeclares it as idempotent or reentrant and the
current mutation remains authorized. A new workflow, new inputs, branch or PR
mutation, destination, or other materially different action still requires
its ordinary authorization.

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
