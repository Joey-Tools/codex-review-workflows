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

Before posting, reread the PR head and enumerate visible exact requests for the
current head epoch. Keep a single recovery owner and at most one POST in
flight. After a successful response, store its stable comment ID, URL, actor,
body, and server time.

If the POST returns an ambiguous transport result, first reread the unchanged
current head and its complete visible exact-request set. If delivery still
cannot be proved, the same exact `@codex review` POST may be repeated after
backoff as an idempotent delivery retry under the named lane's authorized
ambiguous-delivery recovery. Before every repetition, the single recovery
owner performs that reread again; stop POSTing as soon as delivery or another
definite outcome is proved. Never run concurrent POSTs or issue an ordinary
duplicate. Any visible duplicate remains part of the same logical review lane
and is recorded as an audit warning; it never counts as an additional lane.

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
   GitHub Codex review or merge aggregation.
3. If that contract declares `github-synthetic-merge`, independently read the
   current base ref/tip, locally proved unique merge base, PR
   `merge_commit_sha`, and complete check/status collections for that subject.
   If it declares `feature-head`, require the subject SHA to equal
   `headRefOid` and make no base-coverage claim.
4. Follow the associated run URL or API identity to the exact workflow run and
   jobs.
5. Preserve the App ID/slug, workflow ID, run ID/attempt, check-suite ID, check
   ID/name/URL, feature head, base ref/tip, merge base, subject kind/SHA,
   status, conclusion, server time, and producer-contract descriptor.

A name substring is a hint for discovery, not proof. A check attached to an
older head, a generic App success, or a run found only by static name guessing
is not a valid basis.

When a trustworthy related merge/status check exists, prefer it as the
positive GitHub-lane basis, while still enumerating unresolved Codex-provider
findings. Its independently verified contract must define successful completion
as `github-codex-provider-clean`, require zero unresolved applicable findings,
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

Before an Actions mutation, freeze one exact recovery tuple containing the
repository, PR, head, dynamically identified Action or workflow, operation,
and exact inputs. This consumer treats repetitions of that same tuple as
idempotent; no repository-specific idempotency or reentrancy predeclaration is
required. The current task must still authorize the external mutation. When
that authorization is absent, keep the recovery owner in status-only mode,
poll the scoped evidence on the schedule below, and report the missing
authorization instead of triggering the workflow.

After the tuple and authorization are established, choose the smallest
operation that can recover the machine-decidable retryable state:

1. Retry failed jobs when the associated run exists and only jobs failed.
2. Rerun the full associated run for a run-level infrastructure failure or a
   broken aggregate that cannot be repaired by failed-job rerun.
3. Dispatch a new run only for missing, stale, or aggregation-only state, and
   only after dynamic discovery proves the exact workflow and required inputs.

Illustrative commands for an already authorized exact-tuple recovery are:

```bash
gh run rerun <run-id> --failed --repo <owner/repo>
gh run rerun <run-id> --repo <owner/repo>
gh workflow run <workflow-id> --repo <owner/repo> --ref <current-head-branch>
```

Repository-specific inputs come from the discovered workflow contract. Never
invent input names. Single-flight still applies: wait until the current attempt
is terminal or proved lost before repeating the same tuple. A different
repository/PR/head scope, Action, workflow, operation, or input set is not a
retry of that tuple; stop and obtain ordinary confirmation before mutating it.

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
  mutation_gate: authorized-exact-repeat | status-only
  rolling_full_run_equivalents: 0
```

Do not convert a retryable recovery into `pass` or `inconclusive` merely because
the active wait crossed an hour.

Persistent monitoring does not expand authorization. A wake may always reread
scoped evidence; it may repeat an Actions mutation only when the frozen
recovery tuple is type-preservingly unchanged and the current mutation remains
authorized. A new scope, Action, workflow, operation, input set, branch or PR
mutation, destination, or other materially different action requires ordinary
confirmation.

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
