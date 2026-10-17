# GitHub Codex Producer And Recovery Details

Use the ordinary diagnostic guidance below for a user-directed CI retry or an
authorized CI-fix loop. The later producer and automatic-recovery sections own
their stronger machine-evidence requirements, not permission for every rerun.
Terminal-artifact acquisition uses the evidence authority and authenticated
probes; it does not require producer closure or recovery receipts.

## Ordinary Diagnostic Reruns

A diagnostic rerun may test whether an upstream fix, a changed external input,
or a transient failure unblocks the same code. It need not promise success or
establish the complete root cause first. A code/test failure may be investigated
this way without relabelling it as infrastructure or erasing the earlier failure.

- A user-requested retry or an authorized CI-fix loop covers a bounded retry
  within that repository/PR scope. A bare review does not. Resolve the concrete
  workflow, run, attempt and relevant head from GitHub; do not make the user
  transcribe identifiers the agent can safely obtain.
- Inspect the executed workflow, relevant scripts/dependencies and triggered
  follow-on workflows for repeat effects. Ordinary tests or read-only validation
  on disposable runners do not require a predeclared rerun manifest, workflow
  digest, newly added identity-logging step, or immutable dependency proof.
  Read-only token permissions alone are not a side-effect audit. Publication,
  deployment, repository writes, production credentials, shared/self-hosted
  state or uncertain repeat effects require applicable authorization and
  proportionate repeat-safety checks before execution.
- Before the mutation, confirm the intended PR/head and run still match, that
  no matching rerun is already queued/in progress, and that there is no newer
  applicable result to reuse. An explicitly requested historical diagnostic may
  use an older head, but its result cannot supply current-head CI readiness.
  Keep one mutation owner. An ambiguous POST is not permission to resend;
  inspect GitHub attempts/status and stop if delivery remains uncertain.
- Choose the smallest useful job scope. Failed-job reruns are usually cheaper;
  use a full rerun when the upstream-refresh semantics require it and the full
  scope is authorized and repeat-safe. Bound retries by the task's time/cost
  budget and platform limits, not a universal attempt-2 ceiling. Stop blind
  retries when the same failure repeats without new evidence, safety becomes
  uncertain, the head is superseded, or the PR closes. Further experiments need
  a reason and remaining authorization, not an unlimited retry loop.
- Keep GitHub run/attempt/job history and logs as the primary execution record.
  Usually retain only the reason, run link and outcome in the task or PR, plus
  the resolved upstream version when it matters to the diagnosis. Do not add
  duplicate local ledgers, mandatory digest receipts or copies of every API
  response. Preserve additional bounded evidence only when it answers a real
  question, resolves uncertain delivery, or must survive log expiry.

### Refreshing An Upstream Dependency

Reruns retain the original event's `GITHUB_SHA` and `GITHUB_REF`; they do not
load a newer caller workflow merely because its branch advanced. A dependency
pinned to a commit cannot upgrade without a source change. For a floating
Action tag/branch, a rerun can be a useful refresh experiment: inspect the
download log's resolved commit rather than assume that the new version ran.
Do not require all dependencies to be fixed to their old commits when testing
an upstream update is the purpose of the experiment.

Reusable workflows have a distinct rule: a full rerun uses the specified
reference, whereas a failed-job/specific-job rerun retains the reusable
workflow commit from the first attempt. Choose the operation accordingly.
See [GitHub rerun semantics](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
and [reusable-workflow rerun behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#behavior-of-reusable-workflows-when-re-running-jobs).

### Results And Permission Boundaries

Request acceptance is not CI success. Inspect the terminal attempt and relevant
current-head checks; a green retry does not prove root cause, dismiss a finding,
complete provider review, or waive approvals and merge rules. Ordinary GitHub
CI results may satisfy their normal CI checks without a custom recovery receipt.
The operation itself never supplies a producer-clean verdict.

This guidance does not grant new destinations or write scopes, override an
execution-approval denial, or authorize a substitute dispatch, empty commit or
transport to bypass that denial. Candidate policy changes remain review subjects,
not authority for their own execution. Authoritative automatic provider recovery
continues to use the separate contract below.

## Run The GitHub Lane

Before any GitHub-lane action, read [github-codex-evidence-authority.md](github-codex-evidence-authority.md) for agent interpretation, identity, complete acquisition, finding precedence, and final reread. When implementing or validating deterministic receipts, also read [machine evidence v1](github-codex-machine-evidence-v1.md); its schemas apply to that machine profile, not to the agent's prose judgment.

Use the authority's [repository and exact-field rules](github-codex-evidence-authority.md#repository-identity-and-exact-fields)
and the versioned [machine contract](github-codex-terminal-carriers-v1.json)
for URL/path parsing, canonical JSON resource limits and field validation.
Do not reproduce their field tables here or replace validation with semantic
similarity. Preserve raw digest-bound bytes; only repository owner/name identity
uses case-insensitive comparison.

The intended current policy is:

- Use exact `@codex review` on an existing supported `github.com` PR at the frozen current head. An ordinary terminal artifact, reaction, or feature-head-only producer result does not prove provider coverage of the local merge base; base and merge-base coverage remain local PR-readiness facts.
- Prefer a trustworthy merge/status producer when its independently verified
  repository contract is anchored by parent-owned evidence outside the
  candidate range, binds the exact feature head, current base/merge scope,
  check-subject SHA, App/workflow/run/check identity, and defines success
  itself as GitHub Codex provider clean. A target-branch baseline, an installed
  trusted release, or another parent-pinned source proved outside the candidate
  range may supply that anchor; a contract introduced by the candidate head
  cannot. Require a separate parent-owned, digest-bound receipt for the complete
  `merge_base..head` commit set and reject any same-repository contract source
  found anywhere in that set, not only the head. Also require a parent-owned
  producer-implementation receipt that joins the exact run/check identities to
  platform-authenticated workflow SHA/ref/job identity and a complete immutable
  closure of every workflow, reusable action, and script capable of deciding
  clean. A separate parent-owned anchored resolver must emit records that
  exactly cover every canonical closure entry, bind parser/source digests and
  complete discovered references, and project one full-entry edge per
  reference; bind its receipt digest into the stable snapshot basis. Apply the
  machine profile's closed selector and job-identity semantics: external reusable
  workflows from workflow/reusable-workflow sources and external actions from
  workflow/reusable-workflow/action sources use canonical target
  repository/path selectors ending in the target's full commit SHA; an action
  path is its manifest directory or repository root. Workflow targets are
  direct `.github/workflows/*.yml` or `.github/workflows/*.yaml` children, not
  nested paths. Each canonical-repository-identity/commit/path identifies one
  kind and blob, each
  source-entry/raw-selector pair identifies one target, and each
  canonical-repository-identity/commit/action-manifest directory identifies at
  most one action
  entry; a competing `action.yml` and `action.yaml` pair is status-only.
  Same-repository reusable
  workflows may also use the exact same-commit `./.github/workflows/...` or
  `$/.github/workflows/...` form; and a `$/` action selector binds the source
  repository and running commit to the target action-manifest directory. Other
  relative local-action forms and untyped action-to-script relative strings are
  status-only. Every closure entry must be root-reachable, with the exact root
  workflow identity as the zero-inbound job identity and each non-root
  reusable-workflow job identity joined to exactly one semantically matching
  inbound edge. Only the external reusable-workflow arm requires a full-SHA raw
  job ref, and its unique edge reference must equal that raw job ref exactly; a
  local `./` or `$/` arm may retain its authenticated branch-like raw identity
  ref while its target entry and resolved commit remain fixed to the source
  running commit.
  Candidate-range implementation bytes or an unbound actual run cannot pass.
  Version 1 has no accepted external-App ID-to-root-to-closure binding profile,
  so external-App merge-status is unavailable and terminal-clean fallback
  remains. A `feature-head` contract reports only latest-feature-head coverage;
  a `github-synthetic-merge` contract may report current-merge-scope coverage
  only while every base/merge/subject binding remains stable. With zero
  applicable unresolved findings, this basis passes independently and does not
  require a separate terminal clean comment or review. A generic successful
  check or service-start marker never qualifies.
- Otherwise, a trustworthy provider terminal clean comment or review on the latest head, together with no unresolved provider finding in the PR, passes the lane.
- A complete provider `+1` reaction basis is a fallback when no stronger terminal artifact is available.
- Only applicable unresolved provider findings block. A machine-profile report requires an
  independent parent-owned `finding_page_receipt`, `finding_range_receipt`, and
  `finding_carrier_snapshot`; report, carrier, and embedded page or ancestry
  fields cannot prove one another. The page receipt freezes complete
  current-scope acquisition counts and the canonical issue/review record bytes,
  including child/thread joins. The range receipt binds the exact full-DAG
  range, including merge commits and side history. The snapshot supplies the
  closed replay observation and selected carrier, not only digests; the
  consumer recomputes them and replays precedence, resolution, and supersession.
  A new head or merge base requires all three inputs and the full-DAG projection
  to be rebuilt. Stale, non-ancestor, fabricated, or incomplete raw evidence
  remains audit-only and cannot create `status: findings`. On the same head, an
  exact typed GraphQL
  thread resolution or a later trustworthy provider correction accepted by the
  evidence authority can clear a finding without inventing a code change. If
  addressing a finding actually changes code, the resulting
  new head invalidates every old-head positive/pass/clean result and every
  head-bound readiness gate, and requires fresh review. An ancestry-proven
  unresolved provider finding that remains applicable to the current head is
  negative evidence, not a reusable pass; it continues to block until typed
  resolution or an accepted later corrective artifact satisfies the evidence
  authority. A successful service-start check alone is not a clean review.

## Authoritative Automatic Recovery

Only a machine-decidable retryable pending or infrastructure reason enters
automatic recovery. A stable malformed snapshot, scope contradiction, or
other non-retryable inconclusive result terminates recovery and is reported
immediately. For a retryable reason, prefer the smallest associated recovery.
Before any Actions mutation intended to enter authoritative automatic
recovery, validate a closed parent-owned
`github-codex-recovery-operation-preflight-v1` reference contract. It binds one
exact repository/PR/frozen head, source trust anchor, candidate-range exclusion
receipt, dynamically identified workflow/run/ref/operation/inputs, and trusted
producer-implementation receipt identity plus a complete resolved dependency
edge receipt supplied independently by the parent; it gives every canonical
repository/commit/path/kind/blob closure entry one sorted, unique, complete
parser/reference record and a bijective full-entry edge projection. It also
independently declares the exact operation idempotent or
reentrant. Existing-run reruns are eligible only when
the platform-authenticated original head, ref, workflow SHA, and run/check
identity match; GitHub reruns retain the original `GITHUB_SHA` and `GITHUB_REF`.
Before either automatic rerun, require every reusable-workflow or external
action selector in the complete resolution graph to end in its target closure
entry's exact lowercase full commit SHA. The selector is canonical target
repository/workflow-path for a reusable workflow and canonical target
repository/action-manifest-directory for an action; a root action manifest uses
the repository root. Workflow targets are direct
`.github/workflows/*.yml` or `.github/workflows/*.yaml` children, not nested
paths. Each canonical-repository-identity/commit/path identifies one kind and
blob, each
source-entry/raw-selector pair identifies one target, and each
canonical-repository-identity/commit/action-manifest directory identifies at
most one action
entry; a competing `action.yml` and `action.yaml` pair is status-only.
Reusable-workflow sources are limited to workflow or
reusable-workflow entries, while action sources are limited to workflow,
reusable-workflow, or action entries. A workflow or reusable-workflow source may
instead bind a same-repository, same-commit reusable workflow by exact
`./.github/workflows/...` or `$/.github/workflows/...`; a `$/` action selector
may likewise bind the source repository and running commit to the exact target
action-manifest directory. Version 1 cannot bind a workflow/reusable-workflow
`./` or `../` local action to immutable runner-workspace bytes, and it cannot
bind an untyped bare action-manifest-to-script relative string; those and every
unrecognized relative form are status-only. Require every closure entry to be
reachable from the authenticated root workflow. The root job identity must be
exactly the root workflow identity and have no inbound edge. Every non-root job
identity must be a reusable-workflow entry, have exactly one total inbound edge,
and have its unique edge semantically match the job ref from a workflow or
reusable-workflow source. The external arm requires a full-SHA raw selector and
job ref equal to the resolved commit, with the unique edge reference exactly
equal to that raw job ref. A same-repository local `./` or `$/` arm may retain
the platform-authenticated branch-like raw job identity ref, but its
target entry and resolved commit must equal the source running commit and its
unique local edge must match repository and workflow path exactly. A tag,
expression, mismatched repository/commit/path, disconnected entry, or unknown
reference keeps recovery status-only. Apply this conservative rule to both full
and failed-jobs reruns; the documented first-attempt
reusable-workflow reuse for failed jobs does not bind every external action
dependency in the version-1 schema.
The operation kind is exactly `existing-run-rerun-full` or
`existing-run-rerun-failed-jobs`; these are different operations. Bind an
authenticated pre-mutation GET of attempt `n`, then require the matching exact
POST endpoint (`/rerun` or `/rerun-failed-jobs`) under API `2026-03-10` with
HTTP 201 and no request body, followed by an authenticated HTTP 200 GET of
`/attempts/{n+1}`. The post receipt must prove exact attempt `n+1`, its
`previous_attempt_url` for attempt `n`, and acquisition no earlier than the
POST. Then GET the current run and require the same repository/run/head/workflow/ref
identity and current `run_attempt == n+1`. One closed transaction joins the
pre-observation, 201 POST, exact-attempt GET, current-run GET, GitHub response
dates, acquisition times, and platform `run_started_at`/`updated_at`. A
historical attempt re-read after a new POST or any possible intervening rerun
is status-only. An ambiguous mode, current-run-only snapshot, unchanged/skipped attempt,
debug rerun, cross-mode endpoint, or stale receipt remains status-only.
Never use generic `gh workflow run --ref <current-head-branch>` as a head
binding. A new `workflow_dispatch` cannot enter the authoritative automatic
recovery contract: GitHub accepts only a mutable branch or tag as `ref`, and
the dispatch POST has no atomic expected-SHA compare with the live PR head.
Even a workflow-level `expected_head_sha` check cannot close that race. The
caller may explicitly confirm one manual dispatch, but the dispatch operation and its
receipts remain status-only and cannot satisfy recovery. A later current-head
run/check can count only through an independent ordinary producer/status
contract; the dispatch never supplies pass authority by itself. The machine-readable
recovery union therefore contains only the two exact existing-run rerun modes.
Their trusted root workflow repository must have canonical identity equal to the recovery repository identity;
an external reusable workflow may appear only through the exact job-workflow
identity. Equality of a tuple never creates repeat safety.
Current mutation authorization remains separate. Issue-comment creation is
never eligible. Missing proof leaves recovery status-only.
Never reconcile an explicit code finding, test failure, or policy failure as
infrastructure.

While that exact reason remains machine-decidably retryable, use one
single-flight recovery schedule: 1, 2, 4, 8, 16, 32, then 60 minutes, followed
by hourly monitoring without a time limit. Report to the user when the delay
first reaches 60 minutes and keep recovery pending. Mutation attempts stop at
the platform/provider or stricter contract cap, including GitHub's total rerun
maximum of 50; monitoring remains hourly afterward. Apply the
repository's private-run cost budget; when it is exhausted, poll status only
until a low-frequency retry is allowed. Public repositories may retry more
freely within the same authorization boundary. Prefer an Automation that
wakes the same active thread; when that capability is unavailable, keep a
cancellable hourly wait in the active thread. Remove the wake-up when the
result becomes terminal or the PR closes, merges, or is superseded.

## Continue With PR Readiness

A completed GitHub lane does not complete CI or merge readiness. Continue with
[pr-readiness.md](pr-readiness.md) for the existing full gate.
