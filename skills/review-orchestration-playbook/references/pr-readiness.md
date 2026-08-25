# PR Readiness

## Scope

PR readiness combines local range proof, the requested review shape, tests and
CI, all PR conversations, branch and lifecycle state, and a final stable
reread. It is broader than the GitHub Codex lane.

GitHub Codex evidence is interpreted only by
[github-codex-evidence-authority.md](github-codex-evidence-authority.md).
GitHub acquisition and retry mechanics live in
[github-pr-probes.md](github-pr-probes.md). Do not duplicate those contracts
here.

## Authorization And Selection

Operate only on the PR the user named, the PR this task created, or the unique
authenticated open PR for the exact intended head repository and branch.
Multiple candidates require caller selection. Other PRs are read-only
coordination evidence.

When authenticated selection proves that no supported PR exists, emit the
GitHub lane authority's closed `not-applicable` no-PR variant with null PR/head
fields. Do not fabricate a PR-readiness report or enter provider recovery; a
local standalone range may still be reviewed under its own authorization.

A review request alone does not authorize creating a branch, commit, push, PR,
or changing PR metadata. Obtain the authorization required by repository and
workspace policy before each external mutation. Named review egress is covered
by [egress-consent.md](egress-consent.md).

## Freeze The Whole-PR Range

Read these fields independently from GitHub:

```yaml
repository: owner/name
pull_request: 123
url: https://github.com/owner/name/pull/123
base_ref_name: main
base_ref_oid: 40-lowercase-hex
head_ref_name: topic
head_ref_oid: 40-lowercase-hex
```

With lazy fetch disabled, require both commits locally. If an endpoint is
missing, fetch only the exact needed ref or the smallest useful deepen step;
do not default to tags, submodules, broad history, or `--unshallow`.

Require:

```text
git merge-base --all <base_ref_oid> <head_ref_oid>
```

to return exactly one commit. Freeze the local whole-PR range as:

```text
base_sha = pr_merge_base
head_sha = head_ref_oid
```

Every local lane and range-sensitive validation must bind that exact pair.
An explicit caller-supplied range that differs from the selected PR range may
still be reviewed as a standalone range, but it does not satisfy whole-PR
readiness.

Independently bind the selected PR's exact `base_ref_oid` to the current
readiness evidence. It is not interchangeable with `pr_merge_base`: the target
base tip can advance while the unique merge base and feature head remain
unchanged. Any `base_ref_oid` change invalidates every earlier local PR-wide
review, local validation and test result, CI/status result, conversation
decision, merge-readiness decision, and final reread. Reacquire all of them
against the new exact base tip before counting them again. When the unique
merge base and head did not change, the active `range_origin` record remains
the correct range provenance; retaining that immutable record does not retain
or revive any readiness evidence from the prior base tip.

For every range intended to count toward PR readiness, the parent persists one
compact provenance lineage and its active immutable record when it first
freezes the endpoints:

```yaml
range_origin:
  lineage_id: stable-parent-generated-lineage-id
  kind: caller-supplied | pr-derived
  active_record_id: stable-parent-generated-record-id
  record_id: same-as-active-record-id
  predecessor_record_id: null | previous-active-record-id
  base_sha: record-full-object-id
  head_sha: record-full-object-id
```

The parent-owned immutable `range_origin` lineage header consists of
`lineage_id` and `kind`; the first record fixes both for the lifetime of this
selected-PR/head lineage. `caller-supplied` means the caller explicitly
provided or confirmed both original endpoints. `pr-derived` means the parent
derived the original endpoints from the authenticated PR head and its unique
local merge base because no caller range was authoritative. The parent
generates the opaque lineage and record identifiers, retains every immutable
record, and owns the single current `active_record_id` binding. The candidate,
provider, and PR metadata cannot author or replace any of them. The first
record has `predecessor_record_id: null`.

Every successor must reuse the fixed `lineage_id` and `kind`, have a new stable
`record_id`, name the exact previously active record in
`predecessor_record_id`, and record its own exact endpoints. Appending a record
never activates it: only the parent may advance `active_record_id`, and only
as the same parent-owned state transition that creates an authorized successor
below. The active predecessor chain must be unique, gap-free, and acyclic back
to the first record. While the selected PR and head stay fixed, do not start or
substitute a second lineage. In particular, a `caller-supplied` lineage can
never acquire or activate a `pr-derived` record. Only the unique record named
by the current
`(lineage_id, active_record_id)` binding may count as PR-wide evidence, and its
endpoints must equal the exact `base_sha..head_sha` used by every counted local
lane.

A missing field, an unrecognized kind, a reused identifier, a broken or forked
predecessor chain, a stale or mismatched active record, a replacement lineage,
a kind switch, or endpoints that do not match the record or counted lane whose
provenance they claim is `blocked-input` with reason
`range-origin-unverified`; stop before starting or counting a local PR-wide
lane.

### Same-Head Merge-Base Change

When the selected PR keeps the same head but obtains a new unique merge base,
apply the provenance gate before selecting the local rerun range:

- For `pr-derived`, the parent may automatically derive the exact new
  `pr_merge_base..head_ref_oid` pair, append an immutable successor in the same
  `pr-derived` lineage whose predecessor is the current active record, advance
  the active-record binding, and rerun every invalidated local PR-wide lane.
- For `caller-supplied`, preserve the original endpoints and do not silently
  substitute the new merge base. Only the caller's explicit provision or
  confirmation of the exact current `pr_merge_base..head_ref_oid` pair creates
  an immutable successor in the same `caller-supplied` lineage, permits the
  parent to advance the active-record binding, and authorizes that local
  PR-wide rerun. Until then, the old range may remain standalone review
  evidence, but PR readiness is blocked. Never append or activate a
  `pr-derived` successor to bypass this confirmation.
- For missing, unknown, malformed, or mismatched origin, report
  `blocked-input` / `range-origin-unverified`. Do not guess provenance from the
  current PR fields or from an old review artifact.

This gate controls only local PR-wide range selection. A separately trustworthy
GitHub Codex result may remain valid as latest-head-only evidence, but it never
makes the PR ready while the local provenance gate or new-base lanes are
blocked.

Whether or not the merge base changed, a changed `base_ref_oid` also applies
the complete readiness invalidation above. The range-origin transition
answers which range may be rerun; it never authorizes reuse of reviews,
validations, CI, conversations, readiness decisions, or final-reread evidence
from the earlier base tip.

## Lifecycle Gate

At every required snapshot, require:

```text
state == OPEN
merged == false
mergedAt == null
```

A merged PR is terminal. A closed-unmerged PR is not merge-ready. A draft may
be reviewed, but it is not ready to merge until explicitly made ready under
authorization. Missing or contradictory lifecycle data is a blocker, not a
reason to infer state.

Point reads do not prove that no close-and-reopen occurred between them. If
such a transition is observed, invalidate state that depends on continuous
openness and reacquire it.

## Readiness Gates

Evaluate the following for the same frozen current state:

1. **Scope:** selected repository/PR, intended head branch, `baseRefOid`,
   `headRefOid`, and unique local merge base are exact and locally complete.
2. **Lifecycle:** the PR is open, unmerged, and ready rather than draft when
   merge readiness is claimed.
3. **Local review:** every lane required by the requested/effective review
   shape is terminal and clean for exact `base_sha..head_sha`.
4. **Local validation:** relevant build, tests, lint, documentation, and any
   repository-required admission or policy checks pass for the current head.
5. **GitHub Codex:** when required, the lane is `pass` for exact `head_sha` and
   has no unresolved applicable Codex-provider finding.
6. **CI and status:** every required current-head or merge-queue check is
   successful, with no required pending, cancelled, skipped, stale, or missing
   result. Prefer a trustworthy related merge/status check when the repository
   supplies one.
7. **All conversations:** every actionable unresolved conversation is handled,
   including human reviews, other bots, and policy comments. This is separate
   from the GitHub lane, which counts only Codex-provider findings.
8. **Branch policy:** branch protection, rulesets, approvals, mergeability, and
   repository-specific gates permit the intended merge method.

A clean GitHub lane does not waive a human thread, failing test, or required
check. Conversely, an unrelated human conversation does not rewrite the
GitHub Codex provider verdict; it blocks at the all-conversations gate.

## Branch Freshness Is Not Linear History

GitHub names the strict freshness option
**Require branches to be up to date before merging**. It is distinct from
**Require linear history**. A readiness probe may identify the first through
REST `required_status_checks.strict`, GraphQL branch protection
`requiresStrictStatusChecks`, or ruleset input
`strictRequiredStatusChecksPolicy`; GraphQL `requiresLinearHistory` describes
the separate linear-history rule. Never infer a rebase requirement from the
freshness setting.

When a merge queue owns freshness, follow the queue's merge-group and check
semantics instead of updating the feature branch unnecessarily. Queue
freshness alone does not reacquire out-of-band local review or conversation
gates: a target-base change invalidates the current enrollment and requires the
complete rerun plus a new enrollment unless a repository-proved,
non-bypassed required merge-group gate prevents completion until every
invalidated gate has been reacquired for that new exact base tip. When no merge
queue owns freshness and strict freshness blocks the authorized PR workflow,
merge the current base branch into the feature branch with a signed merge
commit. Do not rebase, force-push, or rewrite the branch into linear history
merely to satisfy freshness.

That merge creates a new head. Re-read the PR, require one unique merge base,
freeze the resulting `merge_base..new_head`, and rerun the complete pre-merge
verification for that head: local validation and tests, every required local
review lane, the GitHub Codex lane, CI and status checks, all conversations,
lifecycle/base/head and merge-policy checks, and the final stable reread. Every
positive, pass, or clean result bound to the old head is stale, and every
head-bound readiness gate must be reacquired. An ancestry-proven unresolved
provider finding that remains applicable to the new head is negative evidence,
not reusable positive evidence; it continues to block until typed resolution
or an accepted later corrective artifact satisfies
[github-codex-evidence-authority.md](github-codex-evidence-authority.md).
The old raw finding carrier may be evaluated again, but its old acquisition,
ancestry, and thread inputs are not reusable. The parent must reacquire the
complete current-scope provider observation and freeze a new
`finding_page_receipt`, independently freeze a new `finding_range_receipt`
over the complete `merge_base..new_head` reachable DAG, and apply the evidence
authority's precedence and supersession rules before freezing the selected
`finding_carrier_snapshot`. Merge commits and all in-range side history count;
never replace the range projection with `--first-parent`, `--ancestry-path`, a
single-parent walk, or a linear-history assumption.

Strict freshness catches the ordinary case where the feature branch is behind,
but it does not close the exact-base race after the final reread. A changed
base tip may already be an ancestor of the unchanged feature head, leaving the
strict rule satisfied even though every prior readiness gate is invalid. The
narrow direct-merge exception is not strict alone: it additionally proves that
such an unobserved movement can only contract the already reviewed range under
the complete non-bypassed monotonic policy below. Do not bypass strict
freshness when it does block; apply the signed-merge and complete-rerun rule
above. That refresh remains preparation and never replaces the final mutation's
exact-base or proven monotonic-contraction property.

### Head-Only Provider Responsibility Boundary

The provider/local split is deliberate:

| Proof | Owning gate |
| --- | --- |
| Trustworthy clean/no-unresolved-finding result for exact latest head | GitHub Codex lane |
| Current base, unique merge base, and exact whole-PR range | Local scope and Codex-review gates |
| Base-sensitive behavior | Local validation and required CI |
| Human/bot conversations beyond applicable Codex findings | All-conversations gate |
| Rulesets, approvals, mergeability, and merge method | Branch-policy gate |

Therefore a GitHub-lane `pass` is intentionally head-only. It neither says nor
implies that the provider reviewed the current base. PR readiness is reached
only when all independently owned gates are simultaneously true. Prefer a
trustworthy related merge/status check when one exists, but credit it with base
assurance only when its documented contract actually binds the base.

## Change Invalidation

Re-read PR scope after every push, base retarget, or merge-queue transition.
Treat every observed `baseRefName` change, even when its OID is unchanged, and
every `baseRefOid` change as a new readiness boundary, even when the feature
head and unique merge base are byte-for-byte unchanged.

| Change | Invalidation |
| --- | --- |
| Head changes | All local reviews, head-bound provider evidence, tests tied to the old head, CI, conversations affected by the diff, and final reread |
| Target `baseRefName` changes, even when its OID is unchanged | All local PR-wide reviews, all local validation and tests, all CI/status results, all conversation decisions, merge status, mergeability, queue state, readiness decisions, and final reread. Preserve head-only provider evidence only under its separate complete reread rule. |
| Target `baseRefOid` changes while head and unique merge base stay the same | All local PR-wide reviews, all local validation and tests, all CI/status results, all conversation decisions, merge status, mergeability, queue state, readiness decisions, and final reread. The range endpoints and active range-origin record are unchanged, but no evidence from the old base tip remains countable. |
| Unique merge base changes while head stays the same | All local PR-wide reviews, all local validation and tests, all CI/status results, all conversation decisions, merge status, mergeability, queue state, readiness decisions, and final reread; also apply the range-origin provenance gate before selecting the new range. |
| Conversation or thread state changes | Conversation gate and provider finding projection when the changed thread is provider-owned |
| Required check reruns | CI/status gate and final reread |

Because the GitHub provider contract proves the head rather than the base, a
target-ref, base-tip, or merge-base-only change does not by itself invalidate a
trustworthy current-head terminal clean or reaction fallback. Retain it only
after a fresh, complete authority reread proves its exact head is still current
and proves no applicable provider finding remains unresolved. Pass the
`range_origin`
provenance gate when the merge base changed, rerun every local review,
validation/test, CI/status, conversation, readiness, and final-reread gate for
the new exact base tip, and reconcile any base-sensitive merge/status check.
Do not post another `@codex review` solely because the base changed unless a
future provider contract explicitly binds base input.

This reuse is an explicit acceptance decision. Record it as
`github_codex_scope: latest-head-only`; do not describe the retained artifact
as whole-PR, base-tip, or new-base review evidence. Until every invalidated
local review, validation/test, CI/status, conversation, merge-status,
readiness, and final-reread gate passes, the PR remains blocked or pending
even though the GitHub lane itself may remain passed.

## Fix Loop

When any substantive gate fails:

1. Classify the failure as code, test, policy, conversation, provider finding,
   or retryable infrastructure.
2. Resolve substantive failures on the intended branch; do not rerun them as
   if they were infrastructure. An applicable inline provider finding may be
   cleared on the same head only by the exact GraphQL thread's typed
   `isResolved == true`; a top-level finding may be superseded by the evidence
   authority's trustworthy same-head provider correction. Neither transition
   alone requires a fresh review.
3. Commit and push only when authorized.
4. Re-read lifecycle, base/head, and merge base.
5. Rerun every invalidated local lane and validation.
6. Reacquire GitHub Codex, CI, and conversation evidence for the new state.
7. Repeat until every gate is simultaneously true.

If resolving a finding changes code, that commit creates a new head and the
full invalidation and fresh-review rules apply. Do not manufacture an empty
commit for a resolution-only state change.

Retry only GitHub states whose typed evidence or documented repository
contract supplies a machine-decidable retryable pending or infrastructure
reason, using [github-pr-probes.md](github-pr-probes.md). A stable malformed
snapshot, scope contradiction, or other non-retryable inconclusive state stops
recovery and is reported immediately. An explicit applicable unresolved
provider finding, failed test, or policy failure is never an automatic
reconcile target.

## Final Reread

Immediately before reporting merge-ready or merging, reread all of the
following without reusing stale summaries:

- exact PR lifecycle and draft state;
- repository, `baseRefName`, `baseRefOid`, `headRefOid`, intended head
  ownership/branch, and unique local merge base;
- the parent-owned immutable `range_origin` lineage, its complete predecessor
  chain, and its current active-record binding for every local range counted as
  PR-wide evidence;
- local review artifacts and validations newly acquired for both the resulting
  range and the current exact repository, `baseRefName`, and `baseRefOid`
  binding;
- newly frozen parent-owned `finding_page_receipt`, `finding_range_receipt`,
  and `finding_carrier_snapshot` inputs for the complete current-scope provider
  observation, full-DAG range, authority-selected carrier, and unresolved
  provider findings;
- required check rollup, related merge/status evidence, mergeability, and
  merge-queue state;
- every review and conversation thread relevant to readiness; and
- repository rules, approvals, and merge method.

Require all selected non-provider evidence to remain on the same selected
repository, current exact `baseRefName`, exact `baseRefOid`, head, and
appropriate merge base. A retained head-only GitHub provider artifact must
instead pass its fresh complete current-head and unresolved-finding reread and
still supplies no base or target-ref coverage. If any page is incomplete,
state changes during the reread, or evidence belongs to a stale scope,
target-ref, or base-tip binding, return to the fix/recovery loop.

## Atomic Head Binding For Merge Execution

The final reread produces one exact `merge_expected_head`, equal to the
reviewed `head_sha`; one exact `merge_expected_base_ref`, equal to the current
repository plus `baseRefName`; and one exact `merge_expected_base`, equal to
the current `baseRefOid`. Every authorized state-changing operation that can
lead to merge must carry the expected head as a server-enforced precondition in
the operation itself and must have a server-enforced base-freshness binding.
This applies both to a direct merge and to merge-queue enrollment. A separate
`headRefOid` or `baseRefOid` read followed by an unconditional mutation has a
race and does not satisfy this contract.

GitHub's direct merge request exposes `sha` as a head precondition; it does not
expose an expected-target-base field. Therefore direct merge is eligible only
when a documented server-side expected-base mutation primitive or a
repository-proved exact-base guard rejects every
`baseRefOid != merge_expected_base` mutation without bypass, or the complete
monotonic range-contraction alternative below is proved. Exact base equality is
preferred. A point read of the base, mergeability, or `mergeStateStatus` is not
an atomic substitute.

### Direct Base Protection Decision

The protected property is exactly one of:

1. **Exact base equality:** the merge transaction rejects every
   `baseRefOid != merge_expected_base` while also binding the reviewed head.
2. **Proven monotonic range contraction:** the parent proves all of the
   following before invoking the exact-head-bound direct merge:
   - the frozen `merge_expected_base_ref` equals the final-reread repository
     plus `baseRefName`;
   - the final unique merge base, `merge_expected_base`, and reviewed
     `base_sha` are equal;
   - strict up-to-date is enforced by the server in the merge transaction, not
     inferred from a prior point read;
   - from `merge_expected_base` until that transaction, that same frozen target
     base ref can only move by fast-forward and cannot be deleted or
     non-fast-forward rewritten;
   - the complete current applicable protection/ruleset and actor inventory
     contains no configured base-update or merge bypass, including an
     administrator, App, or ruleset bypass entry, and enumerates actors
     authorized to retarget the PR; and
   - that inventory is complete rather than inferred from one visible rule,
     one ruleset page, or one branch-protection endpoint.

Under the second property, exact-head binding keeps `head_sha` fixed,
fast-forward-only base movement proves `merge_expected_base` is an ancestor of
`current_base`, and transactional strict freshness proves `current_base` is an
ancestor of `head_sha`. Therefore the effective
`current_base..head_sha` range is a subset of the reviewed
`merge_expected_base..head_sha` range. Only an unobserved movement inside the
final reread-to-mutation window may use this contraction. Once the parent
observes any `baseRefName` or `baseRefOid` change, the ordinary full
invalidation and rerun rule applies; never relabel that observed event as an
atomic-window contraction.

Do not infer contraction across two different target ref names: a retarget to
another `head_sha` ancestor need not make that new tip a descendant of
`merge_expected_base`, so the range-subset proof would not follow.

GitHub and authorized repository collaborators or administrators who can
retarget the PR or reconfigure rules are the trusted external control plane for
this consumer proof. Any observed `baseRefName`, applicable-rule, bypass, or
actor-inventory change invalidates the contraction proof and returns to the
ordinary reread and rerun flow. Malicious or concurrent unobserved retargeting
or control-plane reconfiguration after the final reread is outside the consumer
guarantee; never claim that this proof prevents it. This trust boundary is the
operable target-ref condition; do not require or invent a GitHub retarget hold.

The decision is fail closed:

| Direct base condition | Decision |
| --- | --- |
| Atomic expected-base equality plus exact reviewed head | Eligible through exact-base equality |
| Transactional strict plus frozen target ref, complete fast-forward-only/no-delete/no-configured-bypass proof, and exact reviewed head | Eligible through proven monotonic range contraction |
| Strict up-to-date alone | Blocked; not an exact-base comparison or monotonic proof |
| Force push or another non-fast-forward base update is allowed | Blocked |
| Base deletion is allowed | Blocked |
| Any configured base-update or merge bypass exists | Blocked |
| Applicable protection/ruleset or actor/bypass inventory is incomplete | Blocked |
| Base-ref or authorized retarget-actor inventory is incomplete | Blocked |
| An observed `baseRefName` retarget, even to the same OID or another `head_sha` ancestor | Full invalidation; contraction unavailable |
| Any rule, actor, endpoint, or transactional-enforcement proof is missing or ambiguous | Blocked |

For a direct merge, GitHub CLI exposes the required compare-and-mutate
condition as `--match-head-commit`. Select the exact repository and PR rather
than relying on the current directory or branch:

```text
# Direct squash merge on a repository without a required merge queue.
gh pr merge <PR_NUMBER> --repo OWNER/REPO --squash \
  --match-head-commit <HEAD_SHA>
```

An equivalent direct-merge client is acceptable only when the same mutation
carries the exact reviewed head, such as the synchronous pull-request merge
API's `sha` field, and one of the two protected base properties above also
applies. Never emulate either condition with a second read in the client.

The queue path needs a persistent expected-head binding, not merely an atomic
request to enable auto-merge. After every pre-enrollment gate is current and
clean, use GitHub's documented asynchronous merge endpoint with the exact body
fields shown here:

```text
PUT /repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async
{"sha":"<HEAD_SHA>","merge_action":"merge_queue"}

# The same request through GitHub CLI's API transport.
gh api --include --method PUT \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async \
  -f sha="<HEAD_SHA>" -f merge_action="merge_queue"
```

Persist the request's status, response, and UUID. Poll
`GET /repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async/<UUID>` and require every
pending result to report `details.expected_head_sha == merge_expected_head`
and `details.merge_action == "merge_queue"`. A `409` may identify an older
request whose options differ; never adopt it from status alone. It can count
only after its result proves the same expected head and queue action. A `200`
already-merged or already-queued result likewise needs complete current PR,
queue, and final-head evidence rather than an inferred binding.

For a queue path, atomically enroll the exact reviewed feature head, then
follow the resulting latest-base merge-group checks and reread queue state. The
queue, rather than a nonexistent expected-base request field, owns base
freshness only under a repository-proved required hold that prevents merge
after a target-base change. Such a change invalidates the existing enrollment,
`merge_expected_base`, and every earlier local review, validation/test,
CI/status, conversation, readiness, and final-reread result. Cancel or observe
cancellation of that enrollment, complete the full rerun for the new exact
base tip, freeze a new `merge_expected_base`, and enroll again. A rebuilt merge
group never preserves out-of-band evidence. The only narrow equivalent is a
proved repository contract under which every invalidated gate is itself a
required, non-bypassed check on that new merge group. Without either contract,
the queue path is blocked. A later feature-head change must be observed as
cancellation of the bound asynchronous merge; it invalidates the
enrollment, every old-head positive/pass/clean result, and every head-bound
readiness gate, then starts the applicable full pre-merge verification loop
for the new head. An ancestry-proven unresolved provider finding that remains
applicable to the new head continues to block until typed resolution or an
accepted later corrective artifact. An
`autoMergeRequest` is not equivalent to this persistent binding: if
`gh pr merge` would only enable long-lived auto-merge rather than prove an
exact-head queue entry, do not use it. If the async endpoint or an equally
persistent server-side expected-head queue primitive is unavailable, report
the queue path blocked; never fall back to an unbound auto-merge request.
Before any new enrollment, require no active stale `autoMergeRequest` or queue
entry that could promote another head.

If the expected-head condition reports a mismatch, fails with GitHub's
conflict response, or the immediate post-operation reread does not show the
same feature `head_sha`, fail closed. The same applies if direct strict
freshness rejects the merge, becomes inapplicable or bypassable, or a queue
cannot prove its latest-base merge-group binding. Do not retry the stale
mutation. Reread the PR, establish the actual current head, target ref, base
tip, and range, and rerun every invalidated test, review, GitHub, CI,
conversation, lifecycle, merge-policy, and final-reread gate before
constructing a new conditionally bound operation. A signed merge of the
current base into the feature branch under the strict-freshness rule is not an
exception: it intentionally creates a new head and requires that complete
rerun. If the target ref or base tip changes again before the direct merge and
the parent observes it, start the full invalidation loop again. An unobserved
change may reach the mutation only under one of the two protected base
properties above; otherwise the mutation is blocked. When the change leaves
the feature branch behind, strict freshness additionally blocks and the
signed-merge/full-rerun rule applies.

After a direct merge or queue completion, verify merged lifecycle and resulting
default-branch state, and require the PR's final feature head to remain exactly
`merge_expected_head`. A successful command without those postconditions is
not proof that the reviewed head was the one merged.

## Merge-Ready Report

Report the decisive state rather than a long transcript:

```yaml
pr_readiness:
  status: ready | blocked | pending
  repository: owner/name
  pull_request: 123
  url: https://github.com/owner/name/pull/123
  base_ref_name: exact-base-ref-name
  base_ref_oid: 40-lowercase-hex
  head_ref_oid: 40-lowercase-hex
  merge_base: 40-lowercase-hex
  merge_expected_head: same-as-head-ref-oid
  merge_expected_base_ref:
    repository: same-as-report-repository
    base_ref_name: exact-base-ref-name-at-final-reread
  merge_expected_base: same-as-base-ref-oid-at-final-reread
  merge_execution_binding: required-server-side-head-and-base-freshness | not-authorized
  protected_base_property: exact-base-equality | monotonic-range-contraction | merge-queue-full-gate-binding | blocked-unproved
  base_freshness_binding: merge-queue-full-gate-binding | expected-base-precondition | repository-exact-base-guard | monotonic-range-contraction | blocked-unbound
  range_origin:
    lineage_id: stable-parent-generated-lineage-id
    kind: caller-supplied | pr-derived
    active_record_id: stable-parent-generated-record-id
    record_id: same-as-active-record-id
    predecessor_record_id: null | previous-active-record-id
    base_sha: record-full-object-id
    head_sha: record-full-object-id
  local_review_shape: single | double | triple | skill-repo-codex-gate
  local_reviews: pass | blocked | pending
  github_codex_lane: pass | findings | pending | inconclusive | not-applicable
  github_codex_scope: latest-head-only | not-applicable
  base_assurance: local-review-and-readiness-gates
  required_checks: pass | blocked | pending
  conversations: resolved | unresolved | unknown
  mergeability: mergeable | blocked | unknown
  last_reason: stable-machine-readable-reason
```

`ready` means every required gate was simultaneously true on the final reread.
It does not itself authorize the merge. If the user authorized merge, perform
the repository's intended merge method through the atomic expected-head
contract above, then verify the merged lifecycle and resulting default-branch
state.
