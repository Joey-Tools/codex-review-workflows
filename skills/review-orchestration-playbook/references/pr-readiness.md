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

Choose required lanes through [Default Review Routing](default-review-routing.md#default-review-routing) first.
An unnamed PR-bound request with an eligible GitHub Codex or native GitHub
Copilot reviewer uses remote-only review; local review is not required by
default. Every reference below to local reviews or their provenance applies
only to local lanes actually required by that route or an explicit request.
Local scope verification, tests, CI, conversations, and merge policy remain
required independently; do not turn them into a local-review mandate.
Native Copilot uses its own completion evidence, not the Codex classifier.
Apply the playbook's session choice when support is unknown or unavailable:
authorized local fallback, local required plus available remote, or remote-only
wait/retry. Capability observations and historical review never pass a gate.
A session choice cannot remove a repository-required remote check, approval,
or unresolved finding; current-head evidence remains mandatory for every
required lane. New head alone invalidates reviews, not service capability.

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
unchanged. Every observed change requires a fresh scope check and final
reread. In the routine profile, use the read-only
[`readiness_plan.py`](../scripts/readiness_plan.py) classifier to revalidate
only evidence whose declared dependencies intersect the changed dimensions.
For example, a head-bound check or local review of an unchanged
`base_sha..head_sha` range can remain countable when only `base_ref_oid`
advances, while a merge-group check or test declared base-sensitive must be
reacquired. A changed merge base changes the local range and invalidates its
range-bound positive reviews and validations. A changed head invalidates every
head-bound positive/pass/clean result and the complete local range. An
applicable negative provider finding remains a separate blocker until typed
resolution or an accepted later corrective artifact; it is not an item in the
planner's positive evidence array. A retained head-only provider result still
requires the complete fresh provider reread described by its authority.

The classifier accepts one closed JSON object with `profile`, five boolean
`changes` (`head`, `base_ref`, `base_tip`, `merge_base`, `merge_group`), an `evidence` array
whose records give an `id`, `kind`, and exact dependency list, and a closed
`merge` constraint record. It separately names `operation: direct | merge_queue`
and `head_binding`; direct accepts only `match-head-commit` or `none`, while
`merge_queue` accepts only `persistent-queue-merge-async-sha` or `none`.
Repeated JSON object keys are rejected recursively for stdin and file input;
there is no last-key-wins fallback. Mismatched operation/binding pairs fail
closed. Routine `merge` input also
requires `admin_bypass_requested`; every queue input additionally requires
`all_invalidated_gates_on_required_merge_group`,
`non_bypassed_completion_hold`, and `queue_bypass_rules` (the observed request
option, `false` only when proven; `true` or unknown blocks reuse). Strict input
additionally requires the complete strict-base and bypass-audit fields. Strict
queue proof is named
`strict_queue_full_gate_binding`, is accepted only with the `merge_queue`
operation, and requires complete actor inventory plus either proof that every
invalidated gate is bound to the required merge group or a non-bypassed hold
until all are reacquired. This coverage includes every `global_invalidations`
entry as well as every invalidated evidence record; ordinary merge-group
checks alone do not prove coverage of global scope, final-reread, readiness,
or merge-policy gates. The input boolean
`all_invalidated_gates_on_required_merge_group` is parent-owned proof of that
complete coverage, not a statement about only the evidence array. Direct strict
proof types cannot satisfy a queue operation. Unknown fields, dependency
names, kinds, repeated keys, or missing values fail closed. Evidence dependencies are
classified by the readiness owner from producer semantics, not self-declared
by the evidence subject; missing or ambiguous classification blocks reuse.
Invoke it with parent-owned evidence classification, for
example `python skills/review-orchestration-playbook/scripts/readiness_plan.py
--input <readiness-plan.json>`. The output is a revalidation, merge-profile,
and queue-enrollment action plan only. The evidence array contains positive,
pass, or clean artifacts only; negative findings and unresolved conversations
stay in their independent blocking gate and are never eligible for planner
invalidation or reuse. For queue operations, routine mode preserves the
exact-head enrollment across a base-tip or merge-base change on the same target
ref, or an independent merge-group synthetic-SHA change, only when every
invalidated evidence gate and every global invalidation is covered by the
required merge group or a non-bypassed completion hold. Global gates include
the fresh scope/final reread and readiness decision on every observed change,
plus merge-policy snapshot for base changes and current merge-group checks for
queue changes. Thus an empty or head-only evidence array does not permit queue
retention after a base or merge-group change by itself. If any global or
evidence gate is uncovered, cancel/re-enroll and reacquire the affected gate;
the planner distinguishes global-only invalidation from affected evidence.
A target-ref retarget or head change cancels the entry, and strict base changes
cancel/re-enroll after full base revalidation. The queue request must prove
`bypass_rules: false`; an enabled or unknown value never qualifies for
retention. Its `queue_enrollment_action` is one of
`not_applicable`,
`retain_if_exact_head_binding_remains_current`,
`retain_across_merge_group_rebuild`,
`cancel_and_reenroll_after_base_retarget`,
`cancel_and_reenroll_after_head_change`,
`cancel_and_reenroll_after_strict_base_rerun`,
`cancel_and_reenroll_after_affected_evidence_revalidation`,
`cancel_and_reenroll_after_global_gate_revalidation`, or
`cancel_and_reenroll_after_merge_constraints_reacquired`. The caller must inspect
actual request state and verify the exact head binding. The planner never
acquires evidence, establishes full readiness, authorizes a merge, or replaces
the human-owned final gate. Candidate code cannot be used to approve this
playbook's own migration.

When the unique merge base and head did not change, the active `range_origin`
record remains the correct range provenance. Retaining it does not by itself
retain any evidence: the classifier decides evidence reuse from its declared
dependencies, and the parent must disclose why each base-sensitive check is
or is not affected.

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

A changed `base_ref_oid` always requires a fresh scope and final reread. In
routine mode, use the dependency plan to revalidate only evidence affected by
the changed target tip/ref; evidence with unknown dependency classification
cannot be reused. Unaffected reviews, validations, CI, conversations, and
other readiness evidence may remain countable when parent-owned dependency
classification proves them invariant. In strict mode, apply complete
base-bound readiness invalidation, except a separately reread head-only
provider result. The range-origin transition answers which local range may be
rerun; it never independently authorizes evidence reuse.

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
3. **Local review:** every local lane required by the requested/effective review
   shape is terminal and clean for exact `base_sha..head_sha`. On the
   remote-only route report `not-required`, never a fabricated local pass.
4. **Local validation:** relevant build, tests, lint, documentation, and any
   repository-required admission or policy checks pass for the current head.
5. **GitHub Codex:** when required, the lane is `pass` for exact `head_sha` and
   has no unresolved applicable Codex-provider finding.
   Native GitHub Copilot, when selected instead, requires its own current-head
   completed review and no applicable unresolved finding under
   [Default Review Routing](default-review-routing.md#default-review-routing). Neither requires an extra local lane.
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
semantics instead of updating the feature branch unnecessarily. Submit every
new asynchronous queue request with `bypass_rules: false`, and retain the
exact submitted head/action/options together with its acknowledged request
UUID and scope. A 202 alone does not echo those options: when status is still
pending, verify its details show the exact `expected_head_sha`,
`merge_action == "merge_queue"`, and literal `bypass_rules == false`. If an
own acknowledged request has already become `enqueued`, retain its proved
original options and reread the current PR/queue binding; do not infer missing
options from the terminal response alone. Before reusing a pre-existing
request identified by a
409, require the same exact properties from its pending status. Missing, true,
or otherwise unproved bypass state blocks reuse; never infer false from an
omitted field or from an older request's head/action alone. A final `enqueued`
result is not proof of merge and does not update with later queue completion;
do not treat it alone as fresh head/bypass proof. Async results expire after
24 hours, so reacquire current request state when the result is no longer
available. See the [asynchronous merge API](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request-asynchronously) and [merge queue behavior](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).

Treat a changed merge-group synthetic SHA as an independent change even when
the PR head, target ref/tip, and merge base are unchanged. Set
`changes.merge_group: true`; invalidate every artifact that declares the
`merge_group` dependency and reacquire current merge-group checks. Queue
reordering, removal of another queued PR, or another rebuild can produce a new
synthetic SHA ([GitHub documents queue reordering rebuilds in-progress merge
groups](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue#jumping-to-the-top-of-the-queue)).
If the change invalidates out-of-band group-sensitive evidence,
cancel/re-enroll after reacquisition unless every affected gate is protected
by the required merge group or a non-bypassed completion hold. The same rule
applies in routine and strict queue profiles; strict base changes still use
the full strict rerun path. This dimension is queue-only and must be false for
direct merge plans.

In routine mode, a base-tip or merge-base change on the same target ref and
unchanged head preserves the existing persistent `merge-async` SHA-bound
enrollment across a merge-group rebuild only when there is no invalidated
positive out-of-band evidence or the repository proves that every invalidated
gate is covered by the required merge group or a non-bypassed completion hold.
Otherwise cancel/re-enroll after affected evidence is reacquired; required
queue checks cannot serialize an out-of-band test or review.
The selected operation is `merge_queue`, and the binding must be
`persistent-queue-merge-async-sha`; direct `match-head-commit` is not valid for
that operation. A target-ref retarget cancels/re-enrolls the entry even if the
feature head is unchanged. Reacquire
required checks for the current merge group and use the dependency classifier
for out-of-band evidence, retaining unaffected gates only when their
parent-owned dependency classification proves they are invariant. Do not
cancel/re-enroll merely because the merge group rebuilt. A head change always
invalidates and cancels the enrollment. Strict mode invalidates its complete
base-bound evidence set and cancels/re-enrolls after required gates are
reacquired. The strict queue path also requires a repository-proved,
non-bypassed required merge-group gate that prevents completion until every
invalidated gate has been reacquired for the exact base tip, or a proved
contract that puts every such gate on the rebuilt required merge group;
otherwise strict queue merge is blocked. When no merge queue owns freshness
and strict freshness blocks the authorized PR workflow, merge the current base
branch into the feature branch with a signed merge commit. Do not rebase,
force-push, or rewrite the branch into linear history merely to satisfy
freshness.

That merge creates a new head. Re-read the PR, require one unique merge base,
freeze the resulting `merge_base..new_head`, and rerun the complete pre-merge
verification for that head: local validation and tests, every required local
review lane, the selected remote lane, CI and status checks, all conversations,
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
strict rule satisfied. Strict-base-proof mode therefore requires its complete
non-bypassed exact-base or monotonic proof below. Routine mode reports the
remaining race and relies on exact-head binding plus the trusted control plane.
Do not bypass required strict freshness when it blocks; apply the signed-merge
and new-head invalidation rule above. That refresh remains preparation and
never replaces the strict profile's required base property.

### Head-Only Provider Responsibility Boundary

The provider/local split is deliberate:

| Proof | Owning gate |
| --- | --- |
| Trustworthy clean/no-unresolved-finding result for exact latest head | GitHub Codex lane |
| Current base, unique merge base, and exact whole-PR range | Parent scope/readiness proof; local-review binding only when a local lane is required |
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
| Target `baseRefName` changes, even when its OID is unchanged | Re-read PR scope, lifecycle, rules, required checks, and final state. In routine mode, revalidate only evidence that depends on the target ref or whose governing rule changed. In strict mode, invalidate all readiness evidence except a separately reread head-only provider result. |
| Target `baseRefOid` changes while head and unique merge base stay the same | Re-read PR scope and final state. In routine mode, preserve evidence tied only to the unchanged head/range; reacquire base-sensitive tests, merge-group/status results, or other evidence selected by the classifier. Strict mode keeps its full base-change invalidation. |
| Unique merge base changes while head stays the same | Apply the range-origin provenance gate before selecting the new range. Invalidate range-bound local reviews and validations and other evidence declared dependent on the merge base; preserve unaffected head-only evidence after its required reread. Strict mode keeps its full base-change invalidation. |
| Conversation or thread state changes | Conversation gate and provider finding projection when the changed thread is provider-owned |
| Required check reruns | CI/status gate and final reread |

Because the GitHub provider contract proves the head rather than the base, a
target-ref, base-tip, or merge-base-only change does not by itself invalidate a
trustworthy current-head terminal clean or reaction fallback. Retain it only
after a fresh, complete authority reread proves its exact head is still current
and proves no applicable provider finding remains unresolved. Pass the
`range_origin` provenance gate when the merge base changed. In routine mode,
revalidate only other evidence whose dependencies include a changed dimension;
strict mode reruns its complete base-bound evidence set. Reconcile any
base-sensitive merge/status check. Do not post another `@codex review` solely
because the base changed unless a future provider contract explicitly binds
base input.

This reuse is an explicit acceptance decision. Record it as
`github_codex_scope: latest-head-only`; do not describe the retained artifact
as whole-PR, base-tip, or new-base review evidence. Until every invalidated
review, validation/test, CI/status, conversation, merge-status, readiness, and
final-reread gate passes, the PR remains blocked or pending even though the
GitHub lane itself may remain passed.

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
5. Rerun every invalidated required local lane and validation.
6. Reacquire the selected remote provider, CI, and conversation evidence for the new state.
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
- the read-only dependency plan and each still-countable review/validation
  artifact's exact dependency dimensions; range-bound evidence must match the
  active `base_sha..head_sha`, and base-sensitive evidence must match the
  current declared base scope;
- newly frozen parent-owned `finding_page_receipt`, `finding_range_receipt`,
  and `finding_carrier_snapshot` inputs for the complete current-scope provider
  observation, full-DAG range, authority-selected carrier, and unresolved
  provider findings;
- required check rollup, related merge/status evidence, mergeability, and
  merge-queue state;
- every review and conversation thread relevant to readiness; and
- repository rules, approvals, and merge method.

Require each selected non-provider artifact to remain bound to every dimension
in its declared dependencies; every item must also match the current
repository and its applicable head/range scope. A retained head-only GitHub
provider artifact must pass its fresh complete current-head and
unresolved-finding reread and still supplies no base or target-ref coverage.
If any page is incomplete, state changes during the reread, or a dependency
plan is unknown, return to the fix/recovery loop.

## Server Head Binding And Base Profiles

The final reread produces one exact `merge_expected_head`, equal to the
reviewed `head_sha`. Every authorized state-changing operation that can lead
to merge must bind that head in the server mutation itself. For direct merge,
use `--match-head-commit <head_sha>`; for queue enrollment, use the persistent
expected-head binding below. A separate `headRefOid` read followed by an
unconditional mutation has a race. Never request administrator, ruleset, App,
or other bypass.

The default **routine profile** requires the complete ordinary readiness gates
and exact server-side head binding. It does not require an exact-base mutation
precondition, complete bypass/actor inventory, or proof of atomic range
contraction. Its base assurance is the fresh PR scope/lifecycle/rules/required
checks plus the user's trust in GitHub and authorized repository
collaborators/administrators as the control plane. A concurrent base change
after final reread can still race the direct mutation; report this residual
limitation and do not claim the base was atomically frozen. Once an observed
change occurs, re-read scope and apply the dependency plan above.
Routine is only the default: use strict assurance whenever the user or a
higher-level project policy explicitly requires it. Neither profile permits
weakening or skipping existing server-required checks, approvals, or freshness
rules.

The **strict-base-proof profile** is opt-in. GitHub's direct merge request
exposes a head precondition but no expected-target-base field, so strict mode
requires a documented server-side expected-base mutation primitive, a proved
exact-base guard, or the complete monotonic range-contraction proof below.
Point reads of the base, mergeability, `mergeStateStatus`, or strict freshness
alone are not atomic substitutes.

### Strict Base Protection Decision

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
observes any `baseRefName` or `baseRefOid` change, strict mode applies its full
invalidation and rerun rule; never relabel that observed event as an
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

Strict mode's base decision is fail closed:

| Direct base condition | Decision |
| --- | --- |
| Strict atomic expected-base equality plus exact reviewed head and complete bypass audit | Eligible through exact-base equality |
| Strict transactional freshness plus frozen target ref, complete fast-forward-only/no-delete/no-configured-bypass proof, and exact reviewed head | Eligible through proven monotonic range contraction |
| Strict up-to-date alone | Blocked; not an exact-base comparison or monotonic proof |
| Force push or another non-fast-forward base update is allowed | Blocked |
| Base deletion is allowed | Blocked |
| Any configured base-update or merge bypass exists | Blocked |
| Applicable protection/ruleset or actor/bypass inventory is incomplete | Blocked |
| Base-ref or authorized retarget-actor inventory is incomplete | Blocked |
| An observed `baseRefName` retarget, even to the same OID or another `head_sha` ancestor | Full invalidation; contraction unavailable |
| Any rule, actor, endpoint, or transactional-enforcement proof is missing or ambiguous | Blocked |

For a strict merge queue, `base_proof: strict_queue_full_gate_binding` is the
only queue-specific proof type. It requires complete bypass and actor
inventories, no configured bypass, and either proof that all applicable
invalidated evidence gates and global invalidations are required on the rebuilt
merge group or a non-bypassed hold until they are reacquired. It is not a
direct expected-base, exact-base, or monotonic proof and cannot be used for a
direct merge. A direct-only proof cannot satisfy a queue operation.

Routine mode requires the exact reviewed head and ordinary readiness gates
described above; the strict-only blockers in this table do not apply to it.

Read-only inspection of applicable branch protection, rulesets, bypass lists,
and effective permissions is authorized within the current task's repository
and PR scope; it does not need another verbal confirmation. Apply the normal
environment execution permissions. If an endpoint or page cannot be read,
record the result as unknown, not as an empty policy or a skipped gate. This
read-only authorization does not permit changing protection or rulesets,
using a bypass, switching authentication identity, dispatching or rerunning
workflows, or any other external write.

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
API's `sha` field. Routine mode does not require either strict protected-base
property; it accepts the documented GitHub control-plane trust boundary and
residual base race above. Strict-base-proof mode additionally requires one of
the two protected base properties above. Never emulate either condition with
a second read in the client.

The queue path needs a persistent expected-head binding, not merely an atomic
request to enable auto-merge. After every pre-enrollment gate is current and
clean, use GitHub's documented asynchronous merge endpoint with the exact body
fields shown here:

```text
PUT /repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async
{"sha":"<HEAD_SHA>","merge_action":"merge_queue","bypass_rules":false}

# The same request through GitHub CLI's API transport.
gh api --include --method PUT \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async \
  -f sha="<HEAD_SHA>" -f merge_action="merge_queue" -F bypass_rules=false
```

Persist the request's status, response, and UUID. Poll
`GET /repos/OWNER/REPO/pulls/<PR_NUMBER>/merge-async/<UUID>` and require every
pending result to report `details.expected_head_sha == merge_expected_head`
and `details.merge_action == "merge_queue"`, and literal
`details.bypass_rules == false`. A `409` may identify an older request whose
options differ; never adopt it from status alone. It can count only after its
pending result proves the same expected head, queue action, and non-bypassed
option. An `enqueued` result is terminal and does not later become a merged
result; reacquire the current PR and queue state to establish completion.

An HTTP 200 response indicating that a request is already queued is not, by
itself, proof of the queued request's options or head binding. Reuse it only
when the task retained its own exact submitted request and acknowledged UUID/
scope for the same still-current queue enrollment, including the reviewed
head, `merge_queue` action, and literal `bypass_rules: false`. A prior request
from an enrollment that was canceled or replaced is not proof of the current
entry. A generic PR queue read, an `enqueued` status, or an unbound 200 response
cannot supply missing request details; otherwise block or cancel the
enrollment and reacquire a properly bound request.

For a queue path, select `operation: merge_queue` with
`head_binding: persistent-queue-merge-async-sha`; the planner rejects a
binding paired with the wrong operation. Atomically enroll the exact reviewed
feature head, then
follow the resulting latest-base merge-group checks and reread queue state. In
routine mode, apply the positive-evidence dependency plan before retaining the
exact-head enrollment across a same-target-ref base-tip/merge-base rebuild.
Retain it only when every invalidated evidence gate and global invalidation is
covered by the required merge group or a non-bypassed completion hold. Global
invalidations include scope, final reread, and readiness on every observed
change, plus the merge-policy snapshot after a base change and current
merge-group checks after a queue change. An empty or head-only evidence list
does not allow retention through these global invalidations. Otherwise
cancel/re-enroll after affected evidence and global gates are reacquired; a
target-ref retarget also cancels/re-enrolls. Reacquire required checks for the
new current merge group. A rebuilt merge group does not
by itself invalidate an unrelated head/range result. The planner reports safe
retention as `retain_across_merge_group_rebuild`, or otherwise asks to
cancel/re-enroll after affected evidence is reacquired. Every planner retention
action also requires `merge_constraints.constraint_status == "satisfied"`; if
constraints are blocked, cancel any active enrollment and do not re-enroll until
the required proof is reacquired. A covered merge-group gate or non-bypassed
hold does not satisfy an unrelated missing strict audit or base proof; never
infer a hold that was not established. A changed head invalidates every
old-head positive/pass/clean result and cancels the enrollment, requiring the
applicable full pre-merge loop for the new head.
Applicable negative findings are not in the planner's positive evidence array;
reread them independently and keep them blocking until typed resolution or an
accepted later corrective artifact. Strict mode cancels/re-enrolls after its full
base invalidation, and also requires the repository-proved non-bypassed hold
or new-required-merge-group contract described above. Without that strict
contract, strict queue merge is blocked. A later feature-head change must be
observed as cancellation
of the bound asynchronous merge. An ancestry-proven unresolved provider finding
that remains applicable to the new head continues to block until typed resolution or an
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
rerun. If the target ref or base tip changes again before direct merge and the
parent observes it, restart scope/final reread and apply profile-specific
invalidation: routine revalidates affected evidence; strict reruns its complete
base-bound evidence set. An unobserved base change may reach a routine direct
merge under the documented control-plane trust boundary and residual race.
Strict direct merge remains blocked without one of the two protected base
properties above. When the change leaves the feature branch behind, strict
freshness additionally blocks and the signed-merge/full-rerun rule applies.

After a direct merge or queue completion, verify merged lifecycle and resulting
default-branch state, and require the PR's final feature head to remain exactly
`merge_expected_head`. A successful command without those postconditions is
not proof that the reviewed head was the one merged.

## Merge-Ready Report

Report the decisive state rather than a long transcript:

```yaml
pr_readiness:
  status: ready | blocked | pending
  profile: routine | strict
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
  merge_execution_binding: exact-server-side-head | not-authorized
  protected_base_property: routine-trusted-control-plane | exact-base-equality | monotonic-range-contraction | merge-queue-full-gate-binding | blocked-unproved
  residual_base_race: true | false
  range_origin:
    lineage_id: stable-parent-generated-lineage-id
    kind: caller-supplied | pr-derived
    active_record_id: stable-parent-generated-record-id
    record_id: same-as-active-record-id
    predecessor_record_id: null | previous-active-record-id
    base_sha: record-full-object-id
    head_sha: record-full-object-id
  review_route: local | remote-only | explicit-named | explicit-provider
  remote_provider: github-codex | github-copilot | not-required
  local_review_shape: single | double | triple | not-required
  local_reviews: pass | blocked | pending | not-required
  github_codex_lane: pass | findings | pending | inconclusive | not-applicable
  github_codex_scope: latest-head-only | not-applicable
  github_copilot_lane: clean | findings | pending | inconclusive | not-applicable
  base_assurance: parent-readiness-tests-and-required-ci
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
