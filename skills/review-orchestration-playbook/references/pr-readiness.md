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
semantics instead of updating the feature branch unnecessarily. When no merge
queue owns freshness and strict freshness blocks the authorized PR workflow,
merge the current base branch into the feature branch with a signed merge
commit. Do not rebase, force-push, or rewrite the branch into linear history
merely to satisfy freshness.

That merge creates a new head. Re-read the PR, require one unique merge base,
freeze the resulting `merge_base..new_head`, and rerun the complete pre-merge
verification for that head: local validation and tests, every required local
review lane, the GitHub Codex lane, CI and status checks, all conversations,
lifecycle/base/head and merge-policy checks, and the final stable reread. No
clean evidence bound to the old head is reusable.

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

| Change | Invalidation |
| --- | --- |
| Head changes | All local reviews, head-bound provider evidence, tests tied to the old head, CI, conversations affected by the diff, and final reread |
| Target base tip changes while head and unique merge base stay the same | Base-tip/freshness-sensitive tests or CI, merge status, mergeability, queue state, and final reread; the frozen local range itself is unchanged |
| Unique merge base changes while head stays the same | Local whole-PR reviews, merge-base-sensitive tests/CI, merge status, and final reread |
| Conversation or thread state changes | Conversation gate and provider finding projection when the changed thread is provider-owned |
| Required check reruns | CI/status gate and final reread |

Because the GitHub provider contract proves the head rather than the base, a
merge-base-only change does not by itself invalidate a trustworthy current-head
terminal clean or reaction fallback. Revalidate unresolved provider findings
and current head, pass the `range_origin` provenance gate above, rerun the local
whole-PR lanes for the authorized new merge base, and
reconcile any base-sensitive merge/status check. Do not post another
`@codex review` solely because the base changed unless a future provider
contract explicitly binds base input.

This reuse is an explicit acceptance decision. Record it as
`github_codex_scope: latest-head-only`; do not describe the retained artifact
as whole-PR or new-base review evidence. Until the new-base local review, CI,
conversation, merge-status, and final-reread gates all pass, the PR remains
blocked or pending even though the GitHub lane itself remains passed.

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
- `baseRefOid`, `headRefOid`, intended head ownership/branch, and unique local
  merge base;
- the parent-owned immutable `range_origin` lineage, its complete predecessor
  chain, and its current active-record binding for every local range counted as
  PR-wide evidence;
- local review artifacts and validations bound to the resulting range;
- the complete GitHub Codex decision inputs and unresolved provider findings;
- required check rollup, related merge/status evidence, mergeability, and
  merge-queue state;
- every review and conversation thread relevant to readiness; and
- repository rules, approvals, and merge method.

Require all selected evidence to remain on the same head and the appropriate
base-sensitive evidence to remain on the same merge base. If any page is
incomplete, state changes during the reread, or evidence belongs to a stale
scope, return to the fix/recovery loop.

## Merge-Ready Report

Report the decisive state rather than a long transcript:

```yaml
pr_readiness:
  status: ready | blocked | pending
  repository: owner/name
  pull_request: 123
  url: https://github.com/owner/name/pull/123
  base_ref_oid: 40-lowercase-hex
  head_ref_oid: 40-lowercase-hex
  merge_base: 40-lowercase-hex
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
the repository's intended merge method and then verify the merged lifecycle
and resulting default-branch state.
