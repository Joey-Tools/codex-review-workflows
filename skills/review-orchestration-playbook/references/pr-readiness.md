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

GitHub names the strict freshness option **Require branches to be up to date
before merging**. It is distinct from **Require linear history**. A readiness
probe may identify the first through REST `required_status_checks.strict`,
GraphQL branch protection `requiresStrictStatusChecks`, or ruleset input
`strictRequiredStatusChecksPolicy`; GraphQL `requiresLinearHistory` describes
the separate linear-history rule. Never infer a rebase requirement from the
freshness setting.

When a merge queue owns freshness, follow the queue's merge-group and check
semantics instead of updating the feature branch unnecessarily. Otherwise, if
strict freshness blocks the authorized PR workflow, merge the current base
branch into the feature branch with a signed merge commit. Do not rebase,
force-push, or rewrite the branch into linear history merely to satisfy
freshness.

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
and current head, rerun the local whole-PR lanes for the new merge base, and
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
2. Fix substantive failures on the intended branch; do not rerun them as if
   they were infrastructure.
3. Commit and push only when authorized.
4. Re-read lifecycle, base/head, and merge base.
5. Rerun every invalidated local lane and validation.
6. Reacquire GitHub Codex, CI, and conversation evidence for the new state.
7. Repeat until every gate is simultaneously true.

Retry missing, stale, cancelled, skipped, inconclusive, infrastructure, or
aggregation-only GitHub states through the recovery contract in
[github-pr-probes.md](github-pr-probes.md). An explicit provider finding,
failed test, or policy failure is never an automatic reconcile target.

## Final Reread

Immediately before reporting merge-ready or merging, reread all of the
following without reusing stale summaries:

- exact PR lifecycle and draft state;
- `baseRefOid`, `headRefOid`, intended head ownership/branch, and unique local
  merge base;
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
