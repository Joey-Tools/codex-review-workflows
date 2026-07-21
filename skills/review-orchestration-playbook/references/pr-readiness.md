# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, merge-readiness reporting, or merge.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated only when the parent request explicitly asks for a PR, full workflow, merge-ready, or stop-before-merge. A bare named-review request, including `triple review`, does not authorize creating a branch, pushing commits, opening a PR, or updating an existing PR's branch or metadata.
- A bare named-review request also does not authorize an anchor commit. If the implementation checkout is dirty and no committed review range exists, report review preparation as `blocked-authorization` only when the intended review scope includes that dirty or untracked state; do not review the dirty state or mutate it.
- A standalone named review locates an already-existing PR read-only only when the caller names that PR, the local range still needs PR derivation, or triple needs a discoverable PR for its third lane. An explicit-range-only standalone single or double is already fully scoped locally: do not require PR discovery, a no-PR proof, or head comparison when no PR was selected. This lookup does not authorize other PR-state consumption or mutation; only bare triple additionally authorizes the scoped GitHub Codex request comment described below.
- A bare triple-review request authorizes only the scoped GitHub Codex request comment on an already-existing eligible PR whose host is exact `github.com`. If PR discovery proves no PR exists, keep the operation report-only and report `requested: triple`, `effective: double`, with `no existing PR` as the reason. Run the two local lanes only after an explicit committed range or explicitly named target/base supplies their frozen scope. An existing PR on an unsupported host or identity remains on the existing-PR path and still follows the head-alignment preflight before its concrete host/identity/integration reason reduces the shape to effective double. Do not create or mutate a PR to manufacture the third lane.
- For every selected existing PR, compare its current `headRefOid` with the intended frozen `head_sha` before local lanes or PR-readiness checks, regardless of whether the requested shape is single, double, triple, or an unavailable third lane has reduced triple to effective double. Explicit-range-only standalone single/double has no selected PR and needs no comparison. If PR mutation was not separately authorized, leave a mismatched PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also report `effective: triple-inconclusive` with GitHub lane status `blocked-authorization`. For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue. This is a head-alignment blocker, not GitHub Codex unavailability.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- PR creation/update authorization does not authorize merge. Merge only when the parent request explicitly includes it.

## Deterministic Range And PR Selection

Resolve review scope before starting any lane. Apply these inputs in order; a later source must never replace an earlier one:

1. An explicit frozen `base_sha..head_sha` is the authoritative local-lane range. Preserve both immutable commit IDs before consulting PR state. For a standalone single or double with no explicitly selected PR or PR-readiness/full-workflow scope, stop selection here and run only the local lane(s); no PR probe or no-PR proof is required. PR-specific work may still require an explicitly selected PR, but PR metadata must not rewrite this range.
2. Otherwise, use an explicitly named PR and derive `<merge_base>..<pr_head_sha>` from that PR's explicit base and head. Freeze the resulting commit IDs independently from later PR observations.
3. Otherwise, when a PR is needed to derive the local range or to perform PR-specific/triple work, perform one authenticated, complete lookup for open PRs associated with the exact current head repository/branch. Exactly one candidate selects that PR. More than one candidate is ambiguous: report `blocked-input` (the required explicit PR/range/target selector is absent), require an explicit PR or frozen range, and start no lane whose scope still depends on that selection. Do not choose by recency, base branch, PR number, draft state, or matching title.
4. Zero candidates is the no-PR path only when the authenticated lookup completed successfully and returned an empty result. Record that evidence. A failed, partial, unauthenticated, or ambiguous lookup does not prove no PR.

The no-PR path does not supply a review range. Start local lanes only when the parent supplied an explicit committed range or explicitly named the target/base ref from which the parent can resolve and freeze `<merge_base>..HEAD`. Never infer that target/base from the default branch, upstream configuration, workspace manifest, branch naming, or repository convention. If the checkout is clean but neither input exists, report `blocked-input` for the missing range/base input and ask for the exact range or target/base; this is not `blocked-authorization`.

An explicit range by itself does not prove PR presence or absence. For requested triple, if no PR was named and detached HEAD or unknown head-repository ownership prevents exact branch association, run the two fully scoped local lanes but report the GitHub lane `blocked-input` and the overall shape `requested: triple`, `effective: triple-inconclusive`; require an explicit PR selector. Do not manufacture an effective-double fallback from an unproved no-PR state.

Reserve `blocked-authorization` for a different condition: the intended review includes dirty or untracked checkout state, no committed range represents it, and creating a branch or review-anchor commit would be required but was not authorized. A supplied committed range remains reviewable in detached clean lane worktrees; unrelated dirty checkout state is excluded rather than silently added to that range.

## Effective Review Shape

- Use the canonical definitions in the parent skill. A PR/full-workflow request with no named shape defaults to single.
- PR readiness adds CI, conversation, base/head, and merge-policy gates to the effective review shape. It never adds a hidden local Codex review.
- When triple is requested but GitHub Codex is unavailable, continue with effective double and report the downgrade reason.
- A missing or failed local lane remains blocked/inconclusive; GitHub fallback cannot turn it into a clean double.

## Gate Sequence

1. Resolve the range/PR inputs in the exact priority order above. Explicit-range-only standalone single/double stops after local scope resolution and performs no PR probe. A standalone triple or PR-specific request may perform the narrow read-only PR lookup, but must not create or mutate a PR. If no frozen range exists and current-branch discovery returns multiple candidates, report `blocked-input` and stop before every lane. Only authenticated actual PR absence takes the no-PR path; for requested triple that path is effective double. An undiscoverable detached/unknown branch is instead the triple `blocked-input` / `triple-inconclusive` case above. Actual absence requires a successful authenticated discovery result containing zero candidates, and local lanes still wait for an explicit committed range or explicitly named target/base. At this stage do not read or consume review threads, required checks, rulesets, mergeability, or other readiness state; do not require PR-only fields when no PR was selected.
2. Freeze the exact committed range. Preserve any parent-provided frozen `base_sha..head_sha` as the intended range. For a PR/full-workflow request or standalone named review associated with an existing PR, derive `<merge_base>..<pr_head_sha>` only when there is no explicit range and only from the selected PR's explicit base/head. On a proven no-PR path, derive `<merge_base>..HEAD` only from the explicitly named target/base. If the required clean-checkout input is absent, report `blocked-input`; if representing intended dirty state instead requires an unauthorized anchor mutation, report `blocked-authorization`.
3. For a selected existing PR, query and record the current `headRefOid` separately as `pr_head_oid`; never overwrite the intended `head_sha` with it. Compare `pr_head_oid` with the intended `head_sha` before running local lanes or reading PR CI, conversation, ruleset, mergeability, or other readiness state. This applies to a selected PR in single, double, triple, and triple already reduced to effective double by directly known unavailability. On mismatch, publish/freeze the intended head only when PR mutation is separately authorized; otherwise leave the PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also apply the triple-inconclusive rule above. No comparison exists for explicit-range-only standalone single/double with no selected PR, or for the authenticated no-PR path.
4. Run the requested local lanes under [review-lane-contracts.md](review-lane-contracts.md) over the preserved intended range. Each lane gets its own clean Git worktree, clear reviewer context, and read-only access. Never generate or inject a full diff for the reviewer.
5. If triple was requested, make only the pre-request classifications that available evidence can prove:
   - Unavailable before request: proven no PR; any host other than exact `github.com`, including `sqbu-github.cisco.com` and every enterprise host; any operating identity in `{hoteng, hoteng_cisco}`; or a missing integration/service proved by authenticated evidence from the exact accepted provider identity below. Persist `requested: triple`, `effective: double`, and a concrete reason, then continue the double-review readiness gate.
   - Eligible candidate: an existing, head-aligned PR whose host is exact `github.com`, whose operating identity is not in the unsupported set, and which has no other directly known disqualifier. Unknown pre-request integration/service status does not block the request or become an availability claim.
6. For an eligible candidate, post the exact `@codex review` comment after the intended `head_sha` is the unchanged current `pr_head_oid`. Re-read the created request comment and record its API ID, URL, and server `created_at`. Then classify only artifacts whose own server timestamp is strictly later than that exact request: an authenticated provider rejection may prove no-start integration/service unavailability and reduce the shape to effective double only when it comes from the exact accepted provider identity below; acknowledgement or run/review activity proves start only when it comes from that provider or its exact accepted app/check identity; missing response, timeout, comment-write/generic HTTP failure, unknown author/app identity, or evidence proving neither state is `effective: triple-inconclusive`. The comment write alone is neither completion nor proof of service start. Accept triple only from a trustworthy terminal result bound to the same head and causally newer than this request.
7. Read required CI/check state and unresolved PR conversations. Distinguish required checks from informational jobs and stale runs from current-head runs.
8. Apply actionable findings in the implementation workspace, rerun affected tests, publish the new head, and invalidate every earlier review artifact whose range/head changed.
9. Repeat the affected local lanes, the supported GitHub Codex request, CI checks, and conversation scan until the effective shape and all delivery gates are clean or a crisp blocker remains.
10. Recheck base/head, mergeability, approval/ruleset requirements, and the repository's merge model immediately before reporting merge-ready or merging.

## GitHub Codex Evidence

A qualifying third-lane result must prove all of the following:

- The PR host is exact `github.com`, the operating identity is not `hoteng` or `hoteng_cisco`, and the integration was available. Every other host, including `sqbu-github.cisco.com` and all enterprise hosts, is unsupported.
- The exact `@codex review` request occurred after the accepted `head_sha` became current, and its API ID, URL, and server `created_at` were recorded.
- The terminal review/comment author has exact REST `login: chatgpt-codex-connector[bot]` and exact REST `type: Bot`, the artifact is bound to that same current head, and its `submitted_at` or `created_at` is strictly later than this request's server `created_at`. A review artifact's `commit_id` must equal `headRefOid`. If app/check evidence is used, its app slug must be exact `chatgpt-codex-connector`, its `head_sha` must equal `headRefOid`, its `status` must be `completed`, its `conclusion` must be `success`, and its non-null `completed_at` must be strictly later than the current request.
- Findings were resolved or explicitly classified; a finding is not an availability failure.

An unknown, missing, differently cased, or lookalike author or app/check slug cannot prove service start, a terminal result, or an authenticated no-start rejection. Such evidence is `requested: triple`, `effective: triple-inconclusive`; do not use it for effective-double fallback or completed-triple evidence.

Any push invalidates the old evidence. Request a new current-head review rather than reusing a stale comment.

Effective-double fallback requires directly known no-PR/host/identity evidence or an authenticated result from exact `chatgpt-codex-connector[bot]` with REST `type: Bot` that proves the integration/service unavailable before any run starts. Posting the request comment is not service start. Missing response, timeout, comment-write or generic HTTP failure, unknown provider/app identity, or evidence that proves neither unavailable nor started is `requested: triple`, `effective: triple-inconclusive`. Once acknowledgement or run/review activity from the exact accepted provider identity proves service start, malformed, stale, ambiguous, or transiently incomplete evidence is also triple-inconclusive and must not be converted to effective double or completed triple.

## Fix Loop

- Actionable local, GitHub, CI, or conversation findings are fixed in the parent implementation workspace, never inside a read-only reviewer workspace.
- Append fixes on the review branch, freeze a new range, and rerun every invalidated lane.
- Keep a bounded audit record: previous head, new head, finding addressed, validation rerun, and replacement review artifact.
- Stop after bounded retries when authentication, permissions, required infrastructure, or external state prevents progress. Report the exact blocker and retained recovery state.

## Merge-Ready Report

Report:

- repository/PR URL, base, head branch, and current head SHA;
- requested and effective review shape;
- each local lane's workspace/range, runtime/model, terminal status, and findings;
- GitHub Codex current-head evidence or the explicit triple-to-double reason;
- required CI/check state and unresolved-conversation count;
- mergeability/ruleset state and merge authorization;
- tests actually run, workspaces cleaned/retained, and any blocker.

Do not call the PR merge-ready when a required lane in the effective shape, required check, unresolved actionable conversation, or branch/ruleset gate remains non-clean.
