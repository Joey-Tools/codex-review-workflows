# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, merge-readiness reporting, or merge.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated only when the parent request explicitly asks for a PR, full workflow, merge-ready, or stop-before-merge. A bare named-review request, including `triple review`, does not authorize creating a branch, pushing commits, opening a PR, or updating an existing PR's branch or metadata.
- A bare named-review request also does not authorize an anchor commit. If its implementation checkout is dirty and no committed review range exists, report review preparation as `blocked-authorization`; do not review the dirty state or mutate it.
- A bare triple-review request authorizes only the scoped GitHub Codex request comment on an already-existing eligible GitHub Cloud PR. If no PR exists at all, keep the operation report-only, run the two local lanes, and report `requested: triple`, `effective: double`, with `no existing PR` as the reason. An existing but unsupported PR still follows the head-alignment preflight before its concrete host/identity/integration reason reduces the shape to effective double. Do not create or mutate a PR to manufacture the third lane.
- For every existing PR, compare its current `headRefOid` with the intended frozen `head_sha` before local lanes or PR-readiness checks, regardless of whether the requested shape is single, double, triple, or an unavailable third lane has reduced triple to effective double. If PR mutation was not separately authorized, leave a mismatched PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also report `effective: triple-inconclusive` with GitHub lane status `blocked-authorization`. This is a head-alignment blocker, not GitHub Codex unavailability.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- PR creation/update authorization does not authorize merge. Merge only when the parent request explicitly includes it.

## Effective Review Shape

- Use the canonical definitions in the parent skill. A PR/full-workflow request with no named shape defaults to single.
- PR readiness adds CI, conversation, base/head, and merge-policy gates to the effective review shape. It never adds a hidden local Codex review.
- When triple is requested but GitHub Codex is unavailable, continue with effective double and report the downgrade reason.
- A missing or failed local lane remains blocked/inconclusive; GitHub fallback cannot turn it into a clean double.

## Gate Sequence

1. Establish or locate the PR only when the parent request permits that operation. For a bare triple-review request, locate any already-existing PR without creating or mutating one. Only actual PR absence takes the no-PR effective-double path; an existing PR on an unsupported host or identity remains on the existing-PR path even though its third lane is unavailable. At this stage record only the stable repository/PR identity needed to address later probes. Do not yet read or consume review threads, required checks, rulesets, mergeability, or other readiness state; do not require PR-only fields on the no-PR path.
2. Preserve any parent-provided frozen `base_sha..head_sha` as the intended range before deriving it from PR state. Only when a PR/full-workflow request has no preexisting frozen range may the parent query the minimum base/head commit identity needed to derive the intended `<merge_base>..<head_sha>` from the current PR head. Keep that derived intended range independent from later current-head observations.
3. For every existing PR, query and record the current `headRefOid` separately as `pr_head_oid`; never overwrite the intended `head_sha` with it. Compare `pr_head_oid` with the intended `head_sha` before running local lanes or reading PR CI, conversation, ruleset, mergeability, or other readiness state. This applies to single, double, triple, and triple already reduced to effective double by directly known unavailability. On mismatch, publish/freeze the intended head only when PR mutation is separately authorized; otherwise leave the PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also apply the triple-inconclusive rule above. Skip this comparison only on the no-PR path.
4. Run the requested local lanes under [review-lane-contracts.md](review-lane-contracts.md) over the preserved intended range. Each lane gets its own clean Git worktree, clear reviewer context, and read-only access. Never generate or inject a full diff for the reviewer.
5. If triple was requested, make only the pre-request classifications that available evidence can prove:
   - Unavailable before request: no PR, an unsupported host/service, host `sqbu-github.cisco.com`, any operating identity in `{hoteng, hoteng_cisco}`, or a missing integration proved by authenticated provider evidence. Persist `requested: triple`, `effective: double`, and a concrete reason, then continue the double-review readiness gate.
   - Eligible candidate: an existing, head-aligned GitHub Cloud PR with no directly known disqualifier. Unknown pre-request integration/service status does not block the request or become an availability claim.
6. For an eligible candidate, post the exact `@codex review` comment after the intended `head_sha` is the unchanged current `pr_head_oid`. Record the comment URL/time, then classify the response: an authenticated provider rejection may prove no-start integration/service unavailability and reduce the shape to effective double; acknowledgement or run/review activity proves start; missing response, timeout, comment-write/generic HTTP failure, or evidence proving neither state is `effective: triple-inconclusive`. The comment write alone is neither completion nor proof of service start. Accept triple only from a trustworthy terminal result bound to the same head.
7. Read required CI/check state and unresolved PR conversations. Distinguish required checks from informational jobs and stale runs from current-head runs.
8. Apply actionable findings in the implementation workspace, rerun affected tests, publish the new head, and invalidate every earlier review artifact whose range/head changed.
9. Repeat the affected local lanes, the supported GitHub Codex request, CI checks, and conversation scan until the effective shape and all delivery gates are clean or a crisp blocker remains.
10. Recheck base/head, mergeability, approval/ruleset requirements, and the repository's merge model immediately before reporting merge-ready or merging.

## GitHub Codex Evidence

A qualifying third-lane result must prove all of the following:

- The PR is on a supported GitHub Cloud surface and the integration was available.
- The exact `@codex review` request occurred after the accepted `head_sha` became current.
- The terminal review/comment belongs to GitHub Codex and is bound to that same current head.
- Findings were resolved or explicitly classified; a finding is not an availability failure.

Any push invalidates the old evidence. Request a new current-head review rather than reusing a stale comment.

Effective-double fallback requires directly known no-PR/host/identity evidence or an authenticated provider result that proves the integration/service unavailable before any run starts. Posting the request comment is not service start. Missing response, timeout, comment-write or generic HTTP failure, or evidence that proves neither unavailable nor started is `requested: triple`, `effective: triple-inconclusive`. Once acknowledgement or run/review activity proves service start, malformed, stale, ambiguous, or transiently incomplete evidence is also triple-inconclusive and must not be converted to effective double or completed triple.

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
