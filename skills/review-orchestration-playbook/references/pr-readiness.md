# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, merge-readiness reporting, or merge.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated only when the parent request explicitly asks for a PR, full workflow, merge-ready, or stop-before-merge. A bare named-review request, including `triple review`, does not authorize creating a branch, pushing commits, opening a PR, or updating an existing PR's branch or metadata.
- A bare named-review request also does not authorize an anchor commit. If its implementation checkout is dirty and no committed review range exists, report review preparation as `blocked-authorization`; do not review the dirty state or mutate it.
- A bare triple-review request authorizes only the scoped GitHub Codex request comment on an already-existing supported PR. If no such PR exists, keep the operation report-only, run the two local lanes, and report `requested: triple`, `effective: double`, with `no existing PR` as the reason. Do not create or mutate a PR to manufacture the third lane.
- If that existing supported PR's current `headRefOid` does not equal the intended frozen `head_sha` and PR mutation was not separately authorized, leave it unchanged and report `requested: triple`, `effective: triple-inconclusive`, with GitHub lane status `blocked-authorization`. This is a head-alignment blocker, not GitHub Codex unavailability.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- PR creation/update authorization does not authorize merge. Merge only when the parent request explicitly includes it.

## Effective Review Shape

- Use the canonical definitions in the parent skill. A PR/full-workflow request with no named shape defaults to single.
- PR readiness adds CI, conversation, base/head, and merge-policy gates to the effective review shape. It never adds a hidden local Codex review.
- When triple is requested but GitHub Codex is unavailable, continue with effective double and report the downgrade reason.
- A missing or failed local lane remains blocked/inconclusive; GitHub fallback cannot turn it into a clean double.

## Gate Sequence

1. Establish or reuse the PR only when the parent request separately authorizes PR mutation. For a bare triple-review request, reuse an already-existing supported PR only; otherwise take the no-PR effective-double path. Read repository metadata, review threads, required checks, rulesets, base branch, and current head with the bounded probes in [github-pr-probes.md](github-pr-probes.md).
2. Preserve any parent-provided frozen `base_sha..head_sha` as the intended range before reading or deriving PR head state. Record the PR's current `headRefOid` separately as `pr_head_oid`; never overwrite the intended `head_sha` with it. Only when a PR/full-workflow request has no preexisting frozen range may the parent derive the intended `<merge_base>..<head_sha>` from the current PR head.
3. Compare `pr_head_oid` with the intended `head_sha` before running local lanes or posting `@codex review`. On mismatch, publish/freeze the intended head only when PR mutation is separately authorized; otherwise apply the `blocked-authorization` triple-inconclusive rule above without changing the PR.
4. Run the requested local lanes under [review-lane-contracts.md](review-lane-contracts.md) over the preserved intended range. Each lane gets its own clean Git worktree, clear reviewer context, and read-only access. Never generate or inject a full diff for the reviewer.
5. If triple was requested, classify GitHub Codex availability:
   - Supported: a GitHub Cloud PR where the Codex review integration is available for the active identity.
   - Unavailable: no PR, missing integration, unsupported host/service, host `sqbu-github.cisco.com`, or any operating identity in `{hoteng, hoteng_cisco}`, when the condition is directly known or proved by authenticated provider evidence.
   - Inconclusive: missing response, timeout, generic request/HTTP failure, or any state that proves neither unavailability nor a trustworthy result.
   - On unavailable, persist `requested: triple`, `effective: double`, and a concrete reason, then continue the double-review readiness gate.
6. For a supported third lane, post the exact `@codex review` comment after the intended `head_sha` becomes the unchanged current `pr_head_oid`. Record the comment URL/time. The comment write is not completion or proof of service start. An authenticated provider rejection may prove no-start integration/service unavailability; acknowledgement or run/review activity proves start. Accept only a terminal result bound to the same head.
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
