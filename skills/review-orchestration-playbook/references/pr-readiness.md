# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, merge-readiness reporting, or merge.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated only when the parent request explicitly asks for a PR, full workflow, merge-ready, or stop-before-merge. A bare named-review request, including `triple review`, does not authorize creating a branch, pushing commits, opening a PR, or updating an existing PR's branch or metadata.
- A bare triple-review request authorizes only the scoped GitHub Codex request comment on an already-existing supported PR. If no such PR exists, keep the operation report-only, run the two local lanes, and report `requested: triple`, `effective: double`, with `no existing PR` as the reason. Do not create or mutate a PR to manufacture the third lane.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- PR creation/update authorization does not authorize merge. Merge only when the parent request explicitly includes it.

## Effective Review Shape

- Use the canonical definitions in the parent skill. A PR/full-workflow request with no named shape defaults to single.
- PR readiness adds CI, conversation, base/head, exact-secret admission, and merge-policy gates to the effective review shape. It never adds a hidden local Codex review; the low-level stateful helper run that supplies admission evidence is explicit, is never counted as a named local lane, and cannot replace one.
- When triple is requested but GitHub Codex is unavailable, continue with effective double and report the downgrade reason.
- A missing or failed local lane remains blocked/inconclusive; GitHub fallback cannot turn it into a clean double.

## Gate Sequence

1. Establish or reuse the PR only when the parent request separately authorizes PR mutation. For a bare triple-review request, reuse an already-existing supported PR only; otherwise take the no-PR effective-double path. Read repository metadata, review threads, required checks, rulesets, base branch, and current head with the bounded probes in [github-pr-probes.md](github-pr-probes.md).
2. Record the PR head and freeze the local range as `<merge_base>..<head_sha>`.
3. Run the requested local lanes under [review-lane-contracts.md](review-lane-contracts.md). Each lane gets its own clean Git worktree, clear reviewer context, and read-only access. Never generate or inject a full diff for the reviewer.
4. Obtain one low-level stateful helper state for the exact current-head range under the separately authorized reviewer and egress policy. A secret violation or inconclusive count does not suppress this trusted reviewer: it receives the original tracked supplied diff, prompt, and permitted context without redaction or delay. Harvest `stateful final --state-dir <state_dir>` first, then run `stateful admission --state-dir <state_dir>` on that same state. `stateful final` remains independent and may succeed when admission blocks or is inconclusive. This supplied-diff/no-Git helper result is not a named lane.
5. Count each exact raw value globally across tracked raw path bytes, regular blobs, and symlink targets, and require `head_count <= base_count`; for this count, do not derive Base64 or other encodings. Admission exit `0` requires a valid schema-v5 runner-sealed preflight receipt plus `secret_delta.status=clean` and is the only result that permits PR/master/merge-ready; exit `1` is a violation, exit `3` is pending, and exit `75` is inconclusive. Schema-v4 helper state remains usable for `status`, `wait`, `final`, and cleanup but lacks the receipt and therefore fails admission closed. For positive-delta candidates, violation evidence lists only added head locations: raw path plus one-based line for text additions, `line: null` for new-path or binary fallbacks, and line `1` for symlink targets. Unchanged occurrences are omitted; incomplete mapping is inconclusive.
6. If triple was requested, classify GitHub Codex availability:
   - Supported: a GitHub Cloud PR where the Codex review integration is available for the active identity.
   - Unavailable: no PR, missing integration, unsupported host/service, host `sqbu-github.cisco.com`, or any operating identity in `{hoteng, hoteng_cisco}`, when the condition is directly known or proved by authenticated provider evidence.
   - Inconclusive: missing response, timeout, generic request/HTTP failure, or any state that proves neither unavailability nor a trustworthy result.
   - On unavailable, persist `requested: triple`, `effective: double`, and a concrete reason, then continue the double-review readiness gate.
7. For a supported third lane, post the exact `@codex review` comment after `head_sha` becomes current. Record the comment URL/time. The comment write is not completion or proof of service start. An authenticated provider rejection may prove no-start integration/service unavailability; acknowledgement or run/review activity proves start. Accept only a terminal result bound to the same head.
8. Read required CI/check state and unresolved PR conversations. Distinguish required checks from informational jobs and stale runs from current-head runs.
9. Apply actionable findings in the implementation workspace, rerun affected tests, publish the new head, and invalidate every earlier named-lane artifact, low-level helper final, and admission result whose range/head changed.
10. Repeat the affected local lanes, low-level current-head helper final/admission pair, supported GitHub Codex request, CI checks, and conversation scan until the effective shape and all delivery gates are clean or a crisp blocker remains.
11. Recheck base/head, mergeability, same-state current-head admission exit `0`, approval/ruleset requirements, and the repository's merge model immediately before reporting merge-ready or merging.

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
- the low-level helper state/range, reviewer-final status, schema-v5 preflight-receipt binding, and secret-admission exit/status;
- GitHub Codex current-head evidence or the explicit triple-to-double reason;
- required CI/check state and unresolved-conversation count;
- mergeability/ruleset state and merge authorization;
- tests actually run, workspaces cleaned/retained, and any blocker.

Do not call the PR merge-ready when a required lane in the effective shape, the same-state current-head exact-secret admission, a required check, an unresolved actionable conversation, or a branch/ruleset gate remains non-clean.
