# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, merge-readiness reporting, or merge.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated only when the parent request explicitly asks for a PR, full workflow, merge-ready, or stop-before-merge. A bare named-review request, including `triple review`, does not authorize creating a branch, pushing commits, opening a PR, or updating an existing PR's branch or metadata.
- A bare named-review request also does not authorize an anchor commit. If the implementation checkout is dirty and no committed review range exists, report review preparation as `blocked-authorization` only when the intended review scope includes that dirty or untracked state; do not review the dirty state or mutate it.
- A standalone named review locates an already-existing PR read-only only when the caller names that PR, the local range still needs PR derivation, or triple needs a discoverable PR for its third lane. An explicit-range-only standalone single or double is already fully scoped locally: do not require PR discovery, a no-PR proof, or head comparison when no PR was selected. This lookup does not authorize other PR-state consumption or mutation; only bare triple additionally authorizes the scoped GitHub Codex request comment described below.
- A bare triple-review request authorizes only the scoped GitHub Codex request comment on an already-existing eligible PR whose host is exact `github.com`. If PR discovery proves no PR exists, keep the operation report-only and report `requested: triple`, `effective: double`, with `no existing PR` as the reason. Run the two local lanes only after an explicit committed range or explicitly named target/base supplies their frozen scope. An existing PR on an unsupported host or identity remains on the existing-PR path and still follows the head-alignment preflight before its concrete host/identity reason reduces the shape to effective double. Integration/service state cannot supply that reason at the fixed baseline. Do not create or mutate a PR to manufacture the third lane.
- For every selected existing PR, independently read its lifecycle tuple `state` / `merged` / `merged_at` plus current `baseRefName`, `baseRefOid`, and `headRefOid`, then compute and validate one trustworthy local merge base before local lanes or PR-readiness checks. Only exact `state == "open"`, `merged == false`, and `merged_at == null` is eligible. Missing/contradictory lifecycle evidence is `blocked-input` (`pr-lifecycle-unverified`) and triple-inconclusive; closed-unmerged is `blocked-input` (`selected-pr-closed`) and may reduce only an otherwise fully scoped, never-started third lane to effective double; merged is terminal `already-merged` / `selected-pr-merged`. An observed non-open lifecycle at any mandated snapshot after request/service start invalidates evidence and stays triple-inconclusive. These point-in-time snapshots do not prove that no intermediate close-and-reopen occurred between them. A selected PR's explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`); preserve the caller's range, do not silently rewrite it, and never describe its local review results as whole-PR coverage. Explicit-range-only standalone single/double has no selected PR and is unaffected.
- For every selected existing PR, also compare its current `headRefOid` with the intended frozen `head_sha` before local lanes or PR-readiness checks, regardless of whether the requested shape is single, double, triple, or an unavailable third lane has reduced triple to effective double. Explicit-range-only standalone single/double has no selected PR and needs no comparison. If PR mutation was not separately authorized, leave a mismatched PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also report `effective: triple-inconclusive` with GitHub lane status `blocked-authorization`. For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue. This is a head-alignment blocker, not GitHub Codex unavailability.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- PR creation/update authorization does not authorize merge. Merge only when the parent request explicitly includes it.

## Deterministic Range And PR Selection

Resolve the local-lane range and PR selection independently before starting any lane. A later source must never replace an already frozen local range:

1. An explicit frozen `base_sha..head_sha` is the authoritative local-lane range. Preserve both immutable commit IDs before consulting PR state. For a standalone single or double with no explicitly selected PR or PR-readiness/full-workflow scope, stop selection here and run only the local lane(s); no PR probe or no-PR proof is required. A frozen range scopes only the local lanes; it never selects a PR. PR-specific work and the third lane still require an explicit or unambiguous PR selector, and the selected-PR scope preflight below must prove exact whole-PR range equality before that range can count for PR readiness. PR metadata must not rewrite a mismatched caller range.
2. An explicitly named PR selects that PR. Independently read its authenticated `baseRefName`, `baseRefOid`, and `headRefOid`. With lazy fetching and credential prompts disabled, require both endpoint commit objects to be locally complete and require `git merge-base --all pr_base_oid pr_head_oid` to return exactly one full commit ID, recorded as `pr_merge_base`. Missing/ambiguous metadata, missing objects, or zero/multiple merge-base results are `blocked-input` (`scope-unverified`). Only when no explicit range exists, freeze `pr_merge_base..pr_head_oid`; never substitute the PR-derived range for a mismatched explicit range.
3. When a PR is needed for range derivation or PR-specific/triple work and none was explicitly named, perform one authenticated, complete lookup for open PRs associated with the exact current head repository/branch, even when the local range is already frozen. Exactly one candidate selects that PR. More than one candidate is ambiguous: report the GitHub/PR-specific lane `blocked-input` because the required explicit PR selector is absent, and require the caller to name the PR. A frozen range does not resolve this ambiguity. Local lanes may still run when that range already scopes them; if no local range exists, start no lane whose scope still depends on PR selection. Do not choose by recency, base branch, PR number, draft state, or matching title.
4. Zero candidates is the no-PR path only when the authenticated lookup completed successfully and returned an empty result. Record that evidence. A failed, partial, unauthenticated, or ambiguous lookup does not prove no PR.

For every selected PR, the parent-owned audit must persist immutable `range_origin.kind`, `range_origin.base_sha`, and `range_origin.head_sha` at the first range freeze. Use `caller-supplied` only when the caller supplied those exact endpoints; use `pr-derived` only when the parent derived them from authenticated PR metadata. Never infer origin from a later parent-provided range, and never overwrite original caller endpoints. Missing or ambiguous origin is `blocked-input` (`range-origin-unverified`).

The no-PR path does not supply a review range. Start local lanes only when the parent supplied an explicit committed range or explicitly named the target/base ref from which the parent can resolve and freeze `<merge_base>..HEAD`. Never infer that target/base from the default branch, upstream configuration, workspace manifest, branch naming, or repository convention. If the checkout is clean but neither input exists, report `blocked-input` for the missing range/base input and ask for the exact range or target/base; this is not `blocked-authorization`.

An explicit range by itself does not prove PR presence or absence. For requested triple, if no PR was named and detached HEAD or unknown head-repository ownership prevents exact branch association, run the two fully scoped local lanes but report the GitHub lane `blocked-input` and the overall shape `requested: triple`, `effective: triple-inconclusive`; require an explicit PR selector. Do not manufacture an effective-double fallback from an unproved no-PR state.

After a PR is selected, apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json) before the generic same-head/different-base `scope-mismatch` branch. Its version 2 preserves version 1 request-sidecar event semantics and adds the independent terminal-artifact scope receipt plane. If the parent-owned audit records a request on the unchanged `pr_head_oid`, narrowly revalidate that request and require exactly one valid `parent-recorded-request-scope-v1` sidecar bound one-to-one to it. Only a sidecar classification of `valid_same_head_different_merge_base` proves the dedicated event. That event always leaves the GitHub lane `triple-inconclusive` and forbids another same-head request, but local behavior depends on the persisted origin and current pass: missing origin, an inherited stale range, or a parent rewrite of a caller range stops before local lanes; an exact current range newly supplied by the caller recovers local lanes for a caller-origin range, and normal exact-current rederivation recovers them only for a PR-derived range. A recovery pass proceeds to the local lanes while overall readiness remains `blocked-input` (`base-changed-same-head`). A missing, malformed, duplicate, extra, or unmatched sidecar does not prove the event; it makes request policy unknown, forbids another POST while history is unproved, and leaves local/terminal gates on their independently proved scopes. A `valid_old_head` receipt is audit-only and returns the new head to normal producer-policy evaluation. Do not fall through from a proved event to `scope-mismatch`, post a replacement request, or manufacture an empty or anchor commit. Otherwise require exact equality between any explicit frozen range and the selected PR's independently derived `pr_merge_base..pr_head_oid`. A same-head range whose `base_sha != pr_merge_base` may omit earlier PR commits. Stop the PR-specific gate as `blocked-input` (`scope-mismatch`): do not start or count PR-specific local lanes, consume readiness state, or post `@codex review` from that range. If an explicitly requested range-only review is still useful, report its findings only as partial range evidence; it cannot satisfy whole-PR readiness or triple completion. Do not rewrite the caller's range. Explicit-range-only standalone single/double with no selected PR remains fully scoped and does not perform this preflight.

Reserve `blocked-authorization` for a different condition: the intended review includes dirty or untracked checkout state, no committed range represents it, and creating a branch or review-anchor commit would be required but was not authorized. A supplied committed range remains reviewable in detached clean lane worktrees; unrelated dirty checkout state is excluded rather than silently added to that range.

## Effective Review Shape

- Use the canonical definitions in the parent skill. A PR/full-workflow request with no named shape defaults to single.
- PR readiness adds CI, conversation, base/head, exact-secret admission, and merge-policy gates to the effective review shape. It never adds a hidden local Codex review. Required admission is a direct Git-tree scan with no reviewer, workspace, diff, prompt, provider, or reviewer state; an independently requested low-level helper run is optional compatibility evidence and cannot replace a named lane.
- When triple is requested but GitHub Codex is unavailable, continue with effective double and report the downgrade reason.
- A missing or failed local lane remains blocked/inconclusive; GitHub fallback cannot turn it into a clean double.

## Gate Sequence

1. Resolve the local range and PR selector under the independent rules above. Explicit-range-only standalone single/double stops after local scope resolution and performs no PR probe. A standalone triple or PR-specific request may perform the narrow read-only PR lookup, but must not create or mutate a PR. When current-branch discovery returns multiple candidates, an existing frozen range allows only the local lanes to run; the GitHub/PR-specific lane remains `blocked-input` until the caller names the PR. Without a frozen range, report `blocked-input` and stop every lane whose scope depends on that selection. Only authenticated actual PR absence takes the no-PR path; for requested triple that path is effective double. An undiscoverable detached/unknown branch is instead the triple `blocked-input` / `triple-inconclusive` case above. Actual absence requires a successful authenticated discovery result containing zero candidates, and local lanes still wait for an explicit committed range or explicitly named target/base. At this stage do not read or consume review threads, required checks, rulesets, mergeability, or other readiness state; do not require PR-only fields when no PR was selected.
2. Freeze the exact committed range. Preserve any parent-provided frozen `base_sha..head_sha` as the intended range. For a PR/full-workflow request or standalone named review associated with an existing PR, defer PR-derived range freezing to the authenticated base/head preflight in step 3. On a proven no-PR path, derive `<merge_base>..HEAD` only from the explicitly named target/base. If the required clean-checkout input is absent, report `blocked-input`; if representing intended dirty state instead requires an unauthorized anchor mutation, report `blocked-authorization`.
3. For a selected existing PR, independently query and record lifecycle `state` / `merged` / `merged_at`, current `baseRefName` as `pr_base_ref`, `baseRefOid` as `pr_base_oid`, and `headRefOid` as `pr_head_oid`; never overwrite the intended `base_sha` or `head_sha` with them. Require the exact open lifecycle tuple and apply the lifecycle classifications above before any local lane or other PR-state read. At the first selected-PR range freeze, persist the exact `range_origin` fields defined above. In particular, record the current `headRefOid` separately as `pr_head_oid`; never overwrite the intended `head_sha` with it. With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, require `pr_base_oid` and `pr_head_oid` to resolve as locally complete commits and require `git merge-base --all pr_base_oid pr_head_oid` to yield exactly one full `pr_merge_base`. Zero/multiple merge bases, missing metadata, or missing objects are `blocked-input` (`scope-unverified`). Before applying the generic same-head/different-base `scope-mismatch` branch, perform the audited post-request base-only comparison only from a valid one-to-one `parent-recorded-request-scope-v1` sidecar and then apply the state-machine transition defined above. A missing or malformed sidecar does not prove a retarget and closes only the request/reaction planes; local lanes continue under their independently selected scope. A proved non-recovery transition stops before local lanes. An authorized exact-current recovery proceeds to step 4 but keeps readiness `blocked-input` (`base-changed-same-head`) and marks the GitHub lane to skip step 8 permanently for that unchanged head. Otherwise, when no explicit range exists, freeze exactly `pr_merge_base..pr_head_oid`. When one exists, require `base_sha == pr_merge_base` and `head_sha == pr_head_oid` before running local lanes or reading PR CI, conversation, ruleset, mergeability, or other readiness state. A same-head/different-base mismatch is `blocked-input` (`scope-mismatch`); preserve the explicit range, do not silently replace it, and do not count any range-only review as whole-PR evidence. This applies to a selected PR in single, double, triple, and triple already reduced to effective double by directly known unavailability. Compare `pr_head_oid` with the intended `head_sha` before running local lanes or reading PR CI, conversation, ruleset, mergeability, or other readiness state. A `pr_head_oid != head_sha` mismatch continues to follow the separate head-alignment and PR-mutation authorization rule: publish/freeze the intended head only when PR mutation is separately authorized; otherwise leave the PR unchanged and report readiness `blocked-authorization`. For a still-eligible triple candidate, also apply the triple-inconclusive rule above. No comparison exists for explicit-range-only standalone single/double with no selected PR, or for the authenticated no-PR path.
4. Run the requested local lanes under [review-lane-contracts.md](review-lane-contracts.md) only after any selected-PR scope preflight and the trusted control-plane guard passed, over the preserved intended range. For each lane, the parent must use the trusted `materialize-worktree` guard to initialize a private repository and import only the hard-bounded frozen base/head reachable-object closure, then run `validate-worktree` as the first worktree-status query immediately before launch; clone/fetch/upload-pack, `git worktree add`, or any earlier status query is `blocked-safety`. Each reviewer gets that lane-unique read-only worktree and clear control metadata. The reviewer must derive and inspect the complete diff itself in bounded chunks; never prepare or inject a full diff, changed-file payload, or candidate-head executable as lane-control input.
5. Run `isolated_review secret-admission --repo <repo> --base-ref <base_sha> --head-ref <head_sha>` for the exact current-head range. Require its machine fields `operation: exact-secret-admission`, `source: direct-git-tree-scan`, `review_contract: admission-only-no-reviewer`, `reviewer_started: false`, `temporary_cleanup_status: complete`, and the exact resolved SHA range. It creates only a temporary sanitized Git view: it must not prepare a supplied diff, prompt, review workspace/state, authentication, egress, or provider process. A proved violation remains exit `1` even if later location mapping or temporary cleanup is incomplete; a clean scan whose cleanup fails is exit `75`, never admission success.
6. Count each exact raw value globally across tracked raw path bytes, regular blobs, and symlink targets, and require `head_count <= base_count`; for this count, do not derive Base64 or other encodings. Direct admission exit `0` plus `secret_delta.status=clean` is the only result that permits PR/master/merge-ready; exit `1` is a violation and exit `75` is inconclusive. There is no pending state. A non-clean result does not suppress this trusted reviewer or reclassify its artifact. For positive-delta candidates, violation evidence lists only added head locations: raw path plus one-based line for text additions, `line: null` for new-path or binary fallbacks, and line `1` for symlink targets. Unchanged occurrences are omitted; incomplete location mapping never weakens a proven positive global count, while incomplete tree/count integrity is inconclusive. A separately requested low-level helper may retain its schema-v5 `stateful final` / `stateful admission` compatibility contract, but PR readiness never starts that reviewer merely to obtain admission.
7. If triple was requested, make only the pre-request classifications that available evidence can prove:
   - Unavailable before request: proven no PR; any host other than exact `github.com`, including `sqbu-github.cisco.com` and every enterprise host; or any operating identity in `{hoteng, hoteng_cisco}`. The fixed authority baseline has no accepted no-start body grammar and an empty accepted structured capability/installation schema set, so integration/service uncertainty and free-form provider responses do not enter this branch. Persist `requested: triple`, `effective: double`, and a concrete reason, then continue the double-review readiness gate.
   - Eligible candidate: an existing, head-aligned and exact-range-aligned PR whose host is exact `github.com`, whose operating identity is not in the unsupported set, and which has no other directly known disqualifier. Unknown pre-request integration/service status does not block the request or become an availability claim.
   - Base-only local recovery: keep `requested: triple`, `effective: triple-inconclusive`, run only the recovered local lanes and required admission/readiness checks, and skip step 8. This is neither an eligible candidate nor effective-double unavailability.
8. For an eligible candidate, first revalidate exact lifecycle `state == "open"`, `merged == false`, and `merged_at == null`, then read complete authenticated request history for the unchanged current `pr_head_oid`. If no receipt-bound current-scope request is observed and no unmatched request remains, producer policy permits the parent to post one exact `@codex review` comment only after both local lanes are terminal and the current whole-PR scope is exact. Capture closed raw pre-request pull/compare responses, the exact `201` POST response, and raw post-request pull/compare responses in one parent-owned request-time scope sidecar. Never post a second or third request on that unchanged scope. Only one-to-one sidecar-bound requests may support `compliant`, timing/duplicate warnings, or reactions. A missing, malformed, extra, or unmatched sidecar makes `request_policy` `unknown`, forbids another POST while same-scope history is unproved, and disables the affected reaction path without invalidating an independently trustworthy terminal payload. A valid old-head receipt remains old-epoch audit evidence and does not count as a current-head request; a valid same-head/different-merge-base receipt instead takes `base-changed-same-head` and forbids a replacement request. Record `early-request-observed` when a bound request preceded local completion. Record `duplicate-observed` when more than one bound same-scope request exists, including a pending extra request. These producer-policy warnings do not invalidate provider evidence. A lone compliant pending request is not a warning; it remains pending unless trustworthy terminal evidence already exists. Read and fully paginate issue comments, reviews, each selected review's associated inline comments, review threads, and relevant reactions. Reconcile the complete snapshot under [github-codex-evidence-authority.md](github-codex-evidence-authority.md): admit terminal payloads only under its fixed clean/finding/inline-parent grammar; every other terminal-looking exact-provider payload is malformed. Unresolved thread-backed findings block first; otherwise select the latest trustworthy terminal provider artifact by semantic server time, without requiring request/run association. The scope sidecar also does not create that association. A pending request is transport state and does not supersede an already selected current-head clean. Complete duplicate/pending request and reaction pages remain audit inputs, but stable or changing records affect only request/reaction authority and never overturn an independently stable terminal result. A newer finding or malformed terminal artifact blocks; a later strong clean may supersede an older eligible top-level finding; any latest equal-time candidates spanning issue-comment and review channels fail closed before outcome or ID tie-breaking. Recompute `provider_profile` from the final complete snapshot and bounded same-repository history, then record it with the exact `evidence_basis`. Immediately before accepting success, re-read lifecycle, `baseRefName`, `baseRefOid`, `headRefOid`, the unique local `pr_merge_base`, every evidence channel, every applicable request-time sidecar, and the selected artifact, and require the exact whole-PR range plus selected evidence to remain stable. Equal pre/post scope observations are point-in-time reads and do not prove that no intermediate ABA transition occurred. A non-open lifecycle, changed head, changed merge base, incomplete pagination, changed selection, or newly observed blocker invalidates success. A base-only retarget still takes the prioritized `base-changed-same-head` branch and never permits a replacement request or old-epoch reaction reattachment. The fixed authority baseline has neither an accepted integration/service availability schema nor a no-start body grammar, so metadata or free-form provider prose cannot currently prove that unavailability. A missing response remains pending while bounded waiting is meaningful; after exhaustion, timeout or generic write/HTTP failure is `effective: triple-inconclusive`. Unknown identity is immediately inconclusive. The comment write is neither completion nor proof of service start; an exact-App current-head post-request check/run is service-start evidence only and never clean/no-findings evidence.
   For this step, a thread-backed finding is a joined exact-provider
   selected-review REST target child. Every target must map exactly once to raw
   GraphQL thread evidence. Fully fetched human, unrelated-bot, null-parent,
   and unrelated-only thread records remain audit context and cannot supply
   resolution; malformed target joins fail closed.
   If any terminal clean/findings or reaction clean result is considered, its
   `evidence_basis` must also embed independently fetched initial/final raw
   current endpoint inventories and parent-owned initial/final local Git
   ancestry receipts for every raw-derived finding commit. Exact object return
   code `0` and ancestry return code `0` or `1` are the only admitted results.
   The complete raw artifact/thread projection must type-preservingly equal the
   normalized current record. Missing ancestry receipts, another return code,
   commit-set mismatch, evidence-budget overflow,
   provider-artifact/thread/finding projection drift, or ancestry-receipt drift
   selects `unknown`; normalized current snapshot equality
   is insufficient. The basis also records independently derived
   `finding_commits.initial/final`. Any raw-derived applicable top-level
   finding blocks the reaction path; an unresolved applicable target-thread
   finding blocks every clean path.
For detailed payload normalization, provider profiles, reaction fallback, precedence, and stable-final-reread rules, use [github-codex-evidence-authority.md](github-codex-evidence-authority.md) as the authoritative contract.
9. Read required CI/check state and unresolved PR conversations. Distinguish required checks from informational jobs and stale runs from current-head runs.
10. Apply actionable findings in the implementation workspace, rerun affected tests, publish the new head, and invalidate every earlier named-lane artifact, optional low-level helper result, and direct admission result whose range/head changed.
11. Repeat the affected local lanes, direct current-head admission, supported GitHub Codex evidence read, CI checks, and conversation scan until the effective shape and all delivery gates are clean or a crisp blocker remains. Never post another GitHub request while the scope is unchanged, including after an early or duplicate request was observed. For a base-only retarget, rerun local lanes only in a later pass whose current range was explicitly supplied or validly rederived as described above.
12. Re-read the selected PR's base ref/SHA and head SHA, recompute the unique merge base, revalidate exact range equality, then recheck mergeability, direct current-head admission exit `0`, approval/ruleset requirements, and the repository's merge model immediately before reporting merge-ready or merging.

## Trusted Mac Isolation Gate

The pinned GitHub Hosted `macos-26` profile produces only a reviewed fail-closed
signature, not production-equivalent no-child or snapshot-Seatbelt evidence.
Its RLIMIT probes exit before post-exec leader binding, while its Seatbelt and
combined probes bind the leader and then terminate with `SIGKILL` before probe
evidence. When the frozen range changes the independent supervisor's Darwin
isolation implementation, its live-test runner, or the covered integration
tests, the delivery operator must run this command on a trusted Mac that
matches the production runtime pin after the final commit exists. First resolve
and record a parent-validated absolute Python 3.13 interpreter whose entire
resolved execution path satisfies the no-group-write/no-other-write access
policy. A convenience symlink through a standard group-writable Homebrew
`Cellar` does not satisfy that policy. Start from the repository root and enter
the self-contained tool directory before invoking the package-local test
runner:

```bash
TRUSTED_PYTHON=/absolute/path/to/parent-validated/python3.13
cd skills/review-orchestration-playbook/scripts/independent_codex_pr_review
CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE=1 PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B -m tests.run_required_no_child_profile
```

Record the interpreter's absolute path and digest and exact `head_sha`; record
nine tests run, zero skips, and the terminal result in the PR delivery evidence.
Any push invalidates that evidence. Missing, skipped, old-head, sandbox-blocked,
or nonmatching-host evidence blocks merge-readiness;
Hosted CI's blocker-signature probe is not a substitute.

This is an operator-enforced exact-head gate, not a GitHub check run, branch
protection status, cryptographic attestation, or named review lane. Do not claim
machine enforcement until a separately reviewed isolated runner exists.

## GitHub Codex Evidence

The anti-drift comparison is the immutable source
`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`,
released
`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`,
common tree `d03de9035d20f285e6a93986d436403b4a30e9bc`, and the complete
15-path blob manifest in
[github-codex-evidence-authority.md](github-codex-evidence-authority.md).
These pins plus the result-present regression rationale form one atomic
anti-drift receipt; branch/tag references, prose-only matches, and partial
runtime comparisons are insufficient. Only provider-result authority is
inherited. Raw thread proof, whole-PR lifecycle/scope, the closed issue-comment
carrier, request-time and artifact-time scope receipts, ancestor-finding
projection, declaration discovery, and `+1` fallback are playbook extensions.

A qualifying third-lane result must prove all of the following:

- The PR host is exact `github.com`, the operating identity is not `hoteng` or `hoteng_cisco`, and accepted current-scope provider evidence proves that the lane ran. No separate integration/service availability claim is required. Every other host, including `sqbu-github.cisco.com` and all enterprise hosts, is unsupported.
- Authenticated PR metadata supplied `baseRefName`, `baseRefOid`, and `headRefOid`; local object validation produced exactly one `pr_merge_base`; and the frozen local range was exactly `pr_merge_base..headRefOid`. A same-head/different-base range cannot supply whole-PR or third-lane evidence.
- Every request used for request-policy or reaction authority has exactly one closed `parent-recorded-request-scope-v1` sidecar. Its pre/post raw pull-detail and compare receipts derive that request's immutable scope, its exact `201` POST response projects the same seven request fields, and no extra or unmatched receipt exists. Only receipts whose tuple equals the evaluated scope enter that scope's request/reaction authority. A valid old-head receipt remains old-epoch audit evidence; a valid same-head/different-merge-base receipt takes `base-changed-same-head`. The sidecar remains outside raw transcript schema version 3 and proves neither request/run lineage nor an ABA-free interval. Missing or malformed sidecars make request policy unknown and disable reactions without vetoing independently complete terminal evidence.
- Every terminal-looking exact-provider artifact used in current-scope precedence has a singular closed `artifact_scope_receipt` with kind `parent-recorded-terminal-artifact-scope-v1` and exactly the fields `kind`, `pre_artifact_scope_receipts`, `artifact_get_receipt`, and `post_artifact_scope_receipts`. The raw pre/post pull+compare projections bind artifact-time head and merge base; independent mandatory snapshots bind lifecycle; the canonical exact-artifact GET binds repository/PR, channel/native ID, provider projection, semantic time, body/digest, grammar, and artifact commit. Clean and malformed evidence require the exact current tuple. A finding may instead preserve a proved-ancestor artifact-time head while repository, PR, and merge base still match the enclosing scope and normalized `scope.head` remains current. Every pre `Date` is no later than artifact semantic time, which is no later than artifact GET `Date`, which is no later than every post `Date`. An old artifact can reuse only a previously persisted identical receipt that already bracketed it. If it predates every trustworthy pre observation, or the receipt is missing, malformed, unmatched, unstable, or over budget, the artifact is inconclusive; current metadata cannot scope it retroactively. The receipt is independent of request sidecars, supplies no request/run/artifact lineage, and does not prove an ABA-free interval.
- The frozen reaction-history `as_of_server_time` bounds eligible historical artifact semantic times, not receipt collection time. An exact artifact GET or post-scope receipt may have a later `Date` when collected during the bounded decision/final reread; do not reject it solely for being observed after that cutoff.
- A strong current `terminal-payload` or `mixed` result may also have semantic time after declaration discovery when it arrives during the bounded provider wait. The frozen as-of bounds historical samples and the separate current reaction-only basis for `thumbs-up-clean`, not strong current terminal evidence.
- The evidence snapshot completely enumerated issue comments, reviews, every relevant review's raw REST associated inline comments, raw GraphQL review-thread and nested-comment pages, and relevant request-comment reactions. It canonically joins every exact-provider selected-review REST target child exactly once to GraphQL evidence. Fully fetched human, unrelated-bot, null-parent, and unrelated-only records remain audit context and cannot contribute resolution. Incomplete pagination, a broken cursor/link chain, missing target review association, duplicate/orphaned target, or missing typed target `isResolved` fails closed.
- Every counted provider artifact has exact REST `login: chatgpt-codex-connector[bot]` and exact REST `type: Bot`. The enclosing normalized `scope.head` is always the exact current `headRefOid`. A strong clean artifact's parsed/native commit equals that head and contains an explicit provider-authored no-findings outcome. A finding keeps its own artifact commit and may remain applicable on a proved ancestor through its parent-owned local Git ancestry receipt; it is never rewritten to current head or omitted merely to make projections agree. A terminal issue comment also satisfies the authority's closed canonical API/HTML, exact App, raw/normalized body, grammar, parsed-commit, immutable-current-scope, and edit-aware time schema. An empty `APPROVED` review is not clean evidence.
- A proved non-ancestor is raw audit-only and must not appear in normalized `active_top_level_findings` or `unresolved_thread_findings`. Treat any such normalized injection as a raw/normalized projection mismatch and select `unknown`; it cannot become a terminal finding or blocker candidate.
- Review state admissibility is separate from terminal-looking detection. A submitted review artifact uses exact state `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`. `PENDING` is nonterminal. `DISMISSED` is always terminal-looking; a missing or unknown state is likewise terminal-looking when a nonempty body or associated inline child supplies a terminal signal. Each is a whole-snapshot inconclusive blocker: original `submitted_at` is not a trusted state-transition time, so no later-looking clean may supersede it. See the authority's closed review-state rule.
- Every exact-provider selected-review target-thread finding in the applicable history is resolved. Resolution authority comes only from typed `isResolved` in the complete raw GraphQL pages after canonical positive-decimal BigInt/REST-ID joining. Human, unrelated-bot, null-parent, and unrelated-only thread state is audit context and cannot resolve a target. `isOutdated` and synthesized REST `thread_id` / `thread_resolved` fields are not resolution. An unresolved target-thread finding or malformed target join blocks even when a later clean payload exists.
- After thread blockers are applied, the latest trustworthy terminal provider artifact is selected by server timestamp. Any latest equal-time set spanning issue-comment and review channels is `triple-inconclusive` before outcome or numeric-ID tie-breaking. Within one channel, malformed blocks, finding takes precedence over clean, and only then may a same-channel positive ID choose the basis.
- A later strong current-head clean may supersede an older top-level finding on the same or a proven ancestor head when that ancestor finding remains present in the complete projection, has no unresolved thread, and the complete snapshot contains no newer finding or malformed terminal evidence. A resolved ancestor target-thread finding may cease blocking under the thread rule; an unresolved applicable thread remains blocking. The weak reaction fallback never supersedes a finding.
- The selected `provider_profile` was recomputed from the final complete snapshot and bounded same-repository history using the predeclared definitions: `terminal-payload` is the default, `mixed` still makes terminal payload authoritative, `thumbs-up-clean` is the narrowly qualified reaction-only fallback, and `unknown` never accepts reaction-only clean evidence.
- Immediately before success, lifecycle, base/head OIDs, unique merge base, complete evidence snapshot, every applicable artifact-time scope receipt, and the selected artifact were re-read. For terminal clean/findings and reaction clean, this includes a new raw current endpoint traversal, a repeat of every parent-owned local Git ancestry receipt, and a new type-preserving comparison of the complete raw artifact/thread projection with the normalized current record. The exact whole-PR scope, terminal-decision projection, selected artifact, artifact GET binding, and pre/artifact/post receipt envelope remained stable and no new blocker appeared; request/reaction/request-sidecar audit subrecords were evaluated separately on their own plane, while artifact-scope-receipt drift blocks the wrapped artifact. Normalized current snapshots alone are insufficient.

`eyes` is liveness only; it never proves a clean result.

An unknown, missing, differently cased, or lookalike author cannot prove a terminal result or authenticated no-start rejection, and an unknown or lookalike app/check slug cannot prove service start. Such evidence is `requested: triple`, `effective: triple-inconclusive`; do not use it for effective-double fallback or completed-triple evidence.

Request history is producer/audit evidence, not verdict authority. The parent still records every exact request and may itself post at most one request on an unchanged scope, after both local lanes are terminal. Only requests with one-to-one matching request-time scope sidecars may be classified as same-scope or parent reactions; an unbound observed request makes `request_policy` unknown and prevents another POST. Observed early or duplicate bound requests are reported in `request_policy`; `duplicate-observed` is a warning and the parent never posts a third request. Neither duplicate count, missing request/run lineage, nor a request-sidecar failure invalidates a separately trustworthy current-head terminal artifact. Therefore `R1 -> clean1 -> R2 pending`, `R1 -> clean1 -> R2 -> clean2`, and `R1 -> R2 -> clean1 -> clean2` can all pass with a request-policy warning when the selected clean and every other gate remain valid.

That independence assumes the terminal artifact has its own complete
artifact-time whole-PR scope receipt. It never permits a later current scope to
be assigned retroactively to an artifact that lacks a trustworthy pre-scope
observation.

The default `terminal-payload` and `mixed` profiles do not accept `+1` as
independent clean evidence. `thumbs-up-clean` may do so only when a directly
fetched, finally stable GitHub REST issue-comment artifact has exact provider
Bot/App identity and contains the predeclared exact statement
`If Codex has suggestions, it will comment; otherwise it will react with 👍.`.
Arbitrary issuer/source labels, copied prose, local paraphrases,
self-consistent hashes, and caller-synthesized fields are not declaration
authority. Preserve closed initial/final GET receipts, independently project
both declaration snapshots, and freeze the exact
`(as_of - 2592000, as_of]` interval from the initial receipt; the final receipt
never moves it.

Both repository-wide discovery passes also seed and fully traverse the
declaration's bound PR and find the exact raw declaration record once in its
issue comments. That exact declaration and closed progress-only grammar are
audit-only nonterminal evidence; a declaration-only scope is
`confirmed-non-candidate`. Any other exact-provider free-form prose fails
closed, while an in-window terminal-looking malformed artifact remains a
historical candidate. A fully parsed artifact at or before the exclusive lower
boundary remains audit-only `confirmed-non-candidate` evidence.

Each initial/final historical inventory independently embeds the closed
schema-version-3 raw discovery transcript. Its fully paginated repository-wide
`GET /repos/<owner>/<repo>/pulls?state=all&sort=created&direction=asc&per_page=100`
seed drives exactly one complete detail traversal for every PR, including the
current PR, the declaration PR, and confirmed non-candidates. The fixed parser classifies every
seeded PR and excludes current from the historical candidate set only after
full parsing. A version-2 transcript cannot prove reaction fallback. Missing
seed/detail/child coverage or any predeclared page/count/byte/time budget
overflow selects `unknown`; do not truncate and continue. Only
`compare.merge_base_commit.sha` supplies `pr_merge_base`. The fixed projector
derives scope/order/source-evidence entries and count, while the closed
candidate evaluator independently validates every complete candidate.
Self-consistent summaries or selected samples do not prove completeness. The
parent-owned `request_scope_receipts` array is stored beside the transcript;
the version-3 root and fetch-kind set remain unchanged.

Each historical inventory and each current raw endpoint inventory also stores
a parent-owned `resource_budget` sibling beside, never inside, that unchanged
transcript. It must type-preservingly equal this closed profile:

```yaml
profile: github-codex-evidence-resource-budget-v1
schema_version: 1
max_seeded_pull_requests: 512
max_controlled_requests: 512
max_fetch_attempts: 8192
max_retained_pages: 4096
max_records: 20000
max_page_body_bytes: 8388608
max_retained_utf8_bytes: 67108864
deadline_seconds: 900
```

Enforce the profile independently for each complete inventory. Use three
non-borrowing endpoint, request-scope-sidecar, and
terminal-artifact-scope-receipt ledgers with the same inventory start/deadline;
pre-count each sidecar or artifact-wrapper array and each wrapper's five raw
responses. Create the artifact ledger once per inventory decision pass,
validate each immutable wrapper once, and thread its memoized result through
candidate ordering, audit, profile, outcome, and report projection. Never
reset it per candidate/scope/recomputation or recharge the same wrapper. A
memo lookup first applies `github-codex-memo-fingerprint-guard-v1`: iterative
strict-JSON preflight with depth 64, 20,000 entries per container, 2,000,000
value/key occurrences (each object key and each value counts once), a 128-bit
integer ceiling, 8,388,608 UTF-8 bytes per scalar, and 67,108,864 aggregate
scalar bytes. Plane-specific subjects keep endpoint transcripts/fetches,
sidecars, and artifact wrappers out of one another's tracker. Declaration and
ancestry policy inputs receive the same bounded no-hash preflight before their
streaming namespace fingerprint; canonical JSON is forbidden for that key. The
owning ledger must validate successfully before a cache miss uses the
sorted-key, type-tagged subject fingerprint, and a failed ledger defeats any
truthy partial producer result. Healthy positive and negative entries both
retain a digest; every cache hit rechecks the bounded summary and content
fingerprint. It never serializes a complete
untrusted JSON body or recharges transient fingerprint bytes, and its periodic
zero-charge deadline checks remain on the same endpoint, sidecar, or artifact
plane. The root deadline coordinator never owns a memo. Cache identity binds
the exact tracker and exact artifact scope types; a narrow current `fetches`
subject requires its closed transcript scaffold. Mutated immutable negatives
remain fail-closed until a fresh reread/context. Complete, sidecar-blind,
ancestry-filtering, and candidate-ordering consumers share the same
exact-list/dict wrapper-array precharge before iteration, so each wrapper plus
five responses consumes six artifact-ledger records exactly once. A filtered
view must be an identity-preserving subsequence of the charged source arrays.
Before rebuilding a narrow current transcript, require an exact built-in raw
object/fetch list and an exact positive integer PR number; boolean/floating
equality aliases are invalid. A sidecar-ledger overflow makes request policy unknown and disables reaction
authority without erasing a complete terminal payload. Aggregate artifact
ledger overflow invalidates the complete terminal-artifact projection and
selects `unknown`; accepting a validated prefix is forbidden. For endpoint
evidence, charge every REST or GraphQL attempt,
including retries, before the request; charge known page/record counts before
cloning or serialization, then charge UTF-8 bytes before hashing, decoding, or
accumulation; and recheck the monotonic active-work deadline before success.
Endpoint overflow discards the whole traversal and selects `unknown`; it never
permits truncation, newest-N sampling, or a caller-selected subset. A current
raw inventory charges its one real detail fetch set exactly once: no synthetic
repository seed, duplicate pull parse, second deadline, or post-budget byte
mutation. The initial and final inventories must be independent fresh fetches
with independent 900-second starts. The `20000`-record, `8388608`-byte
per-response, and `67108864`-byte aggregate caps intentionally align with the
pinned `codex-review-gate-action` baseline above (20,000 items, 8 MiB per
response, and 64 MiB per work unit). The 512 seeded PRs, 512 controlled
requests, 8192 attempts, 4096 retained pages, and 900-second deadline are
playbook extensions and are not attributed to that Action.

Classify actor identity and validate each carrier's complete schema, native
IDs, canonical URLs, and joins before applying the frozen as-of cutoff. A
confirmed-different non-request issue comment created wholly after the cutoff,
submitted review after the cutoff, or reaction created after the cutoff is a
raw-only future suffix: keep it in the transcript but exclude it from the
fixed semantic projection so independent traversals can converge despite
ordinary concurrent human or unrelated-bot writes. Controlled `@codex review`
comments remain policy-bearing regardless of actor and must be within the
cutoff. Exact-provider and ambiguous/provider-like records also remain
policy-bearing, so a post-cutoff instance selects `unknown`. A cross-cutoff
issue-comment edit remains fail-closed because its earlier body cannot be
reconstructed. An exact or ambiguous child cannot be hidden with an otherwise
confirmed-different future review. Schema version 3 has no independent
inline-child timestamp, so it cannot infer that a human reply on an in-cutoff
provider review is a removable later suffix; the child remains semantic drift.

Validate every seeded PR before sorting, including candidates outside the
newest 10 and scopes that become confirmed non-candidates. Validate current
separately and never count it toward the three-outcome history minimum. Every
historical sample and current reaction record binds the exact
`@codex review` parent's seven fields, exact request-time scope sidecar, its
individual exact-bot child `+1`, strict server ordering, and every same-scope
request/sidecar/reaction page. Both receipt-derived tuples equal the sample
scope, and the exact POST response projects back to that request. The selected
`+1` parent is the unique latest request; a later request, old-epoch
reattachment, cross-parent conflict, or
`eyes` at or after the selected `+1` prevents weak clean.

Current reaction clean additionally embeds independent initial/final raw
current endpoint inventories and parent-owned initial/final local Git ancestry
receipts for every finding commit independently derived from those raw
inventories, plus the matching request-time scope sidecars stored beside the
raw fetches. Local object resolution must return exact `0`, and
`git merge-base --is-ancestor <finding_commit> <current_head>` must return
exact `0` or `1`. A missing request sidecar disables reaction authority; a
missing ancestry receipt, another ancestry return code, commit-set mismatch,
evidence-budget overflow, provider-artifact/thread/finding projection drift,
or ancestry-receipt drift selects `unknown` for the corresponding
provider-result authority. Request/reaction/sidecar-only drift closes that
plane without erasing an independently stable terminal result. Any
top-level finding with return code `0` or unresolved exact-provider
selected-review target-thread finding with return code `0` blocks reaction
clean. Fully fetched human, unrelated-bot, null-parent, and unrelated-only
thread records remain audit context and cannot contribute resolution; malformed
target joins fail closed. Normalized current snapshots are still required
derived views, but they are not substitutes for these raw inventories or
receipts. The reaction `evidence_basis` embeds all four authorities. See
[github-codex-evidence-authority.md](github-codex-evidence-authority.md) for
the complete activation and precedence contract.

Every accepted terminal-payload `evidence_basis` embeds identical initial/final
selection snapshots and selected-artifact snapshots. Every terminal-looking
artifact wrapper also embeds its unique singular closed
`artifact_scope_receipt`, and the initial/final raw receipt plus its projected
scope/artifact join must remain type-preservingly identical. A review basis records
exact actor, state, raw/normalized body, native commit, fully paginated
raw REST associated inline children, raw GraphQL thread/comment pages, and the
canonical one-to-one BigInt join for every exact-provider selected-review
target child. Human, unrelated-bot, null-parent, and unrelated-only records
remain audit context and cannot supply resolution; malformed target joins fail
closed. No synthesized REST resolution field counts.
An issue-comment basis records its full closed canonical API/HTML, exact
actor/App, raw/normalized body, grammar, `created_at`, `updated_at`,
edit-aware server time/field, parsed artifact commit, and immutable current
scope. Clean requires that commit to equal `scope.head`; an applicable finding
may preserve a proved-ancestor artifact commit while `scope.head` remains
current. A sparse ID/time/commit summary cannot prove the grammar,
artifact-time scope, or final reread.

Any push invalidates old current-head clean evidence and creates a new head epoch. The parent may post at most one request for the new scope, but old request overlap does not make new provider evidence inconclusive. An old request/reaction remains bound to its receipt-derived epoch and cannot be relabelled. A post-request base-only retarget with unchanged head is different: it invalidates whole-PR scope, takes `base-changed-same-head`, and never permits a replacement same-head request. Matching pre/post scope receipts are point observations and do not prove that an intermediate ABA change never occurred.

Exact `app.slug == "chatgpt-codex-connector"` check/run evidence is service-start evidence only. It never completes triple or proves clean/no-findings, even when `status == "completed"` and `conclusion == "success"`. Effective-double fallback currently requires a proved no-PR result or directly observed unsupported host/identity. The fixed authority baseline has no accepted no-start body grammar and an empty accepted structured capability/installation schema set, so integration/service uncertainty cannot prove the fallback. Posting the request is not service start. When no complete `thumbs-up-clean` reaction fallback is accepted, missing terminal evidence, an otherwise valid nonterminal/check-only state, or a retryable transport/read failure remains pending while bounded waiting is meaningful; after exhaustion it is `requested: triple`, `effective: triple-inconclusive`. Malformed, stale, unknown-identity, non-retryable, or permanently incomplete evidence is immediately inconclusive.

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
- the direct exact-secret admission range, machine contract, and exit/status; only when separately requested, also report the optional low-level helper state/range, reviewer-final status, and schema-v5 preflight-receipt binding;
- GitHub Codex current-head evidence or the explicit triple-to-double reason, including `request_policy`, `provider_profile`, and `evidence_basis`;
- required CI/check state and unresolved-conversation count;
- mergeability/ruleset state and merge authorization;
- tests actually run, workspaces cleaned/retained, and any blocker.

Do not call the PR merge-ready when a required lane in the effective shape, the direct current-head exact-secret admission, a required check, an unresolved actionable conversation, or a branch/ruleset gate remains non-clean.
