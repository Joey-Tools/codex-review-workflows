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
   Legacy receipt migration never adopts an old artifact retroactively and
   never authorizes an agent-owned replacement request. A pre-version-1
   same-head artifact without a previously persisted valid artifact receipt
   may enter only the closed legacy negative/audit member. In both complete raw
   endpoint passes, prove by `(channel, id)` that raw applicable artifacts are
   exactly the disjoint union of receipt-bound normalized artifacts and the
   closed legacy list, with no overlap or omission. Every legacy semantic time
   is strictly earlier than both selected-artifact pre-scope `Date` values;
   equality, later/unknown/malformed time, or any invalid identity, boundary,
   receipt, or projection fails closed. Only the receipt-bound member may
   supply completion. Old clean is audit-only; old top-level/all-resolved
   finding evidence follows ordinary precedence and may be superseded by a
   later receipt-bound current-head clean; any old unresolved target thread
   remains blocking and cannot enter the tolerated list. A malformed or unknown
   legacy record also fails the partition instead of receiving an audit role.
   Preserve the complete initial/final raw inventories and
   require the provider artifact/thread/nonterminal projection plus both
   partition members to remain type-preserving identical. Request/reaction-only
   drift stays on its separate plane. Every non-null terminal-shaped
   `evidence_basis` exposes one stable closed `legacy_unreceipted_artifacts`
   list with the authority's exact seven-field item schema; ordinary terminal
   bases use `[]`. Derive it independently from both raw inventories and emit
   only their identical sorted projection. If a rejected legacy blocker leaves
   no independently valid stable receipt-bound blocker basis, use literal
   `evidence_basis: null` rather than promoting the legacy item. State that
   neither initial/final digest equality nor the scope receipts prove
   intermediate ABA or post-final-digest stability. Recover either after a
   separately authorized ordinary substantive
   change creates a new head, or after the caller explicitly makes one
   caller-owned manual exact `@codex review` trigger on the unchanged head. The
   manual path is valid only when the parent persisted the standard
   pre-artifact pull/compare scope pair before the caller acted. The agent
   neither performs nor repeats that POST and does not synthesize its request
   sidecar, so request policy stays `unknown` and reaction-only evidence is
   unavailable. Only a later terminal artifact, itself receipt-bound, that
   strictly follows both pre boundaries, closes the partition, and passes the
   complete version-1 artifact receipt/final-stability contract may decide; it
   need not bind to the manual request. This preserves fixed-Action result-present
   authority rather than restoring request/run attribution. Otherwise remain
   `triple-inconclusive`. A proved `base-changed-same-head` event cannot use the
   manual path and requires a real new head. Never manufacture an empty or
   anchor commit to start a new epoch.
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

The pinned GitHub Hosted `macos-26` production-profile probe produces only a
reviewed fail-closed signature, not production-equivalent no-child evidence.
The separate required hosted read-only job remains valuable: it runs the full
deterministic suite from a root-owned isolated source as a randomly named,
receipt-bound ephemeral non-admin account, with bound runtime custody and an
exact terminal summary. The workflow selects an unused dedicated UID/GID,
proves the account and group GUIDs, rejects admin membership or any process
already using that UID, repeats the exact-UID process census immediately before
launch and after the supervised run, and deletes only the same GUID-bound
records after the UID is empty. Account ambiguity, replacement, a census
failure, or a residual process fails closed and retains the records until the
ephemeral runner is disposed. Even without Git metadata, the source is captured
under the shared snapshot resource bounds and copied only from its descriptor
receipt; there is no unbounded copy fallback. Its isolated-account closure is
not the authenticated production no-child proof below. When the frozen range
changes the independent supervisor's Darwin
isolation implementation, its live-test runner, or the covered integration
tests, the delivery operator must run this command on a trusted Mac that
matches the production runtime pin after the final commit exists. First resolve
and record a parent-validated absolute Python 3.13 interpreter whose entire
resolved execution path satisfies the no-group-write/no-other-write access
policy. A convenience symlink through a standard group-writable Homebrew
`Cellar` does not satisfy that policy. Separately resolve and record a physical,
parent-validated Git 2.45 or newer executable, its Developer directory, and its
exact exec-path; do not use the macOS `/usr/bin/git` toolchain dispatcher. The
gate creates one canonical v2 toolchain receipt plus independent closed
`CONTROL_PARENT` and TMPDIR full-chain custody receipts with the frozen gate
source. The readonly v3 binding validates the TMPDIR receipt immediately before
and after a fresh, non-executing measurement and exact-compares the complete
canonical v2 toolchain receipt. The outer control binding freshly
exact-compares both directory receipts before and after the full gate returns.
Each ordered root-to-target chain record binds directory type and device/inode
object identity; owner/group/mode/flags plus zero ACL entries and a closed,
property-scoped permitted xattr set protect access policy. Target directories
permit only benign `com.apple.provenance`; ancestors additionally permit the
system-owned `com.apple.rootless` marker. Observed permitted names are not
serialized, so appearance or disappearance of those policy-equivalent markers
does not create false drift. Directory `nlink`, size, and timestamps are deliberately
excluded because benign child-entry churn does not change either protected
property. Every ancestor owner must be root or the current UID; group/world
writable ancestors are rejected except for a root-owned sticky directory. The
complete uid/gid ownership tuple is selected so reassignment is
access-policy drift even while mode `0700` leaves group permissions dormant;
target flags must remain zero because filesystem flags can change mutability,
ancestor flags are byte-bound, ACLs must remain empty because they can grant
access, and each measurement enforces the fixed permitted-xattr policy.
The outer Developer-directory binding compares device/inode for object identity
and owner/group/mode for access policy. The canonical toolchain receipt binds
only the exact Git path and bytes plus the complete exec-path inventory; it does
not contain TMPDIR custody or version/capability evidence. The readonly v3
profile separately combines the canonical receipt with the independent TMPDIR
full-chain custody receipt and binds `DEVELOPER_DIR`, `GIT_EXEC_PATH`, and
`TMPDIR` into the child environment. Any parent preflight version record is
provenance/capability evidence only and is not part of this security identity.
This candidate gate and its receipts are implementation/self-test evidence only; formal named-review lanes remain controlled by an independently trusted prior bundle.
Create a new owner-private control root beneath a current-UID, exact-`0700`,
zero-flags `CONTROL_PARENT` outside the candidate repository, bind
the source repository's physical common object directory, and reject the
platform path-list separator in either path. The bootstrap initializes an empty
bare control repository and
exposes the source object directory only as a read-only alternate. Source local
configuration, remotes, credential helpers, and promisor settings are therefore
never loaded. Every Git invocation additionally disables lazy fetch, prompts,
user-initiated protocols, optional writes, replacement objects, credential
helpers, and all transport protocols before the first object query.

Start from the repository root and enter the source-only gate by absolute path.
The gate starts under an empty environment with isolated, site-disabled,
bytecode-disabled Python. The gate itself is streamed from the frozen HEAD blob
through bounded stdin, so no candidate worktree path executes before that
binding. A second exact-HEAD blob binds a closed source manifest containing
every regular file's relative path, Git mode, byte length, and SHA-256 under
`review_supervisor/` and `tests/`.
The gate snapshots the complete inventory, rejects missing or extra entries,
symlinks, bytecode/native substitutes, and duplicate module mappings, and only
then compiles the captured matching bytes:

```bash
TRUSTED_PYTHON=/absolute/path/to/parent-validated/python3.13
TRUSTED_GIT_DEVELOPER_DIR=/absolute/path/to/parent-validated/Developer
TRUSTED_GIT=/absolute/path/to/parent-validated/git
TRUSTED_GIT_EXEC_PATH=/absolute/path/to/parent-validated/git-core
CONTROL_ROOT=/absolute/path/to/parent-validated/absent-owner-private-control-root
SOURCE_OBJECTS=/absolute/path/to/parent-validated-common-git-objects
REPO_ROOT="$PWD"
TOOL_REL=skills/review-orchestration-playbook/scripts/independent_codex_pr_review
TOOL_ROOT="$REPO_ROOT/$TOOL_REL"
HEAD_SHA=<full-head-sha>
GATE_SPEC="$HEAD_SHA:$TOOL_REL/tests/trusted_mac_gate.py"
SOURCE_MANIFEST_PATH="$TOOL_ROOT/trusted_mac_gate_sources.index"
SOURCE_MANIFEST_SPEC="$HEAD_SHA:$TOOL_REL/trusted_mac_gate_sources.index"
CONTROL_GIT="$CONTROL_ROOT/repository.git"
CONTROL_HOME="$CONTROL_ROOT/home"
CONTROL_HOOKS="$CONTROL_ROOT/hooks"
CONTROL_TEMPLATE="$CONTROL_ROOT/template"
CONTROL_TMP="$CONTROL_ROOT/tmp"
CONTROL_CONFIG="$CONTROL_GIT/config"
CONTROL_PARENT="$(/usr/bin/dirname "$CONTROL_ROOT")"
CONTROL_UID="$(/usr/bin/id -u)"
probe_source_objects_acl() {
  /usr/bin/find -s "$SOURCE_OBJECTS" -exec /bin/ls -lde {} \; \
    | /usr/bin/awk 'substr($1, 11, 1) == "+" {print "acl"; exit}'
}
probe_source_object_escape_metadata() {
  local promisor_marker=""
  if [[ -L "$SOURCE_OBJECTS/info" ]] \
    || [[ -L "$SOURCE_OBJECTS/pack" ]] \
    || [[ -e "$SOURCE_OBJECTS/info/alternates" ]] \
    || [[ -L "$SOURCE_OBJECTS/info/alternates" ]] \
    || [[ -e "$SOURCE_OBJECTS/info/http-alternates" ]] \
    || [[ -L "$SOURCE_OBJECTS/info/http-alternates" ]]; then
    printf '%s\n' alternate-metadata
    return 0
  fi
  for promisor_marker in "$SOURCE_OBJECTS/pack/"*.promisor; do
    if [[ -e "$promisor_marker" || -L "$promisor_marker" ]]; then
      printf '%s\n' promisor-marker
      return 0
    fi
  done
}
probe_control_acl() {
  /usr/bin/find -s "$CONTROL_ROOT" -exec /bin/ls -lde {} \; \
    | /usr/bin/awk 'substr($1, 11, 1) == "+" {print "acl"; exit}'
}
CONTROL_PARENT_PHYSICAL="$(cd "$CONTROL_PARENT" && pwd -P)"
CONTROL_PARENT_UID="$(/usr/bin/stat -f '%u' "$CONTROL_PARENT")"
CONTROL_PARENT_MODE="$(/usr/bin/stat -f '%Lp' "$CONTROL_PARENT")"
CONTROL_PARENT_FLAGS="$(/usr/bin/stat -f '%f' "$CONTROL_PARENT")"
SOURCE_OBJECTS_PHYSICAL="$(cd "$SOURCE_OBJECTS" && pwd -P)"
SOURCE_OBJECTS_MODE="$(/usr/bin/stat -f '%Lp' "$SOURCE_OBJECTS")"
SOURCE_OBJECTS_ACL_VIOLATION="$(probe_source_objects_acl)" \
  || SOURCE_OBJECTS_ACL_VIOLATION="<unreadable>"
SOURCE_OBJECT_ESCAPE_METADATA="$(probe_source_object_escape_metadata)" \
  || SOURCE_OBJECT_ESCAPE_METADATA="<unreadable>"
TRUSTED_GIT_DEVELOPER_DIR_PHYSICAL="$(cd "$TRUSTED_GIT_DEVELOPER_DIR" && pwd -P)"
TRUSTED_GIT_DEVELOPER_DIR_BINDING="$(
  /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$TRUSTED_GIT_DEVELOPER_DIR"
)"
TRUSTED_GIT_PHYSICAL="$(
  cd "$(/usr/bin/dirname "$TRUSTED_GIT")" && pwd -P
)/$(/usr/bin/basename "$TRUSTED_GIT")"
TRUSTED_GIT_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp:%z:%l' "$TRUSTED_GIT")"
TRUSTED_GIT_SHA256_RECORD="$(/usr/bin/shasum -a 256 "$TRUSTED_GIT")"
TRUSTED_GIT_SHA256="${TRUSTED_GIT_SHA256_RECORD%% *}"
TRUSTED_GIT_EXEC_PATH_PHYSICAL="$(cd "$TRUSTED_GIT_EXEC_PATH" && pwd -P)"
TRUSTED_GIT_EXEC_PATH_BINDING="$(
  /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$TRUSTED_GIT_EXEC_PATH"
)"
if [[ "$CONTROL_ROOT" != /* || "$SOURCE_OBJECTS" != /* ]] \
  || [[ "$CONTROL_ROOT" == *:* || "$SOURCE_OBJECTS" == *:* ]] \
  || [[ "$CONTROL_ROOT" == *$'\n'* || "$SOURCE_OBJECTS" == *$'\n'* ]] \
  || [[ "$CONTROL_PARENT_PHYSICAL" != "$CONTROL_PARENT" ]] \
  || [[ "$SOURCE_OBJECTS_PHYSICAL" != "$SOURCE_OBJECTS" ]] \
  || [[ ! "$CONTROL_UID" =~ ^[[:digit:]]+$ ]] \
  || [[ "$CONTROL_PARENT_UID" != "$CONTROL_UID" ]] \
  || [[ ! "$CONTROL_PARENT_MODE" =~ ^[0-7]{3,4}$ ]] \
  || [[ "$CONTROL_PARENT_MODE" != "700" ]] \
  || [[ "$CONTROL_PARENT_FLAGS" != "0" ]] \
  || [[ ! "$SOURCE_OBJECTS_MODE" =~ ^[0-7]{3,4}$ ]] \
  || (( (8#$SOURCE_OBJECTS_MODE & 0022) != 0 )) \
  || [[ -n "$SOURCE_OBJECTS_ACL_VIOLATION" ]] \
  || [[ -n "$SOURCE_OBJECT_ESCAPE_METADATA" ]] \
  || [[ "$TRUSTED_GIT_DEVELOPER_DIR_PHYSICAL" != "$TRUSTED_GIT_DEVELOPER_DIR" ]] \
  || [[ ! -d "$TRUSTED_GIT_DEVELOPER_DIR" || -L "$TRUSTED_GIT_DEVELOPER_DIR" ]] \
  || [[ "$TRUSTED_GIT" != "$TRUSTED_GIT_DEVELOPER_DIR/"* ]] \
  || [[ "$TRUSTED_GIT_EXEC_PATH" != "$TRUSTED_GIT_DEVELOPER_DIR/"* ]] \
  || [[ "$TRUSTED_GIT_PHYSICAL" != "$TRUSTED_GIT" ]] \
  || [[ ! -f "$TRUSTED_GIT" || -L "$TRUSTED_GIT" ]] \
  || [[ ! "$TRUSTED_GIT_SHA256" =~ ^[[:xdigit:]]{64}$ ]] \
  || [[ "$TRUSTED_GIT_EXEC_PATH_PHYSICAL" != "$TRUSTED_GIT_EXEC_PATH" ]] \
  || [[ ! -d "$TRUSTED_GIT_EXEC_PATH" || -L "$TRUSTED_GIT_EXEC_PATH" ]] \
  || [[ -e "$CONTROL_ROOT" || -L "$CONTROL_ROOT" ]] \
  || [[ ! -d "$SOURCE_OBJECTS" || -L "$SOURCE_OBJECTS" ]]; then
  printf 'unsafe trusted Git bootstrap paths\n' >&2
  exit 1
fi
/bin/mkdir -m 0700 "$CONTROL_ROOT"
/bin/mkdir -m 0700 "$CONTROL_HOME" "$CONTROL_HOOKS" "$CONTROL_TEMPLATE" "$CONTROL_TMP"
CONTROL_ROOT_PHYSICAL="$(cd "$CONTROL_ROOT" && pwd -P)"
CONTROL_ROOT_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$CONTROL_ROOT")"
SOURCE_OBJECTS_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$SOURCE_OBJECTS")"
if [[ "$CONTROL_ROOT_PHYSICAL" != "$CONTROL_ROOT" ]] \
  || [[ "$(/usr/bin/stat -f '%u:%Lp' "$CONTROL_ROOT")" != "$CONTROL_UID:700" ]]; then
  printf 'trusted Git control root failed custody validation\n' >&2
  exit 1
fi
bootstrap_git() {
  /usr/bin/env -i DEVELOPER_DIR="$TRUSTED_GIT_DEVELOPER_DIR" \
    GIT_ASKPASS=/usr/bin/false GIT_ATTR_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null GIT_EXEC_PATH="$TRUSTED_GIT_EXEC_PATH" \
    GIT_NO_LAZY_FETCH=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_PAGER=cat GIT_PROTOCOL_FROM_USER=0 GIT_TERMINAL_PROMPT=0 \
    HOME="$CONTROL_HOME" LANG=C LC_ALL=C PAGER=cat PATH=/usr/bin:/bin \
    TMPDIR="$CONTROL_TMP" \
    "$TRUSTED_GIT" --no-pager --no-replace-objects "$@"
}
bootstrap_git init --bare -q --template="$CONTROL_TEMPLATE" "$CONTROL_GIT"
/bin/chmod -RN "$CONTROL_ROOT"
/bin/chmod -R go-rwx "$CONTROL_ROOT"
/bin/chmod 0600 "$CONTROL_CONFIG"
CONTROL_TMP_PHYSICAL="$(cd "$CONTROL_TMP" && pwd -P)"
CONTROL_TMP_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp:%f' "$CONTROL_TMP")"
CONTROL_GIT_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$CONTROL_GIT")"
CONTROL_CONFIG_BINDING="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp:%z' "$CONTROL_CONFIG")"
CONTROL_CONFIG_SHA256_RECORD="$(/usr/bin/shasum -a 256 "$CONTROL_CONFIG")"
CONTROL_CONFIG_SHA256="${CONTROL_CONFIG_SHA256_RECORD%% *}"
CONTROL_ACL_VIOLATION="$(probe_control_acl)" \
  || CONTROL_ACL_VIOLATION="<unreadable>"
trusted_git() {
  /usr/bin/env -i DEVELOPER_DIR="$TRUSTED_GIT_DEVELOPER_DIR" \
    GIT_ALTERNATE_OBJECT_DIRECTORIES="$SOURCE_OBJECTS" \
    GIT_ASKPASS=/usr/bin/false GIT_ATTR_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null GIT_DIR="$CONTROL_GIT" \
    GIT_EXEC_PATH="$TRUSTED_GIT_EXEC_PATH" GIT_NO_LAZY_FETCH=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 GIT_PAGER=cat \
    GIT_PROTOCOL_FROM_USER=0 GIT_TERMINAL_PROMPT=0 HOME="$CONTROL_HOME" \
    LANG=C LC_ALL=C PAGER=cat PATH=/usr/bin:/bin TMPDIR="$CONTROL_TMP" \
    "$TRUSTED_GIT" --no-pager --no-replace-objects \
      -c core.commitGraph=false -c core.multiPackIndex=false \
      -c core.fsmonitor=false -c core.hooksPath="$CONTROL_HOOKS" \
      -c core.attributesFile=/dev/null -c maintenance.auto=false \
      -c credential.helper= -c protocol.ext.allow=never \
      -c protocol.file.allow=never -c protocol.git.allow=never \
      -c protocol.http.allow=never -c protocol.https.allow=never \
      -c protocol.ssh.allow=never "$@"
}
CONTROL_SYMLINK="$(/usr/bin/find "$CONTROL_ROOT" -type l -print -quit)"
if [[ -n "$CONTROL_SYMLINK" ]] \
  || [[ -n "$CONTROL_ACL_VIOLATION" ]] \
  || [[ "$CONTROL_TMP_PHYSICAL" != "$CONTROL_TMP" ]] \
  || [[ ! "$CONTROL_CONFIG_SHA256" =~ ^[[:xdigit:]]{64}$ ]] \
  || trusted_git config --local --name-only \
    --get-regexp '^(remote|credential|protocol)\.' >/dev/null 2>&1; then
  printf 'unsafe trusted Git control repository\n' >&2
  exit 1
fi
set -o pipefail
if ! GATE_SIZE="$(trusted_git cat-file -s "$GATE_SPEC")"; then
  printf 'unable to read trusted gate size\n' >&2
  exit 1
fi
if ! GATE_SHA256_RECORD="$(
  trusted_git cat-file blob "$GATE_SPEC" | /usr/bin/shasum -a 256
)"; then
  printf 'unable to hash trusted gate blob\n' >&2
  exit 1
fi
GATE_SHA256="${GATE_SHA256_RECORD%% *}"
if [[ ! "$GATE_SIZE" =~ ^[[:digit:]]+$ ]] \
  || (( GATE_SIZE < 1 || GATE_SIZE > 131072 )); then
  printf 'invalid trusted gate size: %s\n' "$GATE_SIZE" >&2
  exit 1
fi
if [[ ! "$GATE_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
  printf 'invalid trusted gate digest\n' >&2
  exit 1
fi
if ! SOURCE_MANIFEST_SIZE="$(trusted_git cat-file -s "$SOURCE_MANIFEST_SPEC")"; then
  printf 'unable to read trusted source manifest size\n' >&2
  exit 1
fi
if ! SOURCE_MANIFEST_SHA256_RECORD="$(
  trusted_git cat-file blob "$SOURCE_MANIFEST_SPEC" | /usr/bin/shasum -a 256
)"; then
  printf 'unable to hash trusted source manifest blob\n' >&2
  exit 1
fi
SOURCE_MANIFEST_SHA256="${SOURCE_MANIFEST_SHA256_RECORD%% *}"
if [[ ! "$SOURCE_MANIFEST_SIZE" =~ ^[[:digit:]]+$ ]] \
  || (( SOURCE_MANIFEST_SIZE < 1 || SOURCE_MANIFEST_SIZE > 1048576 )) \
  || [[ ! "$SOURCE_MANIFEST_SHA256" =~ ^[[:xdigit:]]{64}$ ]] \
  || ! trusted_git cat-file blob "$SOURCE_MANIFEST_SPEC" \
    | /usr/bin/cmp -s - "$SOURCE_MANIFEST_PATH"; then
  printf 'trusted source manifest is not the exact HEAD blob\n' >&2
  exit 1
fi
measure_trusted_git_directory_custody() {
  local directory="$1"
  trusted_git cat-file blob "$GATE_SPEC" \
    | /usr/bin/env -i HOME=/var/empty LANG=C LC_ALL=C PATH=/usr/bin:/bin \
        TMPDIR="$CONTROL_TMP" "$TRUSTED_PYTHON" -I -B -S - \
          --trusted-git-tmpdir-receipt "$directory"
}
verify_trusted_git_bootstrap_structure() {
  local phase="$1"
  local current_control_root_binding=""
  local current_control_tmp_physical=""
  local current_control_tmp_binding=""
  local current_control_git_binding=""
  local current_control_config_binding=""
  local current_control_config_sha256_record=""
  local current_control_config_sha256=""
  local current_control_acl_violation=""
  local current_source_objects_physical=""
  local current_source_objects_binding=""
  local current_source_objects_acl_violation=""
  local current_source_object_escape_metadata=""
  local current_trusted_git_developer_dir_physical=""
  local current_trusted_git_developer_dir_binding=""
  local current_trusted_git_physical=""
  local current_trusted_git_binding=""
  local current_trusted_git_sha256_record=""
  local current_trusted_git_sha256=""
  local current_trusted_git_exec_path_physical=""
  local current_trusted_git_exec_path_binding=""
  current_control_root_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$CONTROL_ROOT"
  )" || current_control_root_binding="<unreadable>"
  current_control_tmp_physical="$(cd "$CONTROL_TMP" && pwd -P)" \
    || current_control_tmp_physical="<unreadable>"
  current_control_tmp_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp:%f' "$CONTROL_TMP"
  )" || current_control_tmp_binding="<unreadable>"
  current_control_git_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$CONTROL_GIT"
  )" || current_control_git_binding="<unreadable>"
  current_control_config_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp:%z' "$CONTROL_CONFIG"
  )" || current_control_config_binding="<unreadable>"
  current_control_config_sha256_record="$(
    /usr/bin/shasum -a 256 "$CONTROL_CONFIG"
  )" || current_control_config_sha256_record="<unreadable>"
  current_control_config_sha256="${current_control_config_sha256_record%% *}"
  current_control_acl_violation="$(probe_control_acl)" \
    || current_control_acl_violation="<unreadable>"
  current_source_objects_physical="$(cd "$SOURCE_OBJECTS" && pwd -P)" \
    || current_source_objects_physical="<unreadable>"
  current_source_objects_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$SOURCE_OBJECTS"
  )" || current_source_objects_binding="<unreadable>"
  current_source_objects_acl_violation="$(probe_source_objects_acl)" \
    || current_source_objects_acl_violation="<unreadable>"
  current_source_object_escape_metadata="$(probe_source_object_escape_metadata)" \
    || current_source_object_escape_metadata="<unreadable>"
  current_trusted_git_developer_dir_physical="$(
    cd "$TRUSTED_GIT_DEVELOPER_DIR" && pwd -P
  )" || current_trusted_git_developer_dir_physical="<unreadable>"
  current_trusted_git_developer_dir_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$TRUSTED_GIT_DEVELOPER_DIR"
  )" || current_trusted_git_developer_dir_binding="<unreadable>"
  current_trusted_git_physical="$(
    cd "$(/usr/bin/dirname "$TRUSTED_GIT")" && pwd -P
  )/$(/usr/bin/basename "$TRUSTED_GIT")" \
    || current_trusted_git_physical="<unreadable>"
  current_trusted_git_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp:%z:%l' "$TRUSTED_GIT"
  )" || current_trusted_git_binding="<unreadable>"
  current_trusted_git_sha256_record="$(
    /usr/bin/shasum -a 256 "$TRUSTED_GIT"
  )" || current_trusted_git_sha256_record="<unreadable>"
  current_trusted_git_sha256="${current_trusted_git_sha256_record%% *}"
  current_trusted_git_exec_path_physical="$(
    cd "$TRUSTED_GIT_EXEC_PATH" && pwd -P
  )" || current_trusted_git_exec_path_physical="<unreadable>"
  current_trusted_git_exec_path_binding="$(
    /usr/bin/stat -f '%d:%i:%u:%g:%Lp' "$TRUSTED_GIT_EXEC_PATH"
  )" || current_trusted_git_exec_path_binding="<unreadable>"
  if [[ "$current_control_root_binding" != "$CONTROL_ROOT_BINDING" ]] \
    || [[ "$current_control_tmp_physical" != "$CONTROL_TMP" ]] \
    || [[ "$current_control_tmp_binding" != "$CONTROL_TMP_BINDING" ]] \
    || [[ "$current_control_git_binding" != "$CONTROL_GIT_BINDING" ]] \
    || [[ "$current_control_config_binding" != "$CONTROL_CONFIG_BINDING" ]] \
    || [[ "$current_control_config_sha256" != "$CONTROL_CONFIG_SHA256" ]] \
    || [[ -n "$current_control_acl_violation" ]] \
    || [[ "$current_source_objects_physical" != "$SOURCE_OBJECTS" ]] \
    || [[ "$current_source_objects_binding" != "$SOURCE_OBJECTS_BINDING" ]] \
    || [[ -n "$current_source_objects_acl_violation" ]] \
    || [[ -n "$current_source_object_escape_metadata" ]] \
    || [[ "$current_trusted_git_developer_dir_physical" != "$TRUSTED_GIT_DEVELOPER_DIR" ]] \
    || [[ "$current_trusted_git_developer_dir_binding" != "$TRUSTED_GIT_DEVELOPER_DIR_BINDING" ]] \
    || [[ "$current_trusted_git_physical" != "$TRUSTED_GIT" ]] \
    || [[ "$current_trusted_git_binding" != "$TRUSTED_GIT_BINDING" ]] \
    || [[ "$current_trusted_git_sha256" != "$TRUSTED_GIT_SHA256" ]] \
    || [[ "$current_trusted_git_exec_path_physical" != "$TRUSTED_GIT_EXEC_PATH" ]] \
    || [[ "$current_trusted_git_exec_path_binding" != "$TRUSTED_GIT_EXEC_PATH_BINDING" ]]; then
    printf 'trusted Git bootstrap custody changed %s\n' "$phase" >&2
    return 1
  fi
}
if ! verify_trusted_git_bootstrap_structure \
  'before directory receipt issuance'; then
  exit 1
fi
if ! CONTROL_PARENT_CUSTODY_RECEIPT="$(
  measure_trusted_git_directory_custody "$CONTROL_PARENT"
)"; then
  printf 'unable to measure CONTROL_PARENT custody\n' >&2
  exit 1
fi
if ! TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT="$(
  measure_trusted_git_directory_custody "$CONTROL_TMP"
)"; then
  printf 'unable to measure trusted Git TMPDIR custody\n' >&2
  exit 1
fi
for custody_receipt in \
  "$CONTROL_PARENT_CUSTODY_RECEIPT" \
  "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT"; do
  if [[ "$custody_receipt" == *$'\n'* ]] \
    || [[ "$custody_receipt" != \
      *'"schema":"trusted-git-tmpdir-custody-v1"'* ]]; then
    printf 'trusted Git directory custody receipt is malformed\n' >&2
    exit 1
  fi
done
verify_trusted_git_directory_custody() {
  local phase="$1"
  local current_control_parent_custody_receipt=""
  local current_control_tmp_custody_receipt=""
  current_control_parent_custody_receipt="$(
    measure_trusted_git_directory_custody "$CONTROL_PARENT"
  )" || current_control_parent_custody_receipt="<unreadable>"
  current_control_tmp_custody_receipt="$(
    measure_trusted_git_directory_custody "$CONTROL_TMP"
  )" || current_control_tmp_custody_receipt="<unreadable>"
  if [[ "$current_control_parent_custody_receipt" != \
    "$CONTROL_PARENT_CUSTODY_RECEIPT" ]] \
    || [[ "$current_control_tmp_custody_receipt" != \
      "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT" ]]; then
    printf 'trusted Git directory chain custody changed %s\n' "$phase" >&2
    return 1
  fi
}
verify_trusted_git_bootstrap_custody() {
  verify_trusted_git_bootstrap_structure "$1" \
    && verify_trusted_git_directory_custody "$1"
}
if ! verify_trusted_git_bootstrap_custody 'before gate execution'; then
  exit 1
fi
measure_trusted_git_toolchain() {
  trusted_git cat-file blob "$GATE_SPEC" \
    | /usr/bin/env -i HOME=/var/empty LANG=C LC_ALL=C PATH=/usr/bin:/bin \
        TMPDIR="$CONTROL_TMP" "$TRUSTED_PYTHON" -I -B -S - \
          --hosted-git-receipt "$TRUSTED_GIT_DEVELOPER_DIR" \
          "$TRUSTED_GIT" "$TRUSTED_GIT_SHA256" \
          "$TRUSTED_GIT_EXEC_PATH"
}
if ! TRUSTED_GIT_TOOLCHAIN_RECEIPT="$(measure_trusted_git_toolchain)"; then
  printf 'unable to measure trusted Git toolchain\n' >&2
  exit 1
fi
if ! TRUSTED_GIT_TOOLCHAIN_RECEIPT_SHA256_RECORD="$(
  /usr/bin/printf '%s\n' "$TRUSTED_GIT_TOOLCHAIN_RECEIPT" \
    | /usr/bin/shasum -a 256
)"; then
  printf 'unable to hash trusted Git toolchain receipt\n' >&2
  exit 1
fi
TRUSTED_GIT_TOOLCHAIN_RECEIPT_SHA256="${TRUSTED_GIT_TOOLCHAIN_RECEIPT_SHA256_RECORD%% *}"
if [[ "$TRUSTED_GIT_TOOLCHAIN_RECEIPT" == *$'\n'* ]] \
  || [[ "$TRUSTED_GIT_TOOLCHAIN_RECEIPT" != \
    *'"schema":"hosted-git-toolchain-receipt-v2"'* ]] \
  || [[ ! "$TRUSTED_GIT_TOOLCHAIN_RECEIPT_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
  printf 'trusted Git toolchain receipt is malformed\n' >&2
  exit 1
fi
if ! trusted_git cat-file blob "$GATE_SPEC" \
  | /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
      "$TRUSTED_PYTHON" -I -B -S - "$TOOL_ROOT" \
      "$SOURCE_MANIFEST_PATH" "$SOURCE_MANIFEST_SHA256" live; then
  printf 'trusted live gate failed\n' >&2
  exit 1
fi
if ! trusted_git cat-file blob "$GATE_SPEC" \
  | /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
      "$TRUSTED_PYTHON" -I -B -S - "$TOOL_ROOT" \
      "$SOURCE_MANIFEST_PATH" "$SOURCE_MANIFEST_SHA256" readonly "$HEAD_SHA" \
      "$CONTROL_TMP" "$TRUSTED_GIT_DEVELOPER_DIR" "$TRUSTED_GIT" \
      "$TRUSTED_GIT_SHA256" "$TRUSTED_GIT_EXEC_PATH" \
      "$TRUSTED_GIT_TOOLCHAIN_RECEIPT" \
      "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT"; then
  printf 'trusted readonly gate failed\n' >&2
  exit 1
fi
if ! verify_trusted_git_bootstrap_custody 'after gate execution'; then
  exit 1
fi
```

The Python receipt and remeasurement logic never executes the measured Git
toolchain. It reads and hashes the parent-selected physical Git executable and
the bounded exec-path closure, then compares the canonical v2 record exactly.
The surrounding operator may use that already bound executable to stream the
gate blob. This keeps the protected property to object/content identity and
access policy; dynamic version output is neither required nor folded into the
receipt.

Record the interpreter, Developer directory, Git executable/exec-path absolute
paths and digests, the canonical Git toolchain receipt and its SHA-256,
the independent canonical `CONTROL_PARENT` and TMPDIR full-chain custody receipts,
the isolated control-repository identity, source-object-directory identity,
exact `head_sha`, gate blob size and SHA-256, and source-manifest blob size and
SHA-256; record
the live runner's thirteen tests, zero skips, and terminal result, followed by the
read-only install runner's complete structured summary. Accept that summary
only when all of these predicates hold:

- `primary_status == "complete"` and `primary_failure == null`
- `child_process_closure == "proven"`
- `cleanup_status == "complete"` and `cleanup_failures == []`
- `release_tree_immutable == true`
- `source_head_bound == true`, `source_head_sha == <full-head-sha>`, and
  `source_head_subtree_manifest_sha256` is one full lowercase SHA-256
- `source_manifest_sha256` is one full lowercase SHA-256
- `no_child_runtime_profile == "production-current"`
- `returncode == 0`
- `retained_paths == []`, `runtime_residue == []`, and `secondary_failures == []`
- `signal_number == null` and `timed_out == false`
- `creation_origin_proven == false`
- `creation_origin_guarantee == "best-effort-128-bit-leaf-immediate-nofollow-open-same-uid-host-tcb"`
- `cleanup_guarantee == "custodied-manifest-quarantine-descriptor-revalidation-same-uid-final-rename-unlink-host-tcb"`

The last three predicates are mandatory platform-boundary evidence, not a
failed run. macOS provides neither an atomic create-directory-and-return-FD
operation nor unlink-by-FD. The `mkdirat` to first no-follow open window and
the final identity-check to `unlinkat`/`rmdir` window therefore rely on a
128-bit unguessable leaf and cooperative same-UID host TCB. After the receipt
exists, identity/access-policy drift fails closed; custodied manifests,
quarantine, and descriptor revalidation are used for cleanup, and a replacement
is never removed after mismatch or unproven identity has been observed.
The two independent custody receipts persist every root-to-target physical
chain record and are freshly exact-compared before and after gate execution.
The TMPDIR receipt is also revalidated immediately before and after the Git
toolchain static remeasurement inside readonly v3. These discrete snapshots do not claim to
exclude a same-UID transient replace-and-restore inside the cooperative host
TCB boundary.

The exact-head source proof does not trust ordinary `git status`. It rejects
repository-visible includes, executable filter/diff configuration,
`core.fileMode=false`, fsmonitor, assume-unchanged, and skip-worktree state.
An isolated Git object-control view reads the raw HEAD tree, blob bytes, and
mode, which must exactly match a descriptor-based double snapshot of the source
path set, directory set, complete file bytes, and executable bits. The
`source_head_subtree_manifest_sha256` binds that raw HEAD proof; the separate
`source_manifest_sha256` binds source path/type, content, mode/flags, and access
policy. Descriptor snapshots separately protect object identity at capture and
revalidation boundaries.

Both commands must use the same recorded interpreter and exact head.
Any push invalidates that evidence. Missing, skipped, old-head, sandbox-blocked,
or nonmatching-host evidence blocks merge-readiness;
neither Hosted CI's blocker-signature probe nor its isolated-account read-only
job substitutes for the production no-child proof.

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
- Every request used for request-policy or reaction authority has exactly one closed `parent-recorded-request-scope-v1` sidecar. Its pre/post raw pull-detail and compare receipts derive that request's immutable scope, its exact `201` POST response projects the same eight request fields—including closed `user: {login, type}` actor identity—and no extra or unmatched receipt exists. Only receipts whose tuple equals the evaluated scope enter that scope's request/reaction authority. A valid old-head receipt remains old-epoch audit evidence; a valid same-head/different-merge-base receipt takes `base-changed-same-head`. The sidecar remains outside raw transcript schema version 4 and proves neither request/run lineage nor an ABA-free interval. Missing or malformed sidecars make request policy unknown and disable reactions without vetoing independently complete terminal evidence.
- Every terminal-looking exact-provider artifact used in the receipt-bound normalized decision member has a singular closed `artifact_scope_receipt` with kind `parent-recorded-terminal-artifact-scope-v1` and exactly the fields `kind`, `pre_artifact_scope_receipts`, `artifact_get_receipt`, and `post_artifact_scope_receipts`. The raw pre/post pull+compare projections bind artifact-time head and merge base; independent mandatory snapshots bind lifecycle; the canonical exact-artifact GET binds repository/PR, channel/native ID, provider projection, semantic time, body/digest, grammar, and artifact commit. Clean and malformed evidence require the exact current tuple. A finding may instead preserve a proved-ancestor artifact-time head while repository, PR, and merge base still match the enclosing scope and normalized `scope.head` remains current. Every pre `Date` is strictly earlier than artifact semantic time, which is no later than artifact GET `Date`, which is no later than every post `Date`. Whole-second equality at the pre edge is inconclusive because it cannot order an old-scope artifact against a same-second same-head base retarget. An old artifact can reuse only a previously persisted identical receipt that already bracketed it. If it does not strictly follow every trustworthy pre observation, or the receipt is missing, malformed, unmatched, unstable, or over budget, the artifact is inconclusive; current metadata cannot scope it retroactively. The receipt is independent of request sidecars, supplies no request/run/artifact lineage, and does not prove an ABA-free interval. Version 1 uses artifact-publication scope: a complete receipt authorizes its publication-time tuple but does not attest the provider's internal input merge base. Only a valid same-head/different-merge-base request sidecar proves `base-changed-same-head`; a missing or malformed sidecar is `not-proved`, makes request policy unknown, and cannot veto an independently trustworthy terminal result. Requiring unavailable launch-time scope would restore the rejected request/run/artifact binding. A future provider-authenticated input-base marker governed by a predeclared provider profile may change this policy explicitly.
- Legacy receipt migration never adopts an old artifact retroactively or permits an agent-owned replacement request. A truly absent pre-v1 receipt is the narrow audit-only exception: it never supplies positive authority or becomes the selected completion basis. A later accepted receipt-bound result may still have a non-null `evidence_basis` that carries the item in `legacy_unreceipted_artifacts`; the legacy item does not by itself veto that result when every migration gate closes. A malformed or unstable receipt is not this exception. From each complete initial/final current raw inventory, derive the raw applicable provider-artifact set after ordinary actor/carrier/grammar/commit/thread validation and prove, one-to-one by exact `(channel, positive native id)`, the closed disjoint union `raw_applicable_artifacts = receipt_bound_normalized_artifacts ⊎ legacy_unreceipted_audit`. Every raw identity appears exactly once on the right; duplication, overlap, omission, or an unprojectable item fails closed. Each legacy item's trusted semantic server time is strictly earlier than both raw HTTP `Date` values in the selected newly receipted artifact's pre-artifact pull and compare receipts. Equality at whole-second authority, later/unknown/malformed time, an absent boundary, or an invalid receipt is `triple-inconclusive`. The selected clean/findings completion basis is always receipt-bound; a legacy item never completes the lane. An old clean is audit-only. An old top-level finding or all-resolved thread finding follows ordinary precedence and may be superseded by the later receipt-bound current-head clean. Any old unresolved applicable target thread remains blocking, and unresolved, malformed, or unknown legacy evidence cannot enter the tolerated list; it fails the partition directly. Preserve both complete raw inventories and require type-preserving initial/final stability of provider artifacts, applicable findings, joined threads, canonical provider nonterminal records, both partition members, and the partition itself. Preserve but evaluate request/reaction-only differences on their separate plane so they do not veto the stable result-present decision. Every non-null terminal-shaped `evidence_basis` includes one stable `(channel, id)`-sorted `legacy_unreceipted_artifacts` list; ordinary terminal bases use `[]`. Each item is exactly `{scope_authority: 'unreceipted-audit-only-v1', role, channel, id, server_time, artifact_commit, source_record_sha256}` under the authority's type rules. Derive the list independently from both raw inventories and emit only their identical projection. When rejected legacy evidence leaves no independently valid stable receipt-bound blocker basis, keep `evidence_basis: null`; never promote an unreceipted artifact for reporting. Initial/final equality proves neither an intermediate provider-state ABA nor stability after the final digest, and the report states both limitations. Recover only through a separately authorized ordinary substantive change that creates a new head, or one caller-owned manual exact `@codex review` trigger after the parent persisted the standard pre-artifact pull/compare scope pair. The agent neither performs nor repeats that POST and creates no request sidecar for it; request policy remains `unknown`, and reaction-only evidence is unavailable. Only a later terminal artifact, itself receipt-bound, that strictly follows both pre boundaries, closes this partition, completes the version-1 receipt/final-stability contract, and wins ordinary precedence may decide without request/run attribution. This preserves the fixed Action's result-present rationale: provider result authority remains independent of request/run lineage, ordinary older findings may be superseded, and only the existing unresolved-thread safety rule persists. A proved `base-changed-same-head` event cannot use the manual path and requires a real new head. Otherwise the lane remains `triple-inconclusive`; never manufacture an empty or anchor commit.
- The frozen reaction-history `as_of_server_time` bounds eligible historical artifact semantic times, not receipt collection time. An exact artifact GET or post-scope receipt may have a later `Date` when collected during the bounded decision/final reread; do not reject it solely for being observed after that cutoff.
- A strong current `terminal-payload` or `mixed` result may also have semantic time after declaration discovery when it arrives during the bounded provider wait. The frozen as-of bounds historical samples and the separate current reaction-only basis for `thumbs-up-clean`, not strong current terminal evidence.
- The evidence snapshot completely enumerated issue comments, reviews, every relevant review's raw REST associated inline comments, raw GraphQL review-thread and nested-comment pages, and relevant request-comment reactions. It canonically joins every exact-provider selected-review REST target child exactly once to GraphQL evidence. Fully fetched human, unrelated-bot, null-parent, and unrelated-only records remain audit context and cannot contribute resolution. Incomplete pagination, a broken cursor/link chain, missing target review association, duplicate/orphaned target, or missing typed target `isResolved` fails closed.
- Every counted provider artifact has exact REST `login: chatgpt-codex-connector[bot]` and exact REST `type: Bot`. The enclosing normalized `scope.head` is always the exact current `headRefOid`. A strong clean artifact's parsed/native commit equals that head and contains an explicit provider-authored no-findings outcome. A finding keeps its own artifact commit and may remain applicable on a proved ancestor through its parent-owned local Git ancestry receipt; it is never rewritten to current head or omitted merely to make projections agree. A terminal issue comment also satisfies the authority's closed canonical API/HTML, exact App, raw/normalized body, grammar, parsed-commit, immutable-current-scope, and edit-aware time schema. An empty `APPROVED` review is not clean evidence.
- A proved non-ancestor is raw audit-only and must not appear in normalized `active_top_level_findings` or `unresolved_thread_findings`. Treat any such normalized injection as a raw/normalized projection mismatch and select `unknown`; it cannot become a terminal finding or blocker candidate.
- Review state admissibility is separate from terminal-looking detection. A submitted review artifact uses exact state `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`. `PENDING` is nonterminal. `DISMISSED` is always terminal-looking; a missing or unknown state is likewise terminal-looking when a nonempty body or associated inline child supplies a terminal signal. Each is a whole-snapshot inconclusive blocker: original `submitted_at` is not a trusted state-transition time, so no later-looking clean may supersede it. See the authority's closed review-state rule.
- One uniquely observed invalid-state blocker may supply a stable inconclusive basis. Two or more cannot be ordered by list position, review ID, channel, or original `submitted_at`: keep all of them in the current-scope audit, set the selected source and `evidence_basis` to `null`, reject both terminal and reaction clean, and retain an independently validated unresolved target-thread basis only under its higher-priority blocker rule.
- Every exact-provider selected-review target-thread finding in the applicable history is resolved. Resolution authority comes only from typed `isResolved` in the complete raw GraphQL pages after canonical positive-decimal BigInt/REST-ID joining. Human, unrelated-bot, null-parent, and unrelated-only thread state is audit context and cannot resolve a target. `isOutdated` and synthesized REST `thread_id` / `thread_resolved` fields are not resolution. An unresolved target-thread finding or malformed target join blocks even when a later clean payload exists.
- After thread blockers are applied, the latest trustworthy terminal provider artifact is selected by server timestamp. Any latest equal-time set spanning issue-comment and review channels is `triple-inconclusive` before outcome or numeric-ID tie-breaking. Within one channel, malformed blocks, finding takes precedence over clean, and only then may a same-channel positive ID choose the basis.
- A later strong current-head clean may supersede an older top-level finding on the same or a proven ancestor head when that ancestor finding remains present in the complete projection, has no unresolved thread, and the complete snapshot contains no newer finding or malformed terminal evidence. A resolved ancestor target-thread finding may cease blocking under the thread rule; an unresolved applicable thread remains blocking. The weak reaction fallback never supersedes a finding.
- The selected `provider_profile` was recomputed from the final complete snapshot and bounded same-repository history using the predeclared definitions: `terminal-payload` is the default, `mixed` still makes terminal payload authoritative, `thumbs-up-clean` is the narrowly qualified reaction-only fallback, and `unknown` never accepts reaction-only clean evidence. An independently trustworthy current terminal clean/findings artifact uses `terminal-payload` even when the provider declaration is missing or historical traversal, pagination, endpoint/artifact budget, or sidecar validation fails; those historical adaptation-plane failures prevent only `mixed` and weak reaction authority. Optional history completes before a fresh final current reread, and elapsed work in one completed inventory cannot expire another inventory's authority. A current endpoint/artifact receipt failure or current identity, scope, lifecycle, thread, ancestry, grammar, selection, or final-stability failure still blocks.
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

Both bounded dual-source discovery passes also include the declaration's bound
PR as an explicit anchor, fully traverse it, and find the exact raw declaration record once in its
issue comments. Declaration authority and terminal classification are
orthogonal: the same artifact may prove the declaration and independently
classify as clean, findings, or malformed. Only an independently nonterminal
declaration record and the closed progress-only grammar are audit-only; a
declaration-only nonterminal scope is `confirmed-non-candidate`. Any other
exact-provider free-form prose fails closed, while an in-window
terminal-looking malformed artifact remains a historical candidate. A fully
parsed artifact at or before the exclusive lower boundary remains audit-only
`confirmed-non-candidate` evidence.

Each initial/final historical inventory independently embeds the closed
schema-version-4 raw discovery transcript. Its bounded updated-desc pull
traversal stops after the first full page containing a row at or before the
cutoff (or at natural end), while its fully paginated since-cutoff repository
issue-comments feed validates every exact-body `@codex review` record regardless
of actor or App, because discovery must seed a canonically routed PR before
complete actor, raw-equal detail, and sidecar validation accepts the request or
selects `unknown`. Canonical ordinary-issue `@codex review` comments are
validated, retained, and budget-charged as raw-only non-seeds; mismatched or
ambiguous PR-like routing fails closed. Canonical decimal page and native-ID
tokens are limited to 39 digits and 128 bits before integer conversion;
overlong values fail closed without raising. Reactions may not update PR metadata. The frozen as-of bounds
semantic historical outcomes, not when the live pull endpoint was observed.
REST Link page relations are validated semantically against the fixed HTTPS
host, path, and non-page query map; omitted page and a literal canonical
`page=1` are equivalent, while each raw `rel=next` URL is followed exactly. A
terminal GraphQL page requires typed `hasNextPage == false`; `endCursor` may be
null or a non-empty string, and a retained terminal cursor never triggers
another fetch.
Updated-desc rows later than as-of therefore form a contiguous validated future
prefix; they stay raw and budget-charged and seed the complete
pull/compare/comments/reviews/inline/thread/reaction traversal. Newer pull
rows, request-bound PRs, and exact current/declaration anchors form the raw
detail union. Historical
reaction-only eligibility requires the parent in that feed and both request and
response in the frozen interval. The fixed parser classifies every union-seeded
PR retained in the semantic union only after fully parsing every raw seed, and
excludes current only after full parsing. Boundary witnesses do not consume the
512 raw-union-seeded-PR cap; raw union member 513, incomplete source/detail closure, or any
budget overflow selects `unknown` without truncation. A version-3 transcript
cannot prove reaction fallback. Only
`compare.merge_base_commit.sha` supplies `pr_merge_base`. The fixed projector
uses deterministic stable `{pull_number, base_oid, head_oid}` retained-seed
identity rather than pull-list `updated_at`, raw row digest, or endpoint order,
then derives scope/order/source-evidence entries and count while the closed
candidate evaluator independently validates every complete candidate.
Self-consistent summaries or selected samples do not prove completeness. The
parent-owned `request_scope_receipts` array and fixed
`scope_discovery_projection` are stored beside the transcript; the latter binds
the cutoff (with as-of separately frozen in the history envelope), stop reason,
stable retained pull seeds, request IDs/PRs/digests, anchors, and the fixed
semantic union. Its closed `retained_pull_scope_audit` covers every complete
local-union seed with exact pull/base/head/merge-base/lifecycle identity,
including request/anchor-only and record-free scopes. A typed recent pull-list
`state` must also equal the pull-detail lifecycle state inside each traversal.
A future-prefix-only scope enters the closed
`future_prefix_omission_eligibility_audit` only when complete detail proves no
request-feed or anchor co-seed, no in-window or provider/policy-bearing
semantic record, and only existing-rule removable confirmed-different
post-as-of activity, if any. The eligibility audit is a closed subset of the
`retained_pull_scope_audit` identities. The per-traversal projection still retains every
eligible scope. The initial/final joint coordinator may remove a scope only
from the derived stable comparison, only when it appears in exactly one
complete local union and is eligible there. This one-sided omission is the only
scope-removal coordination exception; the separately validated complete
stop-reason forms use only the transport-label normalization described below.
A PR present in both unions always
remains and its retained identity/lifecycle and semantic projection must
compare exactly, allowing unrelated post-as-of human activity without erasing
an existing scope. Eligibility items present on both sides must also be
type-preserving identical. Raw discovery/detail bytes and all budget charges
are never omitted. After both traversals independently prove complete, the
joint stable comparison treats `window-boundary-complete` and
`natural-end-complete` as equivalent complete termination forms. The exact
per-traversal stop reason remains in raw-derived and stored evidence; only that
transport label is excluded from the derived comparison, and incomplete or
malformed pagination remains fail-closed.

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
cache-miss order is no-hash admission, a bounded sorted-key/type-tagged
non-authoritative baseline digest, the owning ledger's uncached validator or
producer, and then a bounded confirmation digest. A failed ledger discards the
baseline and defeats any truthy partial result. The admission, baseline, and
confirmation summaries and both cold digests must match before returning or
memoizing; a mismatch does neither. Healthy positive and negative entries
retain only the confirmed digest. A cache hit remains no-hash admission plus
one content digest checked against that entry. This protects exact subject
content stability across cold validation rather than only identity or shape,
but cannot exclude an `A -> B -> A` transition between the two cold digests or
a mutation after the final confirmation hash; immutable snapshots and a fresh
reread/context remain required. It never serializes a complete
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
response, and 64 MiB per work unit). The 512 raw-union-seeded PRs, 512 controlled
requests, 8192 attempts, 4096 retained pages, and 900-second deadline are
playbook extensions and are not attributed to that Action. The stable
future-prefix semantic projection is likewise a playbook extension; it
preserves the Action-aligned provider-result authority rule rather than
changing what a trustworthy result means.

Classify actor identity and validate each carrier's complete schema, native
IDs, canonical URLs, and joins before applying the frozen as-of cutoff. A
terminal issue comment is classified jointly by actor and App: only the exact
Bot actor plus exact `performed_via_github_app.slug ==
"chatgpt-codex-connector"` is exact. If either half claims the provider while
the other is absent or conflicts, the record is ambiguous/provider-like and
fails closed; never classify it as a confirmed-different suffix. A
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
confirmed-different future review. Schema version 4 has no independent
inline-child timestamp, so it cannot infer that a human reply on an in-cutoff
provider review is a removable later suffix; the child remains semantic drift.
Observed base/head/lifecycle drift inside either traversal, retained or
shared-eligibility base/head/merge-base/lifecycle drift across traversals, or any
incomplete source/detail page also fails closed; none can be normalized away as
future-prefix churn.

Validate every raw-union-seeded PR before sorting, including candidates outside the
newest 10 and scopes that become confirmed non-candidates. Validate current
separately and never count it toward the three-outcome history minimum. Every
historical sample and current reaction record binds the exact
`@codex review` parent's eight fields, exact request-time scope sidecar, its
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
