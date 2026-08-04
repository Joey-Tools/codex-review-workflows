# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, lifecycle tuple `state` / `merged` / `merged_at`, `baseRefName`, `baseRefOid`, and `headRefOid`, then independently validate the selected PR's unique local merge base. Only exact `state == "open"`, `merged == false`, and `merged_at == null` is an eligible lifecycle.

- The only supported host is exact `github.com`. Every other host is unsupported, including `sqbu-github.cisco.com` and every GitHub Enterprise host.
- Treat any operating identity in `{hoteng, hoteng_cisco}` as unsupported. Another identity on `github.com` is only an eligible candidate; it does not by itself prove that the integration or service is available.
- When authenticated discovery proves no PR, or an unsupported host/identity is directly known, record `requested: triple`, `effective: double`, and the exact reason without posting a request. The fixed authority baseline has an empty accepted structured capability/installation schema set, so integration/service state cannot currently enter this fallback. Free-form provider prose, absence, timeout, permission error, and generic HTTP/network failure are inconclusive.
- On a supported PR, allow at most one acceptable exact `@codex review` request per unchanged head. Reuse the recorded request when one already exists; never post a second request on that same `headRefOid`.

## Deterministic Range And PR Discovery

Resolve the local range and PR selector independently. Preserve an explicit frozen `base_sha..head_sha` as the authoritative local-lane range before any PR probe. Explicit-range-only standalone single/double needs no PR probe. A frozen range never selects a PR: PR-specific work and triple use an explicitly named PR, otherwise the complete set of open PRs associated with the exact current head repository/branch. Exactly one associated PR selects it. More than one is `blocked-input` for the GitHub/PR-specific lane because the required explicit PR selector is absent; the caller must name the PR, and a frozen range does not cure that ambiguity. Fully scoped local lanes may still run, while any lane that still depends on PR selection stays blocked. Do not select a candidate by recency, base, number, draft state, or title. Once a PR is selected, its explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`.

This narrow open-PR selector is not historical discovery authority for
`thumbs-up-clean`. It cannot replace schema-version-4 updated-desc boundary
discovery, the since-cutoff repository request-comment feed, the two anchors,
their union/detail closure, or post-parse current-scope exclusion.

First obtain the exact current branch and head repository owner. A detached HEAD or unknown head owner cannot drive implicit PR association. Then use an authenticated, paginated lookup and retain the returned candidate array:

```sh
git branch --show-current

gh api --hostname <host> --method GET --paginate --slurp \
  repos/<owner>/<repo>/pulls \
  -f state=open \
  -f 'head=<head-owner>:<current-branch>' \
  -f per_page=100 \
  --jq '[.[][] | {number,html_url,base_ref:.base.ref,base_sha:.base.sha,head_ref:.head.ref,head_sha:.head.sha,head_owner:.head.repo.owner.login}]'
```

An authenticated successful lookup returning `[]` proves the no-PR path. A failed, partial, unauthenticated, or ambiguous probe does not. No PR does not define the local review range: require either an explicit committed range or an explicitly named target/base, then resolve and freeze `<merge_base>..HEAD`. Never guess the target/base from repository defaults, upstream configuration, branch names, or conventions. Missing scope input from an otherwise clean checkout is `blocked-input`; use `blocked-authorization` only when the intended scope includes dirty/untracked state and an unauthorized branch or anchor commit would be required to represent it.

For the selected PR, obtain authenticated metadata independently from the caller's range and bind the request to the already discovered host. Do not use `gh pr view --repo` for this host-sensitive preflight because that form does not preserve `<host>`:

```sh
gh api --hostname <host> --method GET \
  repos/<owner>/<repo>/pulls/<number> \
  --jq '{number,url:.html_url,state,merged,merged_at,baseRefName:.base.ref,baseRefOid:.base.sha,headRefOid:.head.sha}'

GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<pr_base_oid>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<pr_head_oid>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git merge-base --all <pr_base_oid> <pr_head_oid>
```

Require the exact open lifecycle tuple, non-empty `baseRefName`, full immutable base/head OIDs, locally complete commit objects, and exactly one full merge-base result; record it as `pr_merge_base`. Missing, contradictory, or ambiguous lifecycle metadata is `blocked-input` (`pr-lifecycle-unverified`) and `triple-inconclusive`. A selected closed-unmerged PR is `blocked-input` (`selected-pr-closed`): never post a request or claim readiness; when a separately valid frozen local range exists and no request/service start occurred, its third lane is directly unavailable and requested triple may run as effective double. A selected merged PR is terminal `already-merged` (or `blocked-input` / `selected-pr-merged` when the caller requires blocker vocabulary), and no request, CI, or merge loop continues. An observed closed or merged state at any mandated snapshot after request/service start invalidates its evidence and remains `triple-inconclusive`; never retroactively call it effective double. Missing or ambiguous base/head metadata, missing local objects, and zero or multiple merge bases are `blocked-input` (`scope-unverified`), not permission to guess or fetch lazily. If no explicit range exists, freeze `pr_merge_base..pr_head_oid`. If one exists, require exact endpoint equality. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, do not start or count PR-specific lanes from it, and never describe any range-only findings as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR remains unaffected.

Use host-bound REST metadata before and after the request, including the selected PR's base identity. Fully paginate and slurp every list that participates in request-policy auditing or the provider evidence snapshot:

```sh
gh auth status --hostname <host>
gh api --hostname <host> user --jq .login

gh api --hostname <host> --method GET \
  repos/<owner>/<repo>/pulls/<number> \
  --jq '{number,url:.html_url,state,merged,merged_at,baseRefName:.base.ref,baseRefOid:.base.sha,headRefOid:.head.sha}'

# One parent-owned request-time sidecar; retain each response separately.
gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/pulls/<number>

gh api --hostname <host> --method GET --include \
  'repos/<owner>/<repo>/compare/<pre_base_oid>...<pre_head_oid>'

gh api --hostname <host> --method POST --include \
  repos/<owner>/<repo>/issues/<number>/comments \
  -f body='@codex review'

gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/pulls/<number>

gh api --hostname <host> --method GET --include \
  'repos/<owner>/<repo>/compare/<post_base_oid>...<post_head_oid>'

# Before waiting for a new terminal artifact, capture the artifact-scope pre pair.
gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/pulls/<number>

gh api --hostname <host> --method GET --include \
  'repos/<owner>/<repo>/compare/<artifact_pre_base_oid>...<artifact_pre_head_oid>'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/pulls/<number>/reviews?per_page=100' \
  --jq '[.[][] | {id,user:{login:.user.login,type:.user.type},commit_id,submitted_at,state,html_url,body}]'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/issues/<number>/comments?per_page=100' \
  --jq '[.[][] | {id,user:{login:.user.login,type:.user.type},app_slug:.performed_via_github_app.slug,created_at,updated_at,html_url,body}]'

# After observing a bracketed candidate, fetch that exact artifact and the post pair.
gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/issues/comments/<artifact_comment_id>

# For a review candidate, use this exact GET instead of the issue-comment GET.
gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/pulls/<number>/reviews/<artifact_review_id>

gh api --hostname <host> --method GET --include \
  repos/<owner>/<repo>/pulls/<number>

gh api --hostname <host> --method GET --include \
  'repos/<owner>/<repo>/compare/<artifact_post_base_oid>...<artifact_post_head_oid>'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/issues/comments/<request_comment_id>/reactions?per_page=100' \
  -H 'Accept: application/vnd.github+json' \
  --jq '[.[][] | {id,user:{login:.user.login,type:.user.type},content,created_at}]'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/pulls/<number>/reviews/<review_id>/comments?per_page=100' \
  --jq '[.[][] | {id,pull_request_review_id,user:{login:.user.login,type:.user.type},commit_id,original_commit_id,path,line,original_line,side,html_url,body}]'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/commits/<head_sha>/check-runs?per_page=100' \
  --jq '[.[].check_runs[] | {id,name,status,conclusion,head_sha,started_at,completed_at,details_url,app_slug:.app.slug}]'
```

The five request-time calls above are one write path, not five independent
probes that may be replayed. Before the POST, derive the pre base/head from the
raw pull body and bind them into the pre compare URL. After the one and only
POST, repeat that derivation for the post compare URL. Convert each response to
the authority's exact six-field raw receipt
`{method, request_url, status, date_header, body_utf8, body_sha256}`; do not
retain only the `--jq` projection. The pull and compare bodies must derive the
same `(repository, pr, pr_merge_base, head)` before and after the write, and the
exact `201` POST body must independently project the same controlled request's
eight fields, including closed `user: {login, type}` actor identity. Preserve
all individual response Date values and ordering.

Store the resulting `parent-recorded-request-scope-v1` object in the
parent-owned `request_scope_receipts` sidecar. Every accepted request has
exactly one matching receipt and every receipt matches exactly one request.
This sidecar is a sibling of the raw discovery/current inventory; do not add it
to `discovery_endpoint_transcript` schema version 4 or invent another fetch
kind. If any observed request lacks a valid one-to-one sidecar, set
`request_policy.status: unknown`, do not POST again, and exclude that request
and its reactions from reaction-profile authority. Continue to evaluate an
independently complete terminal payload normally, but only through its own
artifact-time scope receipt below.

For each terminal-looking exact-provider artifact admitted to the receipt-bound
normalized decision member, retain one singular closed artifact-wrapper field
`artifact_scope_receipt`. Its object contains exactly `kind`,
`pre_artifact_scope_receipts`, `artifact_get_receipt`, and
`post_artifact_scope_receipts`, with kind
`parent-recorded-terminal-artifact-scope-v1`. Convert each raw response to the
same six-field receipt shape used above. The pre/post pull+compare bodies must
independently project the same artifact-time head and merge base. Clean and
malformed evidence require the exact current tuple; a finding may preserve a
proved-ancestor artifact-time head while normalized `scope.head` remains
current. The exact artifact GET must
bind repository/PR, issue-comment or review channel, native ID, exact provider
projection, raw body/digest, trusted semantic time, grammar, and artifact
commit. Lifecycle is still proved by the separate mandatory snapshots; do not
invent it from these receipt bodies.

Parse the actual full base/head OIDs from each pull response and use those
values—not a fixture-derived or PR-number-derived SHA—to construct its exact
compare URL. The compare response must repeat both as `base_commit.sha` and
`head_commit.sha` and supply the unique `merge_base_commit.sha`; a body for a
different head is not scope evidence.

Require every pre response `Date` to be strictly earlier than the artifact
semantic server time, that time to be no later than the artifact GET response
`Date`, and every post response `Date` to be no earlier than the artifact GET
response `Date`. Capture the pre pair before waiting for the result. If the
candidate does not strictly postdate every trustworthy pre observation, it is
inconclusive unless
the parent reuses a previously persisted, still-identical receipt that already
bracketed that exact artifact. Never create a retrospective pre boundary from
current PR metadata. The receipt is independent of request sidecars and proves
neither request/run/artifact lineage nor an ABA-free interval. A missing
request sidecar still closes only request/reaction authority; a missing or
unstable artifact receipt blocks the wrapped terminal artifact.
A truly absent pre-v1 receipt is the narrow audit-only exception: keep the
strictly older, otherwise well-formed artifact raw, exclude it from normalized
receipt-bound wrappers, and admit it only through the closed
`legacy_unreceipted_audit` partition below. It never supplies positive
authority or becomes the selected completion basis. A later accepted
receipt-bound result may still have a non-null `evidence_basis` that carries
the item in `legacy_unreceipted_artifacts`; the legacy item does not by itself
veto that result when every migration gate closes.

This v1 envelope uses **artifact-publication scope**. If its complete
pre/GET/post receipt binds the current tuple, that tuple authorizes the artifact
even when request history is unbound or a caller says the provider started work
under an earlier merge base. The receipt does not attest the provider's
internal input merge base. Only a valid same-head/different-merge-base request
sidecar proves `base-changed-same-head`; a missing or malformed sidecar is
`not-proved`, makes request policy unknown, and cannot veto an independently
trustworthy terminal result. Requiring an unavailable launch-time tuple would
restore the rejected request/run/artifact binding. A future
provider-authenticated input-base marker governed by a predeclared provider
profile may change this policy explicitly.

The strict pre edge is intentional: GitHub supplies only whole-second time
authority for these fields, so equality cannot distinguish an artifact created
under the old base earlier in the second from a later same-head retarget and
pre read. Equality is inconclusive unless a previously persisted receipt
already supplied a strictly earlier pre boundary for that exact artifact.

Do not apply the frozen reaction-history `as_of_server_time` to artifact
receipt collection `Date` values. It bounds eligible historical artifact
semantic times; the exact artifact GET and post-scope reads may occur later as
part of the bounded decision/final reread, provided the receipt envelope and
all other stability checks hold.

Do not apply that history cutoff to the semantic time of a strong current
`terminal-payload` or `mixed` artifact either. It may arrive during the bounded
provider wait after declaration discovery. The as-of still bounds historical
samples and the separate current reaction-only basis for `thumbs-up-clean`.

A fully sidecar-bound request for the same repository and PR but a different
head is old-epoch audit evidence. When a seeded scope has no current-epoch
provider artifact or reaction and every controlled request is proved old-head,
produce no result entry: classify the exact current PR as `current` and another
seeded PR as `confirmed-non-candidate`. This audit-only exception requires
one-to-one closure over every request and receipt. A missing, malformed, extra,
or unmatched sidecar and a same-head/different-merge-base tuple remain
fail-closed; neither may be relabelled as an old epoch.

The sidecar binds request-time scope, not request/run lineage or continuous
history. A child reaction from a different receipt-derived scope epoch cannot
be relabelled into the current tuple. Matching pre/post observations do not
exclude an intermediate `A -> B -> A` change, so never claim an ABA-free
transaction or lifecycle attestation.

The [GitHub REST issue-comment reaction list endpoint](https://docs.github.com/en/rest/reactions/reactions#list-reactions-for-an-issue-comment)
returns each reaction ID but no reaction self URL. Do not synthesize a
standalone reaction resource URL. Record the exact canonical fully paginated
parent endpoint used for the read plus the returned positive numeric reaction
ID; the tuple `(parent_reactions_api_url, reaction.id)` is the stable native
identity. Re-fetch that parent endpoint and compare the returned record with
the same tuple during the final re-read. A caller-supplied self URL, an
aggregate count, a noncanonical ID, or another API host is not evidence.

When `thumbs-up-clean` is being considered, fetch its predeclared declaration
artifact again from the canonical resource rather than trusting copied fields:

```bash
gh api --hostname github.com --method GET --include \
  'repos/<owner>/<repo>/issues/comments/<declaration_comment_id>'
```

Retain the direct JSON record separately from the response headers. Validate
the exact Bot/App identity, repository/PR/API/HTML binding, artifact ID, body
line, and server timestamps defined by the authority. On the first direct
declaration issue-comment REST GET, parse the authenticated TLS response's
`Date` header as the history `as_of_server_time` and record that exact canonical
issue-comment URL as `as_of_api_url`. Freeze both values before discovery and
derive the fixed 2,592,000-second interval. The final declaration re-read
checks the same URL and JSON artifact but does not replace the first `Date` or
move the window. A current-PR endpoint, local clock, caller-supplied declaration
object, or bare `window_days: 30` label is not evidence.

After freezing that receipt and before classifying any historical candidate,
independently fetch schema-version-4 bounded dual-source discovery for each
initial and final inventory:

```bash
gh api --hostname github.com --method GET --include \
  'repos/<owner>/<repo>/pulls?state=all&sort=updated&direction=desc&per_page=100'
gh api --hostname github.com --method GET --include --paginate \
  'repos/<owner>/<repo>/issues/comments?sort=updated&direction=desc&since=<RFC3339-cutoff>&per_page=100'
```

The trusted parent fetch path must preserve every page separately with its
exact request URL, exact integer status, raw `Link` header or null, raw UTF-8
body, and recomputed body digest. Pull detail and compare are unpaginated
direct-object responses: each has exactly one page, a null `Link`, and a JSON
object root. Collection responses use an array root on every page; each
Link relation preserves the fixed HTTPS host, path, and decoded non-page query
map, uses one literal canonical `page=N` token, and treats omitted page and
`page=1` as the same first page. The fetch path follows the exact raw `next` URL
through consecutive page numbers. For updated-desc pulls, a stable semantic
`last` cannot point after a no-`next` natural end or before the current `next`.
The fetch path follows updated-desc pull pages only through the
first retained page containing an exact `updated_at <= window_start_exclusive`
witness, or through natural end; blindly paginating cumulative repository
history is forbidden. The repository issue-comment source is fully paginated
from the frozen cutoff. A `--jq` projection, `gh pr list`, open-only branch
selector, slurped candidate array, or reuse of the initial bytes for the final
inventory is not raw discovery authority. Newer pull rows, canonically
PR-routed strict controlled-request parents from the comment feed, and exact
current/declaration anchors form the raw detail union. Canonical ordinary-issue
`@codex review` comments remain validated and budget-charged raw-only non-seeds.
Canonical decimal page and native-ID tokens are limited to 39 digits and 128
bits before integer conversion; overlong values fail closed without raising.
The frozen as-of bounds semantic history rather than
raw observation time. Validate rows with `updated_at > as_of_server_time` as a
contiguous descending future prefix, retain and charge them, and start exactly
the same full detail traversal for them as for other raw seeds. Every canonical
PR number in that raw union starts exactly
one complete detail traversal, including the current PR and PRs later
classified as confirmed non-candidates. Both traversals must find the exact declaration raw
record once in that PR's fully paginated issue comments while still treating
the direct canonical declaration GET as declaration authority. Declaration
authority and terminal classification are orthogonal: the same artifact may
prove the declaration and independently classify as clean, findings, or
malformed. Only an independently nonterminal declaration record and the closed
progress-only grammar are audit-only; a declaration-only nonterminal scope is
a confirmed non-candidate. Any other exact-provider free-form prose fails
closed, and an in-window terminal-looking malformed record remains a historical
candidate. A fully parsed malformed record at or before the exclusive lower
boundary remains audit-only `confirmed-non-candidate` evidence. Only the
raw-union/detail PRs count toward `max_seeded_pull_requests: 512`, including
future-prefix-only seeds; boundary witnesses and cumulative old PRs do not. A
513th raw union member or any source,
detail, child-page, count, byte, or time budget overflow makes the historical
adaptation plane unavailable; never truncate and continue. Reaction-only
authority therefore uses `unknown`. An independently trustworthy strong
current terminal artifact instead retains `terminal-payload` under the
plane-isolation rule below.

After each raw seed's complete pull/compare/comments/reviews/inline/thread/
reaction traversal, derive the fixed discovery projection from deterministic
positive-number `{pull_number, base_oid, head_oid}` identities. Do not include
pull-list `updated_at`, raw pull-row digest, or endpoint order in that stable
projection. Require typed pull-list `state` to match pull-detail lifecycle state
whenever that list source contains the PR. The closed
`retained_pull_scope_audit` covers every complete local-union PR with exact
pull/base/head/merge-base/lifecycle identity, including request/anchor-only and
record-free scopes. A future-prefix-only scope enters the closed
`future_prefix_omission_eligibility_audit` only when no request-feed or anchor
co-seed exists and full detail proves no in-window or provider/policy-bearing
semantic record plus only existing-rule removable confirmed-different
post-as-of activity, if any. The eligibility audit is a closed subset of the
`retained_pull_scope_audit` identities. Keep the eligible scope in the traversal's local
projection, and keep all raw rows/detail pages and budget charges. The
initial/final joint coordinator may omit it only from the derived stable view,
and only when the PR occurs in exactly one complete local union. A PR present
in both traversals always remains and compares exactly, allowing unrelated
post-as-of human activity without hiding scope or lifecycle drift. Shared
eligibility items must also be type-preserving identical. After both
traversals independently prove complete, the joint stable comparison treats
`window-boundary-complete` and `natural-end-complete` as equivalent complete
termination forms. Preserve the exact stop reason in each raw-derived and
stored projection; omit only that transport label from the derived comparison,
and never normalize incomplete or malformed pagination.
A controlled request, exact or ambiguous provider/policy evidence, cross-cutoff
edit, retained or shared-eligibility identity/lifecycle drift, incomplete pagination,
or failed join remains fail-closed.

REST does not expose PR review-thread resolution. Preserve the fully paginated
raw REST inline-comment records without adding `thread_id`,
`thread_resolved`, or `is_resolved`. Separately preserve the raw GraphQL pages
from a minimal query that pages
`reviewThreads(first: 100, after: $cursor)`. On every page, also request
`repository.nameWithOwner` and `pullRequest.number`, then require both values
to equal the exact selected repository and PR before consuming even an empty
thread connection. Record each thread's stable `id`, typed `isResolved`, typed
`isOutdated`, and
`pageInfo { hasNextPage endCursor }`. For every paginated thread-comment node,
record GraphQL `id`, REST-compatible `fullDatabaseId: BigInt`, `url`, and
`pullRequestReview { id fullDatabaseId }`. Schema version 4 paginates only the
outer `reviewThreads` connection: it starts with a null cursor, requires each
next request cursor to equal the previous raw `endCursor`, and ends only at
typed `hasNextPage == false`. A terminal GraphQL page requires typed
`hasNextPage == false`; `endCursor` may be null or a non-empty string, and a
retained terminal cursor never triggers another fetch. Each nested `comments`
connection must be complete in its first raw response with typed
`hasNextPage == false`; its terminal cursor follows the same rule. If any
nested response reports another page, fail closed
as profile `unknown`; schema version 4 cannot encode a child-cursor fetch. A
future schema version must define and bind that fetch instead of flattening
multiple normalized pages into one fabricated raw response.

When a top-level GraphQL `errors` member is present, accept only an empty
array. Reject `null`, every non-array value, and every nonempty array on every
page; a nonempty array is partial evidence even when the response also
contains usable-looking `data`.

Normalize each non-null GraphQL BigInt and positive-integer REST JSON ID to
canonical positive decimal text before comparison; reject booleans, floats,
zero, signs, and leading zeros. For the selected review, derive join targets
only from exact-provider REST children whose positive canonical REST `pull_request_review_id`
equals that selected review ID. Join every target
exactly once to a raw GraphQL thread comment by normalized
`id == fullDatabaseId`, require `pullRequestReview.fullDatabaseId` to equal the
same selected review ID, and corroborate the URL. A noncanonical target key,
orphan, duplicate mapping, URL conflict, parent-review conflict, missing page,
broken cursor chain, or non-boolean target `isResolved` makes the snapshot
incomplete and fails closed.

Keep fully fetched human and unrelated-bot comments, null-parent replies,
non-target GraphQL comments, and threads with no target child in the raw audit.
They cannot contribute resolution or repair a malformed target join. Missing
or ambiguous actor identity is not a confirmed non-target and still fails
closed. `isOutdated` is audit context only and never substitutes for target
`isResolved`. Any derived thread summary is recomputed from these raw pages and
is not independent authority.

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Re-read the exact request from the authenticated API and keep its ID, URL, and server `created_at`, the surrounding before/after lifecycle plus `baseRefName` / `baseRefOid` / `headRefOid` observations, immutable selected-PR `range_origin.kind` / `base_sha` / `head_sha`, and the accepted terminal result URL/time/author. The origin kind is exactly `caller-supplied` or `pr-derived`; never infer it from a later parent-provided range or overwrite original caller endpoints. Revalidate the exact open lifecycle tuple during initial selected-PR preflight, immediately before posting, immediately before accepting a result, and during final readiness/merge verification. Immediately before accepting the result, also revalidate both endpoint objects, recompute the unique `pr_merge_base`, and require the frozen range still to equal `pr_merge_base..pr_head_oid`; an observed non-open lifecycle at a mandated snapshot, a changed head, or a changed merge base invalidates whole-PR lane evidence.

These REST lifecycle reads are point-in-time snapshots. They do not prove that no intermediate close-and-reopen occurred between mandated probes. Do not claim a complete lifecycle-history attestation from them. If separately collected, authenticated, fully paginated lifecycle-event history shows a post-start close, reopen, or merge, invalidate the evidence; missing event-history evidence does not strengthen the snapshot claim.

Before posting, inspect authenticated complete issue-comment history and the bounded audit record. Producer policy permits the parent to post one exact `@codex review` only after both local lanes are terminal and only when no request already exists for the unchanged current scope. Never post a second or third request. Record `early-request-observed` when a request preceded the local terminals. Record `duplicate-observed` when more than one same-scope request exists, including an overlapping or pending extra request. These are outcome-neutral warnings. A lone compliant pending request is not a warning; it remains pending unless a trustworthy terminal artifact already exists. Request markers, counts, ordering, and inferred request/run lineage are not provider verdict evidence.

Legacy receipt migration never adopts an old artifact retroactively. The agent
never POSTs a replacement same-scope request. Preserve complete initial and
final current endpoint inventories and, after the ordinary raw actor, carrier,
grammar, commit-applicability, inline-join, and thread validation, derive their
raw applicable artifact identities. Retain exact-provider terminal-looking
identities whose grammar, role, or required thread state is malformed or
unknown so the partition, rather than pre-filtering, fails closed. In each
pass, prove one-to-one by exact `(channel, positive native id)` that
`raw_applicable_artifacts = receipt_bound_normalized_artifacts ⊎ legacy_unreceipted_audit`.
Reject a duplicate, overlap, omission, or raw artifact that cannot enter
exactly one closed member.

Read the selected newly receipted artifact's two raw pre-scope HTTP `Date`
values directly from its pull-detail and compare receipts. Every legacy item's
trusted semantic server time must be strictly earlier than both values in both
passes. Whole-second equality, a later time, an unknown or malformed time or
`Date`, a missing boundary, an invalid receipt, or an unprojectable/malformed
legacy artifact is fail-closed evidence. The selected completion artifact must
come from the receipt-bound normalized member; the legacy member never supplies
clean or findings completion. Within that legacy member, old clean is
audit-only, an old top-level or all-resolved thread finding follows ordinary
precedence and may be superseded by a later receipt-bound current-head clean,
and any old unresolved applicable target thread remains blocking. Unresolved,
malformed, or unknown legacy evidence cannot enter the tolerated list; it makes
the partition fail closed instead.

Require type-preserving equality across the two passes for the provider
decision-authority projection: terminal artifacts, applicable findings, joined
thread state, canonical provider nonterminal audit records, both partition
members, and the partition itself. Preserve the full raw inventories, but keep
request/reaction-only differences on their existing separate plane so they do
not veto an otherwise stable result-present decision. Serialize the closed
`evidence_basis.legacy_unreceipted_artifacts` list under the authority's exact
seven-field item schema; every ordinary non-null terminal-shaped basis uses
`[]`. Derive the list independently from both raw inventories, require the two
projections to be type-preserving identical, then emit only their common
canonical `(channel, id)`-sorted value. When rejected legacy evidence leaves no
independently valid stable receipt-bound blocker basis, keep literal
`evidence_basis: null` rather than promoting an unreceipted artifact merely for
reporting. Equal projection/digest pairs prove neither an intermediate provider
state ABA nor stability after the final digest; report those limits and treat a
later observation as invalidating the prior decision.

Recover only after a separately authorized ordinary substantive change creates
a new head, or after the caller explicitly performs one caller-owned manual
exact `@codex review` trigger on the unchanged head after the parent has
persisted the standard pre-artifact pull/compare scope pair. The agent neither
performs nor repeats that POST and does not synthesize its request sidecar.
Request policy therefore remains `unknown`, and reaction-only evidence is
unavailable. Only a later terminal artifact, itself receipt-bound, that
strictly follows both pre boundaries, closes the partition, passes the complete
version-1 artifact receipt/final-stability contract, and wins ordinary
precedence may decide without request/run attribution. This keeps the fixed Action's
result-present authority: a provider result, not request lineage, completes the
lane; ordinary older top-level/resolved findings can be superseded; and the
existing unresolved-thread rule remains the safety blocker.
A proved `base-changed-same-head` event cannot use the manual path and requires
a real new head. Otherwise remain `triple-inconclusive`; never manufacture an
empty or anchor commit to create a new epoch.

### Provider-evidence reconciliation

Use [github-codex-evidence-authority.md](github-codex-evidence-authority.md) as
the authoritative decision contract.

Only provider-result authority is inherited from the fixed atomic baseline:
source `JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`,
released Action
`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`,
common tree `d03de9035d20f285e6a93986d436403b4a30e9bc`, the complete 15-path
manifest, and the result-present regression rationale pinned in that reference.
Floating refs, prose-only comparisons, and partial runtime diffs are not
anti-drift evidence. The inherited decision is:
complete trustworthy current-scope results decide without request/run
attribution, and early or duplicate requests remain outcome-neutral producer
warnings. Bounded dual-source discovery schema version 4, raw target-thread proof,
exact whole-PR lifecycle/scope, the closed terminal carrier, request-time scope
sidecars, independent artifact-time whole-PR scope receipts,
ancestor-finding projection, declaration discovery, and conditional `+1`
fallback are deliberate playbook extensions, not behaviour attributed to the
fixed Action. Findings, malformed terminal artifacts, unresolved
applicable target threads, incomplete pagination, stale scope, and unstable
final evidence still fail closed.

Build one complete current-scope snapshot from:

- every fully paginated issue comment and review;
- every fully paginated associated inline-comment list for relevant reviews;
- every raw, fully paginated GraphQL review-thread and nested-comment page,
  with every exact-provider selected-review REST target child canonically
  joined exactly once and resolution taken only from that target thread's
  typed `isResolved`; human, unrelated-bot, null-parent, and unrelated-only
  records remain audit context;
- every fully paginated reaction list relevant to a controlled request, plus
  that request's exact one-to-one parent-owned request-time scope sidecar; and
- every terminal-looking exact-provider artifact's singular closed
  `artifact_scope_receipt`, including its pre pull/compare, exact artifact GET,
  and post pull/compare raw responses; and
- the lifecycle, base/head, merge-base, and check/run observations needed to validate scope and distinguish liveness from terminal evidence.

Normalize stable API IDs, source channel, exact provider identity, artifact commit, enclosing current `scope.head`, and semantic server time for each candidate. A review uses `submitted_at`; an unedited issue comment uses `created_at`; an issue comment whose current body was edited uses `updated_at`; and a reaction uses `created_at`. Record the selected native field and do not substitute client receipt order or local clock time. Every terminal issue comment must satisfy the authority's closed record schema, including canonical API and HTML URLs, exact Bot/App identity, raw and normalized body, `created_at`, `updated_at`, selected time/field, grammar status, parsed full artifact commit, and immutable current scope; review-only fields are rejected. Clean must bind the exact current `scope.head`. A finding keeps its parsed/native commit and may remain applicable when local ancestry receipts prove it is current or an ancestor; never rewrite it to current head or omit it from the complete projection. Apply only the authority's fixed terminal-payload grammar: clean issue comments use the exact `Codex Review: Didn't find any major issues.` lead plus one lowercase full-SHA `Reviewed commit` marker; clean reviews use exact `APPROVED`, a native lowercase full-SHA current-head `commit_id`, and body `No findings.`. Every other terminal-looking exact-provider payload is malformed unless it matches the fixed finding or inline-parent branch. Review state admissibility is separate from terminal-looking detection: exact `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED` may enter the grammar; `PENDING` is nonterminal; `DISMISSED` is always terminal-looking; and a missing or unknown state is terminal-looking when a nonempty body or associated inline child supplies a terminal signal. Each invalid-state terminal signal is a whole-snapshot inconclusive blocker. Do not order it by original `submitted_at` or let a later-looking clean supersede it without a trusted state-transition timestamp. An empty `APPROVED` review is not clean.

Apply the evidence in this order:

1. Any unresolved exact-provider selected-review target-thread finding blocks.
   Human, unrelated-bot, null-parent, and unrelated-only threads cannot supply
   resolution; a malformed target join fails closed. `isOutdated` is not
   resolution.
2. Discard progress messages and acknowledgements from terminal selection. An untrusted-identity or stale-scope artifact cannot win selection, but retain every terminal-looking instance as fail-closed evidence; do the same for malformed terminal-looking artifacts. Never drop one and expose an older clean as the apparent winner.
3. Select the latest trustworthy terminal artifact by server time. If the latest equal-time set spans more than one source channel, fail closed before comparing outcomes or numeric IDs. Within one channel, malformed or scope-conflicting evidence blocks, then finding wins over clean, and only a same-channel positive ID may break a remaining tie. A newer malformed terminal artifact is also `triple-inconclusive`.
4. A later strong current-head clean may supersede an older top-level finding on the same or a proven ancestor head only when the ancestor finding remains in the complete projection, no associated thread remains unresolved, and no newer finding or malformed terminal artifact exists. A resolved applicable thread may cease blocking under the thread rule; an unresolved one never does. Reaction-only clean never supersedes a finding.
5. A request or progress artifact after the selected terminal does not replace it. In particular, `R1 -> clean1 -> R2 pending`, `R1 -> clean1 -> R2 -> clean2`, and `R1 -> R2 -> clean1 -> clean2` may all select clean and pass with a request-policy warning. No request/run association is required.

Recompute and report `request_policy`, `provider_profile`, and `evidence_basis` from the final complete snapshot and bounded same-repository history, using this predeclared profile set:

- `terminal-payload`: the default; accept clean only from a commit-bound explicit no-findings comment/review.
- `mixed`: reaction and payload carriers coexist; terminal payload remains authoritative regardless of reaction recency.
- `thumbs-up-clean`: reaction-only weak fallback, enabled only by every condition in the authority reference.
- `unknown`: reaction-only evidence cannot pass.

An independently trustworthy current terminal clean/findings artifact selects
`terminal-payload` even when the provider declaration is missing or a failure
is confined to historical traversal, pagination, endpoint/artifact budget, or
request-sidecar validation. Those historical adaptation-plane failures prevent
only `mixed` and weak reaction authority. Run that optional history before a
fresh final current reread, and do not age a completed inventory's tracker with
elapsed work from another inventory. A current endpoint/artifact receipt failure
or current identity, scope, lifecycle, thread, ancestry, grammar, selection, or
final-stability failure still blocks.

For `thumbs-up-clean`, accept declaration authority only from a directly fetched and finally stable canonical GitHub REST issue-comment artifact with exact provider Bot/App identity and the predeclared line `If Codex has suggestions, it will comment; otherwise it will react with 👍.`. Record its exact repository/PR/API/HTML identity, artifact ID, server times, asserted text, GitHub `+1` mapping, normalization, and digest; arbitrary issuer/source labels, copied prose, self-hashed paraphrases, and caller-synthesized records are not authority. Preserve closed initial/final GET receipts with exact method/URL/integer status/canonical Date/raw body/body digest, independently project each declaration snapshot from its receipt body, and reject unknown receipt fields such as self-reported TLS booleans. Build the complete deterministic 30-day same-repository historical candidate universe before profile selection. Freeze the exact `(as_of - 2592000, as_of]` interval from the initial receipt: `as_of_receipt` is that exact receipt, `as_of_api_url` is its canonical URL, and `as_of_server_time` is its parsed Date. A final declaration re-read must be no earlier and never moves the window. Exclude the exact current scope and collapse duplicate records to one final outcome per repository/PR/`pr_merge_base`/head key.

Each independently fetched initial/final schema-version-4 discovery inventory
embeds the raw `discovery_endpoint_transcript`. Its closed root contains the
updated-desc pull traversal through its first cutoff-boundary page or natural
end, the fully paginated since-cutoff repository issue-comment feed, exact
current/declaration anchors, and one complete detail traversal for every union
member. That repository feed validates every exact-body `@codex review` record
regardless of actor or App; discovery seeds a canonically routed PR before full
actor, raw-equal detail, and sidecar validation either accepts the request or
selects `unknown`. Canonical ordinary-issue `@codex review` comments are
validated, retained, and budget-charged as raw-only non-seeds; mismatched or
ambiguous PR-like routing fails closed. It never silently removes an untrusted
or ambiguous strict PR request. Each detail
traversal contains the policy-required pull detail, compare, issue-comment,
review, inline-comment, raw GraphQL thread/comment, and controlled-request
reaction fetches. The fixed parser excludes current only after every
union-seeded scope is fully parsed and classified. Historical reaction-only
eligibility requires the raw-equal request parent in the repository feed and both request/response
inside the interval. Boundary witnesses and cumulative old PRs do not consume
the 512 union cap. A version-3 transcript cannot prove reaction fallback.
Missing source/union/detail coverage or any budget overflow makes
the profile `unknown`; truncation is forbidden.

Each historical discovery inventory and each current raw endpoint inventory
stores a parent-owned `resource_budget` sibling beside, never inside, the
unchanged version-4 transcript. It must type-preservingly equal this closed
profile:

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

Apply those maxima to three non-borrowing endpoint,
request-scope-sidecar, and terminal-artifact-scope-receipt ledgers that share
one inventory start/deadline. Pre-count each sidecar or artifact-wrapper array
and each wrapper's five raw responses. Create the artifact ledger once per
inventory decision pass, validate each immutable wrapper once, and thread its
memoized result through candidate ordering, audit, profile, outcome, and report
projection; a consumer must never create a per-candidate, per-scope, or
recomputation tracker or recharge the same wrapper. Sidecar overflow makes
request policy unknown and disables reaction authority without erasing an
independently complete terminal payload. Aggregate artifact-ledger overflow
invalidates the complete terminal-artifact projection and selects `unknown`,
never a validated prefix. Before memo lookup, apply the fixed
`github-codex-memo-fingerprint-guard-v1`: an iterative no-hash strict-JSON
preflight capped at depth 64, 20,000 entries per container, 2,000,000
value/key occurrences (each object key and each value counts once), a 128-bit
integer ceiling, 8,388,608 UTF-8 bytes per scalar, and 67,108,864 aggregate
scalar bytes. Fingerprint only the owning plane's endpoint transcript/fetches,
sidecar, or artifact wrapper. Apply the no-hash guard to declaration/ancestry
policy inputs before deriving their streaming namespace fingerprint; never use
canonical JSON for that key. Validate the owning ledger before a cache-miss
subject hash, and discard even a truthy producer result if that ledger failed.
Healthy positive and negative entries both retain a digest; every hit rechecks
the bounded summary and content fingerprint. Do not
build a complete canonical JSON body or charge transient fingerprint bytes as
retained evidence; keep periodic zero-charge deadline checks on that same
endpoint, sidecar, or artifact plane. The root coordinator cannot own a memo;
cache identity binds the exact plane tracker, exact artifact scope types, and
the closed scaffold around a narrowed current `fetches` subject. Mutation of an
immutable cached negative stays fail-closed until a fresh reread/context.
Complete, sidecar-blind, ancestry-filtering, and candidate-ordering consumers share one
exact-list/dict wrapper-array precharge before iteration; one wrapper plus its
five responses consumes six artifact records exactly once. A filtered view must
be an identity-preserving subsequence of those charged arrays. Require an exact
built-in current raw object/fetch list and an exact positive integer PR number
before rebuilding its narrow transcript; reject boolean/floating equality
aliases. For endpoint evidence, charge every REST
or GraphQL attempt, including retries, before the request; charge known page/record counts
before cloning or serialization, bytes before hashing, decoding, or
accumulation, and check the 900-second monotonic deadline again before success.
Endpoint overflow discards the entire traversal and selects `unknown`; it never
permits truncation, newest-N sampling, or a caller-chosen subset. A current raw
inventory parses and charges its one retained detail fetch set exactly once—no
synthetic seed, duplicate pull parse, second deadline, or post-budget byte
mutation. The initial and final inventories are independent fresh traversals
with independent starts. The `20000`-record, `8388608`-byte
per-response, and `67108864`-byte aggregate caps deliberately align with the
fixed Action baseline above (20,000 items, 8 MiB per response, and 64 MiB per
work unit). The 512 raw-union-seeded PRs, 512 controlled requests, 8192 attempts,
4096 retained pages, and 900-second deadline are playbook extensions for
bounded discovery evidence. Stable future-prefix projection is also a
playbook extension; do not attribute these rules to the pinned Action or use
them to change its provider-result authority baseline.

The inventory stores `request_scope_receipts` beside that raw transcript. The
version-4 root remains exactly
`{schema_version, repository, scope_discovery, scopes}` and its fetch-kind set
is unchanged. The fixed projector joins each eight-field request projection to
exactly one parent-owned sidecar only when evaluating request/reaction
authority; terminal-artifact projection does not depend on that join. Sidecar
resource validation charges one controlled request and five response
attempt/page/record units, applies the body cap to each raw body, and counts the
retained request URL, `Date`, and body UTF-8 bytes before digesting or decoding.

`pr_merge_base` comes only from the compare response's
`merge_base_commit.sha`, with the compare URL bound to the pull-detail
response's `base.sha` and `head.sha`. REST pages retain exact request URL,
status, raw Link header, bounded UTF-8 JSON body, and body SHA-256. Raw REST
timestamps stay canonical whole-second RFC3339 `Z` text; the fixed projector
strictly round-trips them to positive integer Unix seconds before ordering or
hashing and rejects numeric, offset, fractional, invalid, or noncanonical
substitutes. REST Link page relations are validated semantically against the
fixed HTTPS host, path, and non-page query map; omitted page and a literal
canonical `page=1` are equivalent, while each raw `rel=next` URL is followed
exactly. GraphQL pages retain the exact requested cursor and raw body from
which the fixed parser validates `repository.nameWithOwner`,
`pullRequest.number`, and `pageInfo` on every page. The first two values must
match the exact transcript scope before an empty or nonempty connection can
count as complete. A raw thread node contains the
real GraphQL `comments { nodes pageInfo }` connection, never the normalized
report `comments.pages` envelope. Version 4 accepts nested comments only when
that first connection is complete (`hasNextPage == false`); a terminal
`endCursor` may still be null or a non-empty string. A child connection with
`hasNextPage == true` requires a future schema version and therefore makes the
current profile `unknown`. Endpoint JSON may gain
unrelated GitHub fields; a fixed projector type-checks every policy field while
the page digest binds all raw bytes.

Before any projection, pass the provider declaration, every request-scope
receipt body, every REST page, and every GraphQL page through the same strict
JSON decoder. At every recursive depth reject duplicate object keys,
nonstandard or decoded non-finite numbers (including overflow to infinity),
and surrogate code points in values or member names. Only after that syntax and
scalar gate may endpoint objects retain unrelated forward-compatible GitHub
fields; a digest paired with a permissive decoder is not sufficient authority.

The parser independently proves raw-source-to-union and raw-union-to-detail
one-to-one coverage, then classifies every local-union PR as current,
historical candidate, or confirmed non-candidate before the joint coordinator
applies only the narrow future-prefix eligibility rule above,
and derives every candidate entry's scope/order plus carrier, channel,
semantic, native identity, projected-source digest, and candidate count. The
closed candidate evaluator separately validates complete candidate arrays and
requires each full authority projection to match the raw-derived entry.
Apply the frozen interval only after that complete parse and scope-final
selection. A fully valid provider-bearing non-current scope at or before the
exclusive lower boundary stays in the raw transcript and classifications as
`confirmed-non-candidate`, but it is audit-only and must not enter candidate
entries or the count. A post-as-of record, malformed projection, ambiguous
identity, or incomplete traversal remains fail-closed rather than becoming an
expired non-candidate.
Deleting an entire union-seeded scope, deleting an in-window candidate plus its entry
and decrementing the count, or substituting the same time/ID with a different
carrier or semantic must fail closed. Confirmed-different human activity
remains raw audit-only after full classification, while ambiguous
provider-like identity fails closed. A terminal artifact needs no observed
request; reaction-only evidence still does. The parent GitHub fetch path is
trusted; the offline transcript and digest preserve its inputs but do not
cryptographically attest GitHub's TLS origin.

Validate the initial and final discovery traversals independently, including
every body digest, REST Link chain, GraphQL cursor chain, source/union join, and
union/detail join.
Do not require the raw inventories or opaque cursor bytes to be identical:
GitHub may issue different valid cursors on the final reread. Require instead
type-preserving equality of the fixed semantic projection core, scope
classifications, candidate entries and arrays, and candidate count. The closed
`retained_pull_scope_audit` covers every complete local-union pull number. Use
the two closed `future_prefix_omission_eligibility_audit` arrays only to derive
effective one-sided omissions at the joint coordinator: a PR must occur in
exactly one union and be eligible on that side. A PR present in both unions is
never omitted, and shared eligibility items must be exactly equal. Any change
to a retained scope's identity, lifecycle, nodes, classification, candidate
membership, or selected source evidence remains unstable and selects
`unknown`.

For each traversal, derive the audit-only `scope_authority_audit` projection
for every scope with policy-relevant evidence. Its closed items retain scope,
lifecycle, every controlled request and valid sidecar binding, every individual
in-cutoff reaction including confirmed-different actors, every selected or
unselected provider artifact with its canonical source digest, exact-provider
pending/progress records, and in-cutoff/null-parent/unrelated audit context.
Represent the complete non-excluded semantic GraphQL thread set as one
scope-level `review-thread-audit` digest in `nonterminal_records`; keep the
selected review result digest target-only. Thus non-target thread drift is
visible without granting those threads provider-result or resolution
authority.
Fully validated post-cutoff
confirmed-different suffix records remain in the raw transcript but do not
enter this semantic projection. Compare the complete projection across the two
traversals; an old audit-only provider scope changing clean/findings/malformed,
or a final-only earlier `eyes`, is semantic drift even when selected entries
and count do not change. Bind every in-window reaction candidate's matching
fields to its raw scope audit. Preserve terminal/request-plane isolation by
excluding request/reaction defects from a terminal-determined candidate
comparison, while still requiring its lifecycle and complete provider artifact
projection to match. The audit list itself never enters entries, count, or the
3–10 sample.

Every legal exact-provider reaction remains in a terminal carrier's complete
audit projection, including content other than `+1` and `eyes`; none can
replace or invalidate the terminal basis. Only reaction-only classification
restricts semantic content to `+1` plus compatible earlier `eyes`, and any
other exact-provider content makes that weaker candidate `unknown`.

The current outcome is validated separately and never counts toward the history minimum. Before sorting, bind every candidate's time/ID basis to its scope-final outcome after terminal precedence and validate the candidate's complete pagination, provider-like reaction sequence, and stable initial/final snapshot even when it will fall outside the selected newest 10. A terminal/finding artifact or incomplete page cannot be hidden behind an older reaction timestamp. Later `+1`/`eyes` records remain audited but cannot replace a terminal basis; when the basis is reaction-only, a later provider-like reaction changes or invalidates it.

Classify actor identity and validate the complete carrier schema, native IDs,
URLs, and joins before applying the frozen as-of cutoff. A confirmed-different
issue comment exists only after jointly classifying actor and App: only the exact
Bot actor plus exact `performed_via_github_app.slug ==
"chatgpt-codex-connector"` is exact, while either half claiming the provider
with the other absent or conflicting is ambiguous/provider-like and fails
closed. It is never a removable confirmed-different suffix. A confirmed-different
non-request issue comment created wholly after the cutoff, submitted review
after the cutoff, or reaction created after the cutoff is a raw-only future
suffix: retain it in the transcript but exclude it from the fixed semantic
projection so concurrent human or unrelated-bot writes can converge.
Controlled `@codex review` comments remain policy-bearing regardless of actor
and must be within the cutoff. Exact-provider and ambiguous/provider-like
records also remain policy-bearing; a post-cutoff instance selects `unknown`.
An issue comment created at or before the cutoff but edited after it is
fail-closed because the cutoff body cannot be reconstructed. An exact or
ambiguous child may not be hidden with an otherwise confirmed-different future
review. Schema version 4 records no independent inline-child timestamp, so it
cannot infer that a human reply on an in-cutoff provider review is a removable
later suffix; that child remains semantic drift.

When 10 or more historical candidates exist, select exactly the newest 10; otherwise select the complete historical candidate set. Never skip an incomplete, conflicting, ambiguous, or unfavourable candidate. Every selected candidate must be eligible; otherwise the profile is `unknown`. At least three selected historical outcomes must remain, all reaction-only and with no clean comment/review. Every sampled outcome must record one selected parent issue comment whose normalized body is `@codex review`, its eight fields, exact matching request-time scope sidecar, and the individual child exact-bot `+1` reaction's positive ID/`parent_request_id`/exact parent reactions endpoint/`created_at`/actor/content, with strict server ordering `reaction.created_at > request.request_server_time`. Both receipt-derived tuples must equal the sample scope and the POST response must project type-preservingly to the request; an old-epoch request or reaction cannot be relocated into another scope. The endpoint-and-ID tuple is the native reaction identity; no standalone reaction resource URL is synthesized. It must also enumerate every accepted same-scope request parent, repeat each matching sidecar, and fully paginate every parent's individual reactions. An edited request uses `updated_at`; a reaction that predates an edit into `@codex review` cannot count. A reaction's parent ID and endpoint must match its enclosing audited request, so an R1 reaction cannot be relocated under R2 by local nesting. Across all parents, de-duplicate only identical endpoint-and-ID reaction identities and order exact-provider reactions globally by `(created_at, positive numeric ID)`: only duplicate `+1` plus strictly earlier `eyes` are compatible. The selected `+1` parent must be the unique latest request by semantic time. Any other reaction content, nonpositive/missing ordering ID, `eyes` at or after the selected `+1`, or request whose `request_server_time >= selected_reaction.created_at` makes the candidate `unknown`. Require the same binding and cross-parent audit for the separate current outcome. Its normalized initial/final snapshots include exact lifecycle `state == open`, `merged == false`, and `merged_at == null`, stable scope, all evidence pages, and no active top-level finding on the current or an ancestor head, unresolved target-thread finding, malformed terminal artifact, terminal payload, or reaction conflict. The current basis cannot be later than the same trusted as-of time. A changed `baseRefOid` does not create another outcome when `pr_merge_base` and head are unchanged. `eyes` is liveness only. A clean-looking `APPROVED` review requires a fully paginated, present, empty exact-provider selected-review target-child set; a valid target child is findings and an unread/malformed target join is inconclusive. Fully fetched human, unrelated-bot, null-parent, and unrelated-only records remain audit context and cannot contribute resolution. If payload and reaction carriers coexist, use `mixed` and keep the payload authoritative.

The edited-request `updated_at` rule above is audit ordering only. Sidecar
version `parent-recorded-request-scope-v1` admits only an unedited creation
response with `updated_at == created_at`; an edited request cannot enter
reaction authority without a future predeclared edit-receipt version.

Those normalized current snapshots are necessary derived views but are not
authority for terminal clean/findings or reaction clean. For every accepted
current provider result, the parent performs independent complete initial and
final raw current endpoint traversals and embeds both inventories in
`evidence_basis`. Each covers the current pull detail, compare, issue comments,
reviews, associated inline comments, raw GraphQL threads/comments, and every
controlled-request reaction page, with the matching parent-owned
`request_scope_receipts` array stored beside the raw fetches. A malformed
sidecar disables reaction authority but does not remove a separately complete
terminal artifact from those raw traversals. Derive every full finding commit
from each raw inventory before ancestry or resolution filtering. With lazy fetch and
prompts disabled, the parent records one initial and final local object and
ancestry receipt for every derived commit:

```bash
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<finding_commit>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git merge-base --is-ancestor <finding_commit> <current_head>
```

The object check must return exact `0`; the ancestry check must return exact
`0` for current/ancestor or exact `1` for proved non-ancestor. A missing
ancestry receipt, another return code, commit-set mismatch,
provider-artifact/thread/finding projection drift, or ancestry-receipt drift
makes the provider result `unknown`. A missing, malformed, or sidecar-only
request-scope drift instead makes request policy and reaction authority
`unknown` without vetoing a separately stable terminal result. The complete
raw request/reaction pages must nevertheless remain fully fetched and
parseable. Stable or changing duplicate/pending requests and reactions stay on
their own audit/policy plane and do not veto terminal selection. The complete
raw artifact/thread projection must type-preservingly equal the normalized
current record; a raw-only omitted finding makes the profile `unknown`. Any
proved non-ancestor remains raw audit-only and must be absent from normalized
`active_top_level_findings` and `unresolved_thread_findings`; an injected
normalized non-ancestor is likewise a projection mismatch selecting `unknown`.
Any
raw-derived applicable top-level finding blocks reaction clean. Any unresolved
applicable exact-provider selected-review target-thread finding blocks every
clean path; terminal precedence may supersede an older top-level finding only
when that finding remains present in the compared projection.

For an inconclusive report, derive a stable unresolved-thread blocker from a
blocker-specific projection of those same complete raw inventories before
ordinary terminal channel arbitration. Select only among fully validated
unresolved exact-provider target threads by greatest server time and positive
native ID. An equal-time clean or malformed artifact on another channel still
makes ordinary terminal selection ambiguous, but it does not erase that stable
blocker basis. Without an unresolved target thread, use the ordinary terminal
selection rules and report only a selected malformed artifact; never relax the
cross-channel ambiguity rule for terminal acceptance.

For a terminal payload, retain identical initial/final selection and selected
artifact snapshots plus the complete raw-current authority above in
`evidence_basis`. Every terminal-looking artifact wrapper also retains its
singular closed `artifact_scope_receipt`; its raw pre/artifact/post response
receipts, time envelope, artifact GET projection, and scope projection are
part of type-preserving initial/final equality. Review snapshots include exact
actor/state/raw and normalized body/native commit plus complete raw REST inline
pages, complete raw GraphQL thread/comment pages, and the canonical derived
target-only join. Human, unrelated-bot, null-parent, and unrelated-only
records remain audit context and cannot supply resolution; synthesized REST
resolution fields are forbidden. Issue-comment
snapshots use the authority's full closed schema: canonical API/HTML identity,
exact actor/App, raw/normalized body, grammar status, `created_at`,
`updated_at`, edit-aware server time/field, parsed commit, and immutable scope.
The scope head is current; clean requires its commit to equal that head, while
an applicable finding may preserve a proved-ancestor artifact commit.
REST request, reaction, parent, selected, and artifact IDs remain exact
positive JSON integers; quoted decimal strings are invalid. An
ID/time/commit summary alone is not acceptance evidence.

Serialize exact nested `scope_assurance: artifact-publication-only` in every
accepted terminal or stable terminal-blocker `evidence_basis`. This field
attests only the receipt-bound publication-time scope; it does not attest the
provider's internal input merge base or whole-PR review coverage. Omit it from
reaction bases, and keep an absent basis as literal `null`.

Immediately before success, repeat the lifecycle, base/head, unique merge-base,
complete evidence, pagination, every applicable artifact-time scope receipt, and
selected-artifact reads. Require the exact whole-PR scope and the recorded
`evidence_basis`—source channel, stable ID/URL, server time, artifact commit,
receipt-bound current scope, and exact artifact GET body/digest/identity—to
remain unchanged. For `thumbs-up-clean`, also re-fetch the authoritative
provider declaration source/version/text without moving the initial-receipt
as-of window, recompute its recorded normalization digest, and independently
re-fetch each final schema-version-4 updated-desc pull boundary, since-cutoff
request-comment feed, current/declaration anchors, and every raw-union-seeded PR
traversal. Rederive and audit each fixed `scope_discovery_projection`
independently, including its cutoff (with as-of separately frozen in the
history envelope), exact complete stop reason, deterministic retained
PR/base/head seeds, request IDs/PRs/digests, anchors, and fixed semantic union.
Only after both traversals independently validate may the coordinated stable
comparison exclude the transport-level stop-reason label. Require exact
equality of the closed
`retained_pull_scope_audit` for every complete local-union PR. Jointly derive
effective omission from `future_prefix_omission_eligibility_audit`: only a PR
present in exactly one union and eligible there may leave the stable comparison
view; a PR present in both unions remains, and shared eligibility items compare
exactly. Do not compare volatile pull `updated_at`, raw row digest, or endpoint
order as semantic state. Then
rederive the complete current/historical/non-candidate
classification, exclude current only after parsing, rederive inventory
scope/order/source-evidence entries and count, revalidate every request-time
scope sidecar and complete candidate projection, and revalidate every ordered
historical `samples[]` request/sidecar/reaction record. For terminal
clean/findings and reaction clean, independently re-fetch the final raw current
endpoint inventory, rederive its artifact/thread projection and finding-commit
set, rerun every parent-owned local Git object/ancestry receipt, and require
exact return-code, projection equality, and initial/final stability. A missing
request sidecar changes only request/reaction authority; a missing or unstable
artifact-scope receipt blocks the wrapped terminal artifact. A missing provider
record, budget overflow, other ancestry return code, or terminal projection
drift is `unknown` for the provider result. Field-by-field normalized current
equality alone cannot pass.

The provider-result budget-overflow clause in the preceding paragraph applies
to the current endpoint/artifact authority. An overflow confined to historical
adaptation evidence has only the profile effect defined above.

Before applying the generic same-head/different-base `scope-mismatch` branch,
compare an accepted same-head request's receipt-derived request-time merge base
with current `pr_merge_base` and apply
[base-only-retarget-state-machine.json](base-only-retarget-state-machine.json).
Version 2 adds the independent terminal-artifact scope receipt while preserving
version 1's request-sidecar event semantics.
If it changed while `headRefOid` remained unchanged, the old request/result no
longer covers the whole PR and the same-head request limit prevents a
replacement. Never relabel that old-epoch request or reaction into the current
tuple. Missing origin, stale-range, and unauthorized parent-rewrite transitions
stop before local lanes as specified by the state-machine input contract. A
missing or malformed sidecar cannot prove this retarget event and therefore
does not invoke that transition; it instead closes only the request/reaction
planes, makes request policy unknown, and forbids another POST while
independently scoped local lanes and terminal evidence keep their own gates;
terminal evidence still requires its separate artifact-time receipt. An
exact current range newly supplied by the caller recovers local lanes for
caller-origin state; normal exact-current rederivation recovers them for
PR-derived state. Either recovery proceeds to local lanes but keeps readiness
`blocked-input` (`base-changed-same-head`) plus `requested: triple`, `effective:
triple-inconclusive`, and neither permits another same-head request. Eligibility
returns only after a separately authorized ordinary change produces a new
head, and no empty or anchor commit may manufacture that epoch. Neither the
request sidecar nor an artifact receipt's matching point reads prove that an
intermediate ABA transition did not occur.

Posting `@codex review` is request transport, not completion or proof that the service started. Accept strong terminal payloads only from exact REST `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. When app/check evidence is used for service-start detection, accept only exact `app.slug == "chatgpt-codex-connector"`, exact current `head_sha`, and non-null `started_at` after an observed request. A check/run is service-start evidence only and never completes triple or proves no findings, even when `status == "completed"` and `conclusion == "success"`. Unknown or lookalike identities prove neither start nor completion.

The fixed authority baseline has no accepted no-start body grammar, so free-form exact-bot prose cannot currently prove unavailability. A future policy version may activate that path only with the provider-backed immutable grammar and regression contract required by the authority reference. An acknowledgement, review activity, or exact-App current-head check/run proves service start only. When no complete `thumbs-up-clean` reaction fallback is accepted, no terminal response, an otherwise valid nonterminal/check-only state, or a retryable transport/read failure remains pending while bounded waiting is meaningful. After that wait is exhausted, it is `triple-inconclusive`. Unknown identity, malformed or stale evidence, a non-retryable request failure, or permanently incomplete enumeration is immediately inconclusive and never proves clean completion.

Classify precisely, applying selected-PR range alignment before the availability branch:

- A post-request base-only retarget with unchanged `pr_head_oid` is readiness `blocked-input` (`base-changed-same-head`) and `effective: triple-inconclusive`; invalidate the old whole-PR evidence but never post a replacement same-head request.
- Any other selected PR whose explicit range has `head_sha == pr_head_oid` but `base_sha != pr_merge_base` is readiness `blocked-input` (`scope-mismatch`). Do not rewrite the explicit range or count its local findings as whole-PR review evidence.
- Any existing PR with current `headRefOid != head_sha` and no separate PR-mutation authorization is a readiness `blocked-authorization` result. For a still-eligible PR, report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Only after an existing PR is head-aligned and its frozen range is exactly `pr_merge_base..pr_head_oid`, classify an unsupported host/identity as third-lane unavailable and effective double. The fixed baseline accepts no structured integration/service availability schema and no no-start body grammar, so integration/service uncertainty cannot currently enter this branch. A future pinned schema or authenticated no-start grammar may join it only after an explicit policy update. No PR is also effective double without a selected-PR range comparison.
- Service ran and returned findings: available lane with findings; fix and rerequest after the new head.
- When no complete `thumbs-up-clean` reaction fallback is accepted, missing terminal evidence that proves neither unavailable nor started is `pending` while bounded waiting remains meaningful; when that wait is exhausted, report `requested: triple`, `effective: triple-inconclusive`.
- A started service with ambiguous authorship, stale head/range, malformed evidence, or a permanently incomplete association is immediately `requested: triple`, `effective: triple-inconclusive`.
- A started service with no complete `thumbs-up-clean` reaction fallback and otherwise valid nonterminal/check-only evidence, missing terminal payload, or retryable incomplete pagination remains `pending` while bounded waiting is meaningful; after exhaustion, report `requested: triple`, `effective: triple-inconclusive`. Neither branch may become effective double, completed triple, or clean evidence.

## Prefer Typed `gh`

Start with stable typed `gh` forms:

- `gh pr view --json ...`
- `gh pr view <number> --json number,url,state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,mergeStateStatus,mergeable,reviewDecision,statusCheckRollup`
- `gh pr checks <number>`
- `gh pr status`
- `gh api repos/<owner>/<repo>/branches/<base>/protection`
- `gh api 'repos/<owner>/<repo>/rules/branches/<base>'`

Only write custom `gh api graphql` when typed forms do not expose the field needed for the current decision.

## GraphQL Shape

Keep custom GraphQL queries minimal: request only fields needed for the immediate PR readiness decision.

Do not paste a query containing `$owner`, braces, aliases, multiline selection, or a long field list into an unquoted shell argument such as `-f query=...`.

For complex queries, write a task-scoped `.codex-tmp/.../*.graphql` query file and pass it with `-F` so `gh` reads file contents:

```sh
gh api graphql -F query=@.codex-tmp/.../query.graphql -F owner=<owner> -F repo=<repo> -F number=<number>
gh api graphql -F query=@.codex-tmp/<task>/query.graphql -F owner=<owner> -F repo=<repo> -F number=<number>
```

Do not use raw-field for a query file; `-f` / `--raw-field` sends the literal `@file.graphql` string.

GraphQL `Field ... doesn't exist on type ...` and `Expected NAME` errors are probe failures. Remove or verify the failing field and retry a smaller query; do not keep expanding the same query.

## REST Paths With Query Strings

When a REST endpoint legitimately contains `?`, quote the whole endpoint so zsh cannot treat it as a glob:

```sh
gh api 'repos/<owner>/<repo>/contents/action.yml?ref=<sha>'
```

Do not use the repository rulesets endpoint with a `ref` query as the branch rules probe. Use `gh api 'repos/<owner>/<repo>/rules/branches/<base>'` for rules that apply to a branch.

## GitHub Actions Logs

Use `gh pr checks <number>` or typed PR status first to identify the failing run and job. Do not run a chat-visible bare log dump such as `gh run view <run> --job <job> --log` or `gh run view <run> --job <job> --log-failed`.

Save full GitHub Actions logs to a task-scoped file under `.codex-tmp/`, then extract only targeted evidence:

```sh
mkdir -p .codex-tmp/<task>
gh run view <run-id> --repo <owner>/<repo> --job <job-id> --log-failed > .codex-tmp/<task>/<job-id>.failed.log
wc -l -c .codex-tmp/<task>/<job-id>.failed.log
rg -n "FAIL|error:|Exception|XCTAssert|#expect|TEST FAILED" .codex-tmp/<task>/<job-id>.failed.log | sed -n '1,80p'
tail -n 120 .codex-tmp/<task>/<job-id>.failed.log
```

If the targeted extraction is still above roughly 800 lines or 10k original tokens, narrow the pattern or print small line windows around the decisive matches. Do not pipe a large `gh run view --log-failed` stream directly into broad `rg -C` output; saving first lets you count, re-filter, and report only the key lines.
