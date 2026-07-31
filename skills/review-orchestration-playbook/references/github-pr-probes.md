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

This narrow open-PR selector is not the repository-wide discovery authority
for `thumbs-up-clean`. It cannot replace the independent state-all raw seed,
all-PR detail traversals, or post-parse current-scope exclusion required by
discovery transcript schema version 3 below.

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

gh api --hostname <host> --method POST \
  repos/<owner>/<repo>/issues/<number>/comments \
  -f body='@codex review' \
  --jq '{id,html_url,created_at}'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/pulls/<number>/reviews?per_page=100' \
  --jq '[.[][] | {id,user:{login:.user.login,type:.user.type},commit_id,submitted_at,state,html_url,body}]'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/issues/<number>/comments?per_page=100' \
  --jq '[.[][] | {id,user:{login:.user.login,type:.user.type},app_slug:.performed_via_github_app.slug,created_at,updated_at,html_url,body}]'

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
independently fetch the complete repository-wide raw PR seed for each initial
and final inventory:

```bash
gh api --hostname github.com --method GET --include --paginate \
  'repos/<owner>/<repo>/pulls?state=all&sort=created&direction=asc&per_page=100'
```

The trusted parent fetch path must preserve every page separately with its
exact request URL, integer status, raw `Link` header or null, raw UTF-8 body,
and recomputed body digest. A `--jq` projection, `gh pr list`, open-only
branch selector, slurped candidate array, or reuse of the initial bytes for the
final inventory is not raw discovery authority. Every canonical PR number in
the seed starts exactly one complete detail traversal, including the current
PR and PRs later classified as confirmed non-candidates. Any seed, detail,
child-page, count, byte, or time budget overflow makes the profile `unknown`;
never truncate and continue.

REST does not expose PR review-thread resolution. Preserve the fully paginated
raw REST inline-comment records without adding `thread_id`,
`thread_resolved`, or `is_resolved`. Separately preserve the raw GraphQL pages
from a minimal query that pages
`reviewThreads(first: 100, after: $cursor)` and records each thread's stable
`id`, typed `isResolved`, typed `isOutdated`, and
`pageInfo { hasNextPage endCursor }`. For every paginated thread-comment node,
record GraphQL `id`, REST-compatible `fullDatabaseId: BigInt`, `url`, and
`pullRequestReview { id fullDatabaseId }`; exhaust every nested comments
cursor. Both connections start with a null cursor, require each next request
cursor to equal the previous raw `endCursor`, and end only at typed
`hasNextPage == false`.

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

### Provider-evidence reconciliation

Use [github-codex-evidence-authority.md](github-codex-evidence-authority.md) as
the authoritative decision contract.

Only provider-result authority is inherited from the fixed
`codex-review-gate` / released Action baseline pinned in that reference:
complete trustworthy current-scope results decide without request/run
attribution, and early or duplicate requests remain outcome-neutral producer
warnings. Repository-wide discovery schema version 3, raw target-thread proof,
exact whole-PR lifecycle/scope, the closed terminal carrier, and conditional
`+1` fallback are deliberate playbook extensions, not behaviour attributed to
the fixed Action. Findings, malformed terminal artifacts, unresolved
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
- every fully paginated reaction list relevant to the controlled request; and
- the lifecycle, base/head, merge-base, and check/run observations needed to validate scope and distinguish liveness from terminal evidence.

Normalize stable API IDs, source channel, exact provider identity, native commit binding or explicit full current-head binding, and semantic server time for each candidate. A review uses `submitted_at`; an unedited issue comment uses `created_at`; an issue comment whose current body was edited uses `updated_at`; and a reaction uses `created_at`. Record the selected native field and do not substitute client receipt order or local clock time. Every terminal issue comment must satisfy the authority's closed record schema, including canonical API and HTML URLs, exact Bot/App identity, raw and normalized body, `created_at`, `updated_at`, selected time/field, grammar status, parsed full commit, and immutable scope; review-only fields are rejected. Apply only the authority's fixed terminal-payload grammar: clean issue comments use the exact `Codex Review: Didn't find any major issues.` lead plus one lowercase full-SHA `Reviewed commit` marker; clean reviews use exact `APPROVED`, a native lowercase full-SHA current-head `commit_id`, and body `No findings.`. Every other terminal-looking exact-provider payload is malformed unless it matches the fixed finding or inline-parent branch. Review state admissibility is separate from terminal-looking detection: exact `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED` may enter the grammar; `PENDING` is nonterminal; `DISMISSED` is always terminal-looking; and a missing or unknown state is terminal-looking when a nonempty body or associated inline child supplies a terminal signal. Each invalid-state terminal signal is a whole-snapshot inconclusive blocker. Do not order it by original `submitted_at` or let a later-looking clean supersede it without a trusted state-transition timestamp. An empty `APPROVED` review is not clean.

Apply the evidence in this order:

1. Any unresolved exact-provider selected-review target-thread finding blocks.
   Human, unrelated-bot, null-parent, and unrelated-only threads cannot supply
   resolution; a malformed target join fails closed. `isOutdated` is not
   resolution.
2. Discard progress messages and acknowledgements from terminal selection. An untrusted-identity or stale-scope artifact cannot win selection, but retain every terminal-looking instance as fail-closed evidence; do the same for malformed terminal-looking artifacts. Never drop one and expose an older clean as the apparent winner.
3. Select the latest trustworthy terminal artifact by server time. If the latest equal-time set spans more than one source channel, fail closed before comparing outcomes or numeric IDs. Within one channel, malformed or scope-conflicting evidence blocks, then finding wins over clean, and only a same-channel positive ID may break a remaining tie. A newer malformed terminal artifact is also `triple-inconclusive`.
4. A later strong current-head clean may supersede an older top-level finding on the same or a proven ancestor head only when no associated thread remains unresolved and no newer finding or malformed terminal artifact exists. Reaction-only clean never supersedes a finding.
5. A request or progress artifact after the selected terminal does not replace it. In particular, `R1 -> clean1 -> R2 pending`, `R1 -> clean1 -> R2 -> clean2`, and `R1 -> R2 -> clean1 -> clean2` may all select clean and pass with a request-policy warning. No request/run association is required.

Recompute and report `request_policy`, `provider_profile`, and `evidence_basis` from the final complete snapshot and bounded same-repository history, using this predeclared profile set:

- `terminal-payload`: the default; accept clean only from a commit-bound explicit no-findings comment/review.
- `mixed`: reaction and payload carriers coexist; terminal payload remains authoritative regardless of reaction recency.
- `thumbs-up-clean`: reaction-only weak fallback, enabled only by every condition in the authority reference.
- `unknown`: reaction-only evidence cannot pass.

For `thumbs-up-clean`, accept declaration authority only from a directly fetched and finally stable canonical GitHub REST issue-comment artifact with exact provider Bot/App identity and the predeclared line `If Codex has suggestions, it will comment; otherwise it will react with 👍.`. Record its exact repository/PR/API/HTML identity, artifact ID, server times, asserted text, GitHub `+1` mapping, normalization, and digest; arbitrary issuer/source labels, copied prose, self-hashed paraphrases, and caller-synthesized records are not authority. Preserve closed initial/final GET receipts with exact method/URL/integer status/canonical Date/raw body/body digest, independently project each declaration snapshot from its receipt body, and reject unknown receipt fields such as self-reported TLS booleans. Build the complete deterministic 30-day same-repository historical candidate universe before profile selection. Freeze the exact `(as_of - 2592000, as_of]` interval from the initial receipt: `as_of_receipt` is that exact receipt, `as_of_api_url` is its canonical URL, and `as_of_server_time` is its parsed Date. A final declaration re-read must be no earlier and never moves the window. Exclude the exact current scope and collapse duplicate records to one final outcome per repository/PR/`pr_merge_base`/head key.

Each independently fetched initial/final schema-version-3 discovery inventory
embeds the raw `discovery_endpoint_transcript`. Its closed root contains the
complete repository-wide state-all pull-list traversal plus exactly one
complete detail traversal for every seeded PR number. Each detail traversal
contains the policy-required pull detail, compare, issue-comment, review,
inline-comment, raw GraphQL thread/comment, and controlled-request reaction
fetches. It includes the exact current PR and every confirmed non-candidate PR;
the fixed parser excludes current from historical candidates only after every
seeded traversal is fully parsed and classified. A version-2 transcript lacks
the independent repository-wide seed and cannot prove reaction fallback.
Missing seed/detail coverage or any page/count/byte/time budget overflow makes
the profile `unknown`; truncation is forbidden.

`pr_merge_base` comes only from the compare response's
`merge_base_commit.sha`, with the compare URL bound to the pull-detail
response's `base.sha` and `head.sha`. REST pages retain exact request URL,
status, raw Link header, bounded UTF-8 JSON body, and body SHA-256. Raw REST
timestamps stay canonical whole-second RFC3339 `Z` text; the fixed projector
strictly round-trips them to positive integer Unix seconds before ordering or
hashing and rejects numeric, offset, fractional, invalid, or noncanonical
substitutes. GraphQL pages retain the exact requested cursor and raw body from
which the fixed parser validates `pageInfo`. A raw thread node contains the
real GraphQL `comments { nodes pageInfo }` connection, never the normalized
report `comments.pages` envelope. Version 3 accepts nested comments only when
that first connection is complete (`hasNextPage == false`,
`endCursor == null`); a child cursor requires a future schema version and
therefore makes the current profile `unknown`. Endpoint JSON may gain
unrelated GitHub fields; a fixed projector type-checks every policy field while
the page digest binds all raw bytes.

The parser independently proves seed-to-detail one-to-one coverage, classifies
every seeded PR as current, historical candidate, or confirmed non-candidate,
and derives every candidate entry's scope/order plus carrier, channel,
semantic, native identity, projected-source digest, and candidate count. The
closed candidate evaluator separately validates complete candidate arrays and
requires each full authority projection to match the raw-derived entry.
Deleting an entire seeded scope, deleting a candidate plus its entry and
decrementing the count, or substituting the same time/ID with a different
carrier or semantic must fail closed. Confirmed-different human activity
remains raw audit-only after full classification, while ambiguous
provider-like identity fails closed. A terminal artifact needs no observed
request; reaction-only evidence still does. The parent GitHub fetch path is
trusted; the offline transcript and digest preserve its inputs but do not
cryptographically attest GitHub's TLS origin.

The current outcome is validated separately and never counts toward the history minimum. Before sorting, bind every candidate's time/ID basis to its scope-final outcome after terminal precedence and validate the candidate's complete pagination, provider-like reaction sequence, and stable initial/final snapshot even when it will fall outside the selected newest 10. A terminal/finding artifact or incomplete page cannot be hidden behind an older reaction timestamp. Later `+1`/`eyes` records remain audited but cannot replace a terminal basis; when the basis is reaction-only, a later provider-like reaction changes or invalidates it. Require every raw historical/current request, reaction, and artifact server time to be no later than the same as-of time before filtering confirmed different actors. When 10 or more historical candidates exist, select exactly the newest 10; otherwise select the complete historical candidate set. Never skip an incomplete, conflicting, ambiguous, or unfavourable candidate. Every selected candidate must be eligible; otherwise the profile is `unknown`. At least three selected historical outcomes must remain, all reaction-only and with no clean comment/review. Every sampled outcome must record one selected parent issue comment whose normalized body is `@codex review`, its ID/URL/`created_at`/`updated_at`/selected semantic server time and field/scope, and the individual child exact-bot `+1` reaction's positive ID/`parent_request_id`/exact parent reactions endpoint/`created_at`/actor/content, with strict server ordering `reaction.created_at > request.request_server_time`. The endpoint-and-ID tuple is the native reaction identity; no standalone reaction resource URL is synthesized. It must also enumerate every accepted same-scope request parent and fully paginate every parent's individual reactions. An edited request uses `updated_at`; a reaction that predates an edit into `@codex review` cannot count. A reaction's parent ID and endpoint must match its enclosing audited request, so an R1 reaction cannot be relocated under R2 by local nesting. Across all parents, de-duplicate only identical endpoint-and-ID reaction identities and order exact-provider reactions globally by `(created_at, positive numeric ID)`: only duplicate `+1` plus strictly earlier `eyes` are compatible. The selected `+1` parent must be the unique latest request by semantic time. Any other reaction content, nonpositive/missing ordering ID, `eyes` at or after the selected `+1`, or request whose `request_server_time >= selected_reaction.created_at` makes the candidate `unknown`. Require the same binding and cross-parent audit for the separate current outcome. Its normalized initial/final snapshots include exact lifecycle `state == open`, `merged == false`, and `merged_at == null`, stable scope, all evidence pages, and no active top-level finding on the current or an ancestor head, unresolved target-thread finding, malformed terminal artifact, terminal payload, or reaction conflict. The current basis cannot be later than the same trusted as-of time. A changed `baseRefOid` does not create another outcome when `pr_merge_base` and head are unchanged. `eyes` is liveness only. A clean-looking `APPROVED` review requires a fully paginated, present, empty exact-provider selected-review target-child set; a valid target child is findings and an unread/malformed target join is inconclusive. Fully fetched human, unrelated-bot, null-parent, and unrelated-only records remain audit context and cannot contribute resolution. If payload and reaction carriers coexist, use `mixed` and keep the payload authoritative.

Those normalized current snapshots are necessary derived views but are not
current reaction-clean authority. The parent performs independent complete
initial and final raw current endpoint traversals and embeds both inventories
in `evidence_basis`. Each covers the current pull detail, compare, issue
comments, reviews, associated inline comments, raw GraphQL threads/comments,
and every controlled-request reaction page. Derive every full finding commit
from each raw inventory before ancestry or resolution filtering. With lazy
fetch and prompts disabled, the parent records one initial and final local
object and ancestry receipt for every derived commit:

```bash
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<finding_commit>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git merge-base --is-ancestor <finding_commit> <current_head>
```

The object check must return exact `0`; the ancestry check must return exact
`0` for current/ancestor or exact `1` for proved non-ancestor. A missing
receipt, another return code, commit-set mismatch, or initial/final inventory
or receipt drift makes the profile `unknown`. Any raw-derived top-level finding
with ancestry return code `0`, or any unresolved exact-provider
selected-review target-thread finding with ancestry return code `0`, blocks
reaction clean.

For a terminal payload, retain identical initial/final selection and selected
artifact snapshots in `evidence_basis`. Review snapshots include exact
actor/state/raw and normalized body/native commit plus complete raw REST inline
pages, complete raw GraphQL thread/comment pages, and the canonical derived
target-only join. Human, unrelated-bot, null-parent, and unrelated-only
records remain audit context and cannot supply resolution; synthesized REST
resolution fields are forbidden. Issue-comment
snapshots use the authority's full closed schema: canonical API/HTML identity,
exact actor/App, raw/normalized body, grammar status, `created_at`,
`updated_at`, edit-aware server time/field, parsed commit, and immutable scope.
An ID/time/commit summary alone is not acceptance evidence.

Immediately before success, repeat the lifecycle, base/head, unique merge-base, complete evidence, pagination, and selected-artifact reads. Require the exact whole-PR scope and the recorded `evidence_basis`—source channel, stable ID/URL, server time, and commit binding—to remain unchanged. For `thumbs-up-clean`, also re-fetch the authoritative provider declaration source/version/text without moving the initial-receipt as-of window, recompute its recorded normalization digest, and independently re-fetch each final schema-version-3 repository-wide seed plus every seeded PR traversal. Rederive the complete current/historical/non-candidate classification, exclude current only after parsing, rederive inventory scope/order/source-evidence entries and count, revalidate every complete candidate projection, and revalidate every ordered historical `samples[]` request/reaction record. Separately re-fetch the final raw current endpoint inventory, rederive its finding-commit set, rerun every parent-owned local Git object/ancestry receipt, and require exact return-code and initial/final stability. A missing record, budget overflow, other return code, or drift is `unknown`; field-by-field normalized current equality alone cannot pass.

Before applying the generic same-head/different-base `scope-mismatch` branch, compare an accepted same-head request's audited request-time merge base with current `pr_merge_base` and apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json). If it changed while `headRefOid` remained unchanged, the old request/result no longer covers the whole PR and the same-head request limit prevents a replacement. Missing origin, stale-range, and unauthorized parent-rewrite transitions stop before local lanes. An exact current range newly supplied by the caller recovers local lanes for caller-origin state; normal exact-current rederivation recovers them for PR-derived state. Either recovery proceeds to local lanes but keeps readiness `blocked-input` (`base-changed-same-head`) plus `requested: triple`, `effective: triple-inconclusive`, and neither permits another same-head request. Eligibility returns only after a separately authorized ordinary change produces a new head, and no empty or anchor commit may manufacture that epoch.

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
