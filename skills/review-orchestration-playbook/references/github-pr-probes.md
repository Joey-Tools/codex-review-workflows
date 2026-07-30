# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, lifecycle tuple `state` / `merged` / `merged_at`, `baseRefName`, `baseRefOid`, and `headRefOid`, then independently validate the selected PR's unique local merge base. Only exact `state == "open"`, `merged == false`, and `merged_at == null` is an eligible lifecycle.

- The only supported host is exact `github.com`. Every other host is unsupported, including `sqbu-github.cisco.com` and every GitHub Enterprise host.
- Treat any operating identity in `{hoteng, hoteng_cisco}` as unsupported. Another identity on `github.com` is only an eligible candidate; it does not by itself prove that the integration or service is available.
- When authenticated discovery proves no PR, or an unsupported host/identity is directly known, record `requested: triple`, `effective: double`, and the exact reason without posting a request. Treat missing integration/service as unavailable only when authenticated structured capability or installation metadata directly proves it. The fixed authority baseline does not accept free-form provider response prose for this purpose; absence, timeout, permission error, or generic HTTP/network failure is inconclusive.
- On a supported PR, allow at most one acceptable exact `@codex review` request per unchanged head. Reuse the recorded request when one already exists; never post a second request on that same `headRefOid`.

## Deterministic Range And PR Discovery

Resolve the local range and PR selector independently. Preserve an explicit frozen `base_sha..head_sha` as the authoritative local-lane range before any PR probe. Explicit-range-only standalone single/double needs no PR probe. A frozen range never selects a PR: PR-specific work and triple use an explicitly named PR, otherwise the complete set of open PRs associated with the exact current head repository/branch. Exactly one associated PR selects it. More than one is `blocked-input` for the GitHub/PR-specific lane because the required explicit PR selector is absent; the caller must name the PR, and a frozen range does not cure that ambiguity. Fully scoped local lanes may still run, while any lane that still depends on PR selection stays blocked. Do not select a candidate by recency, base, number, draft state, or title. Once a PR is selected, its explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`.

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

REST does not expose PR review-thread resolution. Use a minimal GraphQL query that pages `reviewThreads(first: 100, after: $cursor)` and records each thread's stable `id`, `isResolved`, `isOutdated`, and `pageInfo { hasNextPage endCursor }`. For every paginated thread-comment node, record GraphQL `id`, REST-compatible `fullDatabaseId: BigInt`, `url`, and `pullRequestReview { id fullDatabaseId }`; exhaust the comments cursor when present. Normalize each non-null GraphQL BigInt and REST JSON numeric ID to canonical positive decimal text before comparison. Join the REST inline comment to the GraphQL thread comment by exact normalized `fullDatabaseId`, then require normalized REST `pull_request_review_id` to equal `pullRequestReview.fullDatabaseId` and corroborate the URL. A noncanonical, nonpositive, missing/null join key, orphan, duplicate mapping, URL conflict, parent-review conflict, page, cursor, or `isResolved` value makes the snapshot incomplete. Continue both connections until `hasNextPage == false`.

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Re-read the exact request from the authenticated API and keep its ID, URL, and server `created_at`, the surrounding before/after lifecycle plus `baseRefName` / `baseRefOid` / `headRefOid` observations, immutable selected-PR `range_origin.kind` / `base_sha` / `head_sha`, and the accepted terminal result URL/time/author. The origin kind is exactly `caller-supplied` or `pr-derived`; never infer it from a later parent-provided range or overwrite original caller endpoints. Revalidate the exact open lifecycle tuple during initial selected-PR preflight, immediately before posting, immediately before accepting a result, and during final readiness/merge verification. Immediately before accepting the result, also revalidate both endpoint objects, recompute the unique `pr_merge_base`, and require the frozen range still to equal `pr_merge_base..pr_head_oid`; an observed non-open lifecycle at a mandated snapshot, a changed head, or a changed merge base invalidates whole-PR lane evidence.

These REST lifecycle reads are point-in-time snapshots. They do not prove that no intermediate close-and-reopen occurred between mandated probes. Do not claim a complete lifecycle-history attestation from them. If separately collected, authenticated, fully paginated lifecycle-event history shows a post-start close, reopen, or merge, invalidate the evidence; missing event-history evidence does not strengthen the snapshot claim.

Before posting, inspect authenticated complete issue-comment history and the bounded audit record. Producer policy permits the parent to post one exact `@codex review` only after both local lanes are terminal and only when no request already exists for the unchanged current scope. Never post a second or third request. Record `early-request-observed` when a request preceded the local terminals. Record `duplicate-observed` when more than one same-scope request exists, including an overlapping or pending extra request. These are outcome-neutral warnings. A lone compliant pending request is not a warning; it remains pending unless a trustworthy terminal artifact already exists. Request markers, counts, ordering, and inferred request/run lineage are not provider verdict evidence.

### Provider-evidence reconciliation

Use [github-codex-evidence-authority.md](github-codex-evidence-authority.md) as the authoritative decision contract. Build one complete current-scope snapshot from:

- every fully paginated issue comment and review;
- every fully paginated associated inline-comment list for relevant reviews;
- every fully paginated review thread with explicit `isResolved`;
- every fully paginated reaction list relevant to the controlled request; and
- the lifecycle, base/head, merge-base, and check/run observations needed to validate scope and distinguish liveness from terminal evidence.

Normalize stable API IDs, source channel, exact provider identity, native commit binding or explicit full current-head binding, and semantic server time for each candidate. A review uses `submitted_at`; an unedited issue comment uses `created_at`; an issue comment whose current body was edited uses `updated_at`; and a reaction uses `created_at`. Record the selected native field and do not substitute client receipt order or local clock time. A review is terminal only in exact submitted state `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`; `PENDING` is nonterminal, while `DISMISSED`, missing, or unknown state is unusable. A clean payload must explicitly say no findings; an empty `APPROVED` review is not clean.

Apply the evidence in this order:

1. Any unresolved thread-backed finding blocks. `isOutdated` is not resolution.
2. Discard progress messages and acknowledgements from terminal selection. An untrusted-identity or stale-scope artifact cannot win selection, but retain every terminal-looking instance as fail-closed evidence; do the same for malformed terminal-looking artifacts. Never drop one and expose an older clean as the apparent winner.
3. Select the latest trustworthy terminal artifact by server time. A finding wins over clean at the same timestamp. Incompatible cross-channel artifacts with the same server timestamp are `triple-inconclusive` when they cannot be ordered; a newer malformed terminal artifact is also `triple-inconclusive`.
4. A later strong current-head clean may supersede an older top-level finding on the same or a proven ancestor head only when no associated thread remains unresolved and no newer finding or malformed terminal artifact exists. Reaction-only clean never supersedes a finding.
5. A request or progress artifact after the selected terminal does not replace it. In particular, `R1 -> clean1 -> R2 pending`, `R1 -> clean1 -> R2 -> clean2`, and `R1 -> R2 -> clean1 -> clean2` may all select clean and pass with a request-policy warning. No request/run association is required.

Recompute and report `request_policy`, `provider_profile`, and `evidence_basis` from the final complete snapshot and bounded same-repository history, using this predeclared profile set:

- `terminal-payload`: the default; accept clean only from a commit-bound explicit no-findings comment/review.
- `mixed`: reaction and payload carriers coexist; terminal payload remains authoritative regardless of reaction recency.
- `thumbs-up-clean`: reaction-only weak fallback, enabled only by every condition in the authority reference.
- `unknown`: reaction-only evidence cannot pass.

For `thumbs-up-clean`, require a current provider declaration that exact-bot `+1` means no findings; a deterministic 30-day same-repository sample of at least three and at most ten distinct immutable PR scopes, with duplicate requests/reactions collapsed to one final outcome per repository/PR/`pr_merge_base`/head key, all reaction-only and with no clean comment/review; an exact-bot `+1` after a parent-recorded controlled request bound to the exact current scope; no active top-level finding on the current or an ancestor head, unresolved thread finding, malformed terminal artifact, terminal payload, or newer `eyes` in the complete snapshot; and a stable final reread. A changed `baseRefOid` does not create another outcome when `pr_merge_base` and head are unchanged. `eyes` is liveness only. If payload and reaction carriers coexist, use `mixed` and keep the payload authoritative.

Immediately before success, repeat the lifecycle, base/head, unique merge-base, complete evidence, pagination, and selected-artifact reads. Require the exact whole-PR scope and the recorded `evidence_basis`—source channel, stable ID/URL, server time, and commit binding—to remain unchanged.

Before applying the generic same-head/different-base `scope-mismatch` branch, compare an accepted same-head request's audited request-time merge base with current `pr_merge_base` and apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json). If it changed while `headRefOid` remained unchanged, the old request/result no longer covers the whole PR and the same-head request limit prevents a replacement. Missing origin, stale-range, and unauthorized parent-rewrite transitions stop before local lanes. An exact current range newly supplied by the caller recovers local lanes for caller-origin state; normal exact-current rederivation recovers them for PR-derived state. Either recovery proceeds to local lanes but keeps readiness `blocked-input` (`base-changed-same-head`) plus `requested: triple`, `effective: triple-inconclusive`, and neither permits another same-head request. Eligibility returns only after a separately authorized ordinary change produces a new head, and no empty or anchor commit may manufacture that epoch.

Posting `@codex review` is request transport, not completion or proof that the service started. Accept strong terminal payloads only from exact REST `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. When app/check evidence is used for service-start detection, accept only exact `app.slug == "chatgpt-codex-connector"`, exact current `head_sha`, and non-null `started_at` after an observed request. A check/run is service-start evidence only and never completes triple or proves no findings, even when `status == "completed"` and `conclusion == "success"`. Unknown or lookalike identities prove neither start nor completion.

The fixed authority baseline has no accepted no-start body grammar, so free-form exact-bot prose cannot currently prove unavailability. A future policy version may activate that path only with the provider-backed immutable grammar and regression contract required by the authority reference. An acknowledgement, review activity, or exact-App current-head check/run proves service start only. No response, an otherwise valid nonterminal/check-only state, or a retryable transport/read failure remains pending while bounded waiting is meaningful. After that wait is exhausted, it is `triple-inconclusive`. Unknown identity, malformed or stale evidence, a non-retryable request failure, or permanently incomplete enumeration is immediately inconclusive and never proves clean completion.

Classify precisely, applying selected-PR range alignment before the availability branch:

- A post-request base-only retarget with unchanged `pr_head_oid` is readiness `blocked-input` (`base-changed-same-head`) and `effective: triple-inconclusive`; invalidate the old whole-PR evidence but never post a replacement same-head request.
- Any other selected PR whose explicit range has `head_sha == pr_head_oid` but `base_sha != pr_merge_base` is readiness `blocked-input` (`scope-mismatch`). Do not rewrite the explicit range or count its local findings as whole-PR review evidence.
- Any existing PR with current `headRefOid != head_sha` and no separate PR-mutation authorization is a readiness `blocked-authorization` result. For a still-eligible PR, report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Only after an existing PR is head-aligned and its frozen range is exactly `pr_merge_base..pr_head_oid`, classify unsupported host/identity or directly known missing-integration/service evidence as third-lane unavailable and effective double. A future authenticated no-start response may join this branch only after an explicit grammar policy activates it. No PR is also effective double without a selected-PR range comparison.
- Service ran and returned findings: available lane with findings; fix and rerequest after the new head.
- Missing terminal evidence that proves neither unavailable nor started is `pending` while bounded waiting remains meaningful; when that wait is exhausted, report `requested: triple`, `effective: triple-inconclusive`.
- A started service with ambiguous authorship, stale head/range, malformed evidence, or a permanently incomplete association is immediately `requested: triple`, `effective: triple-inconclusive`.
- A started service with otherwise valid nonterminal/check-only evidence, missing terminal payload, or retryable incomplete pagination remains `pending` while bounded waiting is meaningful; after exhaustion, report `requested: triple`, `effective: triple-inconclusive`. Neither branch may become effective double, completed triple, or clean evidence.

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
