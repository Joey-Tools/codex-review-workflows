# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, lifecycle tuple `state` / `merged` / `merged_at`, `baseRefName`, `baseRefOid`, and `headRefOid`, then independently validate the selected PR's unique local merge base. Only exact `state == "open"`, `merged == false`, and `merged_at == null` is an eligible lifecycle.

- The only supported host is exact `github.com`. Every other host is unsupported, including `sqbu-github.cisco.com` and every GitHub Enterprise host.
- Treat any operating identity in `{hoteng, hoteng_cisco}` as unsupported. Another identity on `github.com` is only an eligible candidate; it does not by itself prove that the integration or service is available.
- When authenticated discovery proves no PR, or an unsupported host/identity is directly known, record `requested: triple`, `effective: double`, and the exact reason without posting a request. Treat missing integration/service as unavailable only when authenticated evidence from the exact accepted provider identity below proves it; absence, timeout, permission error, or generic HTTP/network failure is inconclusive.
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

Use host-bound REST metadata before and after the request, including the selected PR's base identity. Fully paginate and slurp every list that participates in request isolation or the provider findings payload:

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
  'repos/<owner>/<repo>/pulls/<number>/reviews/<review_id>/comments?per_page=100' \
  --jq '[.[][] | {id,pull_request_review_id,user:{login:.user.login,type:.user.type},commit_id,original_commit_id,path,line,original_line,side,html_url,body}]'

gh api --hostname <host> --method GET --paginate --slurp \
  'repos/<owner>/<repo>/commits/<head_sha>/check-runs?per_page=100' \
  --jq '[.[].check_runs[] | {id,name,status,conclusion,head_sha,started_at,completed_at,details_url,app_slug:.app.slug}]'
```

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Re-read the exact request from the authenticated API and keep its ID, URL, and server `created_at`, the surrounding before/after lifecycle plus `baseRefName` / `baseRefOid` / `headRefOid` observations, immutable selected-PR `range_origin.kind` / `base_sha` / `head_sha`, and the accepted terminal result URL/time/author. The origin kind is exactly `caller-supplied` or `pr-derived`; never infer it from a later parent-provided range or overwrite original caller endpoints. Revalidate the exact open lifecycle tuple during initial selected-PR preflight, immediately before posting, immediately before accepting a result, and during final readiness/merge verification. Immediately before accepting the result, also revalidate both endpoint objects, recompute the unique `pr_merge_base`, and require the frozen range still to equal `pr_merge_base..pr_head_oid`; an observed non-open lifecycle at a mandated snapshot, a changed head, or a changed merge base invalidates whole-PR lane evidence.

These REST lifecycle reads are point-in-time snapshots. They do not prove that no intermediate close-and-reopen occurred between mandated probes. Do not claim a complete lifecycle-history attestation from them. If separately collected, authenticated, fully paginated lifecycle-event history shows a post-start close, reopen, or merge, invalidate the evidence; missing event-history evidence does not strengthen the snapshot claim.

Before posting, inspect authenticated complete issue-comment history and the bounded audit record. For one unchanged `headRefOid`, exactly one exact `@codex review` request may be accepted. Never post a second exact request while that head is unchanged: if the recorded request already exists, keep waiting for or validating it. Re-read complete authenticated request history immediately before accepting any result. If multiple exact requests were posted on the same head—including a second request that raced with preflight—or history/audit evidence cannot exclude an older request whose run/result could overlap, timestamps alone cannot select a winner and the lane is `triple-inconclusive`. A new push starts a new head epoch, but a result without request/run association still cannot be attributed to the new request while an older request might overlap.

Before applying the generic same-head/different-base `scope-mismatch` branch, compare an accepted same-head request's audited request-time merge base with current `pr_merge_base` and apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json). If it changed while `headRefOid` remained unchanged, the old request/result no longer covers the whole PR and the same-head request limit prevents a replacement. Missing origin, stale-range, and unauthorized parent-rewrite transitions stop before local lanes. An exact current range newly supplied by the caller recovers local lanes for caller-origin state; normal exact-current rederivation recovers them for PR-derived state. Either recovery proceeds to local lanes but keeps readiness `blocked-input` (`base-changed-same-head`) plus `requested: triple`, `effective: triple-inconclusive`, and neither permits another same-head request. Eligibility returns only after a separately authorized ordinary change produces a new head, and no empty or anchor commit may manufacture that epoch.

Server timestamps prove ordering, not request/run lineage. Accept a review artifact only when request isolation is proved, its `commit_id` equals `headRefOid`, its non-null `submitted_at` is strictly later than the one current request's `created_at`, and its exact API state unambiguously denotes a submitted terminal review (`COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`; never `PENDING`, `DISMISSED`, missing, or unknown). Fetch that review's `body` and the fully paginated associated inline-comment list through its exact `<review_id>`. Require every inline record's `pull_request_review_id` to equal that review ID and every payload author to have the exact accepted bot identity. The combined body/comments payload must unambiguously report the complete findings outcome; a clean claim additionally requires an explicit provider-authored no-findings statement and zero associated actionable findings. If Codex answers through an issue comment, require request isolation, require its non-null `created_at` to be strictly later than that exact request, require both comments to post after the head became current, require the exact accepted provider identity below, require `headRefOid` and the whole-PR range to stay unchanged through acceptance, and require the body to unambiguously state a terminal completed findings/no-findings outcome rather than acknowledgement or progress. Review and issue-comment APIs expose no request/run identifier; when any older request might overlap, their later timestamps do not establish attribution and the result is `triple-inconclusive`. Re-read `headRefOid` and the whole-PR range before accepting any result. Evidence from an earlier request on the same unchanged head is stale. Any push invalidates earlier GitHub Codex evidence and permits at most one fresh request on the new head.

Posting `@codex review` is request transport, not completion or proof that the service started. Accept a provider-authored terminal findings payload only when REST reports exact `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. A review payload is the selected review body plus every fully paginated associated inline review comment; an issue-comment payload is its terminal body. Missing or ambiguous payload, terminal nature, pagination completeness, or review/comment association is `triple-inconclusive`. When app/check evidence is used for service-start detection, accept only exact `app.slug == "chatgpt-codex-connector"`, exact current `head_sha`, and non-null `started_at` strictly later than the request; a matching check name is not identity evidence. A check/run is service-start evidence only and never completes triple or proves a clean/no-findings result, even when `status == "completed"`, `conclusion == "success"`, and `completed_at` is post-request. A same-App check may be unrelated to the requested review, and check success can coexist with provider review findings. These comparisons are case-sensitive; missing, unknown, or lookalike authors/apps do not prove service start, a terminal result, or an authenticated no-start rejection.

An authenticated response from that exact accepted provider identity, bound to the unchanged current head, may prove no-start unavailability when it explicitly rejects the request because the integration is missing/unsupported or the service is unavailable. An acknowledgement or review activity from the exact accepted provider identity, or an exact-App current-head post-request check/run, proves service start only. No response, unknown author/app, absent review/comment, request-comment failure, rate limit, permission error, timeout, generic HTTP/network failure, or check-only evidence proves clean completion; report `triple-inconclusive` when no complete terminal exact-bot findings payload follows.

Classify precisely, applying selected-PR range alignment before the availability branch:

- A post-request base-only retarget with unchanged `pr_head_oid` is readiness `blocked-input` (`base-changed-same-head`) and `effective: triple-inconclusive`; invalidate the old whole-PR evidence but never post a replacement same-head request.
- Any other selected PR whose explicit range has `head_sha == pr_head_oid` but `base_sha != pr_merge_base` is readiness `blocked-input` (`scope-mismatch`). Do not rewrite the explicit range or count its local findings as whole-PR review evidence.
- Any existing PR with current `headRefOid != head_sha` and no separate PR-mutation authorization is a readiness `blocked-authorization` result. For a still-eligible PR, report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Only after an existing PR is head-aligned and its frozen range is exactly `pr_merge_base..pr_head_oid`, classify unsupported host/identity or authenticated no-start missing-integration/service-unavailable evidence as third-lane unavailable and effective double. No PR is also effective double without a selected-PR range comparison.
- Service ran and returned findings: available lane with findings; fix and rerequest after the new head.
- Missing or ambiguous evidence that proves neither unavailable nor started: `requested: triple`, `effective: triple-inconclusive`.
- A started service with ambiguous authorship, stale head/range, malformed or nonterminal payload, incomplete pagination or association, or check-only evidence: `requested: triple`, `effective: triple-inconclusive`; do not reinterpret it as effective double, completed triple, or clean evidence.

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
