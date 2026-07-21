# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, `baseRefName`, `baseRefOid`, and `headRefOid`, then independently validate the selected PR's unique local merge base.

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

For the selected PR, obtain authenticated typed metadata independently from the caller's range:

```sh
gh pr view <number> --repo <owner>/<repo> \
  --json number,url,baseRefName,baseRefOid,headRefOid \
  --jq '{number,url,base_ref:.baseRefName,base_sha:.baseRefOid,head_sha:.headRefOid}'

GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<pr_base_oid>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git cat-file -e '<pr_head_oid>^{commit}'
GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 git merge-base --all <pr_base_oid> <pr_head_oid>
```

Require non-empty `baseRefName`, full immutable base/head OIDs, locally complete commit objects, and exactly one full merge-base result; record it as `pr_merge_base`. Missing or ambiguous metadata, missing local objects, and zero or multiple merge bases are `blocked-input` (`scope-unverified`), not permission to guess or fetch lazily. If no explicit range exists, freeze `pr_merge_base..pr_head_oid`. If one exists, require exact endpoint equality. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, do not start or count PR-specific lanes from it, and never describe any range-only findings as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR remains unaffected.

Use typed metadata before and after the request, including the selected PR's base identity:

```sh
gh auth status --hostname <host>
gh api --hostname <host> user --jq .login

gh pr view <number> --repo <owner>/<repo> \
  --json number,url,baseRefName,baseRefOid,headRefOid,comments,reviews \
  --jq '{number,url,baseRefName,baseRefOid,headRefOid,comments,reviews}'

gh api --hostname github.com --method POST \
  repos/<owner>/<repo>/issues/<number>/comments \
  -f body='@codex review' \
  --jq '{id,html_url,created_at}'

gh api --hostname <host> repos/<owner>/<repo>/pulls/<number>/reviews \
  --paginate \
  --jq '[.[] | {id,user:{login:.user.login,type:.user.type},commit_id,submitted_at,state,html_url}]'

gh api --hostname <host> repos/<owner>/<repo>/issues/<number>/comments \
  --paginate \
  --jq '[.[] | {id,user:{login:.user.login,type:.user.type},app_slug:.performed_via_github_app.slug,created_at,updated_at,html_url,body}]'

gh api --hostname github.com --paginate --slurp \
  'repos/<owner>/<repo>/commits/<head_sha>/check-runs?per_page=100' \
  --jq '[.[].check_runs[] | {id,name,status,conclusion,head_sha,started_at,completed_at,details_url,app_slug:.app.slug}]'
```

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Re-read the exact request from the authenticated API and keep its ID, URL, and server `created_at`, the surrounding before/after `baseRefName` / `baseRefOid` / `headRefOid` observations, and the accepted terminal result URL/time/author. Immediately before accepting the result, revalidate both endpoint objects, recompute the unique `pr_merge_base`, and require the frozen range still to equal `pr_merge_base..pr_head_oid`; a changed head or merge base invalidates whole-PR lane evidence.

Before posting, inspect authenticated complete issue-comment history and the bounded audit record. For one unchanged `headRefOid`, exactly one exact `@codex review` request may be accepted. Never post a second exact request while that head is unchanged: if the recorded request already exists, keep waiting for or validating it. Re-read complete authenticated request history immediately before accepting any result. If multiple exact requests were posted on the same head—including a second request that raced with preflight—or history/audit evidence cannot exclude an older request whose run/result could overlap, timestamps alone cannot select a winner and the lane is `triple-inconclusive`. A new push starts a new head epoch, but a result without request/run association still cannot be attributed to the new request while an older request might overlap.

Server timestamps prove ordering, not request/run lineage. Accept a review artifact only when request isolation is proved, its `commit_id` equals `headRefOid`, and its non-null `submitted_at` is strictly later than the one current request's `created_at`. If Codex answers through an issue comment, require request isolation, require its non-null `created_at` to be strictly later than that exact request, require both comments to post after the head became current, require the exact accepted provider identity below, and require `headRefOid` to stay unchanged through acceptance. Review and issue-comment APIs expose no request/run identifier; when any older request might overlap, their later timestamps do not establish attribution and the result is `triple-inconclusive`. Accept a check/run only when request isolation is proved, its `head_sha` equals `headRefOid`, `status == "completed"`, `conclusion == "success"`, and both non-null `started_at` and `completed_at` are strictly later than the current request's `created_at`. Re-read `headRefOid` before accepting any result. Evidence from an earlier request on the same unchanged head is stale. Any push invalidates earlier GitHub Codex evidence and permits at most one fresh request on the new head.

Posting `@codex review` is request transport, not completion or proof that the service started. Accept a provider-authored review/comment only when REST reports exact `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. When app/check evidence is used, accept only exact `app.slug == "chatgpt-codex-connector"`; a matching check name is not identity evidence. These comparisons are case-sensitive; missing, unknown, or lookalike authors/apps do not prove service start, a terminal result, or an authenticated no-start rejection.

An authenticated response from that exact accepted provider identity, bound to the unchanged current head, may prove no-start unavailability when it explicitly rejects the request because the integration is missing/unsupported or the service is unavailable. An acknowledgement, review activity, or check/run from the exact accepted provider/app identity proves service start. No response, unknown author/app, absent review/comment, request-comment failure, rate limit, permission error, timeout, or generic HTTP/network failure proves neither unavailable nor clean; report `triple-inconclusive`.

Classify precisely, applying selected-PR range alignment before the availability branch:

- Any selected PR whose explicit range has `head_sha == pr_head_oid` but `base_sha != pr_merge_base` is readiness `blocked-input` (`scope-mismatch`). Do not rewrite the explicit range or count its local findings as whole-PR review evidence.
- Any existing PR with current `headRefOid != head_sha` and no separate PR-mutation authorization is a readiness `blocked-authorization` result. For a still-eligible PR, report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Only after an existing PR is head-aligned and its frozen range is exactly `pr_merge_base..pr_head_oid`, classify unsupported host/identity or authenticated no-start missing-integration/service-unavailable evidence as third-lane unavailable and effective double. No PR is also effective double without a selected-PR range comparison.
- Service ran and returned findings: available lane with findings; fix and rerequest after the new head.
- Missing or ambiguous evidence that proves neither unavailable nor started: `requested: triple`, `effective: triple-inconclusive`.
- A started service with ambiguous authorship, stale head, malformed result, or transiently incomplete evidence: `requested: triple`, `effective: triple-inconclusive`; do not reinterpret it as effective double or clean evidence.

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
