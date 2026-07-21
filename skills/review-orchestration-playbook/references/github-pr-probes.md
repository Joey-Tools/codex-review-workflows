# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, and `headRefOid`.

- The only supported host is exact `github.com`. Every other host is unsupported, including `sqbu-github.cisco.com` and every GitHub Enterprise host.
- Treat any operating identity in `{hoteng, hoteng_cisco}` as unsupported. Another identity on `github.com` is only an eligible candidate; it does not by itself prove that the integration or service is available.
- When authenticated discovery proves no PR, or an unsupported host/identity is directly known, record `requested: triple`, `effective: double`, and the exact reason without posting a request. Treat missing integration/service as unavailable only when authenticated evidence from the exact accepted provider identity below proves it; absence, timeout, permission error, or generic HTTP/network failure is inconclusive.
- On a supported PR, post the exact `@codex review` comment after the frozen head becomes current.

## Deterministic Range And PR Discovery

Use the first applicable scope source: an explicit frozen `base_sha..head_sha`; otherwise an explicitly named PR; otherwise the complete set of open PRs associated with the exact current head repository/branch. Preserve an explicit range before any PR probe. When there is no explicit range or PR, exactly one associated PR selects it; more than one is `blocked-input` (the required explicit PR/range/target selector is absent), and no lane may start until the caller supplies an explicit PR or frozen range. Do not select a candidate by recency, base, number, draft state, or title.

First obtain the exact current branch and head repository owner. A detached HEAD or unknown head owner cannot drive implicit PR association. Then use an authenticated, paginated lookup and retain the returned candidate array:

```sh
git branch --show-current

gh api --hostname <host> --paginate --slurp \
  'repos/<owner>/<repo>/pulls?state=open&head=<head-owner>:<current-branch>&per_page=100' \
  --jq '[.[][] | {number,html_url,base_ref:.base.ref,head_ref:.head.ref,head_sha:.head.sha,head_owner:.head.repo.owner.login}]'
```

An authenticated successful lookup returning `[]` proves the no-PR path. A failed, partial, unauthenticated, or ambiguous probe does not. No PR does not define the local review range: require either an explicit committed range or an explicitly named target/base, then resolve and freeze `<merge_base>..HEAD`. Never guess the target/base from repository defaults, upstream configuration, branch names, or conventions. Missing scope input from an otherwise clean checkout is `blocked-input`; use `blocked-authorization` only when the intended scope includes dirty/untracked state and an unauthorized branch or anchor commit would be required to represent it.

Use typed metadata before and after the request:

```sh
gh auth status --hostname <host>
gh api --hostname <host> user --jq .login

gh pr view <number> --repo <owner>/<repo> \
  --json number,url,headRefOid,comments,reviews \
  --jq '{number,url,headRefOid,comments,reviews}'

gh pr comment <number> --repo <owner>/<repo> --body '@codex review'

gh api --hostname <host> repos/<owner>/<repo>/pulls/<number>/reviews \
  --paginate \
  --jq '[.[] | {id,user:{login:.user.login,type:.user.type},commit_id,submitted_at,state,html_url}]'

gh api --hostname <host> repos/<owner>/<repo>/issues/<number>/comments \
  --paginate \
  --jq '[.[] | {id,user:{login:.user.login,type:.user.type},app_slug:.performed_via_github_app.slug,created_at,updated_at,html_url,body}]'

gh api --hostname github.com --paginate --slurp \
  'repos/<owner>/<repo>/commits/<head_sha>/check-runs?per_page=100' \
  --jq '[.[].check_runs[] | {id,name,status,conclusion,head_sha,details_url,app_slug:.app.slug}]'
```

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Keep the request URL/time, accepted terminal result URL/time/author, and exact `headRefOid`. Accept a review artifact only when its `commit_id` equals `headRefOid`. If Codex answers only through an issue comment, require that the request and response both post after the head became current, that the author has the exact accepted provider identity below, and that `headRefOid` stayed unchanged through acceptance. Accept a check/run only when its `head_sha` equals `headRefOid`. Re-read `headRefOid` before accepting any result. Any push invalidates earlier GitHub Codex evidence and requires a fresh request on the new head.

Posting `@codex review` is request transport, not completion or proof that the service started. Accept a provider-authored review/comment only when REST reports exact `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. When app/check evidence is used, accept only exact `app.slug == "chatgpt-codex-connector"`; a matching check name is not identity evidence. These comparisons are case-sensitive; missing, unknown, or lookalike authors/apps do not prove service start, a terminal result, or an authenticated no-start rejection.

An authenticated response from that exact accepted provider identity, bound to the unchanged current head, may prove no-start unavailability when it explicitly rejects the request because the integration is missing/unsupported or the service is unavailable. An acknowledgement, review activity, or check/run from the exact accepted provider/app identity proves service start. No response, unknown author/app, absent review/comment, request-comment failure, rate limit, permission error, timeout, or generic HTTP/network failure proves neither unavailable nor clean; report `triple-inconclusive`.

Classify precisely, applying existing-PR head alignment before the availability branch:

- Any existing PR with current `headRefOid != head_sha` and no separate PR-mutation authorization is a readiness `blocked-authorization` result. For a still-eligible PR, report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Only after an existing PR is head-aligned, classify unsupported host/identity or authenticated no-start missing-integration/service-unavailable evidence as third-lane unavailable and effective double. No PR is also effective double without a head comparison.
- Service ran and returned findings: available lane with findings; fix and rerequest after the new head.
- Missing or ambiguous evidence that proves neither unavailable nor started: `requested: triple`, `effective: triple-inconclusive`.
- A started service with ambiguous authorship, stale head, malformed result, or transiently incomplete evidence: `requested: triple`, `effective: triple-inconclusive`; do not reinterpret it as effective double or clean evidence.

## Prefer Typed `gh`

Start with stable typed `gh` forms:

- `gh pr view --json ...`
- `gh pr view <number> --json number,url,state,isDraft,baseRefName,headRefName,headRefOid,mergeStateStatus,mergeable,reviewDecision,statusCheckRollup`
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
