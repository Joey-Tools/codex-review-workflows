# GitHub PR Probes

Use these recipes when `$review-orchestration-playbook` needs PR metadata, review threads, branch protection, rules, check status, or merge state.

## GitHub Codex Availability And Current-Head Evidence

Before requesting the third lane, record the PR URL, host, authenticated/operating identity, and `headRefOid`.

- The lane is supported only on GitHub Cloud when the Codex review integration is available for the active identity.
- Treat host `sqbu-github.cisco.com` and any operating identity in `{hoteng, hoteng_cisco}` as unsupported.
- When no PR or an unsupported host/identity is directly known, record `requested: triple`, `effective: double`, and the exact reason without posting a request. Treat missing integration/service as unavailable only when authenticated provider evidence proves it; absence, timeout, permission error, or generic HTTP/network failure is inconclusive.
- On a supported PR, post the exact `@codex review` comment after the frozen head becomes current.

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
  --jq '[.[] | {id,user:.user.login,commit_id,submitted_at,state,html_url}]'

gh api --hostname <host> repos/<owner>/<repo>/issues/<number>/comments \
  --paginate \
  --jq '[.[] | {id,user:.user.login,created_at,updated_at,html_url,body}]'
```

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Keep the request URL/time, accepted terminal result URL/time/author, and exact `headRefOid`. Prefer a review whose `commit_id` equals `headRefOid`. If Codex answers only through an issue comment, require that the request and response both post after the head became current, that the author is the expected Codex integration identity, and that `headRefOid` stayed unchanged through acceptance. Re-read `headRefOid` before accepting the result. Any push invalidates earlier GitHub Codex evidence and requires a fresh request on the new head.

Posting `@codex review` is request transport, not completion or proof that the service started. An authenticated response from the expected GitHub/Codex identity, bound to the unchanged current head, may prove no-start unavailability when it explicitly rejects the request because the integration is missing/unsupported or the service is unavailable. An acknowledgement, run/check identity, or review activity proves service start. No response, unknown author, absent review/comment, request-comment failure, rate limit, permission error, timeout, or generic HTTP/network failure proves neither unavailable nor clean; report `triple-inconclusive`.

Classify precisely:

- No PR, unsupported host/identity, or authenticated no-start missing-integration/service-unavailable evidence: third lane unavailable; effective double.
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
