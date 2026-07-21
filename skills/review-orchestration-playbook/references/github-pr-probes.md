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

Treat `gh api --hostname <host> user --jq .login` as the operating identity for this invocation; `gh auth status` is supporting account/host context, not the identity value by itself. Keep the request URL/time, accepted terminal result URL/time/author, and exact `headRefOid`. Prefer a review whose `commit_id` equals `headRefOid`; this is the strongest ordinary current-head binding. Require the expected Codex integration identity and a review time after the current-head request. Re-read `headRefOid` before accepting the result. Any push invalidates earlier GitHub Codex evidence and requires a fresh request on the new head.

### Issue-comment-only correlation

This is an evidence-correlation rule inside the existing GitHub Codex lane, not another review lane or readiness gate. Apply it whenever the only candidate terminal result or authenticated no-start rejection is an issue comment.

Keep a request ledger across the PR's issue-comment history. For every exact `@codex review` request, record its comment ID, URL, time, and the full `headRefOid` observed when it was posted. Keep the request unresolved until trustworthy correlated terminal or no-start evidence resolves it. A later push or head change invalidates that request for the new head but does **not** resolve the older request.

Before considering correlation, require all of the following:

- the candidate comment author is the expected GitHub Codex integration identity;
- the current request was posted after the accepted head became current, and the candidate response was posted after that request; and
- the same full `headRefOid` remained current from the request through the final acceptance reread.

For a terminal completion, require one of these correlation paths:

1. **Explicit binding:** trusted provider evidence ties the candidate to the exact request comment ID/URL or to a run/check identity already tied to that request, **or** the candidate names the full exact current `headRefOid`. A completion comment such as `Reviewed commit: <headRefOid>` is sufficient even when it contains no request link.
2. **Unambiguous fallback:** when the candidate has no explicit request, run, or head marker, the current request is the sole still-unresolved `@codex review` request across **all** recorded heads, and no other `@codex review` request intervened between it and the candidate response.

Do not infer resolution from a head change, infer request identity from similar wording, or pair a response to the nearest request by timestamp alone. If an older request remains unresolved and the candidate lacks explicit binding, or if any intervening request makes the fallback ambiguous, classify the third lane as `triple-inconclusive`.

An authenticated no-start rejection has a stricter request-binding requirement because a full SHA proves only which head the response concerns, not which same-head request it rejects. Accept no-start correlation only when trusted provider evidence ties the rejection to the exact request comment ID/URL or to a provider request/dispatch identity already tied to that request, or when the same sole-unresolved/no-intervening fallback applies. A delayed SHA-only rejection while another same-head request remains unresolved is `triple-inconclusive`, even when the head stayed current. An acknowledgement or actual run, check, or review activity proves service start and therefore cannot supply no-start fallback evidence.

| Candidate evidence | Decision |
| --- | --- |
| Expected-author review with `commit_id == headRefOid`, after the current request | Accept as the preferred strong current-head binding. |
| Expected-author completion comment on a stable current head that names the full current SHA, for example `Reviewed commit: <headRefOid>` | Accept the completion; an exact SHA is sufficient without a request URL. |
| Expected-author issue comment on a stable current head tied to the exact request ID/URL or its already-linked run identity | Accept. |
| Marker-free expected-author issue comment; this request is the sole unresolved request across all heads and no request intervened | Accept only through the unambiguous fallback. |
| Expected-author no-start rejection tied to the exact request/dispatch identity, or covered by the sole-unresolved/no-intervening fallback | Correlate it; only an explicit missing-integration/service-unavailable rejection may then prove effective double. |
| SHA-only delayed no-start rejection while another request on the same head remains unresolved | `triple-inconclusive`; the SHA binds the head but not the rejected request. |
| Marker-free comment after a new-head request while an older-head request remains unresolved, or after an intervening request | `triple-inconclusive`; the head change and nearest timestamp do not disambiguate it. |
| Unknown author, response before the request, or head changed before acceptance | Reject as untrustworthy or stale; report `triple-inconclusive` unless separate authenticated evidence proves no-start unavailability. |

Only after an authenticated no-start rejection satisfies its stricter request/dispatch binding or the sole-unresolved fallback may an explicit missing-integration or service-unavailable statement justify effective double. A full SHA by itself, an uncorrelated rejection, or a generic rejection remains `triple-inconclusive`.

Posting `@codex review` is request transport, not completion or proof that the service started. An authenticated response from the expected GitHub/Codex identity, correlated under the rule above and bound to the unchanged current head, may prove no-start unavailability when it explicitly rejects the request because the integration is missing/unsupported or the service is unavailable. An acknowledgement, run/check identity, or review activity proves service start. No response, unknown author, absent review/comment, request-comment failure, rate limit, permission error, timeout, or generic HTTP/network failure proves neither unavailable nor clean; report `triple-inconclusive`.

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
