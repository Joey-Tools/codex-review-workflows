# Review Egress Consent

Use this reference before sending changed tracked content, bounded review evidence, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Codex review, or a separately requested external reviewer.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

Any unambiguous request classified as single, double, or triple review is contemporaneous user authorization for scoped code-review egress to the providers in exactly that named shape. Examples include `single review`, `single code review`, `单重 review`, `单一 review`, `double`, `double review`, `double code review`, `双重 review`, `triple`, `triple review`, and `三重 review`. Single authorizes OpenAI Codex. Double additionally authorizes Anthropic Claude Code. Triple additionally authorizes GitHub Codex on an exact-host `github.com` PR. The authorization covers necessary tracked code in the named repository at the frozen head, bounded tool-derived review evidence, and the review prompt/result. The named Codex `reviewer` agent receives the clean worktree and exact refs and derives `base_sha..head_sha` itself; its prompt must not contain a prebuilt full diff. Actual Claude Code reviews the same frozen range from another independent read-only workspace. These requests do not authorize GitHub Copilot or another substitute reviewer. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

The selected reviewer is a trusted processor. Named-shape consent covers the original tracked diff and necessary tracked context, including tracked repository secrets, plus bounded review evidence and the prompt/result. Do not redact, rewrite, encode, withhold, or block those reviewer inputs based on secret-admission status. Consent does not cover automatic discovery or collection of reviewer/runtime authentication credentials, untracked private files, unrelated repositories, broad workspace dumps, home-directory content, or hidden local-only artifacts.

## Provider Scope

- The only local Codex lane that counts is one clear/fresh-context `reviewer` agent in a separate clean read-only Git worktree. It loads applicable skills, scoped `AGENTS.md` files, and project guidance, then derives and inspects the exact frozen range through bounded Git/tool calls.
- The second named lane is actual Anthropic Claude Code in a different independent read-only workspace over that same range.
- GitHub Copilot requires a separate explicit request and consent. It is supplemental only and never makes a named double review complete. Claude Code unavailability or authentication failure does not expand the named request to another provider.
- The third named lane requires exact `@codex review` on exact host `github.com` and completes only with a complete terminal provider-authored findings payload bound to that PR's current head, whole-PR range, and isolated request. Every other host, including `sqbu-github.cisco.com` and every GitHub Enterprise host, and every operating identity in `{hoteng, hoteng_cisco}` is unsupported. Completion evidence must come from exact REST `user.login == "chatgpt-codex-connector[bot]"` with exact `user.type == "Bot"`: consume the review body plus every fully paginated associated inline review comment, or a terminal issue-comment body. Missing or ambiguous payload, terminal nature, or association is `triple-inconclusive`. Exact `app.slug == "chatgpt-codex-connector"` check/run evidence can prove only current-head post-request service start; it never completes triple or proves clean/no-findings, even when `completed` / `success`, because a same-App check may be unrelated and may coexist with review findings. Unknown identities are inconclusive. If there is no PR or the lane is proved unavailable, report `effective double`, not triple. Missing response or generic failure is inconclusive.

`explicit-claude-review` authorizes only the Anthropic destination and is the helper marker for an explicitly requested Claude-only diagnostic. `explicit-claude-with-copilot-fallback` is permitted only after a separate explicit user request authorizes both Anthropic and this helper's compatibility GitHub Copilot fallback. Named shape phrases and legacy `double-review` / `triple-review` values are never passed as helper consent markers, and a supplemental Copilot artifact never satisfies a named lane.

Record the actual runtime/model used in the terminal review report so consent and retention expectations remain auditable.

The legacy `isolated_review` Codex helper may remain available for low-level compatibility or diagnostics, but it never counts toward named single, double, or triple review. PR readiness likewise adds no retired extra Codex gates.

Reviewer launch and PR/master secret admission are separate decisions. Workspace containment, frozen-scope identity, object completeness, artifact integrity, or reviewer-sandbox failures may block launch; a tracked secret delta may not. Once the scoped egress boundary is valid, the trusted reviewer may inspect original tracked content, including secrets, without redaction. The admission audit uses one global counter per exact raw secret byte value across complete base/head raw Git path bytes, regular-file blobs, and symlink-target bytes. It permits `head_count <= base_count`; only first appearance or count growth violates admission. It deliberately does not derive Base64, hex, URL-encoded, escaped, hashed, or other transformed variants. Incomplete enumeration or count integrity is `inconclusive`, and violation diagnostics list only head-side added locations rather than unchanged occurrences. Exact approved authoring fixtures retain only their declared scanner-rule acceptance; legacy selection is not required.

## Direct Admission And Optional Helper Evidence

Required PR/master admission comes from `isolated_review secret-admission --repo <repo> --base-ref <base_sha> --head-ref <head_sha>` under `review_contract: admission-only-no-reviewer`. This direct current-head Git-tree scan starts no reviewer and has no pending state: exit `0` with `temporary_cleanup_status: complete` is clean, exit `1` means proved violations and remains `1` after a later location/cleanup failure, and exit `75` is an inconclusive scan or a clean scan whose temporary cleanup failed. When a low-level helper run was independently requested, its `stateful final` and `stateful admission` results remain optional helper-only evidence; they never become the PR/master admission producer or an extra named lane. Foreground review is not helper-state admission evidence, and a head change invalidates every affected result.

## Approval-Gated Invocation

Make consent machine-visible in the helper argv:

```bash
isolated_review stateful start \
  --repo /absolute/path/to/repo \
  --reviewer claude \
  --egress-consent explicit-claude-review \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

When sandbox or network approval is required, use a narrow justification with concrete values:

```text
Joey explicitly requested Claude Code review, which is opt-in consent under AGENTS.md and $review-orchestration-playbook for scoped code-review egress to Anthropic. This exact helper diagnostic sends necessary original tracked code and its generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the review prompt/result, to Anthropic Claude Code for read-only review. The reviewer is a trusted processor and may receive tracked repository secrets regardless of the separate PR/master secret-admission result; the helper does not redact those inputs. It does not authorize GitHub Copilot or another provider. This excludes automatic discovery of reviewer/runtime authentication credentials, untracked files, unrelated repositories, and broad workspace/home-directory content. Allow this exact frozen Claude Code helper run?
```

Do not shorten this to `run external reviewer`: the exact user opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> 中必要的 original tracked diff/context、bounded review evidence 和 review prompt/result 原样发送给 <Codex / Claude Code / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。reviewer 是受信处理者，可以读取 tracked repository secrets；不要因 secret-admission 结果 redact 或阻止 reviewer。不要自动发现或发送 reviewer/runtime authentication credentials、untracked private files、无关仓库或 broad workspace dumps，也不要替换成未明确授权的 provider。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
