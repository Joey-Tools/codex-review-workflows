# Review Egress Consent

Use this reference before sending changed tracked content, bounded review evidence, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Codex review, or a separately requested external reviewer.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

Any unambiguous request classified as single, double, or triple review is contemporaneous user authorization for scoped code-review egress to the providers in exactly that named shape. Examples include `single review`, `single code review`, `单重 review`, `单一 review`, `double`, `double review`, `double code review`, `双重 review`, `triple`, `triple review`, and `三重 review`. Single authorizes OpenAI Codex. Double additionally authorizes Anthropic Claude Code. Triple additionally authorizes GitHub Codex on a supported GitHub Cloud PR. The authorization covers necessary tracked code in the named repository at the frozen head, bounded tool-derived review evidence, and the review prompt/result. The named Codex `reviewer` agent receives the clean worktree and exact refs and derives `base_sha..head_sha` itself; its prompt must not contain a prebuilt full diff. Actual Claude Code reviews the same frozen range from another independent read-only workspace. These requests do not authorize GitHub Copilot or another substitute reviewer. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

No consent covers secrets, credentials, untracked private files, unrelated repositories, broad workspace dumps, or hidden local-only artifacts.

## Provider Scope

- The only local Codex lane that counts is one clear/fresh-context `reviewer` agent in a separate clean read-only Git worktree. It loads applicable skills, scoped `AGENTS.md` files, and project guidance, then derives and inspects the exact frozen range through bounded Git/tool calls.
- The second named lane is actual Anthropic Claude Code in a different independent read-only workspace over that same range.
- GitHub Copilot requires a separate explicit request and consent. It is supplemental only and never makes a named double review complete. Claude Code unavailability or authentication failure does not expand the named request to another provider.
- The third named lane requires exact `@codex review` on a supported GitHub Cloud PR and completes only with a trustworthy terminal GitHub Codex result bound to that PR's current head. If there is no PR, or GitHub Codex is proved unavailable for the integration, host, or identity—including host `sqbu-github.cisco.com` and operating identity in `{hoteng, hoteng_cisco}`—report `effective double`, not triple. Missing response or generic failure is inconclusive.

`explicit-claude-review` authorizes only the Anthropic destination and is the helper marker for an explicitly requested Claude-only diagnostic. `explicit-claude-with-copilot-fallback` is permitted only after a separate explicit user request authorizes both Anthropic and this helper's compatibility GitHub Copilot fallback. Named shape phrases are never passed as helper consent markers, and a supplemental Copilot artifact never satisfies a named lane.

Record the actual runtime/model used in the terminal review report so consent and retention expectations remain auditable.

The legacy `isolated_review` Codex helper may remain available for low-level compatibility or diagnostics, but it never counts toward named single, double, or triple review. PR readiness likewise adds no retired extra Codex gates.

The helper enforces the intended scope with a frozen detached workspace, runtime-specific minimal environment, provider path/tool restrictions, an escaping-symlink preflight, and a conservative scan of all base-to-head changed paths, both sides of every changed raw blob, the head snapshot, frozen diff, and prompt for credential-like paths and high-confidence secret patterns. Raw-blob scanning covers deleted binary credentials that a Git binary patch would encode, while changed-path scanning covers deleted credentials and nested credential filenames. A match blocks external launch and reports only its side/path/rule, never the matched value. Exact helper-catalog authoring tokens may suppress only their declared generic assignment finding, while credential-like paths and all other rules continue to block; explicitly selected legacy envelopes additionally require non-increasing complete-tree counts and never apply to prompts. This scan is a safety backstop, not proof that content is secret-free and not an expansion of consent: if a credential or unrelated private artifact is known to be present, stop and narrow the scope even when the scanner does not match it.

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
Joey explicitly requested Claude Code review, which is opt-in consent under AGENTS.md and $review-orchestration-playbook for scoped code-review egress to Anthropic. This exact helper diagnostic sends necessary tracked code and its generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the review prompt/result, to Anthropic Claude Code for read-only review. It does not authorize GitHub Copilot or another provider. This excludes credentials, untracked files, unrelated repositories, and broad workspace or home-directory content. Allow this exact frozen Claude Code helper run?
```

Do not shorten this to `run external reviewer`: the exact user opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> 中必要的 tracked changed-file context、bounded review evidence 和 review prompt/result 发送给 <Codex / Claude Code / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。不要发送 secrets、credentials、untracked private files、无关仓库或 broad workspace dumps，也不要替换成未明确授权的 provider。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
