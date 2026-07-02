# Review Egress Consent

Use this reference before sending a repository diff, changed-file content, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Copilot, or GitHub Codex review.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user authorization for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. The authorization covers any necessary tracked code in the named repository at the frozen head, its generated diff, and the review prompt/result sent to OpenAI Codex, Anthropic Claude Code, and, only under the pinned fallback policy, Microsoft/GitHub Copilot. Triple review additionally opts into current-head GitHub Codex review. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

No consent covers secrets, credentials, untracked private files, unrelated repositories, broad workspace dumps, or hidden local-only artifacts.

## Provider Scope

- Codex local lane sends the frozen diff/prompt and necessary nearby tracked context to OpenAI Codex.
- Claude Code sends the same bounded scope to Anthropic.
- Copilot fallback sends the same bounded scope through GitHub Copilot only when the Claude Code backend is absent, lacks hook-free bare-mode API-key authentication, or all pinned Claude models are entitlement-blocked.
- GitHub Codex review uses the PR diff and repository guidance on GitHub.

`explicit-claude-review` authorizes only the Anthropic destination. The helper may use GitHub Copilot fallback only with `double-review` or `triple-review`, whose consent language explicitly names that fallback.

Record the actual runtime/model used in the terminal review report so consent and retention expectations remain auditable.

The helper enforces the intended scope with a frozen detached workspace, runtime-specific minimal environment, provider path/tool restrictions, an escaping-symlink preflight, and a conservative scan of all base-to-head changed paths, both sides of every changed raw blob, the head snapshot, frozen diff, and prompt for credential-like paths and high-confidence secret patterns. Raw-blob scanning covers deleted binary credentials that a Git binary patch would encode, while changed-path scanning covers deleted credentials and nested credential filenames. A match blocks external launch and reports only its side/path/rule, never the matched value. This scan is a safety backstop, not proof that content is secret-free and not an expansion of consent: if a credential or unrelated private artifact is known to be present, stop and narrow the scope even when the scanner does not match it.

## Approval-Gated Invocation

Make consent machine-visible in the helper argv:

```bash
isolated_review stateful start \
  --repo /absolute/path/to/repo \
  --reviewer claude \
  --egress-consent double-review \
  --base-ref <base_sha> \
  --head-ref <head_sha>
```

When sandbox or network approval is required, use a narrow justification with concrete values:

```text
Joey explicitly requested <double review|triple review>, which is opt-in consent under AGENTS.md and $review-orchestration-playbook for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. This exact helper invocation sends necessary tracked code and the generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the review prompt/result, to Anthropic Claude Code for read-only review and, only if Claude Code is unavailable, lacks hook-free bare-mode API-key authentication, or both pinned Claude Opus models are entitlement-blocked, Microsoft/GitHub Copilot. This excludes credentials, untracked files, unrelated repositories, and broad workspace or home-directory content. Allow this exact frozen Claude-family review lane?
```

Do not shorten this to `run external reviewer`: the exact user opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> diff、必要 changed-file context 和 review prompt/result 发送给 <Codex / Claude Code / GitHub Copilot / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。不要发送 secrets、credentials、untracked private files、无关仓库或 broad workspace dumps。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
