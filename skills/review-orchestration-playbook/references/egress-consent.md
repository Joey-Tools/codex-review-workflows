# Review Egress Consent

Use this reference before sending a repository diff, changed-file content, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Copilot, or GitHub Codex review.

## Decision

Record repository visibility/trust, remote, PR URL when present, base/head identity, workspace content mode, data categories, destinations, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same review head.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user authorization for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. In default clean mode, authorization covers necessary tracked code in the named repository at the frozen head, its generated diff, and the review prompt/result. Triple review additionally opts into current-head GitHub Codex review. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

WIP content requires separate explicit authorization through `--include-source-wip`. That opt-in covers staged changes, unstaged changes, deletions, and non-ignored untracked files captured into the fixed digest-bound review artifact after sensitive-content scanning. It does not authorize ignored files, credentials, unrelated repositories, or any other local-only content, and it does not turn WIP evidence into formal PR-readiness evidence.

No consent covers credentials, broad workspace dumps, unrelated repositories, or home-directory content. Claude receives the ordinary real `HOME`, but the helper does not add HOME files to the review artifact or scan them as repository context; the reviewer prompt forbids reading them and explicit deny rules protect sensitive paths. Do not describe `--allowedTools` as a complete filesystem boundary.

## Provider Scope

- Codex local lane sends the selected clean or explicitly authorized WIP artifact, prompt, and necessary nearby context to OpenAI Codex.
- Claude Code sends the same bounded scope to Anthropic.
- Copilot fallback sends the same bounded scope through GitHub Copilot only when the verified Claude runtime is deterministically unavailable or both pinned Claude models are entitlement-blocked. Authentication failure is `blocked-authentication` and never authorizes fallback.
- GitHub Codex review uses the PR diff and repository guidance already present on GitHub.

`explicit-claude-review` authorizes only Anthropic. Only `double-review` and `triple-review` authorize the narrow GitHub Copilot fallback. Record the actual runtime/model and clean/WIP artifact identity in the terminal report.

The helper enforces artifact scope with a detached helper-owned worktree, runtime-specific model-tool restrictions, effective `dontAsk`/tool init evidence, escaping-symlink checks, and a conservative scan of the exact selected artifact, changed paths/blobs, diff, and prompt. It also requests Claude's native sandbox as defense in depth without claiming that the 2.1.212 init schema proves its effective settings or merged admin-managed permission arrays. After every completed Claude attempt, the same exact validation rejects observable worktree, private-Git, diff, or prompt mutation before a result or model fallback is accepted. This does not prove that no transient write or out-of-workspace side effect occurred. WIP mode includes every non-ignored untracked file in that scan. Findings report only side/path/rule metadata, never matched values. Synthetic authoring tokens may suppress only their exact catalog-declared finding. The scan is a backstop, not proof that content is secret-free; stop and narrow scope when sensitive or unrelated content is known to be present.

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

For WIP review, add `--include-source-wip` and name staged, unstaged, and non-ignored untracked content in the approval justification.

Use a narrow justification with concrete values:

```text
Joey explicitly requested <double review|triple review|Claude review>, authorizing scoped code-review egress for <owner/repo> at <base_sha>..<head_sha> in <clean exact-head|explicit digest-bound WIP> mode. This helper invocation sends the selected repository artifact, generated diff, necessary nearby context, and review prompt/result to Anthropic Claude Code and, only for double/triple review when the verified Claude runtime is deterministically unavailable or both pinned Claude models are entitlement-blocked, Microsoft/GitHub Copilot. Claude authentication failure pauses as `blocked-authentication` and does not fall back. WIP mode includes staged, unstaged, and non-ignored untracked files after sensitive-content scanning. This excludes credentials, ignored files, unrelated repositories, broad workspace dumps, and real-HOME content. Allow this exact Claude-family review lane?
```

Do not shorten this to `run external reviewer`: exact user opt-in, destination, repository, range/artifact, clean/WIP data categories, and exclusions let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的 <clean frozen range|包含 staged、unstaged、non-ignored untracked files 的 digest-bound WIP artifact>、必要 context 和 review prompt/result 发送给 <Codex / Claude Code / GitHub Copilot / GitHub Codex>，用于本次 review 及同一内容修复后的 rerun。不要发送 secrets、credentials、ignored files、无关仓库、broad workspace dumps 或 real-HOME 内容。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
