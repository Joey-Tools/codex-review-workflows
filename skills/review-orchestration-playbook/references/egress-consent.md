# Review Egress Consent

Use this reference before sending a repository diff, changed-file content, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Copilot, or GitHub Codex review.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user authorization for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. The authorization covers any necessary tracked code in the named repository at the frozen head, its generated diff, and the review prompt/result sent to OpenAI Codex, Anthropic Claude Code, and, only under the pinned fallback policy, Microsoft/GitHub Copilot. Triple review additionally opts into current-head GitHub Codex review. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

The selected reviewer is a trusted processor inside this workflow's trust boundary. Scoped consent covers necessary tracked review data in its original form, including a repository secret that passes the reduction gate; the helper need not rewrite the frozen diff or tracked context before the reviewer receives it. Consent still does not cover reviewer/runtime authentication credentials, untracked private files, unrelated repositories, broad workspace dumps, or hidden local-only artifacts.

## Provider Scope

- Codex local lane sends the frozen diff/prompt and necessary nearby tracked context to OpenAI Codex.
- Claude Code sends the same bounded scope to Anthropic.
- Copilot fallback sends the same bounded scope through GitHub Copilot only when the Claude Code backend is absent, has no usable local/API authentication, or all pinned Claude models are entitlement-blocked.
- GitHub Codex review uses the PR diff and repository guidance on GitHub.

`explicit-claude-review` authorizes only the Anthropic destination. The helper may use GitHub Copilot fallback only with `double-review` or `triple-review`, whose consent language explicitly names that fallback.

Record the actual runtime/model used in the terminal review report so consent and retention expectations remain auditable.

The helper enforces the intended scope with a frozen detached workspace, runtime-specific minimal environment, provider path/tool restrictions, an escaping-symlink preflight, and a bounded scan of complete base/head content, both sides of changed raw blobs, changed head-side paths, and the materialized head for credential-like paths and high-confidence secret patterns. The frozen diff and prompt remain bounded and integrity-checked, but they are not secret-egress filters. For each unregistered dynamic candidate that can be safely represented as exact bytes, it counts exact raw occurrences across every blob and symlink target in the complete base and head trees and requires a strict decrease: `head_raw_count < base_raw_count`. It also requires `head_unembedded_count <= base_unembedded_count`, where an occurrence is unembedded only when no strictly longer candidate completely contains it. An equal residual count, a candidate present only at head, a move, rename, copy, net increase, extracted substring, incomplete count, exceeded budget, or otherwise unsafe/uncountable candidate blocks egress. A changed sensitive path may pass only when it was deleted and the complete head contains no sensitive path; any credential-like or otherwise sensitive path at head blocks.

Exact helper-catalog authoring tokens and explicitly selected legacy envelopes keep their existing rules; the dynamic reduction gate does not broaden or replace them. In particular, legacy envelopes retain their catalog-declared non-increasing raw and unembedded count semantics, while unregistered dynamic candidates require a strict raw-count decrease. The preflight is a remediation gate, not the primary prevention layer: PR/master protection should reject secret introduction before merge. Once the frozen range passes, the reviewer receives the necessary tracked diff and context as recorded so it can judge the security-sensitive change accurately.

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
Joey explicitly requested <double review|triple review>, which is opt-in consent under AGENTS.md and $review-orchestration-playbook for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. This exact helper invocation sends necessary tracked code and the generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the review prompt/result, in their original form to Anthropic Claude Code for read-only review and, only if Claude Code is unavailable, has no usable local/API authentication, or both pinned Claude Opus models are entitlement-blocked, Microsoft/GitHub Copilot. The reviewer is a trusted processor inside this workflow's trust boundary; tracked repository secrets are included only when the helper proves the frozen range strictly reduces their complete-tree exact raw counts without increasing unembedded counts. This excludes reviewer/runtime authentication credentials, untracked files, unrelated repositories, and broad workspace or home-directory content. Allow this exact frozen Claude-family review lane?
```

Do not shorten this to `run external reviewer`: the exact user opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> diff、必要 changed-file context 和 review prompt/result 原样发送给 <Codex / Claude Code / GitHub Copilot / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。reviewer 是该工作流信任边界内的受信处理者；tracked repository secret 仅在 helper 证明完整 base/head 的精确 raw count 严格下降且 unembedded count 不增长时纳入。不要发送 reviewer/runtime authentication credentials、untracked private files、无关仓库或 broad workspace dumps。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
