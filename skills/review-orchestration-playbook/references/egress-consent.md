# Review Egress Consent

Use this reference before sending a repository diff, changed-file content, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Copilot, or GitHub Codex review.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user authorization for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. The authorization covers any necessary tracked code in the named repository at the frozen head, its generated diff, and the review prompt/result sent to OpenAI Codex, Anthropic Claude Code, and, only under the pinned fallback policy, Microsoft/GitHub Copilot. Triple review additionally opts into current-head GitHub Codex review. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

The selected reviewer is a trusted processor inside this workflow's trust boundary. Scoped consent covers necessary tracked review data and an explicitly supplied review prompt in their original form, including repository secrets; the helper need not rewrite those inputs before the reviewer receives them. Consent does not authorize the helper to automatically discover or collect reviewer/runtime authentication credential sources, untracked private files, unrelated repositories, broad workspace dumps, or hidden local-only artifacts. Explicitly supplied prompt or tracked-review bytes are not compared against runtime credential values; byte equality does not remove them from the trusted reviewer input.

## Provider Scope

- Codex local lane sends the frozen diff/prompt and necessary nearby tracked context to OpenAI Codex.
- Claude Code sends the same bounded scope to Anthropic.
- Copilot fallback sends the same bounded scope through GitHub Copilot only when the secure Claude Code runtime is deterministically absent/unavailable or all pinned Claude models are entitlement-blocked. Authentication failure is `blocked-authentication` and never authorizes fallback.
- GitHub Codex review uses the PR diff and repository guidance on GitHub.

`explicit-claude-review` authorizes only the Anthropic destination. The helper may use GitHub Copilot fallback only with `double-review` or `triple-review`, whose consent language explicitly names that fallback.

Record the actual runtime/model used in the terminal review report so consent and retention expectations remain auditable.

The helper enforces the intended scope with a frozen detached workspace, runtime-specific minimal environment, provider path/tool restrictions, an escaping-symlink preflight, and a bounded scan of complete base/head content, both sides of changed raw blobs, complete changed-path metadata, and the materialized head for credential-like paths and high-confidence secret patterns. The frozen diff and rendered prompt remain bounded and integrity-checked but are not secret-egress filters after the tracked range passes. For each unregistered dynamic candidate that can be safely represented as exact bytes, the helper counts exact raw occurrences across every blob and symlink target in the complete base and head trees and requires a strict decrease: `head_raw_count < base_raw_count`. It also requires `head_unembedded_count <= base_unembedded_count`, where an occurrence is unembedded only when no strictly longer candidate completely contains it. An equal residual count, a candidate present only at head, a move, rename, copy, net increase, extracted substring, incomplete count, exceeded budget, or otherwise unsafe/uncountable candidate blocks review. Exact dynamic raw values and their canonical Base64 encodings are forbidden in every frozen or materialized head path. Changed-path audit evidence contains ordered, domain-separated digests for head-present (`H`) and base-only (`B`) records; the matching side-tagged raw list remains helper-private and ephemeral. Both sides are rechecked against the complete catalog loaded immediately before egress, while dynamic and sensitive-path checks remain head-only so an unregistered pure deletion stays reviewable. A removed base-only path may still appear unchanged in the trusted review diff. A changed sensitive path may pass only when it was deleted and the complete head contains no sensitive path; any credential-like or otherwise sensitive path at head blocks.

Helper-private raw changed paths and Base64 dynamic-candidate state exist only until preflight consumes them. Preparation creates both fixed files as empty exact-`0600` slots, captures their container and file device/inode identities from the creation descriptors, syncs the slots and container directory, and publishes the complete preparation binding before materializing the workspace or writing sensitive bytes. Writers then reopen only the bound inodes without create or truncate and revalidate identity after the synced write. The identities are carried independently by the review workspace/state marker and helper-private control state. Cleanup accepts only those preparation identities, quarantines each fixed file before revalidating and removing it, and atomically records a monotonic per-file removal receipt through the same verified container descriptor. A missing or replaced identity without its receipt fails closed; a recorded name that reappears is preserved and rejected. Successful preflight requires both receipts before publishing `preflight.json` or launching any reviewer, while validation failure and every later cleanup path retry the same bound scrub. A symlinked review root, replaced container, moved private file, or identity change fails closed without following it or deleting the replacement. Explicit keep and clean-context fallback therefore retain the frozen workspace and durable bounded evidence, not raw helper-private inputs. Fallback requires both the preflight proof and the bound control-state removal receipts.

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
Joey explicitly requested <double review|triple review>, which is opt-in consent under AGENTS.md and $review-orchestration-playbook for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. This exact helper invocation sends necessary tracked code and the generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the explicitly supplied review prompt/result, in their original form to Anthropic Claude Code for read-only review and, only if the secure Claude runtime is deterministically absent/unavailable or both pinned Claude Opus models are entitlement-blocked, Microsoft/GitHub Copilot. Claude authentication failure pauses as `blocked-authentication` and does not fall back. The reviewer is a trusted processor inside this workflow's trust boundary; tracked repository secrets are included only when the helper proves the frozen range strictly reduces their complete-tree exact raw counts without increasing unembedded counts, while the explicit prompt is trusted reviewer input rather than part of that count domain. This excludes automatic discovery or collection of reviewer/runtime authentication credential sources, untracked files, unrelated repositories, and broad workspace or home-directory content. Explicitly supplied prompt or tracked-review bytes are not compared against runtime credential values. Allow this exact frozen Claude-family review lane?
```

Do not shorten this to `run external reviewer`: the exact user opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> diff、必要 changed-file context 和明确提供的 review prompt/result 原样发送给 <Codex / Claude Code / GitHub Copilot / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。reviewer 是该工作流信任边界内的受信处理者；tracked repository secret 仅在 helper 证明完整 base/head 的精确 raw count 严格下降且 unembedded count 不增长时纳入，明确提供的 prompt 则属于受信 reviewer input。不要自动发现或采集 reviewer/runtime authentication credential sources、untracked private files、无关仓库或 broad workspace dumps；明确提供的 prompt 或 tracked-review bytes 不与 runtime credential values 做字节比对。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with a different executable, shell wrapper, model family, or indirect service.
