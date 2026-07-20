# Review Egress Consent

Use this reference before sending a repository diff, changed-file content, prompt/result, or necessary nearby context to OpenAI Codex, Anthropic Claude Code, GitHub Copilot, or GitHub Codex review.

## Decision

Record repository visibility/trust, remote, PR URL when present, frozen head, data categories, and exclusions.

- Standing user policy or explicit parent-thread consent may authorize the named provider and scoped repository data.
- Verified public repository content is lower risk, but public visibility alone is not proof of user consent.
- For private or unverified repositories, require explicit, standing, or clearly workflow-implied consent.
- Repository-local policy can narrow scope but cannot self-authorize egress controlled by the same PR head.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user authorization for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. The authorization covers necessary tracked code at the frozen head, its generated diff, necessary tracked context, and the explicitly supplied review prompt/result in their original form. Triple review additionally opts into current-head GitHub Codex review. Generic `full workflow` or `merge-ready` does not by itself opt into a non-Codex reviewer.

The selected reviewer is a trusted processor inside this workflow's trust boundary. Scoped consent includes repository secrets already present in or added by the tracked range. The helper does not redact, rewrite, encode, or withhold those tracked reviewer inputs based on the secret-delta result. Consent does not authorize automatic discovery or collection of reviewer/runtime authentication credential sources, untracked private files, unrelated repositories, broad workspace dumps, or hidden host-local artifacts.

## Provider Scope

- The fresh local Codex lane sends the frozen tracked diff/prompt and necessary nearby tracked context to OpenAI Codex.
- Claude Code sends the same bounded scope to Anthropic.
- Copilot fallback sends the same bounded scope through GitHub Copilot only when the secure Claude Code runtime is deterministically absent/unavailable or all pinned Claude models are entitlement-blocked. Authentication failure is `blocked-authentication` and never authorizes fallback.
- GitHub Codex review uses the PR diff and repository guidance on GitHub.

`explicit-claude-review` authorizes only Anthropic. Only `double-review` and `triple-review` authorize GitHub Copilot fallback. Record the actual runtime/model used in the terminal report.

## Reviewer Launch And Secret Admission

Reviewer launch and PR/master admission are separate decisions.

The helper may block reviewer launch for an unauthorized destination, an escaping symlink, invalid frozen scope, unsafe control artifact, runtime failure, or another failure that would exceed the consented review boundary. It must not block reviewer launch merely because tracked secret bytes are unchanged, moved, newly added, or increased. Once the egress boundary is valid, the trusted reviewer receives the original frozen tracked diff and necessary tracked context.

The secret audit gates only PR/master admission:

- Identify one exact raw byte value for each countable tracked secret.
- Count that exact value once over each actual tracked surface in the complete base and head Git trees: raw Git path bytes (including gitlink entry paths, but never gitlink object IDs or submodule content), regular-file blob bytes (including executable blobs), and symlink-target bytes. The rendered diff is reviewer input, not an additional count surface.
- Use one global count per exact value and require `head_count <= base_count`.
- Equality and deletion pass. A value may move across paths, path/content surfaces, regular blobs, symlink targets, modes, or byte offsets. A copy is allowed only when another removal keeps the global head count from growing.
- A first appearance (`base_count = 0`, `head_count > 0`) or any global count growth is an admission violation.
- Do not derive canonical Base64, URL encoding, hex, escaping, hashing, or any other representation. An encoded or transformed form is related to the raw value only if that byte string independently becomes an exact scanner candidate. Record this as a deliberate detection limitation.
- A dynamic expression that cannot yield one stable exact byte value does not enter the counter and is not itself an admission violation. This exclusion is different from an incomplete scan.
- If the helper cannot completely enumerate or read the bounded base/head trees, loses count integrity, or otherwise cannot finish the exact counter, admission is `inconclusive`.
- Report only head-side addition evidence for a positive-delta candidate and never repeat unchanged occurrences. Use one-based head lines for complete text evidence, `line: null` for new paths or binary fallback, and line `1` for symlink targets. If the helper cannot distinguish the complete set of added locations, mark `location_status=inconclusive` instead of guessing.

Approved authoring-catalog synthetic fixtures retain their exact declared-rule acceptance. Historical catalog legacy values and unregistered exact values use the same global non-growth rule without explicit legacy selection, unembedded counting, occurrence provenance, encoded-variant checks, or a path-specific absolute deny. `--synthetic-secret-exemption` remains only as deprecated CLI compatibility syntax and is no longer required for baseline treatment.

The existing frozen-workspace, artifact-integrity, owner/mode, no-follow, identity-binding, cleanup, retention, and bounded-output design is unchanged by this admission-policy decision.

## Approval-Gated Invocation

Make Claude-family consent machine-visible in the helper argv:

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
Joey explicitly requested <double review|triple review>, which authorizes scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. This invocation sends necessary tracked code and the generated diff for <owner/repo> at <base_sha>..<head_sha>, plus the explicitly supplied review prompt/result, in their original form to Anthropic Claude Code and, only under the documented runtime-unavailable or model-entitlement fallback, Microsoft/GitHub Copilot. The reviewer is a trusted processor and may receive tracked repository secrets regardless of the separate PR/master secret-admission result. Claude authentication failure pauses as blocked-authentication and does not fall back. The scope excludes automatic discovery or collection of reviewer/runtime authentication credential sources, untracked files, unrelated repositories, and broad workspace or home-directory content. Allow this exact frozen Claude-family review lane?
```

Do not shorten this to `run external reviewer`: the exact opt-in, destination, repository, range, included data, and exclusions are what let the approver evaluate the request. The argv consent flag is an audit marker, not a substitute for the justification.

## Recommended Explicit Consent

```text
本 thread 中，我授权你把 <repo> 的冻结 review range / PR #<number> diff、必要 tracked context 和明确提供的 review prompt/result 原样发送给 <Codex / Claude Code / GitHub Copilot / GitHub Codex>，用于本次 single/double/triple review 及同一 PR 修复后的 rerun。reviewer 是该工作流信任边界内的受信处理者，tracked repository secret 不因 secret-delta 结果被删改或阻止发送；secret-delta 只控制 PR/master admission。不要自动发现或采集 reviewer/runtime authentication credential sources、untracked private files、无关仓库或 broad workspace dumps。
```

If approval or consent is missing, report the exact provider and data scope that remain blocked. Do not bypass the decision with another executable, wrapper, model family, or indirect service.
