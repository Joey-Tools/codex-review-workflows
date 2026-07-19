---
name: review-orchestration-playbook
description: Orchestrate Joey's single, double, and triple code reviews plus PR readiness through one policy-bound workflow, and govern read-only Claude Code review runtimes across macOS, Linux, and WSL2. Use for helper-backed or clean-context Codex review, Claude-family review, GitHub `@codex review`, WIP review snapshots, PR comment/CI fix loops, merge-readiness, or Claude Code CLI provenance, authentication, sandbox, and upgrade-compatibility changes. Review-only children that forbid orchestration should inspect directly and return findings only.
---

# Review Orchestration Playbook

## Review Shapes

Count independent reviewer families, not retries, helper implementations, or fallback attempts.

- Single/local internal review: one clean-context Codex lane.
- Local double review / `本地双重 review`: the Codex lane plus one Claude-family lane.
- Triple review / `三重 review`: local double review plus GitHub Codex review on the current PR head.
- PR readiness: the requested review shape plus required CI, PR comments/conversation resolution, and branch/base checks. Those delivery gates do not increase the review count.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user consent for scoped code-review egress to OpenAI, Anthropic, and Microsoft/GitHub. Clean-mode consent covers necessary tracked code at the frozen head, the generated diff, nearby tracked context, and the review prompt/result. It excludes credentials, unrelated repositories, broad workspace dumps, and home-directory content. Read [egress-consent.md](references/egress-consent.md) before starting an external lane.

`--include-source-wip` is a separate explicit consent boundary. It adds staged changes, unstaged changes, and non-ignored untracked files to the scanned, digest-bound review snapshot. It is for review-only WIP feedback and never supplies formal PR-readiness or merge-ready exact-commit evidence.

## Reviewer And Runtime Policy

The helper and clean-context `reviewer` agent use explicit models; they do not inherit a possibly older parent or global default.

- Codex CLI: `gpt-5.6-sol` with `xhigh`; fall back to `gpt-5.5` with `xhigh` only after an explicit account, plan, organization-policy, or model-entitlement denial.
- Claude Code: `claude-opus-4-8` with `max`; fall back to `claude-opus-4-7` with `max` only after an explicit account, plan, organization-policy, or model-entitlement denial for Opus 4.8.
- Copilot CLI: one runtime fallback inside the Claude-family lane, available only with `double-review` or `triple-review` consent when the verified Claude runtime is deterministically unavailable or both Claude models are entitlement-blocked. Claude authentication failure never authorizes this fallback.

Claude Code releases `>=2.1.212,<3.0.0` must pass the signed-manifest provenance, native-platform, capability, structured-output, and sandbox checks in [claude-runtime-trust.md](references/claude-runtime-trust.md). WSL1 and native Windows remain unsupported.

Every Claude attempt uses one combined runtime boundary:

- cwd is a helper-owned literal detached Git worktree at the exact resolved head;
- the default source must be clean;
- `--include-source-wip` changes only the worktree contents and snapshot identity, never the HOME or tool boundary;
- Claude's trusted ordinary CLI control plane uses the current account's real `HOME` for ordinary login and supported configuration, including admin-managed policy;
- model tools run in plan mode with `Read`, `Grep`, and `Glob` exposed for detached-workspace review, plus Claude Code's built-in read-only `Bash` set; the prompt forbids out-of-workspace reads and file-tool rules deny sensitive HOME paths;
- every accepted stream proves effective plan mode, the exact built-in tool set, requested model, and authentication indicator in its unique first `system/init` event; a unique matching terminal result must be last;
- the launch requests disabled sandboxed-Bash auto-approval, `failIfUnavailable`, no unsandbox escape, credential/proxy removal, workspace/HOME write denials, and a real-HOME Bash read denial that re-opens the detached workspace and private Git view. The model-backed launch explicitly disables Claude Code's broad subprocess scrub because v2.1.212 otherwise forces permission mode to `default`; the fail-closed native sandbox credential rules remain the compatible sandboxed-Bash credential boundary, while hooks, MCP, plugins, skills, and slash commands are separately disabled and checked. Claude Code 2.1.212 does not report effective sandbox settings or merged managed permission arrays in `system/init`, so the helper records these settings as requested rather than claiming independent proof;
- immediately before launch, the Claude provider records whether the exact `.claude/.cc-writes` entry is absent and, when `.claude` already exists as a real directory, binds its filesystem identity; after the attempt it may use no-follow directory descriptors to verify and non-recursively remove only a newly created, empty, current-user-owned, `0700` staging directory from Claude Code 2.1.212, while any pre-existing entry is not cleaned; a newly created empty parent is atomically moved to a helper-private quarantine and identity-checked before removal, any swapped candidate is retained there and rejected, and any different or remaining topology still fails closed through the common validator;
- after every completed Claude attempt, exact workspace validation must still match the detached snapshot, private Git state, diff, and prompt before a result or model fallback is accepted. An observable mutation is terminal `permission-mismatch` evidence.

The review prompt plus the verified effective plan mode and exact tool set require model behavior to remain read-only. Because admin-managed policy is part of the ordinary CLI control plane and its merged permission arrays are not observable in the 2.1.212 init schema, the helper does not claim that a non-interactive run can never receive a preapproval. Post-attempt validation proves only that the validated review workspace and private Git artifacts are unchanged at that point; it does not prove that no transient write occurred or that no out-of-workspace side effect occurred.

Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. Only the winning explicit value is selected and opaque-forwarded; the helper never parses, logs, writes to disk, stages, brokers, or persists it. Claude Code owns ordinary local-login lookup and refresh through its supported control plane. Before review content enters a child process, `claude auth status --json` must prove a compatible effective provider/method/API-key-source tuple; gateway, cloud-provider, `apiKeyHelper`, or otherwise conflicting observable state is blocked. A rejected API key directs the operator to unset or replace `ANTHROPIC_API_KEY`; a rejected OAuth token directs the operator to unset or replace `CLAUDE_CODE_OAUTH_TOKEN`; a rejected local login directs the operator to run `claude auth login`. Every authentication failure is `blocked-authentication` and never a model or Copilot fallback reason.

Capacity, overload, rate limits, timeouts, network errors, 5xx responses, missing final artifacts, silent model substitution, or reviewer findings are not model-fallback reasons. Retry the same runtime/model only within a bounded transient retry policy; otherwise report `inconclusive`.

## Workflow

1. Classify the request.
- Review-only child: if the prompt says `independent code reviewer`, `review-only`, `不要启动其他 reviewer`, `不要等待 CI`, or equivalent, inspect the supplied scope directly and return findings only. Do not start this workflow, another reviewer, PR actions, fixes, or CI waiting.
- Local single/double review: freeze the exact `base_sha..head_sha`, then run the requested local lanes through the helper.
- WIP review: require explicit `--include-source-wip` consent and treat the digest-bound artifact as review-only evidence.
- Triple review: establish the PR/current head, run the local double review, then require final current-head GitHub Codex evidence.
- PR readiness/full workflow: follow [pr-readiness.md](references/pr-readiness.md) after a clean local delivery commit exists. Full PR readiness retains separate required `independent-codex-pr-review` and helper-backed `offline-frozen-diff-review` evidence.

2. Freeze scope.
- Prefer a `wip/<topic>` branch and an exact `base_sha..head_sha` range.
- If the target branch moved, compute the merge base and review `<merge_base>..<head_sha>`.
- Default to a clean source checkout. Do not use `--include-source-wip` for formal PR-readiness evidence; commit the intended content and rerun clean mode.

3. Run local lanes.
- Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`.
- When source or tests need credential-shaped fixtures, use `$synthetic-token-fixtures` to select an exact helper-catalog token.
- Start one stateful helper run per logical reviewer: `--reviewer codex` and, for double/triple review, `--reviewer claude`.
- A Claude-family run must pass `--egress-consent double-review`, `--egress-consent triple-review`, or `--egress-consent explicit-claude-review`, matching the user's request.
- Add `--include-source-wip` only when the user explicitly opts into sending the complete WIP snapshot, including non-ignored untracked files.
- Before egress, require the helper's escaping-symlink and sensitive-content preflight over the complete selected snapshot, diff, and prompt. A match is a hard stop.
- When approval is needed, repeat the exact repository, frozen range, clean/WIP content category, destinations, and exclusions from [egress-consent.md](references/egress-consent.md).
- Use `stateful start`, bounded `stateful status` / `stateful wait`, and finally `stateful final --state-dir <dir>`.
- A bounded `stateful wait` that expires while the same reviewer remains healthy is only an intermediate poll, not task completion. Keep the parent task active and continue bounded status/wait checks until `stateful final` is terminal or a real `blocked` / `inconclusive` decision point is reached; do not end the task merely because one wait window expires.
- Treat only the terminal final artifact as review evidence. Intermediate reasoning, tool traces, stdout tails, and keepalives are not findings.

4. Apply evidence budgets.
- Read [review-lane-contracts.md](references/review-lane-contracts.md).
- Start from counts, diff headers, `--stat` / `--numstat`, `rg -l`, `rg --count`, one hunk, or one exact symbol window.
- Do not begin with whole-file reads, broad `rg -n`, wide diffs, or large untracked inventories.
- If a broad single-file sample is unavoidable, use `rg -n --max-count 80 --max-columns 200 <exact-file>` and then narrow further.
- After any 800+ line or 10k+ token result, narrow the next read.

5. Handle findings and failures.
- `No findings.` / `LGTM`: clean terminal result.
- Actionable findings: fix in the parent workflow, rerun affected tests, freeze the new clean head, and rerun every invalidated requested lane.
- `blocked`: deterministic auth, policy, permission, configuration, or missing-runtime problem.
- `inconclusive`: transient/capacity/timeout/network failure or no trustworthy final artifact.
- Never report a requested double/triple review as clean when one requested logical lane is blocked, missing, or inconclusive.

6. Report precisely.
- Name the logical lane, runtime, requested/effective model, effort, workspace content mode, frozen range or WIP digest, and terminal status.
- Keep model fallback attempts within the same logical lane; they do not increase the review count.
- For triple review, bind GitHub Codex evidence to the current PR head.

## Helper Contract

Read [helper-contract.md](references/helper-contract.md) before modifying or debugging the helper. For Claude Code CLI upgrades or platform support, also read [claude-runtime-trust.md](references/claude-runtime-trust.md). The helper intentionally exposes only `codex` and `claude` logical reviewers and preserves stateful final artifacts.

## References

- [helper-contract.md](references/helper-contract.md): helper CLI, workspace modes, state lifecycle, and safety boundaries.
- [claude-runtime-trust.md](references/claude-runtime-trust.md): Claude Code provenance, real-HOME control plane, read-only model tools, authentication, and failure classification.
- [review-lane-contracts.md](references/review-lane-contracts.md): evidence budget, output contract, and PR reply note.
- [review-prompt-templates.md](references/review-prompt-templates.md): bounded prompt variants.
- [pr-readiness.md](references/pr-readiness.md): PR authorization, clean-scope review gates, CI/comments, fix loop, and merge-ready reporting.
- [github-pr-probes.md](references/github-pr-probes.md): bounded `gh` probes.
- [egress-consent.md](references/egress-consent.md): scoped clean/WIP review egress rules.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): long-running task recovery.
- [synthetic-token-fixtures.md](references/synthetic-token-fixtures.md): fixture catalog authority and migration contract.

## Guardrails

- Do not count fallback attempts or multiple helper implementations as additional reviews.
- Do not silently replace Claude-family review with OpenCode, Cursor Agent, or another model family.
- Do not treat authentication failure as runtime unavailability or entitlement; report `blocked-authentication` and pause.
- Do not let model aliases or global defaults override pinned policy.
- Do not run an unverified or mutable source Claude executable with authentication or review content.
- Do not accept a Claude result without matching effective plan/tool/model/auth evidence from the unique first `system/init` and unique last result. Shell availability requires the documented v2.1.212 read-only Bash contract and a launch that requests disabled sandbox auto-approval and no unsandboxed escape; do not promote requested sandbox settings to independently verified evidence.
- Run exact external-workspace validation after every completed Claude attempt and before accepting its result or retrying another model. Treat any observable worktree, private-Git, diff, or prompt mutation as terminal `permission-mismatch`; do not claim this check rules out transient writes or out-of-workspace side effects.
- Keep real-HOME content outside review scope: forbid it in the prompt, deny sensitive HOME paths to file tools, and deny broad real-HOME reads to sandboxed Bash. Do not claim `--allowedTools` makes all built-in file reads workspace-only.
- Do not run Claude Code on WSL1, native Windows, or any host where the native sandbox is unavailable.
- Do not use a WIP snapshot as formal PR-readiness, merge-ready, or exact-commit review evidence.
- Do not start another reviewer from a findings-only review child.
- Do not claim a clean result without a terminal artifact for every requested logical lane.
- Do not invent token variants or use a legacy exemption for new fixtures.
- Do not restore compatibility skill aliases; update callers to `review-orchestration-playbook`.
