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

Claude Code `2.1.212` must pass the signed-manifest provenance, native-platform, capability, structured-output, and sandbox checks in [claude-runtime-trust.md](references/claude-runtime-trust.md). Every other release fails closed until its read-only permission, path-rule, sandbox, and output contracts are revalidated and the exact supported version is deliberately advanced. WSL1 and native Windows remain unsupported.

Helper-backed Codex CLI and Copilot CLI are not pinned to exact executable versions; their acceptance remains identity-, capability-, and output-contract based. The independent ephemeral Codex lane instead trusts the executable selected from the reviewer environment and records its path/version only as observational metadata when available. Claude Code was the only exact-version CLI pin. After its signed manifest and SHA-256 match the source candidate, the helper materializes a current-user-only verified executable snapshot; the same snapshot is captured before the model chain and runs every `--help`, post-provenance dependency inspection, authentication preparation, and final model attempt. The mutable source installation is never rediscovered between Opus attempts.

Every Claude attempt uses one combined runtime boundary:

- cwd is a helper-owned literal detached Git worktree at the exact resolved head;
- the default source must be clean;
- workspace and state live outside the source checkout in a private per-run container under the fixed system temporary root `/tmp`; the helper canonicalizes the root, requires root ownership and mode `01777`, and uses current-user-owned `0700` per-effective-UID and per-canonical-source-path-digest namespaces;
- source status is never filtered for helper containers: `.codex-tmp` follows ordinary Git ignore/status rules, any reported entry makes clean mode dirty, and WIP capture rejects it as a reserved helper path; retained `/tmp` state may disappear after reboot or host temporary-file cleanup;
- `--include-source-wip` changes only the worktree contents and snapshot identity, never the HOME or tool boundary;
- Claude's trusted ordinary CLI control plane uses the current account's real `HOME` for ordinary login and supported configuration, including admin-managed policy;
- model tools run in `dontAsk` mode with `Read`, `Grep`, `Glob`, and `Bash`; `Read(./**)` authorizes detached-workspace file access, unmatched permission requests are denied, recognized Bash file readers inherit those Read rules, arbitrary interpreters are outside the non-prompting read-only command set, and explicit file-tool rules deny real-HOME secrets plus `/proc` and `/dev` escape surfaces;
- every accepted stream proves effective `dontAsk` mode, the exact built-in tool set, requested model, and authentication indicator in its unique first `system/init` event; a unique matching terminal result must be last;
- the launch requests disabled sandboxed-Bash auto-approval, `failIfUnavailable`, no unsandbox escape, credential/proxy removal, workspace/HOME write denials, and original-source-checkout, per-UID review-namespace, real-HOME, `/proc`, and `/dev` Bash read denials that re-open only the current detached workspace and private Git view. The model-backed launch explicitly disables Claude Code's broad subprocess scrub because v2.1.212 otherwise forces permission mode to `default`; the fail-closed native sandbox credential rules remain the compatible sandboxed-Bash credential boundary, while hooks, MCP, plugins, skills, and slash commands are separately disabled and checked. Claude Code 2.1.212 does not report effective sandbox settings or merged managed permission arrays in `system/init`, so the helper records these settings as requested rather than claiming independent proof;
- immediately before launch, the Claude provider records whether the exact `.claude/.cc-writes` entry is absent and, when `.claude` already exists as a real directory, binds its filesystem identity; after the attempt it may use no-follow directory descriptors to verify and non-recursively remove only a newly created, empty, current-user-owned, `0700` staging directory from Claude Code 2.1.212, while any pre-existing entry is not cleaned; a newly created empty parent is atomically moved to a helper-private quarantine and identity-checked before removal, any swapped candidate is retained there and rejected, and any different or remaining topology still fails closed through the common validator;
- after every completed Claude attempt, exact workspace validation must still match the detached snapshot, private Git state, diff, and prompt before a result or model fallback is accepted. An observable mutation is terminal `permission-mismatch` evidence.

The review prompt plus the verified effective `dontAsk` mode, workspace file allowlist, explicit denies, and exact tool set require model behavior to remain read-only. Admin-managed policy is part of the trusted ordinary CLI control plane, while its merged permission arrays are not observable in the 2.1.212 init schema. Post-attempt validation proves only that the validated review workspace and private Git artifacts are unchanged at that point; it does not prove that no transient write occurred or that no out-of-workspace side effect occurred.

Authentication precedence is `ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > ordinary local login. Only the winning explicit value is selected and opaque-forwarded; the helper never parses, logs, writes to disk, stages, brokers, or persists it. Claude Code owns ordinary local-login lookup and refresh through its supported control plane. Before review content enters a child process, `claude auth status --json` must prove a compatible effective provider/method/API-key-source tuple; its valid JSON is parsed even when the CLI uses a nonzero exit for `loggedIn: false`, which becomes `blocked-authentication` rather than runtime failure. Gateway, cloud-provider, `apiKeyHelper`, or otherwise conflicting observable state is blocked. A rejected API key directs the operator to unset or replace `ANTHROPIC_API_KEY`; a rejected OAuth token directs the operator to unset or replace `CLAUDE_CODE_OAUTH_TOKEN`; a rejected local login directs the operator to run `claude auth login`. Every authentication failure is `blocked-authentication` and never a model or Copilot fallback reason.

Capacity, overload, rate limits, timeouts, network errors, 5xx responses, missing final artifacts, silent model substitution, or reviewer findings are not model-fallback reasons. Retry the same runtime/model only within a bounded transient retry policy; otherwise report `inconclusive`. For helper-backed lanes, invalid configuration or an unexpected effective model/effort is `blocked`, not a reason to downgrade models, and missing runtime-verification metadata is also `blocked`. The independent ephemeral gate records requested and observed values without treating a difference as a blocker by itself, because trusted higher-priority managed policy may override the request.

## Workflow

1. Classify the request.
- Review-only child: if the prompt says `independent code reviewer`, `review-only`, `不要启动其他 reviewer`, `不要等待 CI`, or equivalent, inspect the supplied scope directly and return findings only. Do not start this workflow, another reviewer, PR actions, fixes, or CI waiting.
- Local single/double review: freeze the exact `base_sha..head_sha`, then run the requested local lanes through the helper.
- WIP review: require explicit `--include-source-wip` consent and treat the digest-bound artifact as review-only evidence.
- Triple review: establish the PR/current head, run the local double review, then require final current-head GitHub Codex evidence.
- PR readiness/full workflow: follow [pr-readiness.md](references/pr-readiness.md) after a clean local delivery commit exists. Full PR readiness retains separate required `independent-codex-pr-review` and helper-backed `offline-frozen-diff-review` evidence.
  The independent lane uses a clean detached worktree plus `codex exec --ephemeral` while preserving normal user and tracked project instructions. Those delivery gates do not alter the standalone double/triple definitions above.

2. Freeze scope.
- Prefer a `wip/<topic>` branch and an exact `base_sha..head_sha` range.
- If the target branch moved, compute the merge base and review `<merge_base>..<head_sha>`.
- Default to a clean source checkout. Do not use `--include-source-wip` for formal PR-readiness evidence; commit the intended content and rerun clean mode.

3. Run local lanes.
- Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`.
- When source or tests need credential-shaped fixtures, use `$synthetic-token-fixtures` to select an exact helper-catalog token.
- Start one stateful helper run per logical reviewer: `--reviewer codex` and, for double/triple review, `--reviewer claude`.
- A Claude-family run must pass `--egress-consent double-review`, `--egress-consent triple-review`, or `--egress-consent explicit-claude-review`, matching the user's request.
- `explicit-claude-review` authorizes only Anthropic Claude Code. Only `double-review` and `triple-review` authorize GitHub Copilot fallback when the secure Claude runtime is deterministically absent/unavailable or all pinned Claude models are entitlement-blocked. Authentication failure is always `blocked-authentication`, never fallback.
- Add `--include-source-wip` only when the user explicitly opts into sending the complete WIP snapshot, including non-ignored untracked files.
- Before egress, require the helper's escaping-symlink and sensitive-content preflight over the complete selected snapshot, diff, and prompt. A match is a hard stop.
- In WIP mode, that preflight must additionally scan the helper-private Git database's original source `HEAD`-to-snapshot delta paths and original-`HEAD`-side raw blobs; the current snapshot side is already covered by the complete snapshot scan. Base-to-snapshot and current-snapshot scans alone are insufficient because a WIP deletion or reversion must not hide sensitive content that remains reachable from the original source `HEAD`.
- When approval is needed, the escalation justification must repeat the explicit user request, exact repository, frozen range, clean/WIP content category, Anthropic destination plus GitHub Copilot fallback only when authorized, included snapshot/diff/prompt scope, and exclusions from [egress-consent.md](references/egress-consent.md). A generic `run external reviewer` justification is insufficient.
- Use `stateful start`, bounded `stateful status` / `stateful wait`, and finally `stateful final --state-dir <dir>`.
- For `independent-codex-pr-review`, use the lightweight trust boundary in [review-lane-contracts.md](references/review-lane-contracts.md): a clean detached raw-materialized worktree and a fresh `codex exec --ephemeral --strict-config --json --sandbox read-only` process with normal `~/.codex` configuration, Rules, MCP servers, Plugins, and tracked project instructions. Pass the table-valued worktree trust entry, sole `.git` project-root marker, `features.hooks=false`, and `notify=[]` as four direct per-invocation argv overrides. Ordinary user configuration and organization-managed configuration are trusted parts of the reviewer environment. The CLI overrides express the values requested for this invocation; higher-priority managed policy may prevail, and that possibility is accepted within this trust model. Do not add a separate runtime-identity, authentication/account, managed-configuration, feature, or effective-configuration probe, and do not claim independent attestation of the effective configuration. Never run `codex debug prompt-input`, because it adds another Session and configured MCP startup. If the actual structured output or exit explicitly reports a configuration conflict before reviewer execution, classify the attempt as prelaunch `blocked` / `not-run`; once launch is possible, or whenever hook/notify execution is observed, the attempt is `inconclusive`. Do not add another probe to search for those conditions.
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
- Name the logical lane, runtime, requested model and effort, effective values when observable, workspace content mode, frozen range or WIP digest, and terminal status.
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
- Do not downgrade on capacity or other transient failures, and do not infer account entitlement from silent model substitution.
- Do not accept a helper-backed Codex result unless the persisted rollout verifies both the effective model and effort. For the independent ephemeral gate, require explicit requested model/effort plus the requested-runtime and structured-output contract in [review-lane-contracts.md](references/review-lane-contracts.md); report observed differences without treating them as blockers by themselves, do not require a rollout that `--ephemeral` intentionally does not persist, and do not claim that requested values attest the effective configuration.
- Do not describe the independent ephemeral gate as full instruction/process isolation or as proof against silent model substitution. Its normal project/customization loading, PGID escape risk, and unobserved effective metadata are explicit accepted tradeoffs; stricter repo-local policy still wins.
- For helper-backed pinned lanes, do not let model aliases or global defaults override the pinned policy. The independent ephemeral lane instead accepts trusted higher-priority managed policy overriding its requested values.
- Do not let model aliases or global defaults override the pinned Claude policy.
- Do not run an unverified or mutable source Claude executable with authentication or review content.
- Do not accept a Claude result without matching effective `dontAsk`/tool/model/auth evidence from the unique first `system/init` and unique last result. File tools require the workspace allowlist plus explicit sensitive-path denies; Shell availability requires the documented v2.1.212 non-prompting read-only Bash contract and a launch that requests disabled sandbox auto-approval and no unsandboxed escape. Do not promote requested sandbox settings to independently verified evidence.
- Run exact external-workspace validation after every completed Claude attempt and before accepting its result or retrying another model. Treat any observable worktree, private-Git, diff, or prompt mutation as terminal `permission-mismatch`; do not claim this check rules out transient writes or out-of-workspace side effects.
- Keep the original source checkout, retained reviews, and real-HOME content outside review scope: forbid them in the prompt, require `dontAsk` with the detached-workspace file allowlist, deny sensitive HOME, `/proc`, and `/dev` paths to file tools, and deny broad source-checkout, per-UID review-namespace, real-HOME, `/proc`, and `/dev` reads to sandboxed Bash before re-opening only the current workspace and private Git view. Do not claim the allowlist overrides trusted admin-managed policy.
- On WSL2, require mount provenance to prove both the source checkout and external review container use supported local native Linux filesystems. Do not run Claude Code on WSL1, native Windows, an unproven WSL2 mount, or any host where the native sandbox is unavailable.
- Do not use a WIP snapshot as formal PR-readiness, merge-ready, or exact-commit review evidence.
- Do not start another reviewer from a findings-only review child.
- Do not claim a clean result without a terminal artifact for every requested logical lane.
- Do not invent token variants or use a legacy exemption for new fixtures.
- Do not restore compatibility skill aliases; update callers to `review-orchestration-playbook`.
