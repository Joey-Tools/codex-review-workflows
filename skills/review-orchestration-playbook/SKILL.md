---
name: review-orchestration-playbook
description: Orchestrate Joey's single, double, and triple code reviews plus PR readiness through one pinned review workflow. Use for helper-backed or clean-context Codex review, Claude-family review, GitHub `@codex review`, review-only child prompts, PR comment/CI fix loops, or merge-readiness. Local double review means one Codex lane plus one Claude-family lane; triple review adds the current-head GitHub Codex PR review. Review-only children that forbid orchestration should inspect directly and return findings only.
---

# Review Orchestration Playbook

## Review Shapes

Count independent reviewer families, not retries, helper implementations, or fallback attempts.

- Single/local internal review: one clean-context Codex lane.
- Local double review / `本地双重 review`: the Codex lane plus one Claude-family lane.
- Triple review / `三重 review`: local double review plus GitHub Codex review on the current PR head, triggered automatically by the repository or with the exact `@codex review` comment.
- PR readiness: the requested review shape plus required CI, PR comments/conversation resolution, and branch/base checks. Those delivery gates do not increase the review count.

The explicit phrases `double review`, `双重 review`, `triple review`, and `三重 review` are contemporaneous user consent for the scoped Claude-family lane. That consent covers any necessary tracked code in the named repository at the frozen head, the generated diff, and the review prompt/result sent to Anthropic Claude Code and, only under the pinned fallback policy, GitHub Copilot. It never covers credentials, untracked files, unrelated repositories, broad workspace dumps, or home-directory content. Read [egress-consent.md](references/egress-consent.md) before starting that lane.

## Pinned Local Review Policy

The helper and the clean-context `reviewer` agent use explicit models; they do not inherit a possibly older parent or global default.

- Codex CLI: `gpt-5.6-sol` with `xhigh`; fall back to `gpt-5.5` with `xhigh` only after an explicit account, plan, organization-policy, or model-entitlement denial.
- Claude Code: when `ANTHROPIC_API_KEY` is available for verified hook-free bare mode, use `claude-sonnet-5` with `max`; fall back to `claude-opus-4-8`, then `claude-opus-4-7`, both with `max`, under the same entitlement-only rule. OAuth and keychain authentication are intentionally treated as unavailable because Claude Code bare mode does not read them.
- Copilot CLI: use only after Claude Code is unavailable, lacks bare-mode API-key authentication, or all Claude Code models are entitlement-blocked; try `claude-sonnet-5`, then `claude-opus-4.8`, then `claude-opus-4.7`, all with `max`, under the same rule.

Capacity, overload, rate limits, timeouts, network errors, 5xx responses, missing final artifacts, silent model substitution, or reviewer findings are not model-fallback reasons. Retry the same runtime/model only within a bounded transient retry policy; otherwise report `inconclusive`. Authentication, invalid configuration, an unexpected effective model/effort, or missing runtime-verification metadata is `blocked`, not a reason to downgrade models.

## Workflow

1. Classify the request.
- Review-only child: if the prompt says `independent code reviewer`, `review-only`, `不要启动其他 reviewer`, `不要等待 CI`, or equivalent, inspect the supplied scope directly and return findings only. Do not start this workflow, another reviewer, PR actions, fixes, or CI waiting.
- Local single/double review: freeze the exact `base_sha..head_sha`, then run the requested local lanes through the helper.
- Triple review: establish the PR/current head, run the local double review, then require final current-head GitHub Codex evidence.
- PR readiness/full workflow: follow [pr-readiness.md](references/pr-readiness.md) after the local delivery commit exists.
  Full PR readiness retains separate required `independent-codex-pr-review` and helper-backed `offline-frozen-diff-review` evidence; those delivery gates do not alter the standalone double/triple definitions above.

2. Freeze scope.
- Prefer a `wip/<topic>` branch and an exact `base_sha..head_sha` range.
- If the target branch moved, compute the merge base and review `<merge_base>..<head_sha>`.
- Do not use a live working tree as formal review evidence. For truly uncommitted review, use a direct review-only child or create an explicit review anchor first.

3. Run local lanes.
- Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`.
- Start one stateful helper run per logical reviewer: `--reviewer codex` and, for double/triple review, `--reviewer claude`.
- A Claude-family run must also pass `--egress-consent double-review`, `--egress-consent triple-review`, or `--egress-consent explicit-claude-review`, matching the user's request. This makes the authorization visible in the command and saved state.
- `explicit-claude-review` authorizes only Anthropic Claude Code. Only `double-review` and `triple-review` authorize GitHub Copilot fallback when Claude Code is unavailable, lacks bare-mode API-key authentication, or all pinned Claude models are entitlement-blocked.
- Before any Codex or Claude-family egress, require the helper's escaping-symlink and sensitive-content preflight to pass. A blocked credential path or high-confidence secret pattern is a hard stop; remove the secret or narrow the review content instead of overriding the scan.
- When the Claude-family helper needs approval, the escalation justification must repeat the explicit user request, exact repository, frozen `base_sha..head_sha`, Anthropic destination plus GitHub Copilot fallback when Claude Code is unavailable, lacks bare-mode API-key authentication, or all pinned models are entitlement-blocked, included tracked-code/diff/prompt scope, and exclusions. Use the template in [egress-consent.md](references/egress-consent.md); a generic `run external reviewer` justification is insufficient.
- Use `stateful start`, then bounded `stateful status` / `stateful wait`, and finally `stateful final --state-dir <dir>`.
- Treat only the terminal final artifact as review evidence. Intermediate reasoning, tool traces, stdout tails, and keepalives are not findings.
- If the Codex runtime is deterministically unavailable after successful preflight, use the helper-retained frozen workspace with the clean-context `reviewer` agent and the same diff/evidence and output contracts. After collecting that fallback artifact, run `stateful cleanup --state-dir <dir>`. Do not use inherited-context/default coding agents or bypass a failed preflight.

4. Apply evidence budgets.
- Read [review-lane-contracts.md](references/review-lane-contracts.md) for the exact bounded-read contract.
- Start from counts, diff headers, `--stat` / `--numstat`, `rg -l`, `rg --count`, one hunk, or one exact symbol window.
- Do not begin with whole-file reads, broad `rg -n`, wide diffs, or large untracked inventories.
- If a broad single-file sample is unavoidable, use `rg -n --max-count 80 --max-columns 200 <exact-file>` and then narrow further. Do not combine ripgrep's only-matching mode with a per-line match cap; one matching line can still emit an unbounded number of matches.
- After any 800+ line or 10k+ token result, narrow the next read.

5. Handle findings and failures.
- `No findings.` / `LGTM`: clean terminal result.
- Actionable findings: fix in the parent workflow, rerun affected tests, freeze the new head, and rerun every requested lane affected by the change.
- `blocked`: deterministic auth, policy, permission, configuration, or missing-runtime problem.
- `inconclusive`: transient/capacity/timeout/network failure or no trustworthy final artifact.
- Never report a requested double/triple review as clean when one requested logical lane is blocked, missing, or inconclusive.

6. Report precisely.
- Name the logical lane, runtime, requested/effective model, effort, frozen range, and terminal status.
- Keep model fallback attempts within the same logical lane; they do not increase the review count.
- For triple review, bind GitHub Codex evidence to the current PR head and distinguish automatic review from `@codex review`.
- If the user names a Codex app-server thread for review handoff, verify that exact thread with read-only thread checks before sending anything; never probe or notify a different thread as a substitute.

## Helper Contract

Read [helper-contract.md](references/helper-contract.md) before modifying or debugging the helper. The helper intentionally exposes only `codex` and `claude` logical reviewers, requires a `.git`-free frozen range, avoids reviewer-visible helper shims, and preserves stateful final artifacts.

## References

- [helper-contract.md](references/helper-contract.md): helper CLI, model policy, state lifecycle, and safety boundaries.
- [review-lane-contracts.md](references/review-lane-contracts.md): evidence budget, output contract, and PR reply note.
- [review-prompt-templates.md](references/review-prompt-templates.md): bounded prompt variants.
- [pr-readiness.md](references/pr-readiness.md): PR authorization, GitHub review, CI/comments, fix loop, and merge-ready reporting.
- [github-pr-probes.md](references/github-pr-probes.md): bounded `gh` probes.
- [egress-consent.md](references/egress-consent.md): scoped review egress rules.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): long-running task recovery.

## Guardrails

- Do not count fallback attempts or multiple Codex helper implementations as additional reviews.
- Do not silently replace Claude-family review with OpenCode, Cursor Agent, or another model family.
- Do not downgrade on capacity or other transient failures.
- Do not infer account entitlement from silent model substitution.
- Do not accept a Codex result unless the persisted rollout verifies both the effective model and effort.
- Do not let model aliases or global defaults override the pinned policy.
- Do not start another reviewer from a findings-only review child.
- Do not claim a clean result without a terminal artifact for every requested logical lane.
- Do not restore compatibility skill aliases. This migration intentionally removes the old skill entrypoints; update repository and release call sites to `review-orchestration-playbook` instead of relying on discovery-time redirection.
