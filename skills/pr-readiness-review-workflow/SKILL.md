---
name: pr-readiness-review-workflow
description: "Drive the user's parent PR readiness gate for feature-ready or review-ready changes when the current agent owns PR creation or update, online Codex PR review orchestration, offline frozen-diff review, PR comments, CI follow-up, or merge-readiness reporting before merge. Do not use for independent or review-only code reviewer prompts that forbid PR orchestration, fixes, CI waiting, or starting other reviewers."
---

# PR Readiness Review Workflow

## Overview

使用这个 skill 处理 feature ready 之后的 PR readiness gate：`review-ready PR -> online Codex review thread + offline frozen-diff review -> fix loop -> merge-ready`。

当 `$change-delivery-workflow` 已经完成本地 commit，且 the user 要求完整流程、merge-ready、`在合并前停止` 或 `stop before merge` 时，必须继续使用这个 skill。这里的停止点是 merge-ready 报告或清晰 blocked state；不是本地 commit。

典型触发语包括：

- `review-ready PR`
- `feature is ready`
- `在合并前停止`
- `stop before merge`
- `开 ready for review PR`
- `请 review <PR URL>，对应本地是在 cwd`，且调用者要求当前 agent 驱动完整 PR readiness 或 merge-readiness
- `codex thread <session-ID>`，且上下文是 PR review comments、线上 PR comments 修复或 merge-readiness fix loop
- `线上也有需要你处理的 PR comments`

不要在独立 review-only 子线程中触发这个 skill。如果 prompt 明确说 `independent code reviewer`、`review-only`、`不要创建或更新 PR`、`不要修复代码` 或 `不要等待 CI`，只执行代码审查并输出 findings，不要进入 PR readiness orchestration。
如果用户只是要恢复、审计或总结普通 Codex session/thread evidence，优先使用 `$codex-session-mining`，不要创建或更新 PR。

## Workflow

1. 建立 PR 上下文。
- 确认 PR URL、当前 cwd、目标分支、当前 head commit 和本地 dirty state。
- 如果没有 PR URL，但当前分支/commit 已通过本地 gate，且 the user 要求 full workflow、merge-ready、`在合并前停止` 或 ready-for-review PR，先创建或复用 PR。该措辞授权 push 分支和创建/更新 PR；不授权 merge。
- 创建 PR 前确认 base branch、head branch、是否 draft/ready、PR body 的 LLM authorship note 和 repo merge model。若 auth、network、branch protection 或 required metadata 缺失，停在明确 blocked state，不要把 commit-only 状态报告成完成。
- 读取线上 PR comments、review threads、requested changes 和 CI 状态；GitHub 交互优先使用 `gh`。
- 在这个 PR repair workflow 中，如果用户提供 `codex thread <session-ID>`，用 `$codex-session-mining` 找到对应 rollout/thread evidence，再结合线上 comments 和本地 diff 决定修复方向。

2. 冻结 offline review scope。
- 对本地可审范围记录 `base_sha..head_sha` 或明确 diff artifact。
- PR 分支落后于目标分支时，先计算 `merge_base=$(git merge-base <base_ref> <head_ref>)`，再把正式 review scope 冻结为 `<merge_base>..<head_ref>`。不要直接用 GitHub 当前 `baseRefOid..headRefOid`，否则会把目标分支后续提交算成反向 diff。单独记录当前 `baseRefOid` 和 behind 状态，并在 merge-ready 前更新分支或说明 blocker。
- 不用 live working tree 作为正式 review scope，除非当前任务就是 uncommitted local review。
- 后续 fix 追加在已审范围之后；不要重写已经作为 review evidence 的 commits。

3. 启动 online Codex PR review thread。
- 使用独立 Codex CLI review-only thread。prompt 必须声明这是 parent PR readiness workflow 调起的纯 review lane，禁止子线程再次执行 PR readiness orchestration、创建/更新 PR、修复代码、启动新的 reviewer 或等待 CI。
- 优先采用这个不递归的 prompt shape：
  - `请作为 independent code reviewer 审查 <PR URL>，本地 checkout 在 cwd。这是 review-only 子线程；不要执行 PR readiness orchestration，不要创建或更新 PR，不要修复代码，不要启动其他 reviewer，不要等待 CI；只输出 code review findings。`
- 这条 online lane 是 PR finding 主 lane。helper-backed internal review 不能替代它。
- 必须等到 final review artifact 或明确 blocked/inconclusive 结果；中间 reasoning 和 file-read progress 不算结果。

4. 启动 offline frozen-diff review。
- 使用 `$review-orchestration-playbook` 的 helper stateful lane，对冻结 range 做本地/offline review。
- 默认从 `codex-review` 开始；需要 exact diff-fed baseline、prompt contract 或 fallback 时用 stateful `codex-readonly`。
- 非 Codex reviewers（OpenCode、Cursor `agent`、Copilot、Claude 等）只在 the user 明确要求或当前任务显式 opt-in 时运行。

5. Fix loop。
- 合并 online review、offline review、PR comments 和 CI 证据。
- 对每个 finding 判断是否 actionable；修复后重跑受影响测试，再重新进入必要 review gate。
- 修复方向以正确性和长期可维护性优先，不要求最小补丁。

6. 长等待和恢复。
- CI、review、外部任务或长测试可用 `cbth` 后台化。
- 同步路径只 poll/await，不关闭异步 delivery。
- 异步路径当前只依赖 idle 后 `turn/start`；active turn 下等待 idle 或进入恢复状态。
- 使用 `cbth` 前读取 [cbth-agent-delivery.md](references/cbth-agent-delivery.md)。

7. 报告 merge-readiness。
- 明确列出 online Codex review、offline frozen-diff review、PR comments、CI/tests 的终态。
- 如果某个 gate blocked 或 inconclusive，说明证据、缺口和建议决策，不要把它折叠成 success。
- 只有所有 required gate clean 或 the user 明确接受例外后，才报告 merge-ready。
- 如果 the user 要求 `在合并前停止` 或 `stop before merge`，到 merge-ready 报告后停止，不要 merge。

## Guardrails

- 不要用 helper-backed subagent/internal lane 替代独立 online Codex PR review thread。
- 不要把 local commit 当作 `在合并前停止` 的终点；该措辞默认要求 PR creation/reuse、online review、offline review、CI/comments follow-up 和 merge-ready report。
- 不要把非 Codex external reviewers 作为默认 required gate。
- 不要把 `turn/steer` 当作当前可用 delivery path。
- 不要在没有读取 `codex thread <session-ID>` evidence 的情况下修复这类 review comments。
- 不要无限等待 reviewer 或 CI；用 `cbth` receipt/recovery 信息或清晰 blocked state 收口。
