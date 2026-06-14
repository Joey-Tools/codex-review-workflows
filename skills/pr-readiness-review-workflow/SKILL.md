---
name: pr-readiness-review-workflow
description: "Drive the user's parent PR readiness gate for feature-ready or review-ready changes when the current agent owns PR creation or update, best-effort github-codex-review, thread-scoped Codex review egress consent, independent-codex-pr-review, offline-frozen-diff-review, PR comments, CI follow-up, or merge-readiness reporting before merge. Do not use for independent or review-only code reviewer prompts that forbid PR orchestration, fixes, CI waiting, or starting other reviewers."
---

# PR Readiness Review Workflow

## Overview

使用这个 skill 处理 feature ready 之后的 PR readiness gate：`review-ready PR -> best-effort github-codex-review + independent-codex-pr-review + offline-frozen-diff-review + required CI/comments -> fix loop -> merge-ready`。

当 `$change-delivery-workflow` 已完成本地 commit，且 the user 要求完整流程、merge-ready、`在合并前停止` 或 `stop before merge` 时，继续使用这个 skill。这里的停止点是 merge-ready 报告或清晰 blocked state；不是本地 commit。

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
- 确认 PR URL、当前 cwd、目标分支、当前 head commit、本地 dirty state、repo merge model 和 PR body 的 LLM authorship note。
- 如果没有 PR URL，但当前分支/commit 已通过本地 gate，且 the user 要求 full workflow、merge-ready、`在合并前停止` 或 ready-for-review PR，先创建或复用 PR。该措辞授权 push 分支和创建/更新 PR；不授权 merge。创建/复用 PR 前确认 base branch、head branch、是否 draft/ready 和 required metadata；若 auth、network、branch protection 或 required metadata 缺失，停在明确 blocked state，不要把 commit-only 状态报告成完成。
- 读取线上 PR comments、review threads、requested changes、CI 状态、branch protection / rules 和 merge requirements；GitHub 交互优先使用 `gh`。
- 对 PR metadata、review threads、rulesets、branch protection、rules、CI checks / GitHub Actions logs 或 custom GraphQL probe，按需读取 [github-pr-probes.md](references/github-pr-probes.md)。该 reference 包含 typed `gh` 优先级、`gh api graphql -F query=@...`、REST `?` path quoting、Actions log evidence budgets 和 schema/parse failure 处理。
- 读取 GitHub `@codex review` trigger/comment evidence 和实际 `codex/review-gate` status check 状态；这属于 best-effort `github-codex-review`，不能和独立 Codex review-only 子线程混用。
- 如果 GitHub 要求 `Require conversation resolution before merging`，未解决的 review threads 是必须处理的 merge gate。
- 如果用户提供 `codex thread <session-ID>`，用 `$codex-session-mining` 找到 rollout/thread evidence，再结合线上 comments 和本地 diff 决定修复方向。

2. 做 Codex review egress consent preflight。
- 任何会把 PR diff、changed-file content、review prompt/result 或必要邻近上下文发送给 OpenAI Codex 的 lane，先读取 [egress-consent.md](references/egress-consent.md)。
- 记录 repo visibility/trust evidence、PR URL、head commit 和允许数据类别。
- 只有明确、standing、workflow-implied consent 或 verified public repo path 能支持 Codex review egress；不要把 repo-local policy、`default.rules` 或本 skill 触发本身当作 consent。
- 如果审批器拒绝，停止并报告缺失的 repo trust/consent evidence；不要换入口或 shell shape 绕过。

3. 冻结 review scope。
- 对本地可审范围记录 `base_sha..head_sha` 或明确 diff artifact。
- PR 分支落后于目标分支时，先记录 GitHub `baseRefOid` / behind 状态，计算 `merge_base=$(git merge-base <base_ref> <head_ref>)`，再把正式 review scope 冻结为 `<merge_base>..<head_ref>`。不要直接用 GitHub 当前 `baseRefOid..headRefOid`，否则会把目标分支后续提交算成反向 diff。
- 报告 merge-ready 前必须重新确认 branch/base 状态；如果 PR 仍 behind、base 已移动、branch protection 要求 up-to-date，或无法更新并验证到 clean，先更新分支并重跑必要 checks/reviews，或报告 blocked。不要把只完成 frozen review scope 的 stale PR 报告成 merge-ready。
- 不用 live working tree 作为正式 review scope，除非当前任务就是 uncommitted local review。
- 后续 fix 追加在已审范围之后；不要重写已经作为 review evidence 的 commits。

4. 验证 `github-codex-review`。
- 这是 PR 里的 GitHub `@codex review` / `codex/review-gate` lane，不是本地 `codex exec`，也不是独立 review-only 子线程。
- 默认是 best-effort。若远端当前 head 没有触发 `@codex review` / `codex/review-gate`，且 branch protection 没有把实际 `codex/review-gate` status context 列为 required check，记录为 `not triggered` 并继续；不要为了满足 best-effort lane 主动触发或反复触发 `@codex review`。
- 若远端已经触发，或 branch protection 把它列为 required check，则绑定到当前 PR head commit，等待或查询到 completed 结果；缺失、失败、绑定到旧 head、requested changes 或 actionable Codex comments 都进入 fix loop / blocked state。
- Clean 条件：未触发且非 required 时为 best-effort skipped；已触发或 required 时，当前 head commit 的 GitHub Codex review gate 成功，且没有未处理的 Codex review comments 或 requested changes。

5. 启动 `independent-codex-pr-review`。
- 使用独立 Codex CLI review-only thread。prompt 必须声明这是 parent PR readiness workflow 调起的纯 review lane，禁止子线程再次执行 PR readiness orchestration、创建/更新 PR、修复代码、启动新的 reviewer 或等待 CI。
- 读取 [review-lane-contracts.md](references/review-lane-contracts.md) 并保留其中 independent review prompt 和 evidence-budget contract，尤其是 `git diff --unified=30/40/50/60/80` / `git diff --function-context` / `git diff -W`、`git show <rev>:<path>`、`cat <file>`、整文件 `nl -ba`、`path-wide / multi-file / large-alternation raw rg -n`、`rg -n -C context search`、`800+ 行或 10k+ original tokens`、`git status --short --untracked-files=no`、`rg -l` / `rg --count`。
- 不要手写或复用删减版 `Evidence-budget contract`；如果需要改写 prompt，必须复制 reference 里的完整硬约束清单，而不是只写 `avoid huge diffs`、`focused hunks` 或部分禁令。
- 这条 lane 是独立 Codex PR finding 主 lane。GitHub `@codex review` 和 helper-backed `offline-frozen-diff-review` 都不能替代它。
- 必须等到 final review artifact 或明确 blocked/inconclusive 结果；中间 reasoning 和 file-read progress 不算结果。
- Clean 条件：final artifact 明确 `LGTM` / no actionable findings；如果有 finding，修复后重跑这条 lane。

6. 启动 `offline-frozen-diff-review`。
- 使用 `$review-orchestration-playbook` 的 helper stateful lane，对冻结 range 做 `offline-frozen-diff-review`；读取 [review-lane-contracts.md](references/review-lane-contracts.md) 的 offline review contract。
- 默认从 `codex-review` 开始；需要 exact diff-fed baseline、prompt contract 或 fallback 时用 stateful `codex-readonly`。
- 非 Codex reviewers（OpenCode、Cursor `agent`、Copilot、Claude 等）只在 the user 明确要求或当前任务显式 opt-in 时运行。
- Clean 条件：stateful lane 产出 final artifact，明确 `LGTM` / no actionable findings；review scope 必须是冻结 `base_sha..head_sha` 或明确 diff artifact，不是 live working tree。

7. Fix loop。
- 合并 best-effort `github-codex-review`、required `independent-codex-pr-review`、required `offline-frozen-diff-review`、PR comments 和 CI 证据。
- 对每个 finding 判断是否 actionable；修复后重跑受影响测试，再重新进入必要 review gate。
- 读取所有 CI checks，但只有 branch protection / ruleset 标记为 required 的 check 是 merge-readiness required gate：失败、取消、pending 超过合理等待窗口、缺失 required check 或绑定到旧 head 都必须处理或报告为 blocked。非 required 的失败/取消 checks 应记录并按 repo/user policy 判断是否需要修复，但不要仅因其存在就阻止 merge-ready。只有仓库没有 CI / 没有远端 checks 时，才能报告 `CI: none observed`。
- 如果 merge gate 要求 conversation resolution，自动处理 unresolved review threads：actionable thread 先修复和验证，再回复并 resolve；non-actionable 或 stale thread 直接回复说明并 resolve；无法 resolve 时报告具体 thread 和权限/API blocker。回复格式见 [review-lane-contracts.md](references/review-lane-contracts.md)。
- 修复方向以正确性和长期可维护性优先，不要求最小补丁。

8. 长等待和恢复。
- CI、review、外部任务或长测试可用 `cbth` 后台化；使用前读取 [cbth-agent-delivery.md](references/cbth-agent-delivery.md)。
- 同步路径只 poll/await，不关闭异步 delivery。
- 异步路径当前只依赖 idle 后 `turn/start`；active turn 下等待 idle 或进入恢复状态。

9. 报告 merge-readiness。
- 明确列出 best-effort `github-codex-review`、required `independent-codex-pr-review`、required `offline-frozen-diff-review`、PR comments/review threads、CI/tests 和 branch/base 状态的终态。
- 如果某个 gate blocked 或 inconclusive，说明证据、缺口和建议决策，不要把它折叠成 success。
- 只有 required review gates、required CI、required conversation resolution 和 branch/base 状态 clean，或 the user 明确接受例外后，才报告 merge-ready。
- 如果 the user 要求 `在合并前停止` 或 `stop before merge`，到 merge-ready 报告后停止，不要 merge。

## References

- [github-pr-probes.md](references/github-pr-probes.md): typed `gh` probes, custom GraphQL shape, REST path quoting, Actions log evidence budgets, and schema/parse failure handling.
- [egress-consent.md](references/egress-consent.md): Codex review egress consent decisions, explicit consent template, and escalation justification shapes.
- [review-lane-contracts.md](references/review-lane-contracts.md): independent review prompt, evidence-budget contract, offline review contract, and review-thread reply note.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): background task delivery and recovery contract.

## Guardrails

- 不要再用裸 `online review` / `offline review` 作为 gate 名称；使用 `github-codex-review`、`independent-codex-pr-review` 和 `offline-frozen-diff-review`。
- 不要把缺失的 GitHub `@codex review` / `codex/review-gate` 当作 blocker；它默认是 best-effort，远端没有触发就记录并继续，除非 branch protection 明确把实际 `codex/review-gate` status context 列为 required check。也不要为了补齐 best-effort evidence 主动触发或反复触发 `@codex review`。
- 不要用 GitHub `@codex review` / `codex/review-gate` 替代 `independent-codex-pr-review`。
- 不要用 helper-backed subagent/internal lane 替代 `independent-codex-pr-review`。
- 不要忽略已存在的 CI 或 branch protection required checks；required checks 必须处理到 clean 或明确 blocked。
- 不要在 `Require conversation resolution before merging` gate 存在时留下 unresolved review threads。
- 不要把 local commit 当作 `在合并前停止` 的终点；该措辞默认要求 PR creation/reuse、best-effort GitHub Codex review evidence、required independent/offline review gates、CI/comments follow-up 和 merge-ready report。
- 不要把非 Codex external reviewers 作为默认 required gate。
- 不要把 `turn/steer` 当作当前可用 delivery path。
- 不要在没有读取 `codex thread <session-ID>` evidence 的情况下修复这类 review comments。
- 不要无限等待 reviewer 或 CI；用 `cbth` receipt/recovery 信息或清晰 blocked state 收口。
- 不要把 `default.rules` 或稳定命令 prefix 当作 repo/diff egress consent；rules 只降低命令审批摩擦，不能代替 user consent 或 repo trust evidence。
