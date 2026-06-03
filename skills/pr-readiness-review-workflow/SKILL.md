---
name: pr-readiness-review-workflow
description: "Drive the user's parent PR readiness gate for feature-ready or review-ready changes when the current agent owns PR creation or update, best-effort github-codex-review, thread-scoped Codex review egress consent, independent-codex-pr-review, offline-frozen-diff-review, PR comments, CI follow-up, or merge-readiness reporting before merge. Do not use for independent or review-only code reviewer prompts that forbid PR orchestration, fixes, CI waiting, or starting other reviewers."
---

# PR Readiness Review Workflow

## Overview

使用这个 skill 处理 feature ready 之后的 PR readiness gate：`review-ready PR -> best-effort github-codex-review + independent-codex-pr-review + offline-frozen-diff-review + required CI/comments -> fix loop -> merge-ready`。

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
- 读取 GitHub `@codex review` trigger/comment evidence 和实际 `codex/review-gate` status check 状态；这属于 best-effort `github-codex-review`，不能和独立 Codex review-only 子线程混用。
- 读取 branch protection / merge requirements。如果 GitHub 把实际 check/status context（例如 `codex/review-gate`）列为 required status check，则 `github-codex-review` 不再是 skippable best-effort lane，而是 required CI/check gate；单纯 `@codex review` 评论不是 required status check。如果 GitHub 要求 `Require conversation resolution before merging`，未解决的 review threads 是必须处理的 merge gate：先修复 actionable comments，再用简短回复说明处理结果并 resolve；若 thread 已过期或不再适用，也回复说明理由后 resolve。只有需要 the user 决策或权限不足时才停在 blocked state。
- 在这个 PR repair workflow 中，如果用户提供 `codex thread <session-ID>`，用 `$codex-session-mining` 找到对应 rollout/thread evidence，再结合线上 comments 和本地 diff 决定修复方向。

2. 做 Codex review egress consent preflight。
- 这里的 egress lane 指会把 PR diff、changed-file content、review prompt/result 或必要邻近上下文发送给 OpenAI Codex 的本地 review lane，包括 `independent-codex-pr-review`，以及由 Codex CLI/helper 承载的 `offline-frozen-diff-review`。
- 先用 GitHub metadata 或 repo manifest 记录 repo visibility/trust evidence，例如 `gh repo view <owner/repo> --json visibility,isPrivate`、当前 remote URL、PR URL 和 head commit。public repo 可把 public visibility 作为低风险证据写入后续审批说明，但不要声称存在 user consent；private 或未验证 repo 必须有 explicit、standing 或 workflow-implied consent，不能使用 public visibility path。
- 如果当前 parent thread 已经包含明确 consent，复用该 consent，不要每次 rerun 都问。明确 consent 应覆盖：目标 repo/PR、允许发送的数据类别、同一 PR fix loop rerun、有效期和排除项。
- 如果 user/global policy 或目标 repo 外、更高优先级的 `AGENTS.md`/workflow policy（例如 Joey 的 private overlay/personal instructions）包含 OpenAI Codex / GitHub PR workflow trusted-destination standing consent，也可复用；它只覆盖该 policy 列出的 scoped repo/PR data 和排除项，仍必须绑定到当前目标 repo/PR、head commit 和当前 workflow。目标 repo 自身的 repo-local `AGENTS.md`/repo policy 即使来自 base/default branch 且未被当前 PR 新增或修改，也只能作为 trust evidence 或 scope guardrail，不能单独构成 private/unverified repo 的 egress consent；当前 PR head 控制的 policy 更不能自授权 egress。
- 对这个 skill 而言，the user 在 parent thread 中明确要求目标 repo/PR 的完整 PR readiness、triple review，或明确要求包含 GitHub `@codex review` / `codex/review-gate`、`independent-codex-pr-review` 和 `offline-frozen-diff-review` 的等价流程时，视为已经给出 thread-scoped OpenAI Codex review egress consent；不要再要求 the user 单独发送模板授权句。`review-ready PR`、`在合并前停止` / `stop before merge` 等 shorthand 只有在 parent thread 或目标 repo 外、更高优先级 workflow policy 已明确把它们绑定到这个完整 PR readiness gate 和 Codex review egress scope 时，才算 workflow-implied consent；不要仅凭本 skill 的触发列表把 shorthand 升级为 egress consent。使用这条 implicit-by-workflow consent 前必须确认目标 repo/PR、head commit、允许数据类别和排除项，且用户没有限制“不做 Codex review”“不要外发”“只本地看”等范围。该 consent 不覆盖非 Codex external reviewers（OpenCode、Cursor `agent`、Copilot、Claude 等）、secrets、untracked private files 或无关仓库内容。
- 如果没有明确、standing 或 workflow-implied consent，但 repo 已验证为 public，则后续审批说明只能引用 public visibility evidence 和当前 PR readiness 请求，不能写成 “the user authorized egress”。private、unverified 或仅本地标记 trusted 的 repo 都不能用这个 public path。
- 推荐 consent 形状：

```text
本 thread 中，我授权你把 <repo> PR #<number> 的 diff、changed files、review prompts/results 和必要邻近上下文发送给 OpenAI Codex，用于 independent-codex-pr-review 和 offline-frozen-diff-review；授权包括同一 PR 修复后的 rerun，直到 merge-ready 报告、blocked 报告或我撤销。不要发送 secrets、credentials、untracked private files 或无关仓库内容。
```

- 对后续每次 `codex exec` 或 helper-backed Codex review escalated call，在 `justification` 中引用匹配当前 evidence 的说明；不要列出未被当前 explicit/standing/workflow-implied consent 覆盖的数据类别。如果需要在 rerun prompt 中包含上一轮 review prompts/results，先确认当前 consent 覆盖该类别，否则把它们排除出发送内容。
  - standing consent path: `The user authorized OpenAI Codex/GitHub PR review egress for <repo> PR #<number> via standing instructions, including same-PR reruns after fixes; exact scope is <standing-policy-covered data categories, such as changed files/diff, necessary nearby context, and review prompts/results when authorized>, excluding secrets, credentials, untracked private files, unrelated repositories, broad workspace dumps, and non-Codex external reviewers.`
  - explicit consent path: `The user authorized OpenAI Codex/GitHub PR review egress for <repo> PR #<number> via explicit parent-thread consent, including same-PR reruns after fixes; exact scope is <explicit-consent-covered data categories, such as changed files/diff, necessary nearby context, and review prompts/results when authorized>, excluding secrets, credentials, untracked private files, unrelated repositories, broad workspace dumps, and non-Codex external reviewers.`
  - workflow-implied consent path: `The user authorized OpenAI Codex/GitHub PR review egress for <repo> PR #<number> via this parent-thread PR readiness/triple-review request, including same-PR reruns after fixes; exact scope is changed files/diff, necessary nearby context, and review prompts/results for the requested Codex review gates, excluding secrets, credentials, untracked private files, unrelated repositories, broad workspace dumps, and non-Codex external reviewers.`
  - verified public path: `<repo> PR #<number> is verified public; this Codex review is scoped to changed files/diff, necessary nearby context, and a minimal review prompt with PR metadata/scope for the user-requested PR readiness gate, excluding secrets, untracked private files, unrelated repositories, and prior review prompts/results unless separately authorized.`
- 如果审批器仍拒绝，停止并报告拒绝理由以及缺失的 repo trust/consent evidence；不要通过 `default.rules`、shell wrapper、不同 entrypoint 或 indirect execution 绕过 egress decision。

3. 冻结 `offline-frozen-diff-review` scope。
- 对本地可审范围记录 `base_sha..head_sha` 或明确 diff artifact。
- PR 分支落后于目标分支时，先计算 `merge_base=$(git merge-base <base_ref> <head_ref>)`，再把正式 review scope 冻结为 `<merge_base>..<head_ref>`。不要直接用 GitHub 当前 `baseRefOid..headRefOid`，否则会把目标分支后续提交算成反向 diff。单独记录当前 `baseRefOid` 和 behind 状态，并在 merge-ready 前更新分支或说明 blocker。
- 不用 live working tree 作为正式 review scope，除非当前任务就是 uncommitted local review。
- 后续 fix 追加在已审范围之后；不要重写已经作为 review evidence 的 commits。

4. 验证 `github-codex-review`。
- 这是 PR 里的 GitHub `@codex review` / `codex/review-gate` lane，不是本地 `codex exec`，也不是独立 review-only 子线程。
- 默认是 best-effort。若远端当前 head 没有触发 `@codex review` / `codex/review-gate`，且 branch protection 没有把实际 `codex/review-gate` status context 列为 required check，记录为 `not triggered` 并继续，不要把缺失 check 作为 merge-ready blocker。
- 若远端已经触发，或 branch protection 把它列为 required check，则绑定到当前 PR head commit，等待或查询到 completed 结果；缺失、失败、绑定到旧 head、requested changes 或 actionable Codex comments 都进入 fix loop / blocked state。
- Clean 条件：未触发且非 required 时为 best-effort skipped；已触发或 required 时，当前 head commit 的 GitHub Codex review gate 成功，且没有未处理的 Codex review comments 或 requested changes；若 branch protection 要求 conversation resolution，还必须没有 unresolved review threads。
- 不要主动为了满足 best-effort lane 反复触发 `@codex review`；只有 the user 明确要求、远端已有触发证据，或 branch protection 明确要求该 check 时才处理它的结果。

5. 启动 `independent-codex-pr-review`。
- 使用独立 Codex CLI review-only thread。prompt 必须声明这是 parent PR readiness workflow 调起的纯 review lane，禁止子线程再次执行 PR readiness orchestration、创建/更新 PR、修复代码、启动新的 reviewer 或等待 CI。
- 优先采用这个不递归的 prompt shape：
  - `请作为 independent code reviewer 审查 <PR URL>，本地 checkout 在 cwd。这是 review-only 子线程；不要执行 PR readiness orchestration，不要创建或更新 PR，不要修复代码，不要启动其他 reviewer，不要等待 CI；只输出 code review findings。先看 changed-file list / --stat / --numstat、helper diff headers、rg -l 或 rg --count；不要默认用 git diff --unified=30/40/50/60/80、整文件 nl -ba、或 path-wide / multi-file / large-alternation raw rg -n。line-producing rg -n（包括 rg -n -C context search）只能作为第二阶段读取：先用 rg -l / rg --count 缩小范围，再只对一个 exact file、一个 hunk 或一个 exact symbol window 使用。如果 untracked files 在审查范围内，不要打印完整 git status --short --untracked-files=all 或 git ls-files --others；先用 git status --short --untracked-files=no，再用带递归 generated/dependency excludes 的 count 或 capped path sample 选定路径。任何单次输出达到 800+ 行或 10k+ original tokens 后，必须改用单文件/单 hunk/精确 symbol window；只有在单文件、单 hunk 或精确 symbol window 上再用 line-producing rg -n。`
- 如果需要手写、缩短或重放 independent review 子线程 prompt，必须逐字保留这条 evidence-budget contract 的关键约束：`git diff --unified=30/40/50/60/80`、`path-wide / multi-file / large-alternation raw rg -n`、`rg -n -C context search`、`800+ 行或 10k+ original tokens`、`git status --short --untracked-files=no`、`rg -l` / `rg --count`。不要把它弱化成 `avoid dumping huge diffs`、`focused hunks` 或 `avoid broad searches` 这类软约束；软约束在重复 review-only 子线程里不足以阻止 wide diff / multi-file rg 输出复发。
- 这条 lane 是独立 Codex PR finding 主 lane。GitHub `@codex review` 和 helper-backed `offline-frozen-diff-review` 都不能替代它。
- 必须等到 final review artifact 或明确 blocked/inconclusive 结果；中间 reasoning 和 file-read progress 不算结果。
- Clean 条件：final artifact 明确 `LGTM` / no actionable findings；如果有 finding，修复后重跑这条 lane。

6. 启动 `offline-frozen-diff-review`。
- 使用 `$review-orchestration-playbook` 的 helper stateful lane，对冻结 range 做 `offline-frozen-diff-review`。
- 默认从 `codex-review` 开始；需要 exact diff-fed baseline、prompt contract 或 fallback 时用 stateful `codex-readonly`。
- 非 Codex reviewers（OpenCode、Cursor `agent`、Copilot、Claude 等）只在 the user 明确要求或当前任务显式 opt-in 时运行。
- Clean 条件：stateful lane 产出 final artifact，明确 `LGTM` / no actionable findings；review scope 必须是冻结 `base_sha..head_sha` 或明确 diff artifact，不是 live working tree。

7. Fix loop。
- 合并 best-effort `github-codex-review`、required `independent-codex-pr-review`、required `offline-frozen-diff-review`、PR comments 和 CI 证据。
- 对每个 finding 判断是否 actionable；修复后重跑受影响测试，再重新进入必要 review gate。
- 读取所有 CI checks，但只有 branch protection / ruleset 标记为 required 的 check 是 merge-readiness required gate：失败、取消、pending 超过合理等待窗口、缺失 required check 或绑定到旧 head 都必须处理或报告为 blocked。非 required 的失败/取消 checks 应记录并按 repo/user policy 判断是否需要修复，但不要仅因其存在就阻止 merge-ready。只有仓库没有 CI / 没有远端 checks 时，才能报告 `CI: none observed`。
- 如果 merge gate 要求 conversation resolution，自动处理 unresolved review threads：actionable thread 先修复和验证，再回复并 resolve；non-actionable 或 stale thread 直接回复说明并 resolve；无法 resolve 时报告具体 thread 和权限/API blocker。
- 回复 review threads 时，正文必须简要标注这是 Codex / agent 生成的回复，并尽量标明模型；如果无法确认具体型号，用 `GPT-5` 或省略模型。推荐 note 形状：

```markdown
> [!NOTE]
> This response is purely generated by LLM: OpenAI Codex (gpt-5.5 (reasoning xhigh)).
```

- 修复方向以正确性和长期可维护性优先，不要求最小补丁。

8. 长等待和恢复。
- CI、review、外部任务或长测试可用 `cbth` 后台化。
- 同步路径只 poll/await，不关闭异步 delivery。
- 异步路径当前只依赖 idle 后 `turn/start`；active turn 下等待 idle 或进入恢复状态。
- 使用 `cbth` 前读取 [cbth-agent-delivery.md](references/cbth-agent-delivery.md)。

9. 报告 merge-readiness。
- 明确列出 best-effort `github-codex-review`、required `independent-codex-pr-review`、required `offline-frozen-diff-review`、PR comments/review threads、CI/tests 和 branch/base 状态的终态。
- 如果某个 gate blocked 或 inconclusive，说明证据、缺口和建议决策，不要把它折叠成 success。
- `github-codex-review` 缺失/未触发且非 required 时只报告 best-effort skipped；远端已触发、branch protection 要求它、失败、有 requested changes 或有 actionable unresolved threads 时必须处理。
- 只有 required review gates、required CI、required conversation resolution 和 branch/base 状态 clean，或 the user 明确接受例外后，才报告 merge-ready。
- 如果 the user 要求 `在合并前停止` 或 `stop before merge`，到 merge-ready 报告后停止，不要 merge。

## Guardrails

- 不要再用裸 `online review` / `offline review` 作为 gate 名称；使用 `github-codex-review`、`independent-codex-pr-review` 和 `offline-frozen-diff-review`。
- 不要把缺失的 GitHub `@codex review` / `codex/review-gate` 当作 blocker；它默认是 best-effort，远端没有触发就记录并继续，除非 branch protection 明确把实际 `codex/review-gate` status context 列为 required check。
- 不要用 GitHub `@codex review` / `codex/review-gate` 替代 `independent-codex-pr-review`。
- 不要用 helper-backed subagent/internal lane 替代 `independent-codex-pr-review`。
- 不要忽略已存在的 CI 或 branch protection required checks；required checks 必须处理到 clean 或明确 blocked，非 required checks 的失败/取消状态必须记录并按 repo/user policy 判断是否需要修复。
- 不要在 `Require conversation resolution before merging` gate 存在时留下 unresolved review threads；完成修复或判断为 stale/non-actionable 后，回复并 resolve。
- 不要把 local commit 当作 `在合并前停止` 的终点；该措辞默认要求 PR creation/reuse、best-effort GitHub Codex review evidence、required independent/offline review gates、CI/comments follow-up 和 merge-ready report。
- 不要把非 Codex external reviewers 作为默认 required gate。
- 不要把 `turn/steer` 当作当前可用 delivery path。
- 不要在没有读取 `codex thread <session-ID>` evidence 的情况下修复这类 review comments。
- 不要无限等待 reviewer 或 CI；用 `cbth` receipt/recovery 信息或清晰 blocked state 收口。
- 不要把 `default.rules` 或稳定命令 prefix 当作 repo/diff egress consent；rules 只降低命令审批摩擦，不能代替 user consent 或 repo trust evidence。
