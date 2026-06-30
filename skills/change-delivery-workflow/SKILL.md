---
name: change-delivery-workflow
description: "Run a local pre-commit delivery gate for non-trivial repo changes: implement, build, test, update docs, run local/internal review, then commit. Use when wrapping up local work before commit, probing local gate readiness, or as the first phase before PR readiness when the user asks for a full workflow before merge."
---

# Change Delivery Workflow

## Overview

这个 skill 只负责本地落地到 commit 前的门禁：`plan -> code -> test -> review -> commit`。

不要把 PR readiness、线上 PR comments、merge 前 review、远端 CI 等待混入这个 skill。那些任务 hand off 到 `$review-orchestration-playbook` 的 PR-readiness 流程。

如果 the user 要求的是完整流程、feature ready 到 merge-ready、`在合并前停止`、`stop before merge`，或类似“用 workflow 完成”且上下文已经在讨论 PR readiness，这个 skill 只是第一阶段。commit 通过后必须继续 hand off 到 `$review-orchestration-playbook`；PR creation/update 仍受其 PR target authorization preflight 约束。不要把本地 commit 当作终点，除非 the user 明确说只做 local/pre-commit gate。

## Workflow

1. 确认本地门禁范围。
- 如果 the user 只是要求 probe workflow readiness，先检查构建/测试、e2e、文档同步、签名 commit、内部 review helper 是否可用。
- 如果 the user 要求 full workflow、merge-ready、`在合并前停止`、`stop before merge`，先记录需要 PR readiness handoff。该措辞只在 `$review-orchestration-playbook` 的 PR target authorization preflight 通过后，允许后续创建/更新 review-ready PR 和等待 review/CI；不允许 merge。
- 只修复当前门禁直接需要的 blocker。需要 token、登录、TCC、设备授权或人工审批时，停在清晰 handoff 点。
- 对 reviewable work，优先在 `wip/<topic>` 分支上做临时 commits，用固定 `base_sha..head_sha` 冻结 review range；最终目标分支 commit 仍在全部门禁通过后形成。

2. 完成实现。
- 先完成代码变更和明显低级错误修复，再进入构建/测试。
- 如果实施中发现原方案不成立，先重新收敛方案，不要继续推进后续门禁。

3. 跑构建和测试。
- 优先选择当前 repo 最宽但合理的验证：build、unit tests、integration tests、e2e。
- 失败时回到最早受影响步骤修复，再重跑受影响验证。
- 无法运行的 gate 要明确说明原因和风险，不得声称已覆盖。

4. 更新本地跟踪文档。
- 按 repo 约定更新 project journal、`docs/PROJECT_STATE.md`、`docs/PROJECT_TODO.md` 或对应短入口。
- squash-merge repo 的 PR-bound journal 应写成目标分支合并后的稳定状态；临时 `ready for review` / `waiting for merge` 放 PR body 或 comments。

5. 运行本地/internal review。
- 默认用 `$review-orchestration-playbook` 的 stateful `--reviewer codex` lane，并绑定固定 `base_sha..head_sha`。
- 如果本地 Codex helper lane unavailable / blocked / inconclusive，而当前门禁仍需要 Codex-lane fallback，只能启动 clean-context `reviewer` agent，并在 prompt 中提供完整 review scope、diff/range、evidence-budget contract 和 output contract；不要用普通 coding subagent、inherited-context subagent 或 parent-thread continuation 代替 internal review。
- clean-context `reviewer` fallback 必须使用最新配置的 Codex model 和最高配置 reasoning effort；如果该形态不可用，报告 blocked/inconclusive，不要静默降级。
- 对 reviewable `wip/<topic>` range，把 reviewer 绑定到固定 `base_sha..head_sha`，不要审 live working tree。
- 如果本地/internal review 发现问题，修复后回到测试和文档步骤。

6. Commit。
- 只有实现、验证、文档和本地/internal review 都干净后才 commit。
- Commit 保持聚焦；本地 review anchor commits 可以用于冻结范围，最终目标分支落地仍应是经过 gate 的 landing shape。
- local-gate-only 任务不 push，除非 the user 另行明确要求。
- 如果第 1 步记录了 PR readiness handoff，commit 不是终点，且该 handoff 在 PR target authorization preflight 通过后授权后续阶段 push 当前分支并创建/更新 review-ready PR。继续进入 `$review-orchestration-playbook` 的 PR-readiness 流程，在那里创建/更新 PR、处理 requested review shape、CI/comments，并最终停在 merge-ready 或清晰 blocked state。

## cbth For Long Gates

当测试、CI 等待、review lane 或其他本地任务可能超出当前 turn 的稳定等待窗口时，可以使用 `cbth` 作为后台任务基座。

- 默认从 `CODEX_THREAD_ID` 读取 `source_thread_id`；缺失时要求显式传入。
- 提交任务后立即向用户输出并持久化 `source_thread_id`、`task_id`、`job_id`、预计的 `batch_id` 查询方式和 recovery commands。
- 同步等待只 poll/await，不消费 delivery。agent 提前停止等待时，异步投递必须保留。
- 当前自动异步投递只依赖 idle 后 `turn/start`；不要依赖尚未启用的 `turn/steer`。
- 需要详细约定时读取 [cbth-agent-delivery.md](../review-orchestration-playbook/references/cbth-agent-delivery.md)。

## Guardrails

- 这个 skill 是本地 pre-commit gate，不是 PR merge gate。
- `在合并前停止` / `stop before merge` 的终点是 PR readiness 的 merge-ready 报告，不是本地 commit。
- PR creation/update 仍受 `$review-orchestration-playbook` 的 PR target authorization preflight 约束；不要把 local handoff 记录当作对任意 target repository 的授权。
- Claude-family review 只在 the user 明确要求 double/triple review 或等价 opt-in 时运行。
- Review progress、file-read trace、keepalive output 都不是 final review artifact。
- 如果 gate 持续 inconclusive，停在有证据的决策点，不要无限重试。
