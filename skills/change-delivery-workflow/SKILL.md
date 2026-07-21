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
- 如果 the user 只是要求 probe workflow readiness，先检查构建/测试、e2e、文档同步、签名 commit、Codex reviewer lane 是否可用。
- 如果 the user 要求 full workflow、merge-ready、`在合并前停止`、`stop before merge`，先记录需要 PR readiness handoff。该措辞只在 `$review-orchestration-playbook` 的 PR target authorization preflight 通过后，允许后续创建/更新 review-ready PR 和等待 review/CI；不允许 merge。
- 只修复当前门禁直接需要的 blocker。需要 token、登录、TCC、设备授权或人工审批时，停在清晰 handoff 点。
- 对 reviewable work，优先在 `wip/<topic>` 分支上做临时 commits，用固定 `base_sha..head_sha` 冻结 review range；最终目标分支 commit 仍在全部门禁通过后形成。

2. 完成实现。
- 先完成代码变更和明显低级错误修复，再进入构建/测试。
- 如果实施中发现原方案不成立，先重新收敛方案，不要继续推进后续门禁。

3. 跑构建和测试。
- 优先选择当前 repo 最宽但合理的验证：build、unit tests、integration tests、e2e。
- 先确定当前验证所需的每个 runtime/toolchain 采用单版本还是多版本形态。同一 runtime/toolchain 的最低支持版本和 CI matrix 本身不构成本地多版本门禁。只有 the user 或 repo-local policy 明确要求本地多版本验证，或本次改动目标就是跨版本兼容性时，才选择多版本形态；否则使用单版本形态。
- 单版本形态下，先只按 authority/instruction/config 是否存在选择最高优先级来源，不预先判断其能否解析或是否兼容：the user 对本地验证版本的 instruction；repo-local policy 对本地验证版本的 instruction；repo 的 version-selection config 或 pin（例如 `.python-version`，兼容性范围本身不算 version-selection pin）；可用的 repo 常规 runner 或项目工具默认解析（例如常规 `uv run`）；本机已安装版本 inventory。只有当前 authority/config/runner/inventory 来源完全不存在时才检查下一个来源。选中来源后再解析并验证；若选定 instruction 显式委托给一个具名 repo 机制（例如 `repo default` 或常规 `uv run`），该机制属于选中来源的解析过程。若选中 installed inventory，按该工具的 canonical version ordering 选择满足项目约束的最高已安装版本；只有 the user 或项目约束明确允许 prerelease 时，才把 prerelease 纳入候选。最终必须得到唯一且与项目约束兼容的版本；若选中来源内部冲突、无法唯一解析或不兼容，停止并报告 blocker，不得静默降级。将所选 version 及其来源固定用于同一轮验证并记录。
- 在多版本形态下，同样先只按 authority/instruction/declaration 是否存在选择最高优先级来源，不预先判断其是否能解析为有效集合：the user 或本次任务对本地多版本验证的 instruction；repo-local policy 对本地多版本验证的 instruction；repo 明确声明的 supported-version set；repo 的 CI matrix。只有当前 authority/instruction/declaration 完全不存在时才检查下一个来源。选中来源后再解析并验证；若选定 instruction 显式委托给具名 repo 声明（例如 `all supported versions` 或 `CI matrix`），该声明属于选中来源的解析过程。最终集合必须有限、非空、无重复且每个版本都与项目兼容。选定来源后不比较或合并其他较低优先级来源，较低优先级来源的不同集合不构成冲突；来源冲突仅指选中来源及其显式委托的解析过程内部给出相互矛盾的集合。若选中来源内部冲突、只能得到开放范围或无法确定有限集合，停止并报告 blocker，不得根据本机已安装版本任意扩张集合。记录最终版本集合及其来源。
- 执行多版本集合前，识别共享的 checkout 产物、缓存、固定端口及其他机器级可变状态。只有 suite 已证明顺序复用安全时，才可在同一 checkout 串行执行；版本敏感的 checkout 产物、缓存或状态必须使用独立 worktree/cache/state，或在版本间显式清理并重建。无论使用一个还是多个 worktree，固定端口及其他机器级共享资源只有在为每次运行分配唯一值或命名空间时才可并发；否则必须跨所有 worktree 串行执行。持久机器级状态只有在已证明为当前任务专属且可丢弃时，才可在版本间显式 clean/reset；若状态为共享、所有权不清或不可安全丢弃，停止并报告 blocker，需要额外权限时请求明确授权。只有 checkout-local 与机器级资源都已证明隔离时才可并发。
- 失败时回到最早受影响步骤修复，再重跑受影响验证。
- 无法运行的 gate 要明确说明原因和风险，不得声称已覆盖。

4. 更新本地跟踪文档。
- 按 repo 约定更新 project journal、`docs/PROJECT_STATE.md`、`docs/PROJECT_TODO.md` 或对应短入口。
- squash-merge repo 的 PR-bound journal 应写成目标分支合并后的稳定状态；临时 `ready for review` / `waiting for merge` 放 PR body 或 comments。

5. 运行本地/internal review。
- 默认且唯一可计为 named single review 的本地门禁是用 `fork_turns="none"`（或平台等价的零继承上下文启动方式）启动的 Codex `reviewer` agent；不要用普通 coding subagent、inherited-context subagent 或 parent-thread continuation 代替。
- 为 reviewer 创建独立 clean Git worktree，固定 `base_sha..head_sha`，并保持整个 lane read-only。Prompt 只提供 review-control metadata：worktree、两个 SHA、instruction-loading order、read-only/evidence limits、review focus/non-goals 和 output contract；不要预先生成、粘贴或附加 full diff、changed-file content、suspected finding 或另一 reviewer 的结果。Reviewer 先加载 review skill 与 repo-wide `AGENTS.md`，取得 changed-path metadata 后再加载适用的 path-scoped `AGENTS.md`、domain skills 与 project guidance，最后自行用 bounded Git/tool calls 获取和审查该 range。
- `reviewer` agent 必须使用 skill 配置的 Codex model、最高配置 reasoning effort 和 read-only sandbox；如果该形态不可用，报告 blocked/inconclusive，不要静默降级或用旧 helper 补位。
- 旧 `isolated_review` Codex helper 如仍用于低层 compatibility/diagnostics，不计入 named single、double 或 triple review。
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
- Named double review 只在 the user 明确 opt in 后运行，且必须由上述 single lane 加上在另一独立只读 worktree 中直接启动的 actual Claude Code process、绑定同一 frozen range；supplied-diff `isolated_review` helper 与另行显式请求的 Copilot diagnostic 都不计入或满足 named double。
- Named triple review 必须再包含 exact host `github.com` PR 当前 head 上的 exact `@codex review` 请求，以及 exact REST `chatgpt-codex-connector[bot]` / `Bot` 身份提供的 complete terminal provider-authored findings payload：选中的 review body 加上 every fully paginated associated inline review comment，或明确的 terminal issue-comment body。Exact App `chatgpt-codex-connector` 的 current-head post-request check/run 只能作为 service-start evidence；即使 `completed` / `success`，也不能完成 triple 或证明 clean/no-findings。无 PR、integration/service 不受支持、任何 non-`github.com` host（包括 `sqbu-github.cisco.com` 与所有 GitHub Enterprise host），或 operating identity in `{hoteng, hoteng_cisco}` 时，明确报告 `effective double`，不得声称 triple；已启动但 payload、terminal nature、分页、关联或归属证据 missing/malformed/stale/ambiguous/incomplete 时报告 `triple-inconclusive`，不得降成 double。
- PR readiness 不再强制已退役的额外 Codex gates。
- Review progress、file-read trace、keepalive output 都不是 final review artifact。
- 如果 gate 持续 inconclusive，停在有证据的决策点，不要无限重试。
