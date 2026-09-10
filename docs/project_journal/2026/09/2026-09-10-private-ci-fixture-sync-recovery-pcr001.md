---
id: 20260910-pcr001
title: Recover Private CI Fixture Synchronization
status: active
created: 2026-09-10
updated: 2026-09-10
branch: codex/daily-skill-friction-20260910-codex-review-workflows-private-ci-fixture-sync-repair
pr:
supersedes: []
superseded_by:
---

# 恢复 Private CI Fixture 同步

## Summary

- 修复 canonical `codex-review-workflows` 中落后的 private CI fixture，使 private overlay 的受控同步不会把已验证的分片 CI 图覆盖回旧的单体布局。
- 该修复是 reviewer role 发布恢复链的一部分：只有同步测试恢复通过后，private overlay 才能吸收已发布的 toolbox receipt 并交付新的安装包。

## Current State

- 修复前，private overlay scheduled sync run `34422162989` 在测试阶段失败：2064 项测试中 9 项失败，未创建同步 PR 或新的 private release。
- 原因是 source sync 从 canonical fixture 复制了旧的 `platform_tests` 布局，而 private `master` 已采用 `review_tests`、`private_overlay_tests`、`private_overlay_contract_tests`、`linux_isolation_tests` 和 macOS shard 等分片 job。
- 当前提交已将 canonical fixture 对齐到分片 CI 图；与当前 private `master` 的差异仅为将随 toolbox `5de600c` 一起投影的五个新增测试矩阵条目。下游 private source-lock/overlay PR 和 release 仍未完成。

## Decisions

- 先在 `codex-review-workflows` 修正 canonical fixture，再运行 private source sync；不直接修改 private CI 以掩盖来源漂移。
- fixture 应精确反映已验证的 private `master` CI 图，保留现有 required aggregate `test` 语义与所有叶节点，而非删减门禁或回退分片。
- source fixture 修复与后续 private source-lock/overlay PR 分开交付：前者恢复上游契约，后者在上游已验证后吸收新的 toolbox release receipt。
- 不重跑已失败的 `34422162989`；scheduled sync 不用于自举尚未物化的 toolbox 变更，只有完整的 atomic promotion 合并后才作为无漂移确认触发。
- canonical fixture 已预先列出 toolbox `5de600c` 的五个新增测试，但现有 scheduled sync 既不提升 toolbox pin，也还没有对应五条同步规则；因此 canonical 合并与 private atomic promotion PR 合并之间不触发 scheduled sync。该 private PR 会原子更新 pin/receipt、managed-path contract、同步规则、物化测试文件和 workflow；完成后再触发 scheduled sync 作为确认，而非已知失败的自举尝试。

## Next Steps

- 合并后先落 private atomic promotion PR，再触发新的 private scheduled sync 确认无漂移，审核 release 和安装包。
- 使用发布后的安装器安装到目标机器，并 smoke-test `reviewer` role 的原生热加载。

## Evidence

- private scheduled sync: `34422162989`，基线 `25814d8ec438c3e2f19e85e44f1fd345bc632250`。
- public toolbox release: `personal-codex-20260910-003724-5de600c`，目标提交 `5de600c38271e422a74c23ed6260bbff64674b55`。
- canonical fixture: `skills/review-orchestration-playbook/tests/fixtures/ci/private.yml`。
- private target workflow: `.github/workflows/ci.yml` on private `master`.
- 该 fixture 与当前 private `master` CI 的差异精确只剩五个计划随 toolbox `5de600c` 同步的测试矩阵条目。
- canonical frozen-range full suite：3258 项中 3250 项通过、7 项跳过、1 项失败（1578.736s）；唯一失败是 `test_claude_keychain_broker_serves_one_in_memory_value` 的本机 `sandbox-exec: sandbox_apply: Operation not permitted`。该测试文件与 base 未变，且同一精确测试随后在干净 `master` 上也以相同退出码 `71` 和错误文本失败，故不是本提交引入。
- fresh-context review 发现 private-profile 的 review 测试枚举遗漏 `tests/` 子目录；已修正为枚举真实目录，避免 private CI 将非空矩阵错误地与空集合比较。
- 随后的 frozen-range review 还发现 project-journal CI matrix 没有与实际测试目录绑定；private-profile 契约现会验证 overlay、project-journal、review 和 macOS 分片/排除四组布局，防止未来新增测试被静默遗漏。
- frozen-range review 还要求 canonical profile 直接把 private fixture 的 `review_tests` matrix 与 review skill 的实际 `test_*.py` 集合绑定，避免上游先静默遗漏、仅在下游 private sync 才暴露。
- 最终 review 将 matrix 合同进一步收紧为“名单且实际执行”：overlay、review 和 project-journal job 必须消费各自的 `${{ matrix.module }}`，aggregate job 必须以自身 job-level `if: ${{ always() }}` 执行；避免列表仍在而测试被固定命令绕过，或叶节点失败时 aggregate 被跳过。
- 聚焦 canonical contract suite：38 项执行，其中 37 项通过、1 项 private-layout 专属跳过。一次性 future private-layout smoke 真实执行该专属契约并通过：23 个 overlay 测试模块、project-journal/review matrix 与 macOS 分片例外均与实际文件集合一致；临时验证布局已清理。
