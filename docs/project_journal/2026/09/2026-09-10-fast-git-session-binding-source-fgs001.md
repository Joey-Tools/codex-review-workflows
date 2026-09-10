---
id: 20260910-fgs001
title: Preserve Fast Git Session-Binding Recovery in the Canonical Source
status: active
created: 2026-09-10
updated: 2026-09-10
branch: codex/fast-git-session-binding-recovery-20260910
pr:
supersedes: []
superseded_by:
---

# 保留 Canonical Fast Git Session-Binding 恢复

## Summary

- 私有 overlay 的全范围独立审阅发现，已合入 private `master` 的快速 Git 子进程退出修复没有位于其锁定的 canonical `codex-review-workflows` 源中。
- 后续受控 source reconciliation 因而会正确地从 canonical 重新生成文件，却意外回退该修复；不能只手工修改私有产物。
- 本工作流把同一最小修复及确定性回归测试提升到 canonical 源，随后由正常 release/source-lock 链重新投影到 private overlay。

## Decision

- 仅当 `Popen(start_new_session=True)` 后的 session bind 因 `ProcessLookupError` 失败、并且 `waitid(WNOWAIT)` 证明原 PID 是尚未 reap 的终态子进程时，才把它作为正常 fast exit 收集结果。
- 存活、身份不明或无法证明终态的情况继续 fail closed；不会把任意 PID 缺失当作成功。
- 不保留 private-only divergence：canonical 合并、下游 source promotion 和 private release 必须形成同一个可重建的来源链。

## Evidence and Next Steps

- Canonical base: `32028658d8d7497dba30a29715f3868f3cf76d8d`.
- Private review finding: `Popen()` 与第一次子进程身份读取之间的快速退出会重新触发已知 macOS `ProcessLookupError`；先前 private `master` 修复已证明该路径需要终态 child 验证和有界 stdout/stderr 回收。
- 变更通过本地定向和完整 runtime-process 测试、Ruff、Python 编译与 diff 检查后，执行 frozen-range fresh-context review 与 current-head GitHub review/CI。
- 合并后由下游 public release、private source-lock promotion、private release 和原生安装器完成交付；private 同步不得在 source 链尚未完整前被当作自举工具。
