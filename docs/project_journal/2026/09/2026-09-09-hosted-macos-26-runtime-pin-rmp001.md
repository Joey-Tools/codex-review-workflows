---
id: 20260909-rmp001
title: Review GitHub macOS 26 Hosted Runtime Pin
status: active
created: 2026-09-09
updated: 2026-09-09
branch: codex/daily-skill-friction-2026-09-09-codex-review-workflows-archify-runtime-pin
pr:
supersedes: []
superseded_by:
---

# Review GitHub macOS 26 Hosted Runtime Pin

## Summary

- 更新 GitHub `macos-26` hosted runner 的已审查 runtime identity。
- 保留 no-child supervisor 和 broker 的 fail-closed 行为，不绕过未知环境。

## Current State

- CI 观测到 `26.6.2 / 25G83 / Darwin 25.6.0 / Python 3.13`。
- 现有 catalog 仍只接受 `26.5.2 / 25F84` 和旧版 `26.4 / 25E246`。
- 已确认当前 runner 的 `/usr/bin/sandbox-exec` SHA-256 为 `abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a`。

## Decisions

- 为当前 runner 增加精确 profile；原因是 GitHub `macos-26` 已切换到该系统版本，现有检查因此 fail closed。
- broker 使用相同的精确 OS/build gate；在 hosted runner 通过 OS gate 后，仅更新实际观测到变化的 `codesign` digest：`844d30a12929b59c9f2215e2a308c3e1db572831a478f35906e452a54025603e`。
- 不新增 CI，不删除旧 profile，不把未知 runner 自动视为可信。

## Next Steps

- 重新运行 broker reproducibility，确认新的 `codesign` digest 后其余 toolchain pin 仍保持一致。
- 在 canonical source 完成本地测试和 PR CI 验证，再刷新 private overlay 的 review-workflows source pin。

## Evidence

- GitHub Actions run `34290326303`，`independent-supervisor` job `102275203799`。
- GitHub Actions run `34317951947`，`broker-reproducibility` job `102358061142`：OS gate、clang、ld、lipo、vtool、codesign_allocate 通过；`codesign` actual 为 `844d30a12929b59c9f2215e2a308c3e1db572831a478f35906e452a54025603e`。
- `skills/review-orchestration-playbook/scripts/independent_codex_pr_review/tests/test_no_child_profile.py`
- `skills/review-orchestration-playbook/scripts/build_claude_keychain_broker_macos.sh`
