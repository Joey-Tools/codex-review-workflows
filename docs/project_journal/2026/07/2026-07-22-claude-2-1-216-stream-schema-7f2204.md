---
id: 20260722-7f2204
title: Claude 2.1.216 Stream Schema Compatibility
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/claude-2-1-216-stream-schema
pr:
supersedes: []
superseded_by:
---

# Claude 2.1.216 Stream Schema Compatibility

## Summary

- Admit the authoritative Claude Code 2.1.216 stream through the existing versioned `extended-2x` profile without globally pinning the compatible runtime range.
- Model analytics and feedback settings as required JSON booleans rather than treating the observed analytics setting as a safety invariant.
- Close the extended assistant-message surface over required `diagnostics: null` while preserving the legacy profile and unknown-field rejection.
- Prove observed cwd-relative `Grep.path` values against the exact bound workspace while retaining fail-closed home-shorthand, parent-escape, and symlink-escape behavior.

## Current State

- The seven extended init fields remain required. Ordered agents and capabilities, `output_style: default`, `fast_mode_state: off`, and nonempty `uuid` retain their exact contracts; `analytics_disabled` and `product_feedback_disabled` accept either JSON boolean and reject every other type.
- The extended intermediate profile requires `diagnostics: null` in every assistant message. The legacy profile forbids that field, and every unreviewed nested field still fails closed.
- The five extended terminal fields remain required on success and strictly validated when present on failure: both fast-mode and terminal-reason values are fixed, while all three latency fields are nonnegative integers.
- A present relative `Grep.path` is anchored to the exact descriptor-bound cwd and checked for lexical and symlink-resolved containment. Relative `Read.file_path` and `Glob.path`, home shorthand, parent escapes, and external symlink targets remain unaccepted or blocked according to the existing global precedence.
- The retained 537-record Claude Code 2.1.216 stream for portable-codex-runtime PR #13 validates as `accepted` against the exact frozen tracked tree. Its raw result SHA-256 is `0e6ed5e781394357d6078b2e9c76b034d669d9bfb476babbd71afca657c5e725`; post-acceptance `summary-only` disposition preserves the raw string and yields `clean` / `extended-clean`.
- The final Python 3.13 suite passes 2,398 tests with 5 platform skips. The focused stream/preflight/result/contract gate passes 242 tests; Ruff lint, Python compilation, JSON parsing, both C warning-as-error syntax checks, Actionlint, skill validation, synthetic-token validation, journal validation, and whitespace checks pass. The task-owned WIP was fully Ruff-formatted; after integration, the tree matches `master`'s existing four-file Ruff-format drift without adding another file.

## Next Steps

- No canonical policy work remains. Downstream private overlay sync and host installation follow the public squash merge.

## Evidence

- Parent session `019f6fcd-390d-79d3-a8c6-df96bf2ab8f5`
- Portable review range `83542fa2a29661c1422c108887bc13cb5bddd7eb..01c3f9da03e7adfdcd4176cb927dc450436da8f4`
- `skills/review-orchestration-playbook/references/claude-stream-schema.json`
- `skills/review-orchestration-playbook/scripts/validate_claude_stream.py`
- `skills/review-orchestration-playbook/scripts/review_runtime/review_result.py`
- `skills/review-orchestration-playbook/tests/test_validate_claude_stream.py`
- `skills/review-orchestration-playbook/tests/test_contracts.py`
