---
id: 20260803-c22001
title: Claude 2.1.220 Stream Schema Compatibility
status: completed
created: 2026-08-03
updated: 2026-08-03
branch: codex/claude-2-1-220-stream-schema
pr:
supersedes: []
superseded_by:
---

# Claude 2.1.220 Stream Schema Compatibility

## Summary

- Admit the observed Claude Code 2.1.220 stream through an exact-version overlay without pinning or narrowing the canonical `>=2.1.211,<3.0.0` runtime range.
- Preserve the closed `extended-2x` contract: adjacent versions, unknown fields, malformed values, and capability drift remain inconclusive.

## Current State

- Exact 2.1.220 requires the ordered `capabilities` sequence `interrupt_receipt_v1`, `interrupt_cancel_queued_v1`, `msg_lifecycle_v1`.
- Its init and terminal events may each add optional `fast_mode_disabled_reason` only with exact value `sdk_opt_in_required`.
- The compatibility and aggregate stream-contract digests bind the overlay, so stale preflight evidence cannot activate it.
- The 2.1.212 baseline and the shared `extended-2x` structural profile remain unchanged.

## Next Steps

- Downstream private-overlay release and host sync follow the public squash merge.

## Evidence

- BL Codex thread `019f17fc-5756-7fb2-8d9f-34c0330bd59b`
- Retained Claude stream SHA-256 `f33bbdd6ab5bfaf3d2447a4fdf3e813142bfab8e4159401d08be5cb79c1d150e`
- Old-validator reasons `init.capabilities.mismatch`, `init.unknown-field`, and `terminal.unknown-field`
- Retained local audit merge `88e8b2ed08b0434dc9116c65f90265df95a985c4`
- `skills/review-orchestration-playbook/references/claude-stream-compatibility.json`
- `skills/review-orchestration-playbook/scripts/validate_claude_stream.py`
- `skills/review-orchestration-playbook/tests/test_validate_claude_stream.py`
- Focused stream-validator suite: 109 tests passed in 8.393 seconds.
- Complete review-orchestration suite: 2,833 tests passed in 1118.221
  seconds outside the restricted sandbox, with 6 platform-gated skips. The
  sandboxed run reached the same 2,833-test inventory but its 18 failures were
  all loopback or Unix-socket permission denials.
- Ruff lint/format, JSON parsing, Actionlint, skill validation, project-journal
  validation, and `git diff --check` passed.
