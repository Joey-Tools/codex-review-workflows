---
id: 20260803-c22001
title: Claude 2.1.220 Stream Schema Compatibility
status: completed
created: 2026-08-03
updated: 2026-08-04
branch: codex/claude-2-1-220-stream-schema
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/88
supersedes: []
superseded_by:
---

# Claude 2.1.220 Stream Schema Compatibility

## Summary

- Admit the reviewed capability and reason fields observed in Claude Code 2.1.220 across the canonical `>=2.1.211,<3.0.0` runtime range without adding a version floor.
- Accept only the enumerated old/new capability shapes and exact reason value; unknown fields, malformed values, and every third capability shape remain inconclusive.

## Current State

- Every in-range release accepts either ordered `capabilities` sequence: `interrupt_receipt_v1`, `msg_lifecycle_v1`; or `interrupt_receipt_v1`, `interrupt_cancel_queued_v1`, `msg_lifecycle_v1`.
- Legacy may omit `capabilities`; extended still requires it. Init and terminal may each add optional `fast_mode_disabled_reason` only with exact value `sdk_opt_in_required`.
- The compatibility and aggregate stream-contract digests bind the range-wide known-shape contract, so stale preflight evidence cannot activate the old policy.
- The 2.1.212 baseline, structural version split, and exact 2.1.216 estimated-token overlay remain unchanged.

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
- Focused stream-validator suite: 108 tests passed in 6.550 seconds.
- Complete review-orchestration suite after the range-wide compatibility update:
  2,832 tests passed in 1,207.429 seconds outside the restricted sandbox, with
  6 platform-gated skips.
- The first PR CI run exposed the stale exact recovery-pointer assertion on
  both platforms; the focused repaired contract test passed while preserving
  the historical read-only supervisor evidence checks.
- Ruff lint/format, JSON parsing, Actionlint, skill validation, project-journal
  validation, and `git diff --check` passed.
