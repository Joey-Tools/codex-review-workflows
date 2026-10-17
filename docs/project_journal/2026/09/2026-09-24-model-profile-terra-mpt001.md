---
id: 20260924-mpt001
title: Runtime Model Profile Alignment
status: completed
created: 2026-09-24
updated: 2026-10-17
branch: codex/daily-skill-friction-20260924-codex-review-workflows-model-profile-terra
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/119
supersedes: []
superseded_by:
---

# Runtime Model Profile Alignment

## Summary
- Pin low-level Codex CLI/app-server execution to `gpt-6.1-sol / high` without automatic model fallback.
- Pin Claude Code to `claude-opus-5-5 / high` and authorized Copilot CLI to `claude-opus-5.5 / high`.
- Preserve the canonical reviewer role and peer CLI adapter at `gpt-6.1-sol / medium`.

## Current State
- Reconcile the original task with the current canonical source, preserving remote-first routing, routine readiness, recovery, and source inventory changes.
- The original Terra/Luna retry implementation is superseded and is not part of the runtime policy.
- Copilot model evidence must preserve the exact provider-native ID across session, message, and usage records and at the final attempt gate; punctuation aliases do not verify the pinned model.
- Historical parsing and explicit negative fixtures may retain legacy model names; no default execution selects a pre-GPT-6 model.

## Evidence
- Reviewer/routing baseline: canonical PR #127.
- Routine-readiness baseline: canonical PRs #137 and #138.
- Preserve the semantic GitHub review evidence and risk-based diagnostic rerun policies from canonical PRs #139, #140, and #141.
- Private generated copies follow canonical source promotion rather than manual edits.
