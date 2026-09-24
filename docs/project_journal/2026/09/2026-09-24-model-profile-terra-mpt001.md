---
id: 20260924-mpt001
title: Model Profile Terra Migration
status: active
created: 2026-09-24
updated: 2026-09-24
branch: codex/daily-skill-friction-20260924-codex-review-workflows-model-profile-terra
pr:
supersedes: []
superseded_by:
---

# Model Profile Terra Migration

## Summary
- Move the installed reviewer profile to `gpt-5.6-terra` with Codex `ultra` mode.
- Move Codex CLI/app-server review execution to Terra first, Luna fallback, and `max` reasoning; use Opus 5 with `max` for Claude Code and Copilot.

## Current State
- Runtime constants, reviewer configuration, stream contracts, and supervisor ledgers are aligned with the new profile policy.
- Claude and Copilot retry slots stay within the Opus 5 family: `claude-opus-5` is primary and `claude-opus-5.0` is the closed wire alias; the stream validator accepts both current identities.
- Runtime model matching canonicalizes only the exact dotted Opus 5 alias, keeping lookalike model IDs rejected.
- Targeted provider, app-server, stream, lane, contract, and execution tests pass; two supervisor/CLI cases remain unverified because the macOS sandbox denied their phase helper with `Operation not permitted`, outside model-policy coverage.

## Next Steps
- Land the validated local change and synchronize the private overlay through its normal release path.

## Evidence
- Worktree: `codex/daily-skill-friction-20260924-codex-review-workflows-model-profile-terra`
- Skill validation: `codex_skill_validate.py` reports `Skill is valid!`.
