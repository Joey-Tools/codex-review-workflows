---
name: external-review-playbook
description: Compatibility alias for older prompts that still name `$external-review-playbook`; route new work to `$review-orchestration-playbook`, which now owns the canonical external-review and helper-backed internal-review workflow.
---

# External Review Playbook

## Status

This is now a compatibility entry for older prompts, docs, and approved helper paths.
The canonical skill is `$review-orchestration-playbook`.

## Use This Alias Only When Needed

- If the user or an older prompt explicitly names `$external-review-playbook`, load this alias and then follow `../review-orchestration-playbook/SKILL.md`.
- Keep this directory during the transition because it still holds the compatibility wrappers, shared references, tests, and older approved script paths.
- For new prompts, docs, and helper references, prefer `$review-orchestration-playbook` plus the installed helper path `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`. Use repo-local `scripts/...` helper paths only when intentionally testing the checkout copy.

## Compatibility Entry Points

- `scripts/isolated_external_review`: legacy helper path that still resolves to the current implementation.
- `scripts/isolated_copilot_review`: older runtime alias retained for approved prefixes.
- `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`: canonical installed helper path for fresh callers.
- `../review-orchestration-playbook/scripts/isolated_review`: checkout-copy wrapper for local development and tests.
