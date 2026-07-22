---
id: 20260722-7f2202
title: Review Result Semantics
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/review-result-semantics
pr:
supersedes: []
superseded_by:
---

# Review Result Semantics

## Summary

- Named-lane records separate artifact validation, semantic review outcome, and output presentation while preserving the accepted raw result verbatim.
- Claude stream validation remains transport/schema-only. The canonical post-acceptance `review_result.py` helper classifies exact sentinel, extended clean, actionable, contradictory, ambiguous, and nonconforming result presentations.
- Presentation differences do not trigger automatic review reruns. Only invalidated range/head evidence, a finding fix on a new head, or an explicit request does.

## Current State

- `artifact_status` records whether the provider artifact passed its existing validator. A validator-accepted artifact is not automatically a clean review.
- `review_outcome` records `clean`, `findings`, or `undetermined`; `presentation` records the result shape independently.
- Exact `No findings.` with outer ASCII whitespace only is `canonical-clean`. A concise non-actionable positive/coverage summary whose unique final nonempty logical line is exact `No findings.` is `extended-clean`.
- A concrete actionable finding overrides a terminal clean sentinel as `findings` / `contradictory`. Uncertainty, inability to confirm, or semantic conflict is `undetermined` / `ambiguous`; other accepted nonconforming prose remains undetermined.
- The prompt permits a concise positive coverage summary only for clean results and forbids the sentinel whenever a finding exists.

## Next Steps

- No canonical policy work remains for this correction. Downstream distributions should sync from the corrected canonical default branch.

## Evidence

- Session `019f6fcd-390d-79d3-a8c6-df96bf2ab8f5`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/review-lane-contracts.md`
- `skills/review-orchestration-playbook/references/canonical-claude-lane.md`
- `skills/review-orchestration-playbook/references/review-prompt-templates.md`
- `skills/review-orchestration-playbook/scripts/review_runtime/review_result.py`
- `skills/review-orchestration-playbook/tests/test_review_result.py`
- `skills/review-orchestration-playbook/tests/test_contracts.py`
- `README.md`
