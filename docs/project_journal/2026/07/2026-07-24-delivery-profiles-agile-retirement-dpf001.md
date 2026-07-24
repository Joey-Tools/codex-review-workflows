---
id: 20260724-dpf001
title: Unify Delivery Profiles And Retire Standalone Agile Delivery
status: completed
created: 2026-07-24
updated: 2026-07-24
branch: codex/delivery-profiles-agile-retirement-20260724
pr:
supersedes: []
superseded_by:
---

# Unify Delivery Profiles And Retire Standalone Agile Delivery

## Summary

- `change-delivery-workflow` is the thin active orchestrator for
  `focused-checkpoint`, `local-gate`, and `pr-readiness-handoff`.
- `agile-delivery-workflow` is a compatibility alias that maps legacy
  MVP/agile/scout triggers to `focused-checkpoint`.
- `synthetic-token-fixtures` routes authoring through the existing review
  helper's authoritative catalog CLI without defining a second pool or runtime.

## Current State

- Focused checkpoints and local landing commits are created automatically with
  the repository signing policy after their gates pass, unless the user
  explicitly requests a report-only, probe-only, or no-commit result.
- Commit mode is resolved before profile selection or any review anchor. A
  no-commit run may reuse an already-correct committed range, but it never
  creates history merely to satisfy a formal lane.
- Explicit local-only, report-only, probe-only, read-only, and no-remote
  constraints are resolved before terminal-outcome signals. They prevent a
  conflicting `full workflow` or PR phrase from selecting PR readiness or
  authorizing remote mutation.
- Every terminal result or permitted handoff carries a closed, versioned record
  with the selected profile, immutable constraint list, commit mode, remote
  mutation mode, and handoff target. Conflicting or widened records fail closed.
- Terminal-outcome precedence makes a combined MVP-plus-PR request run the
  focused slice, full local gate, and PR handoff in that order. A clean signed
  review checkpoint is already the landing commit; the workflow never creates
  an empty relabeling commit or rewrites history for that purpose.
- Version-sensitive validation loads a dedicated reference that deterministically
  selects single- or multi-version authority and isolates checkout, cache,
  ports, and persistent state before concurrent execution.
- The journal automation gate updates repositories that already adopted the
  convention, repositories whose policy requires it, and durable cross-session
  or PR handoffs with an existing tracking product. A short checkpoint does not
  introduce first-time tracking by itself.
- Formal review details remain in `review-orchestration-playbook`. When commit
  mode allows fixes, the workflow reruns affected validation and journal work,
  creates a new signed review checkpoint, and reviews the new exact range. When
  commit mode forbids fixes, it preserves the existing committed range, reports
  the findings as a blocker, and stops without creating or requiring history.
- Synthetic fixture authoring exposes only catalog validation, metadata-only
  listing, and single-ID retrieval. Legacy exemptions remain helper
  compatibility surfaces rather than authoring paths.

## Next Steps

- No code follow-up is required for this workstream.

## Evidence

- `python3 -B skills/change-delivery-workflow/tests/test_delivery_profiles.py`
  passed (`14` tests), including deterministic constrained-scope conflicts,
  positive PR-handoff controls, closed result-record rejection cases, and the
  existing-range/no-commit/review-findings regression.
- `python3 -B skills/synthetic-token-fixtures/tests/test_skill_contract.py -v`
  passed (`2` tests).
- `python3 -B skills/review-orchestration-playbook/tests/test_synthetic_tokens.py SyntheticTokenCliTest -v`
  passed (`5` tests).
- `python3 -B skills/review-orchestration-playbook/tests/test_contracts.py -q`
  passed (`86` tests).
- `uv run --isolated --with pyyaml python3 /Users/hoteng/.codex/skills/joey-skill-authoring/scripts/codex_skill_validate.py skills/change-delivery-workflow skills/agile-delivery-workflow skills/synthetic-token-fixtures`
  passed (`3/3` skills valid) after the constrained-scope review-fix round.
- `python3 -m json.tool` passed for the delivery-result schema, deterministic
  profile-selection fixture, and review-findings fixture.
- `python3 /Users/hoteng/.codex/personal-sync/overlays/private/releases/9257aca19dc7c370418c1dcf7b8c194b0353eafe/personal_codex/skills/project-journal/scripts/project_journal.py validate --repo .`
  passed.
- `ruff check skills/change-delivery-workflow/tests/test_delivery_profiles.py skills/synthetic-token-fixtures/tests/test_skill_contract.py skills/review-orchestration-playbook/tests/test_contracts.py`
  passed, and `ruff format --check` passed for the same files.
- The validator's task-local `uv` cache and test-created Python bytecode were
  removed after validation; the final ignored-cache scan passed.
- `git diff --check` passed for tracked changes.
