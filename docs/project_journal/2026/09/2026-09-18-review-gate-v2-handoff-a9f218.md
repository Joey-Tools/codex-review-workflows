---
id: 20260918-a9f218
title: Review Gate v2 Handoff
status: completed
created: 2026-09-18
updated: 2026-10-01
branch: codex/daily-skill-friction-2026-09-29-codex-review-workflows-remove-v1-bridge
pr:
supersedes: []
superseded_by:
---

# Review Gate v2 Handoff

## Summary
- Complete the v2 review-gate handoff and retire the temporary v1 legacy bridge after the organization cutover.
- Protect the review-gate control plane with `@JoeyTeng` CODEOWNERS coverage.

## Current State
- The verifier and controller use the canonical v2 workflows with `JoeyTeng/codex-review-gate-action@v2`.
- The verifier grants read-only Actions access for v2 review-run evidence reconciliation.
- When `CODEX_REVIEW_GATE_AUTO_REQUEST=true`, the controller requests review for first-attempt pull-request verifier failures and passes `workflow_run.head_sha` as the expected head; the v2 action validates the run's PR association and current PR head.
- The temporary `codex/review-gate` bridge workflow has been removed; `codex/github-review-gate` remains the review-gate check.
- `@JoeyTeng` retains CODEOWNERS coverage for the review-gate control plane.

## Evidence
- Canonical producer: `JoeyTeng/codex-review-gate-action@v2`.
- Source handoff implementation: https://github.com/Joey-Tools/codex-review-gate/pull/51.
- Post-cutover receipt SHA-256: `9a8b38f2188a14168423a07639d6662c87e198fe2dd12041f67fc224f363817e`.
