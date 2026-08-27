---
id: 20260813-rci001
title: Add the Required CI v2 Entry
status: completed
created: 2026-08-13
updated: 2026-08-13
branch: codex/daily-skill-friction-20260813-codex-review-workflows-codex-review-v2
pr:
supersedes: []
superseded_by:
---

# Add the Required CI v2 Entry

## Summary

- Add a caller-only, read-only reusable workflow for the central Required CI
  rollout without changing the existing CI workflow.
- Bind every checkout to the fixed target repository and the caller event's
  `github.sha`, guarded by the exact target repository identity.
- Preserve the complete dependency graph behind the required `test` job.

## Current State

- `.github/workflows/required-ci.yml` exposes only input-free `workflow_call`
  with the exact top-level permission mapping `contents: read`; callers must
  not pass `repository` or `ref` inputs.
- Its environment and jobs are byte-for-byte derived from
  `.github/workflows/ci.yml`, including all four prerequisite jobs and the
  `test` aggregator, except for the closed repository guards and checkout
  bindings.
- Before each checkout, the workflow fails closed unless `github.repository`
  is exactly `Joey-Tools/codex-review-workflows`. All four `actions/checkout`
  steps use that same literal repository, `ref: ${{ github.sha }}`, and
  `persist-credentials: false` while preserving the existing fetch depth.
- This entry supports only caller event contexts where `github.repository` is
  that exact target repository and the caller event's `github.sha` is the
  commit being validated.
- The contract test lives under
  `skills/review-orchestration-playbook/tests/test_required_ci_workflow.py`,
  so the existing test discovery in both CI workflows executes it without a
  new job. It rejects input, checkout, trigger, permission, secret, or job-graph
  drift during the canary rollout.

## Next Steps

- The central ruleset rollout owns invoking this reusable entry and retiring
  the canary only after live evidence is accepted.

## Evidence

- Direct execution of
  `skills/review-orchestration-playbook/tests/test_required_ci_workflow.py`
  passes all three focused contract tests under Python 3.13.0.
- The existing `python3 -B -m unittest discover` path with test root
  `skills/review-orchestration-playbook/tests` and pattern
  `test_required_ci_workflow.py` also selects and passes all three tests.
- `actionlint -shellcheck= .github/workflows/required-ci.yml` validates the
  reusable workflow structure and expressions.
