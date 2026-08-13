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
- Preserve the complete dependency graph behind the required `test` job.

## Current State

- `.github/workflows/required-ci.yml` exposes only `workflow_call` with
  `contents: read`.
- Its environment and jobs are byte-for-byte derived from
  `.github/workflows/ci.yml`, including all four prerequisite jobs and the
  `test` aggregator.
- The contract test lives under
  `skills/review-orchestration-playbook/tests/test_required_ci_workflow.py`,
  so the existing test discovery in both CI workflows executes it without a
  new job. It rejects trigger, permission, secret, or job-graph drift during
  the canary rollout.

## Next Steps

- The central ruleset rollout owns invoking this reusable entry and retiring
  the canary only after live evidence is accepted.

## Evidence

- Direct execution of
  `skills/review-orchestration-playbook/tests/test_required_ci_workflow.py`
  passes both focused contract tests under Python 3.13.0.
- The existing `python3 -B -m unittest discover` path with test root
  `skills/review-orchestration-playbook/tests` and pattern
  `test_required_ci_workflow.py` also selects and passes both tests.
- `actionlint -shellcheck= .github/workflows/required-ci.yml` validates the
  reusable workflow structure and expressions.
