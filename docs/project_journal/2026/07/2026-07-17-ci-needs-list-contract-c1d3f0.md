---
id: 20260717-c1d3f0
title: Pin Reviewed CI Workflow Snapshots
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/ci-direct-dependency-contract
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/56
supersedes: []
superseded_by:
---

# Pin Reviewed CI Workflow Snapshots

## Summary

Replace the open-ended handwritten GitHub Actions parser with a closed-world
contract: each supported repository profile must match a reviewed CI workflow
snapshot byte for byte.

## Current State

- The canonical skill carries both reviewed fixtures under
  `tests/fixtures/ci/`: `canonical.yml` for `codex-review-workflows` and
  `private.yml` for the synchronized private overlay.
- The contract selects its profile only from the skill's exact path relative to
  the repository root: `skills/review-orchestration-playbook` or
  `personal_codex/skills/review-orchestration-playbook`. Repository directory
  names do not participate in profile selection, and unknown layouts fail.
- The selected repository's `.github/workflows/ci.yml` must equal the selected
  fixture as bytes. Any YAML spelling, job, step, default, shell, environment,
  dependency, or success-guard change therefore requires an intentional
  reviewed fixture update.
- Small human-readable assertions retain the intended aggregate-status blocks:
  canonical CI directly gates on `platform_tests`; private CI gates on
  `platform_tests`, `python-39-compatibility`, and `platform-safety`, and checks
  every corresponding result for `success`.
- The contract does not claim to parse or validate arbitrary YAML. The former
  `_workflow_*` parser helpers and adversarial parser fixtures were removed.

## Validation Evidence

- Both focused contract files passed (`16` tests each) after the snapshot
  redesign.
- The complete canonical review suite passed (`707` tests; `9` skipped), and
  the synchronized private review suite passed (`707` tests; `10` skipped).
- The canonical and private fixtures were created from and byte-compared with
  their respective live CI workflows.
- Ruff, Python compilation, Actionlint 1.7.12 for both live workflows, private
  source-sync tests (`133` tests), project-journal validation, normalized test
  comparison, fixture comparisons, and diff checks passed.

## Next Steps

- Merge the canonical snapshot contract before publishing the synchronized
  private overlay update.
