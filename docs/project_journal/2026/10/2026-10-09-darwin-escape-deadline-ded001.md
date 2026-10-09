---
id: 20261009-ded001
title: Darwin Escape Deadline Coverage
status: completed
created: 2026-10-09
updated: 2026-10-09
branch: codex/readonly-escape-deadline
pr:
supersedes: []
superseded_by:
---

# Darwin Escape Deadline Coverage

## Summary

- Verify default and explicit process-census deadlines with a controlled clock while preserving persistent escaped-process identity and fail-closed behavior.
- Give the live double-fork integration a total-call bound that includes both census stages, the child timeout, and scheduling overhead.

## Decision and Rationale

- Private overlay PR #220 failed only its live integration's elapsed-time assertion: 6.046 seconds against a six-second limit.
- The old limit counted the whole supervised call against one five-second census budget plus one second, although the call also performs an initial census and starts a real child.
- Runtime deadlines remain unchanged. The controlled-clock regression checks exact expiry and deadline propagation for both the default five-second budget and an explicit 20-millisecond budget.
- Preserve the existing test identity and 851-case digest. Refresh only the changed test file's size and SHA-256 in the trusted Mac gate source manifest.
- The real-process integration retains escape detection, exact process identity, error-cause checks, and cleanup. Its outer bound is the ten-second child budget, two five-second census budgets, and five seconds of scheduling allowance.

## Validation

- Python 3.13.0 passed four focused tests in 5.684 seconds, including the real Darwin double-fork integration, both controlled-clock deadline cases, PID-binding expiry, and terminal-child absence.
- Four trusted-source-manifest tests passed. The complete 851-case deterministic suite kept its original test-identity digest: 849 cases passed locally and two unchanged phase-helper cases returned `EPERM`, including a retry outside the outer application sandbox. Complete hosted CI remains required.
- The installed skill-authoring validator accepted the review skill.

## Evidence

- [Private overlay PR #220](https://github.com/Joey-Tools/codex-private-workflows/pull/220)
- [Failed hosted integration job](https://github.com/Joey-Tools/codex-private-workflows/actions/runs/37980174668/job/113988380941)
- `skills/review-orchestration-playbook/scripts/independent_codex_pr_review/tests/test_readonly_install_runner.py`
