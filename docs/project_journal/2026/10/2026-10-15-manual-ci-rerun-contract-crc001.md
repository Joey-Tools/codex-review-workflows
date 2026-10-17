---
id: 20261015-crc001
title: Risk-Based CI Diagnostic Reruns
status: completed
created: 2026-10-15
updated: 2026-10-17
branch: wip/ci-rerun-contract
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/139
supersedes: []
superseded_by:
---

# Risk-Based CI Diagnostic Reruns

Ordinary authorized CI diagnostics now use side-effect, scope and cost checks,
including experiments that may pick up an upstream dependency fix. They do not
require a predeclared workflow digest, custom receipt ledger or attempt-2 cap.
GitHub run/attempt history and logs remain the primary execution record.

The earlier PR-specific manifest, checker, tests and CI instrumentation were
removed. CI workflow bytes and the canonical fixture match the target branch.
The playbook routes diagnostics separately from its unchanged machine producer
and authoritative automatic-recovery requirements. Review, execution approval
and merge protections remain intact; the PR holds validation and review status.
