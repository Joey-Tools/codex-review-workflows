---
id: 20261015-crc001
title: Manual CI Diagnostic Rerun Contract
status: completed
created: 2026-10-15
updated: 2026-10-17
branch: wip/ci-rerun-contract
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/139
supersedes: []
superseded_by:
---

# Manual CI Diagnostic Rerun Contract

## Outcome

The repository declares reentrant, manually authorized diagnostic execution for
one exact CI workflow and only the existing-run failed-jobs operation. The
declaration binds reviewed workflow bytes, a maximum run attempt of two, finite
job budgets, and an independently trusted operator preflight/receipt procedure.
The consistency checker is read-only and explicitly grants neither mutation
permission nor automatic provider-recovery authority.

CI pins checkout/setup-python Action commits, disables credential persistence,
binds checkout to the event SHA, and logs minimal execution identity before
checkout in each test-producing leaf job. The platform budget is 60 minutes:
historical run 38552908494's successful macOS leg took 35m34s. Existing test,
isolation, cleanup, source-only, and aggregate-pass gates are retained. The
canonical CI fixture is synchronized; private workflow fixtures and review-gate
workflows are unchanged.

This does not retroactively authorize old PR #119 run 38552908494, diagnose its
signal/cleanup failure, rerun any CI, or override execution approval. Automatic
GitHub Codex recovery retains its separate stronger contract. The declaration
must be independently reviewed and merged before it is a trusted policy source.

## Validation

Python 3.10.19: nine new declaration tests, 52 repository contract tests
(two expected private-layout skips), and 23 recovery contract tests. The
checker, Ruff, workflow syntax, whitespace, and skill metadata validation were
also exercised. Final repository contract rerun passed. Bash syntax and
ShellCheck passed for the newly added run snippets. Full Actionlint integration
with ShellCheck did not complete: the bounded supervisor hit process-group
cleanup EPERM both inside and outside the sandbox. Actionlint without ShellCheck
passed on the final workflow. Project-journal validation passed. Full-suite and
remote CI results are not asserted here.

The 2026-10-17 base refresh incorporates master
`7c11e820e2db55ed23488258032a724d927ec572` without conflicts and preserves
the independently merged semantic review-evidence policy. Python 3.10.19
passed 129 focused tests (two expected private-layout skips): nine declaration,
52 repository-contract, 23 recovery, and 45 terminal-carrier tests. The CI
workflow digest is unchanged; checker smoke, Ruff, Actionlint syntax-only,
and whitespace checks passed. Current-head remote review/CI remain separate
PR evidence rather than a claim from this local validation.
