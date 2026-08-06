---
id: 20260806-pci001
title: Reduce Private Overlay CI Cost
status: completed
created: 2026-08-06
updated: 2026-08-06
branch: wip/private-ci-faster
pr:
supersedes: []
superseded_by:
---

# Reduce Private Overlay CI Cost

## Summary

- Keep the reviewed private CI fixture pull-request-only because the target
  repository requires strict successful PR checks and squash merges preserve
  the reviewed tree at the resulting default-branch commit.
- Cancel superseded CI runs for the same pull request and use `ubuntu-slim`
  for the short Python 3.9 compatibility and aggregate-status jobs.
- Preserve every real Darwin gate while consolidating broker reproduction and
  reconciliation safety into the existing macOS independent-supervisor job.

## Current State

- The private fixture no longer repeats the complete Linux/macOS CI graph on
  `master` pushes.
- Reconciliation safety remains covered by the Linux full private test
  discovery and by the explicit budgeted Python `3.x` step in the existing
  macOS independent-supervisor job.
- The Python 3.9 `ubuntu-slim` job retains its eight compatibility selectors
  and failure-independent source-tree guard, but no longer invokes a second
  nominal `python-version: "3.x"` setup step or repeats the complete
  reconciliation-safety module. That nominal step resolved to CPython 3.9.25
  in run `31116849182`.
- The macOS consolidated gates use failure-independent continuations, so a
  supervisor failure does not suppress later reconciliation, broker, or
  source-tree diagnostics while the job still reports failure.
- A fresh-context review identified a P2 timeout-budget risk: the consolidated
  private macOS gates could consume the original 15-minute job budget before
  later `if: always()` diagnostics were scheduled.
- The private independent-supervisor job now has a 20-minute budget. Its
  deterministic suite is capped at 10 minutes, Python `3.x` setup and
  reconciliation are each capped at 2 minutes, and broker reproduction is
  capped at 2 minutes.
- The full macOS review and project-journal suites, independent supervisor,
  and read-only installed supervisor remain required because they exercise
  Darwin ACL, kqueue, Xcode, codesign, and Seatbelt behavior.
- The compatibility-status workflow uses `ubuntu-slim` for its bounded GitHub
  API-only jobs, with its reviewed fixture kept byte-identical.
- The removed Linux repetition was redundant: `platform_tests` already runs
  `python3 -m unittest discover -s tests` on Ubuntu, while the independent
  macOS job intentionally retains its two-minute reconciliation budget.

## Next Steps

- None in this repository. The private overlay sync owns publication of the
  reviewed fixture and the release-workflow optimization that consumes it.

## Evidence

- Private repository Actions runs `31074970581` and `31076151831` show the
  complete nine-job CI graph on the PR and the same-tree squash push.
- In run `31074970581`, the independent supervisor took 5m48s, broker
  reproduction took 24s, and macOS reconciliation took 45s, for about 6m57s
  combined.
- Private PR #153 run `31116849182` passed all eight Python 3.9 selectors, then
  the duplicate full reconciliation module ran 305 tests and reported 18
  failing cases (16 failures and 2 errors, with 1 skipped) because its `/tmp`
  fixtures and the workspace were on different devices. Removing that repeat
  avoids the cross-device-only failure without reducing Linux or macOS suite
  coverage.
- The independent-supervisor job in the same run failed while Actions was
  downloading an action with `Service Unavailable`, before repository steps
  ran; that is infrastructure evidence and requires no code change here.
- The 20-minute job budget leaves about 13m03s of headroom against that
  observed combined runtime. The 10/2/2/2-minute step caps bound the longest
  merged gates and retain practical margin for later failure-independent
  diagnostics; this is empirical headroom, not a formal timing guarantee.
- The most recent four same-tree squash pushes repeated about 115 raw macOS
  job-minutes and 56 raw Ubuntu job-minutes in aggregate.
- GitHub documents `ubuntu-slim` as available to private repositories, with a
  15-minute per-job limit:
  <https://docs.github.com/en/actions/reference/runners/github-hosted-runners#single-cpu-runners>.
- GitHub announced the one-vCPU Linux runner as generally available:
  <https://github.blog/changelog/2026-01-22-1-vcpu-linux-runner-now-generally-available-in-github-actions/>.
