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
- Reconciliation safety remains explicit under Python `3.x` on both Linux and
  macOS without restoring a standalone macOS runner.
- Consolidated gates use failure-independent continuations, so a compatibility
  or supervisor failure does not suppress later reconciliation, broker, or
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

## Next Steps

- None in this repository. The private overlay sync owns publication of the
  reviewed fixture and the release-workflow optimization that consumes it.

## Evidence

- Private repository Actions runs `31074970581` and `31076151831` show the
  complete nine-job CI graph on the PR and the same-tree squash push.
- In run `31074970581`, the independent supervisor took 5m48s, broker
  reproduction took 24s, and macOS reconciliation took 45s, for about 6m57s
  combined.
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
