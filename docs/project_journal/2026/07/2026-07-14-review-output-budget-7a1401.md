---
id: 20260714-7a1401
title: Bound Independent Codex Review Output
status: completed
created: 2026-07-14
updated: 2026-07-16
branch: codex/daily-skill-friction-20260714-codex-review-workflows-review-stdout-artifact-budget
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/43
supersedes: []
superseded_by:
---

# Bound Independent Codex Review Output

## Summary

- Independent Codex PR reviews now keep complete process output in task-scoped files and expose only bounded status probes plus a separate final-message artifact to the parent workflow.

## Current State

- The PR-readiness gate requires stdout and stderr capture instead of streaming reviewer traces into the parent transcript.
- The Codex CLI invocation writes its terminal artifact with `--output-last-message` so the final result never has to be recovered from stdout.
- A missing final-message file permits one bounded stderr tail so deterministic authentication, permission, configuration, or runtime-verification failures remain classified as blocked.
- Every attempt uses a fresh final-message path and accepts it only after a zero exit with a newly created nonempty file, preventing stale or partial clean results from crossing retries.
- The shared review-lane contract limits polling to process state, counts, or a short error tail and classifies a missing terminal artifact as inconclusive.
- Independent review attempts default to a 30-minute wall-clock deadline and 16 MiB per stdout/stderr file; hitting either limit terminates the process, rejects its final-message artifact, and retains only bounded diagnostics.
- The final-message artifact has a separate 64 KiB limit checked before reading; an oversized artifact is rejected as inconclusive and removed after recording only its byte count.
- Deadline expiry follows the same TERM/grace/KILL path as a process-log limit, and both logs are statted again after exit so a final-write race cannot bypass the caps.
- The reviewer runs in a dedicated process group with write-time log enforcement; acceptance waits for every group member and inherited sink to close, preventing descendant writers from escaping cleanup.
- Failure diagnosis reads at most the final 8 KiB of stderr by bytes, so a single long JSON or trace line cannot bypass the parent-transcript budget.
- Process cleanup requires OS containment; a fully self-contained artifact-only review may instead use a verified kernel no-child policy, while process-group or descendant polling never substitutes for containment.
- The final-message artifact is written through a bounded FIFO/pipe sink or quota-bounded target so its 64 KiB cap is enforced while the reviewer runs, not only after exit.
- FIFO mode uses two paths: a freshly created transport target and a distinct fresh ordinary artifact written by the bounded reader; only the ordinary artifact is statted and accepted.
- A parent supervisor applies reviewer byte caps to parent-owned sinks and final-message transport or artifacts. Process-wide `RLIMIT_FSIZE` is explicitly forbidden because it also limits Codex session and state files and can terminate a review with `SIGXFSZ` before any valid result exists.
- Repository contract tests pin the process-output budget and cleanup language.

## Next Steps

- None for this workstream.

## Evidence

- Daily Skill Friction session `019f20b9-b864-70b3-ae54-effa0d13ca3e` produced eight independent-review poll outputs ranging from 20,888 to 59,888 original tokens.
- Archived sessions `019f6525-c24a-7240-8255-56e67d6bf744` and `019f6542-d9f2-7e00-9fbd-bfa42770c845` independently applied `RLIMIT_FSIZE` to the reviewer process, hit `SIGXFSZ`, and succeeded only after switching to parent-supervised bounded sinks and FIFO transport.
- `uv run --isolated --with pyyaml python3 .../quick_validate.py skills/review-orchestration-playbook` passed.
- `python3 -B skills/review-orchestration-playbook/tests/test_contracts.py` passed 13 tests.
- `python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py'` passed 674 tests with 4 skips on the refreshed `d8d310d` baseline using the prepared worktree's test-fixture directories.
