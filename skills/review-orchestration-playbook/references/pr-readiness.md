# PR Readiness

Use this reference after the local delivery gate has produced a reviewable commit and the parent request owns PR creation/update, review/CI follow-up, or merge-readiness reporting.

## Authorization

- Confirm repository owner/name, base branch, head repository/branch, draft/ready state, current head commit, dirty state, and merge model.
- Joey-owned/default-authorized repositories may be pushed and opened/updated when the parent request asks for a PR, full workflow, merge-ready, stop-before-merge, or triple review.
- For any other target, stop and request explicit confirmation listing the exact repository, base, head, and draft/ready state.
- These phrases authorize PR creation/update when the target check passes; they never authorize merge.

## Gate Sequence

1. Establish or reuse the PR and read metadata, review threads, required checks, rulesets, and branch/base state with the bounded probes in [github-pr-probes.md](github-pr-probes.md).
2. Record the current PR head and freeze the local scope as `<merge_base>..<head_sha>`.
3. Run `offline-frozen-diff-review` first through the stateful pinned Codex helper on the exact frozen range. Require its retained `preflight.json` before launching any separate Codex session; this proves the frozen workspace, diff, and prompt passed the sensitive-content and escaping-symlink checks. If the reviewer runtime becomes unavailable only after that preflight, use the helper-retained frozen workspace for the configured clean-context `reviewer` fallback with the same evidence contract, collect the artifact, then run `stateful cleanup`. If the helper cannot complete the preflight itself, stop instead of bypassing it.
4. After the helper preflight passes, run `independent-codex-pr-review` in a fresh Codex CLI review-only session. Capture its complete stdout and stderr in task-scoped files instead of streaming either process output into the parent thread, and pass `--output-last-message <task-scoped-file>` with a fresh path that did not exist before this attempt. Before launch, record a finite wall-clock deadline plus byte limits for each process log and the final-message artifact; use the default 30-minute / 16-MiB / 64-KiB limits from the shared contract unless a stricter repo-local contract applies. Enforce the process-log caps with hard file limits or bounded sinks. Use an OS-enforced job/cgroup/container whose membership survives `setsid` / `setpgid`, or continuously track every descendant by PID plus stable start identity from a dedicated process group or session; a bare PGID is insufficient. Poll only with bounded status probes and terminate the containment unit plus all tracked descendants when the deadline expires or either process-log limit is reached, repeating discovery and termination until the tree is quiescent. A limit-terminated attempt is inconclusive, cannot contribute a final-message result, and retains only bounded diagnostic evidence. Require tree quiescence and close inherited sinks within a separate 10-second deadline before you stat both process logs again; reject an attempt whose final log size reaches or exceeds its limit, even after exit zero. If quiescence or sink closure cannot be confirmed, retain bounded evidence and report `inconclusive` instead of waiting indefinitely. Only then accept the final-message file when this attempt exits zero and creates a nonempty file within its byte limit; check its byte count before reading it, and reject, classify, and remove an oversized artifact without reading it. Never reuse a stale or partial result. For a nonzero exit or a missing/empty final-message file, read at most the final 8 KiB of stderr with a byte-count-limited read that truncates before parent-transcript insertion; a line-count-only tail is not bounded. Use that evidence to distinguish a deterministic blocker from an otherwise inconclusive run, and never relay the complete process logs. Disable project-instruction injection, preserve the complete **Scope And Evidence Budget** and **Parent-Process Output Budget** contracts from [review-lane-contracts.md](review-lane-contracts.md), forbid PR orchestration/fixes/other reviewers/CI waiting, and require a terminal `LGTM` or no-findings artifact. GitHub Codex and the helper-backed frozen-diff lane cannot replace this gate.
5. Add the requested logical review shape without removing either PR-readiness Codex gate:
   - explicit double review adds the Claude-family lane;
   - explicit triple review adds the Claude-family lane and requires GitHub Codex review;
   - a request for double/triple review alone remains exactly the named two/three logical lanes; the extra independent/offline gates apply only when the parent also requests PR readiness, full workflow, or merge-ready.
6. GitHub Codex review:
   - default PR readiness treats an absent, non-required review as best-effort skipped;
   - an already-triggered or required review must finish clean on the current head;
   - explicit triple review requires current-head evidence, using repository automatic review or the exact `@codex review` trigger when needed.
7. Process actionable findings, requested changes, unresolved conversations, and required CI. Fix in the parent thread, rerun affected tests, freeze the new head, and rerun every invalidated requested or PR-readiness review lane.
8. Recheck that the PR is current with its base and that both required Codex gates, all requested logical review lanes, required checks, and required conversations are terminal and clean.

## Review Counting

- The pinned Codex helper or clean-context `reviewer` fallback is one logical Codex lane.
- Claude Code and its Copilot runtime/model fallbacks are one logical Claude-family lane.
- GitHub Codex review is the third logical lane only for triple review.
- `independent-codex-pr-review` and `offline-frozen-diff-review` are separate full-PR-readiness evidence gates. They do not redefine what a standalone double/triple-review request means.
- CI, comments, branch status, model retries, and helper fallback implementations do not increase the named review shape.

## Terminal Report

Report:

- PR URL and current head
- frozen local review range
- independent Codex PR review runtime/model/effort/status
- offline frozen-diff Codex runtime/model/effort/status
- Claude-family lane runtime/model/effort/status when requested
- GitHub Codex trigger/head/status when requested, already present, or required
- required CI and conversation-resolution status
- branch/base state
- `merge-ready`, `blocked`, or `inconclusive`

Stop before merge unless Joey explicitly asks to merge.
