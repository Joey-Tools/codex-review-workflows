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
3. Run the requested logical local review shape through `$review-orchestration-playbook`:
   - ordinary PR readiness requires the pinned Codex lane;
   - explicit double review adds the Claude-family lane;
   - explicit triple review requires both local lanes and GitHub Codex review.
4. GitHub Codex review:
   - default PR readiness treats an absent, non-required review as best-effort skipped;
   - an already-triggered or required review must finish clean on the current head;
   - explicit triple review requires current-head evidence, using repository automatic review or the exact `@codex review` trigger when needed.
5. Process actionable findings, requested changes, unresolved conversations, and required CI. Fix in the parent thread, rerun affected tests, freeze the new head, and rerun every invalidated requested review lane.
6. Recheck that the PR is current with its base and that all required checks/conversations and requested logical review lanes are terminal and clean.

## Review Counting

- The pinned Codex helper or clean-context `reviewer` fallback is one logical Codex lane.
- Claude Code and its Copilot runtime/model fallbacks are one logical Claude-family lane.
- GitHub Codex review is the third logical lane only for triple review.
- CI, comments, branch status, model retries, and helper fallback implementations do not increase the count.

## Terminal Report

Report:

- PR URL and current head
- frozen local review range
- Codex lane runtime/model/effort/status
- Claude-family lane runtime/model/effort/status when requested
- GitHub Codex trigger/head/status when requested, already present, or required
- required CI and conversation-resolution status
- branch/base state
- `merge-ready`, `blocked`, or `inconclusive`

Stop before merge unless Joey explicitly asks to merge.
