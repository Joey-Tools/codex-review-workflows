---
name: review-orchestration-playbook
description: Orchestrate the user's helper-backed internal Codex review, fresh-context GPT/Codex subagent-style review requests, offline-frozen-diff-review baselines, and explicit opt-in external reviewer lanes when entrypoint choice, sandbox/runtime shape, frozen review scope, or deterministic fallback behavior is part of the problem. Do not orchestrate review-only child prompts that forbid starting reviewers; those prompts should directly inspect and output findings.
---

# Review Orchestration Playbook

## Overview

Use this skill when the hard part is not "what code changed" but "which review lane can produce a trustworthy final result in the current environment."

For PR readiness, load `$pr-readiness-review-workflow` first. That workflow owns `independent-codex-pr-review` and also checks the separate best-effort-by-default GitHub `@codex review` / `codex/review-gate` lane when it exists or is required by branch protection. This playbook provides `offline-frozen-diff-review` and explicit external-review opt-ins; it must not silently replace either PR-level lane.

## Workflow

1. Classify the review job first.
- Review-only child lane: if the prompt says `independent code reviewer`, `review-only`, `不要启动其他 reviewer`, `不要等待 CI`, or `不要执行 PR readiness orchestration`, perform direct findings-only code review. Do not call `$pr-readiness-review-workflow` and do not start another helper or external reviewer.
- Parent PR readiness `independent-codex-pr-review` orchestration: do not handle it here as a helper lane. Use `$pr-readiness-review-workflow` and start a separate Codex CLI review-only thread for the PR.
- `offline-frozen-diff-review` / internal Codex review: default to `codex-review`, fall back to `codex-readonly` for a deterministic diff-fed baseline, and use `codex-parallel` only when the caller explicitly wants dual-lane coverage and can consume an aggregate final artifact.
- Non-Codex external review: choose among `opencode`, Cursor `agent`, `copilot`, `gh copilot`, Claude, or similar only when the user explicitly asks for that lane or the active workflow explicitly marks it opt-in.
- Fresh-context GPT/Codex subagent review requests are still review-lane work. First decide whether the helper-backed `codex-review` lane satisfies the request. If the user specifically wants an in-process child agent, use the `reviewer` agent role; do not prompt a `default` coding worker as the reviewer unless the user explicitly requires an exact model that the reviewer role cannot provide, and report that as a non-standard fallback.
- When `codex-readonly` is the chosen lane, default to the helper's `stateful start|status|wait|final` lifecycle instead of a plain one-shot run.
- A helper-backed subagent/internal lane is not equivalent to `independent-codex-pr-review`, and GitHub `@codex review` / `codex/review-gate` is also a separate best-effort-by-default lane. Do not substitute any one of these for another in PR readiness gates.

2. Preflight the real runtime.
- Probe the exact local entrypoint, model id, auth state, report-sink shape, and sandbox behavior before building a large review prompt.
- Use the installed helper path when approval reuse, isolated workspaces, or frozen review ranges matter: `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review`. In public docs and prompts, prefer `$HOME` over account-specific absolute paths, and avoid repo-local `skills/...` helper invocations unless you are intentionally testing the checkout copy.
- On Linux or Ubuntu, treat `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` as a helper/runtime issue, not a prompt issue; let the helper probe and select the backend.
- Distinguish `blocked by approval/auth/sandbox` from `runtime exists but the review still fails to converge`.

3. Prefer an explicit review scope.
- For reviewable work, prefer a `wip/<topic>` branch plus frozen `base_sha..head_sha` over a live working tree.
- Use `$HOME/.codex/skills/review-orchestration-playbook/scripts/isolated_review --base-ref <base_sha> --head-ref <head_sha>` when you need the helper to snapshot the exact range.
- Move to `codex-readonly` when you need a deterministic findings-only baseline or when builtin `codex-review` cannot honor the required prompt contract.
- Once you move to `codex-readonly`, keep it on `stateful` by default so the lane has a pollable state dir and durable final artifact instead of a silent one-shot pipe.
- In a review subprocess, do not combine skill reads or setup probes with a full `git diff` in one shell invocation. First inspect a bounded changed-file list or the helper-provided diff-file headers, then read focused diff chunks or source files; avoid dumping large diffs into a single tool result.
- Avoid wide selected-file diffs as a default review tactic: do not start with `git diff --unified=30/40/50/60/80`, a whole-file `nl -ba` read, or raw path-wide / large-alternation `rg -n` when `--stat`, `--numstat`, changed-file lists, helper diff-file headers, `rg -l`, `rg --count`, or exact symbol windows would answer the question. When any selected-file diff, source read, or search returns a large result, such as 800+ lines or a tool-reported 10k+ original tokens, stop widening and re-scope with `--stat` / `--numstat`, one file or hunk at a time, or a capped file list before using line-producing `rg -n` plus `sed -n '<start>,<end>p'`. When untracked files are in review scope, do not dump full `git status --short --untracked-files=all` or `git ls-files --others` output; start with `git status --short --untracked-files=no`, then use counts or capped path samples with recursive generated/dependency excludes before inspecting selected paths. For path-limited Git diff probes, put output/control options before `--`; use `git diff --name-only -- <paths>` or `git diff --stat -- <paths>`, never `git diff -- <paths> --name-only`.
- On macOS isolated review workspaces, treat `xcrun_db` cache errors, `DARWIN_USER_TEMP_DIR` warnings, and `write_stdin failed: stdin is closed` after a non-TTY git command as command-shape friction. Switch to the helper-provided diff file or the helper-installed shimmed `git`; do not bypass the readonly shim by calling `$CODEX_REAL_GIT` or Homebrew Git directly. If the shim itself emits `python3` / `xcrun_db` noise before Git output, refresh the helper so the installed shim uses an absolute non-Apple Python shebang when Homebrew or another trusted Python is available, never `#!/usr/bin/env python3`. Use a PTY only when you intentionally need to poll a long-running child process.

4. Drive the lane to a terminal artifact.
- Use the helper's `stateful start|status|wait|final` path when the final reviewer message matters more than stream progress.
- For `stateful status`, `stateful wait`, and `stateful final`, always pass the state directory as `--state-dir <dir>`; the state dir is not a positional argument.
- For external stateful lanes such as `opencode`, `agent`, `copilot`, or `gh-copilot`, prefer a frozen range or explicit diff file. If no prompt or child args were supplied, the helper injects a conservative findings-only default prompt for that diff.
- Pass a custom prompt only when the review needs specialized scope or output. Promptless live-scope external lanes still need explicit child args before waiting.
- Treat `codex-readonly` as stateful-by-default; reserve direct one-shot readonly runs for quick smoke/debug probes where losing the final artifact would be acceptable.
- Treat intermediate reasoning, file reads, and keepalive output as non-final.
- For external lanes that write structured `stdout.log` / `stderr.log`, especially OpenCode, prefer `stateful status`, `stateful final`, and the configured report path. Do not inspect raw structured logs with `tail` or broad `rg`; if raw log inspection is unavoidable, parse only terminal records or bounded text/error snippets with explicit row and byte caps.
- Extend waits only while the lane is making substantive progress; do not loop forever on the same stalled shape.
- If you leave a stateful lane running past the main turn's wait budget, preserve and report the state dir, current status, and exact follow-up command to run `stateful status`, `stateful wait`, or `stateful final`.
- If you intentionally stop or clean a lane before it produces a final artifact, say that no background reviewer remains to poll and classify the lane as `inconclusive` or `blocked` in the same response.
- If a lane stays inconclusive, change one variable at a time: scope, prompt delivery, runtime, or entrypoint.

5. Report outcome precisely.
- Distinguish `final findings`, `LGTM/No findings`, `blocked`, `unavailable`, and `inconclusive`.
- Say which lane, runtime shape, and scope actually ran.
- When the requested lane cannot deliver a trustworthy final result, state what was still verified locally and what remains unverified.
- If the user asks you to forward review results to a specific Codex app-server thread, first verify that exact thread with read-only protocol checks such as `thread/read`, `thread/resume`, `thread/list`, and local session-index lookup. If the target thread is missing or not loadable, report the notification as blocked; do not send a connectivity probe or summary to a different loaded thread just to prove the app-server is reachable.

## Load More Only When Needed

- Load `../external-review-playbook/references/isolated-review-helper.md` for the exact helper contract, lane semantics, stateful controls, cleanup rules, and compatibility wrappers.
- Load `../external-review-playbook/references/review-prompt-templates.md` when you need bounded diff prompts or explicit-file review templates.

## Guardrails

- Do not claim a clean review unless the final reviewer artifact actually says so.
- Do not silently replace the default internal `codex-review` lane with `codex-parallel`.
- Do not treat helper-backed internal review as a replacement for `$pr-readiness-review-workflow`'s `independent-codex-pr-review`.
- Do not make OpenCode, Cursor `agent`, Copilot, Claude, or other non-Codex external reviewers required by default.
- Do not treat a cheap readiness smoke or trivial prompt as a finished review.
- Do not widen git or sandbox access just because one reviewer tried the wrong command shape.
- Do not use macOS `xcrun` / `git diff` warning noise from an oversized combined command as evidence that the repository itself is broken; reshape the review input first.
- Do not notify, probe, or steer an app-server thread other than the exact thread the user named for the review handoff.
