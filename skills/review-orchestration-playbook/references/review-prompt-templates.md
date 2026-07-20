# Review Prompt Templates

Use these templates for bounded findings-only review. Named review shapes have one fixed composition:

- Single is exactly one clear/fresh-context Codex `reviewer` agent in a separate clean, read-only Git worktree.
- Double is single plus actual Claude Code in another independent read-only workspace over the same frozen `base_sha..head_sha`.
- Triple is double plus exact `@codex review` on a supported GitHub Cloud PR and a trustworthy terminal GitHub Codex result bound to that PR's current head.

A separately requested Copilot diagnostic never counts toward named double. If GitHub Codex is unavailable because there is no PR or the integration, host, or identity is unsupported—including host `sqbu-github.cisco.com` and operating identity in `{hoteng, hoteng_cisco}`—the completed shape is `effective double`. The legacy `isolated_review` Codex helper and any pre-materialized-diff review do not count toward single, double, or triple.

## Prompt Construction Rules

- Give a named Codex reviewer only review-control metadata: the clean worktree path, exact `base_sha`, exact `head_sha`, authoritative instruction source/version, instruction-loading order, read-only/evidence limits, focus/non-goals, and output contract. Never prebuild, paste, attach, or otherwise inject the full diff, changed-file content, suspected finding, or another reviewer's output into its prompt.
- Require the reviewer to load the review skill and repository-wide `AGENTS.md`, inspect changed-path metadata, then load every applicable path-scoped `AGENTS.md`, domain skill, and project-guidance file before judging hunks.
- Require the reviewer to verify the two refs and derive the diff, changed paths, hunks, and necessary nearby tracked context itself with bounded Git/tool calls.
- State that the parent has already proved the frozen scope locally complete with lazy fetching disabled, and forbid `fetch`, `pull`, credential prompts, or any other networked Git operation.
- Keep the worktree read-only. Do not ask the reviewer to fix findings, modify files, stage changes, commit, switch branches, or perform other Git mutations.
- Ask for findings only, ordered by severity, with file references and concrete failure modes or triggering conditions.
- Use exact `No findings.` output when there are no findings.
- Include performance and resource risk only when the change plausibly affects hot paths, complexity, allocation, I/O, contention, startup, fan-out, query shape, repeated work, or build cost.
- Tell the reviewer to avoid style-only nits, speculative micro-optimizations, and unrelated rewrites.
- Prefer direct argv tool calls. Avoid `bash -lc`, `zsh -lc`, here-docs, and similar wrapper probes unless shell syntax is essential.

## Shared Evidence Budget

Apply this budget to both local named lanes:

- Start with count-only or compact range metadata, then `--stat` / `--numstat`, bounded changed-path samples, and exact file, hunk, or symbol windows.
- Treat line-producing `rg -n` as a second-stage read after `rg -l` or `rg --count`. Run it against one exact file or symbol window and cap unavoidable samples with `--max-count 80 --max-columns 200`.
- Do not default to a multi-file full diff, wide selected-file diff, `git diff -W`, whole-file `cat` / `nl -ba`, path-wide raw `rg -n`, or a full untracked inventory.
- Before every tool call, rewrite broad reads into counts, narrow metadata, exact symbol lookups, single-hunk reads, or narrow `sed` windows.
- After any result of 800 or more lines or roughly 10,000 original tokens, narrow the next read instead of widening it.
- In a read-only or approval-gated lane, start with a small syntax/targeted validation or a low visible-output cap. Do not launch a noisy full build/test with a huge visible-output budget.
- Never inspect untracked/private files. Nearby context must be tracked content needed to understand the frozen range.

## Named Single: Fresh-Context Codex Reviewer

```text
<context>
Workspace: {clean_worktree}
Base SHA: {base_sha}
Head SHA: {head_sha}
Frozen review range: {base_sha}..{head_sha}
Authoritative review instruction source/version: {review_skill_path_or_version}

This is a clean, independent, read-only Git worktree. Review only the frozen range above; do not review a live working tree.
The prompt intentionally does not include a prebuilt full diff. Verify the refs and obtain range metadata, changed paths, hunks, and necessary nearby tracked context yourself with bounded Git and tool calls.

Before reviewing, load the review skill and repository-wide AGENTS.md. Inspect only changed-path metadata next; then load every applicable path-scoped AGENTS.md file, domain skill, and project-guidance document before inspecting hunks.

Evidence budget:
- Start with count-only or compact metadata, then --stat/--numstat and one file, hunk, or symbol at a time.
- Use rg -l / rg --count before bounded line-producing searches.
- Avoid multi-file full or wide diffs, whole-file dumps, broad inventories, untracked files, and noisy validation output.
- Prefer direct argv calls and keep every operation read-only.
- Do not run fetch, pull, or any networked Git operation; the parent already proved the frozen scope locally complete with lazy fetching disabled.
</context>

<focus_areas>
Check for:
1. Correctness bugs and behavioral regressions.
2. Security, reliability, cleanup, concurrency, and operability regressions.
3. Missing or inadequate tests for changed behavior.
4. Concrete performance or resource regressions plausibly introduced by this range.
</focus_areas>

<non_goals>
Do not report style-only nits.
Do not suggest speculative micro-optimizations.
Do not expand into unrelated rewrites.
Do not edit files or run mutating Git commands.
</non_goals>

<output_contract>
Return findings only, ordered by severity. Each finding must include a concise title, file/line reference, impact, concrete evidence and triggering condition, and a remediation direction.
If there are no findings, reply exactly: No findings.
</output_contract>
```

Launch this prompt only through the configured clear/fresh-context `reviewer` agent with `fork_turns="none"`, or the platform-equivalent zero inherited turns. Do not use a default coding agent, inherited-context child, parent-thread continuation, or legacy helper as a substitute.

## Named Double: Actual Claude Code Lane

Run this after freezing the same range used by the named single lane. The Claude Code workspace must be independent from the Codex reviewer worktree and read-only.

```text
<context>
Workspace: {claude_readonly_workspace}
Base SHA: {base_sha}
Head SHA: {head_sha}
Frozen review range: {base_sha}..{head_sha}
Canonical Claude lane contract version: {review_contract_version}

Review exactly this frozen range from this independent read-only workspace. Explicitly read repository-wide AGENTS.md, inspect only changed-path metadata, then read applicable path-scoped AGENTS.md, repo-local domain skills, and project guidance before inspecting hunks. Obtain bounded range evidence and necessary nearby tracked context yourself; no prepared diff or other reviewer's output is supplied. The parent already proved the frozen scope locally complete with lazy fetching disabled; do not run `fetch`, `pull`, credential prompts, or another networked Git operation. Do not directly read any path outside this detached workspace, including its parent, the source checkout, other reviews, real-HOME content, installed skills, or unrelated repositories. Read-only Git may internally use only this worktree's registered Git metadata/object paths for the frozen refs. Do not inspect untracked/private files or mutate the workspace. This outside-workspace exclusion is a model/prompt scope rule; do not assume native-sandbox `allowRead` is a global host-read whitelist.
</context>

<task>
Review for correctness, security, behavioral regressions, missing tests, and concrete performance, reliability, or operability risks introduced by the range.
Return findings only, ordered by severity. Each finding must include a concise title, file/line reference, impact, concrete evidence and triggering condition, and a remediation direction. Do not report style-only nits or unrelated rewrites.
</task>

<output_contract>
If there are findings, output only the findings.
If there are no findings, reply exactly: No findings.
</output_contract>
```

Only a terminal result from actual Anthropic Claude Code satisfies this lane. A separately requested supplemental Copilot diagnostic can be reported on its own, but it does not complete named double.

## Named Triple: GitHub Cloud Codex Trigger

After both local lanes are terminal on the frozen range, post the exact comment below on a supported GitHub Cloud PR whose current head corresponds to `{head_sha}`:

```text
@codex review
```

Posting the comment requests the third lane but does not complete it. Record the PR URL, triggered head, and trustworthy terminal current-head result. A PR/head mismatch is not an availability fallback. Publish/freeze the intended head and rerun affected lanes only when the parent separately authorized PR mutation; otherwise report the mismatch without changing the PR. If there is no existing PR or GitHub Codex is proved unsupported for the integration, host, or operating identity—including host `sqbu-github.cisco.com` and identity in `{hoteng, hoteng_cisco}`—do not create or mutate a PR to manufacture the lane. Report `requested triple; effective double` with the exact reason. An authenticated provider rejection may prove no-start unavailability; missing response or generic failure is `triple-inconclusive`.

## Low-Level Helper Results

A legacy `isolated_review` Codex helper result or any review driven by a supplied/pre-materialized diff is compatibility or diagnostic evidence only. It never satisfies or increments single, double, or triple, and PR readiness adds no retired extra Codex gates.
