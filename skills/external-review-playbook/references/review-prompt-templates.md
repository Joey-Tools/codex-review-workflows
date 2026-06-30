# Review Prompt Templates

Use these templates when drafting bounded external review prompts. They are optimized for:

- explicit scope
- findings-only output
- performance and resource regression coverage without inviting style-only review
- long-context ordering that keeps workspace and diff material before the task contract

## Prompt Construction Rules

- Put concrete context and artifact paths first, then the task and output contract.
- Ask for findings only, ordered by severity, with file references.
- Use an exact `No findings.` fallback so the final result is machine-readable and easy to quote back.
- Include performance and resource risk as a first-class dimension only when the change plausibly affects hot paths, complexity, allocations, I/O, lock contention, startup latency, network fan-out, query shape, repeated work, or build graph cost.
- Tell the reviewer not to spend time on style-only nits or unrelated rewrites.
- Prefer concrete failure modes, triggering conditions, or measurable regression risks over vague quality comments.
- For readonly Codex review lanes, also tell the reviewer to prefer direct argv tool calls and avoid `bash -lc`, `zsh -lc`, here-docs, or similar shell-wrapper probes.
- Include an evidence budget for agentic reviewers: start from the supplied diff, changed-file list, `--stat` / `--numstat`, `rg -l`, `rg --count`, or exact symbol windows; first-stage summaries are budgeted too, so before printing changed-file lists, `git diff --stat` / `git diff --numstat`, helper diff-file headers, or diff-header samples such as `rg -m 80 '^diff --git ' <diff>` for a large/generated diff, run count-only probes first and cap any sample with `head -n 80`; do not assume low-context `git diff --unified=3/4/5/6` is safe across multiple docs/schema/project_journal/test files; treat line-producing `rg -n`, including `rg -n -C` context searches, as a second-stage read after `rg -l` / `rg --count`, and run it only against one exact file, one hunk, or one exact symbol window; single-file broad-pattern `rg -n` is still risky on large source, test, schema, or documentation files, so common terms such as markdown, summary, scenario, broker, error, state, or test need `rg --count` / `rg -l` first; if a printed sample is unavoidable, use `rg -n --max-count 80 --max-columns 200` against one exact file before exact symbol/window reads; do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80` / `git diff --function-context` / `git diff -W`, low-context multi-file selected diffs, whole-file `nl -ba`, path-wide / multi-file / large-alternation raw `rg -n`, bare whole-file reads such as `cat <file>` or `git show <rev>:<path>`, or full untracked inventories such as `git status --short --untracked-files=all` / `git ls-files --others`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.
- Include a pre-tool-call self-check for agentic reviewers: before every tool call, compare the command to the evidence budget and rewrite bare `nl -ba <file>`, `cat <file>`, `git show <rev>:<path>`, path-wide or multi-file `rg -n`, single-file broad-pattern `rg -n`, wide selected-file diffs, and low-context multi-file selected diffs into count probes, exact symbol lookups, single-hunk reads, or narrow `sed -n '<start>,<end>p'` windows.
- Include a validation-output budget for agentic reviewers in read-only or approval-gated lanes: do not start full tests/builds with huge visible output caps such as `max_output_tokens=60000` or `max_output_tokens=100000`; use a small syntax/targeted probe or a low visible cap first, and if sandbox tempdir, pyenv shim, or repeated `unittest` `E` output appears, summarize that failure shape before rerunning with escalation or a task-scoped log file.

## Bounded Diff Review

```text
<context>
Workspace: {workspace}
Primary diff: {diff_file}
Review scope: Review the current change only. Use the diff as the primary review surface, but you may read nearby workspace files when needed for context.
Evidence budget: Start with the supplied diff, changed-file list, `--stat` / `--numstat`, `rg -l`, `rg --count`, or exact symbol windows. First-stage summaries are budgeted too: before printing changed-file lists, `git diff --stat` / `git diff --numstat`, helper diff-file headers, or diff-header samples such as `rg -m 80 '^diff --git ' <diff>` for a large/generated diff, run count-only probes first and cap any sample with `head -n 80`. Do not assume low-context `git diff --unified=3/4/5/6` is safe across multiple docs/schema/project_journal/test files; use `--stat` / `--numstat` first, then one file or hunk. Treat line-producing `rg -n`, including `rg -n -C` context searches, as a second-stage read after `rg -l` / `rg --count`, and run it only against one exact file, one hunk, or one exact symbol window. Single-file broad-pattern `rg -n` is still risky on large source, test, schema, or documentation files; common terms such as markdown, summary, scenario, broker, error, state, or test need `rg --count` / `rg -l` first; if a printed sample is unavoidable, use `rg -n --max-count 80 --max-columns 200` against one exact file before exact symbol/window reads. Do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80` / `git diff --function-context` / `git diff -W`, low-context multi-file selected diffs, whole-file `nl -ba`, path-wide / multi-file / large-alternation raw `rg -n`, bare whole-file reads such as `cat <file>` or `git show <rev>:<path>`, or full untracked inventories such as `git status --short --untracked-files=all` / `git ls-files --others`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it. If untracked files are in scope, start with `git status --short --untracked-files=no`, then use counts or capped path samples with recursive generated/dependency excludes before inspecting selected paths.
Tool-call self-check: Before every tool call, rewrite bare `nl -ba <file>`, `cat <file>`, `git show <rev>:<path>`, path-wide or multi-file `rg -n`, single-file broad-pattern `rg -n`, wide selected-file diffs, and low-context multi-file selected diffs into count probes, exact symbol lookups, single-hunk reads, or narrow `sed -n '<start>,<end>p'` windows.
Validation-output budget: In read-only or approval-gated lanes, do not start full tests/builds with huge visible output caps such as `max_output_tokens=60000` or `max_output_tokens=100000`; use a small syntax/targeted probe or a low visible cap first. If sandbox tempdir, pyenv shim, or repeated `unittest` `E` output appears, summarize that failure shape before rerunning with escalation or a task-scoped log file.
</context>

<focus_areas>
Check for:
1. Correctness bugs and behavioral regressions.
2. Performance or resource regressions that are plausibly introduced by this change, especially in hot paths, algorithmic complexity, allocation behavior, I/O volume, lock contention, startup latency, network fan-out, query shape, and repeated work.
3. Reliability, safety, or operability regressions if the change affects failure handling, cleanup, concurrency, build graph behavior, or external interactions.
</focus_areas>

<non_goals>
Do not report style-only nits.
Do not suggest speculative micro-optimizations without concrete evidence from the diff or surrounding code.
Do not expand into unrelated rewrites.
</non_goals>

<task>
Return findings only, ordered by severity.
Prefer findings that identify a concrete failure mode, triggering condition, or measurable regression risk.
Include file references.
</task>

<output_contract>
If there are findings, output only the findings.
If there are no findings, reply exactly: No findings.
</output_contract>
```

## Bounded Diff Review Without Agentic Git

Use this variant when Cursor Agent keeps looping on rejected `git diff` / `git status` calls, or when local policy disables broad command-unblock flags such as `--force`.

```text
<context>
Workspace: {workspace}
Primary diff: {diff_file}
Review scope: Review the current change only.
The diff is already available at {diff_file}. Read that file directly instead of running git commands such as `git diff` or `git status`.
You may read nearby workspace files when needed for context, but keep the review centered on the supplied diff and touched files.
Prefer direct argv tool calls over shell wrappers; avoid `bash -lc`, `zsh -lc`, here-docs, or `python - <<'PY'` probes.
Evidence budget: Start with the supplied diff file, its headers, `rg -l`, `rg --count`, and exact symbol windows from nearby source files. First-stage summaries are budgeted too: before printing diff-file headers or diff-header samples such as `rg -m 80 '^diff --git ' <diff>` for a large/generated diff, run count-only probes first and cap any sample with `head -n 80`. Do not assume low-context `git diff --unified=3/4/5/6` is safe across multiple docs/schema/project_journal/test files; use diff-file headers/counts first, then one file or hunk. Treat line-producing `rg -n`, including `rg -n -C` context searches, as a second-stage read after `rg -l` / `rg --count`, and run it only against one exact file, one hunk, or one exact symbol window. Single-file broad-pattern `rg -n` is still risky on large source, test, schema, or documentation files; common terms such as markdown, summary, scenario, broker, error, state, or test need `rg --count` / `rg -l` first; if a printed sample is unavoidable, use `rg -n --max-count 80 --max-columns 200` against one exact file before exact symbol/window reads. Do not run `git diff --stat` / `git diff --numstat`, wide selected-file diffs such as `git diff --unified=30/40/50/60/80` / `git diff --function-context` / `git diff -W`, low-context multi-file selected diffs, whole-file `nl -ba`, bare whole-file reads such as `cat <file>` or `git show <rev>:<path>`, path-wide / multi-file / large-alternation raw `rg -n`, or full untracked inventories such as `git status --short --untracked-files=all` / `git ls-files --others`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it. If the supplied artifacts include untracked files, inspect their diff headers or capped path samples rather than recreating a full untracked inventory.
Tool-call self-check: Before every tool call, rewrite bare `nl -ba <file>`, `cat <file>`, `git show <rev>:<path>`, path-wide or multi-file `rg -n`, single-file broad-pattern `rg -n`, wide selected-file diffs, and low-context multi-file selected diffs into count probes, exact symbol lookups, single-hunk reads, or narrow `sed -n '<start>,<end>p'` windows.
Validation-output budget: In read-only or approval-gated lanes, do not start full tests/builds with huge visible output caps such as `max_output_tokens=60000` or `max_output_tokens=100000`; use a small syntax/targeted probe or a low visible cap first. If sandbox tempdir, pyenv shim, or repeated `unittest` `E` output appears, summarize that failure shape before rerunning with escalation or a task-scoped log file.
</context>

<focus_areas>
Check for:
1. Correctness bugs and behavioral regressions.
2. Performance or resource regressions that are plausibly introduced by this change, especially in hot paths, algorithmic complexity, allocation behavior, I/O volume, lock contention, startup latency, network fan-out, query shape, and repeated work.
3. Reliability, safety, or operability regressions if the change affects failure handling, cleanup, concurrency, build graph behavior, or external interactions.
</focus_areas>

<non_goals>
Do not report style-only nits.
Do not suggest speculative micro-optimizations without concrete evidence from the diff or surrounding code.
Do not expand into unrelated rewrites.
Do not spend time trying to recover git metadata that the prompt has already supplied via {diff_file}.
</non_goals>

<task>
Return findings only, ordered by severity.
Prefer findings that identify a concrete failure mode, triggering condition, or measurable regression risk.
Include file references.
</task>

<output_contract>
If there are findings, output only the findings.
If there are no findings, reply exactly: No findings.
</output_contract>
```

## Explicit File Review

```text
<context>
Workspace: {workspace}
Review scope:
- path/to/file_a
- path/to/file_b
You may read nearby workspace files when needed for context, but keep the review centered on the listed files.
Evidence budget: Start with exact symbol windows, `rg -l`, `rg --count`, and directly relevant nearby context. Treat line-producing `rg -n`, including `rg -n -C` context searches, as a second-stage read after `rg -l` / `rg --count`, and run it only against one exact file, one hunk, or one exact symbol window. Single-file broad-pattern `rg -n` is still risky on large source, test, schema, or documentation files; common terms such as markdown, summary, scenario, broker, error, state, or test need `rg --count` / `rg -l` first; if a printed sample is unavoidable, use `rg -n --max-count 80 --max-columns 200` against one exact file before exact symbol/window reads. Do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80` / `git diff --function-context` / `git diff -W`, low-context multi-file selected diffs, whole-file `nl -ba`, bare whole-file reads such as `cat <file>` or `git show <rev>:<path>`, or path-wide / multi-file / large-alternation raw `rg -n`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.
Tool-call self-check: Before every tool call, rewrite bare `nl -ba <file>`, `cat <file>`, `git show <rev>:<path>`, path-wide or multi-file `rg -n`, single-file broad-pattern `rg -n`, wide selected-file diffs, and low-context multi-file selected diffs into count probes, exact symbol lookups, single-hunk reads, or narrow `sed -n '<start>,<end>p'` windows.
Validation-output budget: In read-only or approval-gated lanes, do not start full tests/builds with huge visible output caps such as `max_output_tokens=60000` or `max_output_tokens=100000`; use a small syntax/targeted probe or a low visible cap first. If sandbox tempdir, pyenv shim, or repeated `unittest` `E` output appears, summarize that failure shape before rerunning with escalation or a task-scoped log file.
</context>

<focus_areas>
Check for:
1. Correctness bugs and behavioral regressions.
2. Performance or resource regressions that are plausibly introduced by this change, especially if the listed files participate in hot paths, expensive loops, allocations, I/O, concurrency, query execution, or repeated work.
3. Reliability, safety, or operability regressions if the change affects cleanup, retries, failure handling, state transitions, or external interactions.
</focus_areas>

<non_goals>
Do not report style-only nits.
Do not suggest speculative micro-optimizations without concrete evidence from the code under review.
Do not expand into unrelated rewrites outside the listed scope.
</non_goals>

<task>
Return findings only, ordered by severity.
Prefer findings that identify a concrete failure mode, triggering condition, or measurable regression risk.
Include file references.
</task>

<output_contract>
If there are findings, output only the findings.
If there are no findings, reply exactly: No findings.
</output_contract>
```
