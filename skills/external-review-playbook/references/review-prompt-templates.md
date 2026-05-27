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
- Include an evidence budget for agentic reviewers: start from the supplied diff, changed-file list, `--stat` / `--numstat`, `rg -l`, `rg --count`, or exact symbol windows; do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80`, whole-file `nl -ba`, or path-wide / large-alternation raw `rg -n`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.

## Bounded Diff Review

```text
<context>
Workspace: {workspace}
Primary diff: {diff_file}
Review scope: Review the current change only. Use the diff as the primary review surface, but you may read nearby workspace files when needed for context.
Evidence budget: Start with the supplied diff, changed-file list, `--stat` / `--numstat`, `rg -l`, `rg --count`, or exact symbol windows. Do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80`, whole-file `nl -ba`, or path-wide / large-alternation raw `rg -n`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.
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
Evidence budget: Start with the supplied diff file, its headers, `rg -l`, `rg --count`, and exact symbol windows from nearby source files. Do not run `git diff --stat` / `git diff --numstat`, wide selected-file diffs such as `git diff --unified=30/40/50/60/80`, whole-file `nl -ba`, or path-wide / large-alternation raw `rg -n`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.
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
Evidence budget: Start with exact symbol windows, `rg -l`, `rg --count`, and directly relevant nearby context. Do not default to wide selected-file diffs such as `git diff --unified=30/40/50/60/80`, whole-file `nl -ba`, or path-wide / large-alternation raw `rg -n`; after any 800+ line or 10k+ original-token result, narrow the next read instead of widening it.
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
