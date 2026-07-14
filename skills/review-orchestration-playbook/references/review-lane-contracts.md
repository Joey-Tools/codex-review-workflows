# Review Lane Contracts

Use this contract for helper-backed review, a clean-context `reviewer` fallback, or a findings-only child.

## Scope And Evidence Budget

- Bind the review to one frozen `base_sha..head_sha` range or an explicit diff artifact.
- Use the supplied diff as the primary surface; read nearby tracked files only to validate a concrete concern.
- Count before printing changed-file lists, diff headers, `--stat` / `--numstat`, or large search results; cap first-stage samples.
- Treat line-producing `rg -n`, including `rg -n -C`, as a second-stage read against one exact file, hunk, or symbol window after `rg -l` / `rg --count`.
- Do not start with `git diff --unified=30/40/50/60/80`, `git diff --function-context`, `git diff -W`, low-context multi-file diffs, bare `cat`, whole-file `nl -ba`, bare `git show <rev>:<path>`, broad multi-file `rg -n`, or full untracked inventories.
- Before every tool call, rewrite a forbidden broad shape into a count probe, one hunk, one exact symbol, or a narrow `sed` window.
- After an 800+ line or 10k+ token result, narrow the next read.
- Do not run broad builds/tests/package-manager commands from the review lane. Use a small read-only probe only when necessary to validate a finding.

## Output

- Return findings only, ordered by severity, with file/line references when possible.
- Report correctness, security, data-loss, behavioral regression, performance/resource, reliability, and missing-test risks.
- Skip style-only, naming-only, formatting-only, and speculative comments.
- If there are no actionable findings, reply exactly `No findings.`
- Intermediate reasoning, file reads, progress, and keepalives are not final artifacts.

## Parent-Process Output Budget

- When a parent workflow launches a fresh Codex CLI review process, capture the complete stdout and stderr in task-scoped files; do not stream either process output into the parent transcript. Also pass `--output-last-message <task-scoped-file>` with a unique path that does not exist before the attempt so the terminal artifact is written separately from those process logs.
- Before launch, record a finite wall-clock deadline, a byte limit for each process log, and a byte limit for the final-message artifact. Unless a stricter repo-local contract applies, use a 30-minute deadline, 16 MiB per stdout/stderr file, and 64 KiB for the final-message file. During bounded polling, terminate the process when either process-log limit is reached; send `TERM`, allow one bounded grace interval, then use `KILL` only if it is still alive. Classify the attempt as `inconclusive` unless the bounded evidence proves a deterministic blocker. Do not accept a final-message artifact from a limit-terminated attempt.
- While the process runs, use only bounded status probes such as PID/name state, file byte or line counts, or a short error tail. Do not repeatedly relay complete logs, growing tails, internal tool traces, or keepalives.
- Accept the separate final-message file only when the attempt exits zero and creates it as a nonempty file within the recorded artifact byte limit. Check its byte count before reading it. If it exceeds the limit, do not read it, classify the attempt as `inconclusive`, record only its byte count, and remove the artifact. On a nonzero exit or a missing/empty file, reject any stale or partial result, read one bounded stderr error tail, and classify an explicit authentication, permission, configuration, or runtime-verification failure as `blocked`; otherwise report `inconclusive`. Never read the complete stderr or reconstruct a clean result from stdout. Retained stdout and stderr are recovery evidence, not review findings.
- Remove task-scoped process logs and the final-message file after recording the terminal result unless they are intentionally retained for a reported blocker or recovery handoff. When a limit fires, retain only bounded diagnostic evidence and remove the oversized log instead of handing it off intact.

## Clean-Context Codex Fallback

If the helper-backed Codex reviewer runtime is deterministically unavailable after the helper has written a matching successful `preflight.json`, `stateful final` retains the immutable frozen workspace and reports it through `fallback_workspace_retained`. Use only that retained scope with the `reviewer` agent and the complete diff/evidence and output contracts, then run `stateful cleanup --state-dir <dir>`. If the helper cannot complete that preflight, stop instead of bypassing it. The fallback's pinned configuration is `gpt-5.6-sol` with `xhigh`. Do not use an inherited-context/default coding agent. A `gpt-5.5` fallback is allowed only after explicit model entitlement/policy denial.

## PR Readiness Codex Gates

`independent-codex-pr-review` is a fresh Codex CLI review-only session, separate from the helper. Launch it only after the offline helper has retained successful preflight evidence for the same frozen range. Its prompt must identify the parent PR readiness workflow, bind the exact PR and frozen range, include every rule in **Scope And Evidence Budget** and **Parent-Process Output Budget**, disable project-instruction injection, and forbid PR actions, fixes, other reviewers, and CI waiting. Only its final `LGTM` or no-findings artifact is evidence.

`offline-frozen-diff-review` is the first stateful helper-backed pinned Codex lane over the same range. Its retained preflight evidence gates the later independent Codex session. Its terminal artifact, or the **Clean-Context Codex Fallback** artifact when only the helper-backed reviewer runtime is deterministically unavailable after preflight, is separate required evidence. GitHub Codex cannot replace either local PR-readiness gate.

These two gates apply to full PR readiness / merge-ready workflows. They do not add lanes to a standalone request whose only requested shape is double review or triple review.

## PR Thread Replies

When replying to GitHub review threads, use the actual runtime/model from the review artifact when practical:

```markdown
> [!NOTE]
> This response is purely generated by LLM: OpenAI Codex (GPT-5.6-Sol, reasoning xhigh).
```

If the exact model is unavailable, omit the model rather than guessing.
