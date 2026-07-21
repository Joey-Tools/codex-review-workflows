# Review Prompt Templates

Use these templates for bounded findings-only review. Named review shapes have one fixed composition:

- Single is exactly one clear/fresh-context Codex `reviewer` agent in a separate clean, read-only Git worktree.
- Double is single plus actual Claude Code in another independent read-only workspace over the same frozen `base_sha..head_sha`.
- Triple is double plus exact `@codex review` on an exact-host `github.com` PR and a complete terminal provider-authored GitHub Codex findings payload bound to that PR's current head, whole-PR range, and isolated request.

A separately requested Copilot diagnostic never counts toward named double. The third lane supports only exact host `github.com`; every other host, including `sqbu-github.cisco.com` and every GitHub Enterprise host, is unsupported. If GitHub Codex is unavailable because there is no PR or the integration, host, or operating identity in `{hoteng, hoteng_cisco}` is unsupported, the completed shape is `effective double`. The legacy `isolated_review` Codex helper and any pre-materialized-diff review do not count toward single, double, or triple.

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
Authoritative review skill path: {review_skill_path}
Authoritative review skill version/digest: {review_skill_version_or_digest}

This is a clean, independent, read-only Git worktree. Review only the frozen range above; do not review a live working tree.
The prompt intentionally does not include a prebuilt full diff. Verify the refs and obtain range metadata, changed paths, hunks, and necessary nearby tracked context yourself with bounded Git and tool calls.

Before reviewing, verify that the exact authoritative review skill path above exists and matches the supplied version/digest. If it is missing or mismatched, report the lane blocked; never choose another installed copy. Load exactly that review skill, then repository-wide AGENTS.md. Inspect only changed-path metadata next; then load every applicable path-scoped AGENTS.md file, domain skill, and project-guidance document before inspecting hunks.

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

For this lane, inspect complete authenticated request history and the bounded audit record before posting. For one unchanged current head, allow at most one acceptable exact `@codex review` request and never post a second one; reuse the recorded request when it already exists. Multiple same-head requests, a second request that races with preflight, or evidence that cannot exclude an older request whose run/result might overlap makes the lane `triple-inconclusive`. Re-read complete authenticated request history immediately before accepting any result.

Record the accepted request comment's API ID and server `created_at`. Server timestamps prove ordering, not request/run lineage. Review/comment APIs expose no request/run identifier, so review/comment evidence is `triple-inconclusive` whenever an older request might overlap, even if its trusted server timestamp is strictly later than the current request. Completion requires an exact-bot complete terminal findings payload: fetch the review body plus every fully paginated associated inline review comment, or a terminal issue-comment body, and bind it to the same current head, whole-PR range, and isolated request. Missing or ambiguous payload, terminal nature, pagination completeness, or association is `triple-inconclusive`. An exact-App current-head check/run whose non-null `started_at` is strictly later than the request is service-start evidence only; it never completes triple or proves clean/no-findings, even when `completed` / `success`. A same-App check may be unrelated, and success may coexist with provider review findings. Same-head evidence from an earlier request is stale.

Before counting either local lane for a selected PR, independently require exact authenticated lifecycle `state == "open"`, `merged == false`, and `merged_at == null`; read `baseRefName`, `baseRefOid`, and `headRefOid`; require locally complete base/head commits with lazy fetching disabled; and require `git merge-base --all pr_base_oid pr_head_oid` to produce exactly one full `pr_merge_base`. Missing/contradictory lifecycle evidence is `pr-lifecycle-unverified`; closed-unmerged is `selected-pr-closed`, and merged is terminal `already-merged` / `selected-pr-merged`. Revalidate lifecycle before posting, before result acceptance, and before readiness/merge; an observed non-open lifecycle at any mandated snapshot after request/service start invalidates evidence and remains triple-inconclusive. These point-in-time snapshots do not prove that no intermediate close-and-reopen occurred between them. At the first selected-PR range freeze, persist immutable parent-owned `range_origin.kind`, `range_origin.base_sha`, and `range_origin.head_sha`; use only `caller-supplied` or `pr-derived`, never infer origin from a later parent-provided range, and never overwrite original caller endpoints. A selected PR's explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, and never describe its local review results as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR is unaffected.

Before applying the generic same-head/different-base `scope-mismatch` branch, if the audited request-time merge base changes after the accepted request while the head stays unchanged, invalidate the old whole-PR artifacts and apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json), but do not post a replacement same-head request. Missing origin, an inherited stale range, or a parent rewrite of caller-owned endpoints stops before local lanes. An exact current range newly supplied by the caller recovers local lanes for caller-origin state; normal exact-current rederivation recovers them for PR-derived state. Either recovery runs only the local lanes and does not unblock the GitHub lane. Report readiness `blocked-input` (`base-changed-same-head`) and `requested: triple`, `effective: triple-inconclusive`; do not create an empty or anchor commit to manufacture a new head epoch.

After both local lanes are terminal on that exact whole-PR frozen range, post the exact comment below only when complete authenticated history proves that no accepted exact request exists for the unchanged head of the exact-host `github.com` PR corresponding to `{head_sha}`. Otherwise reuse the one recorded request and do not post another:

```text
@codex review
```

Posting the comment requests the third lane but does not complete it. Record the PR URL, triggered head, and complete terminal provider-authored current-head findings payload. Accept completion evidence only from exact REST `user.login == "chatgpt-codex-connector[bot]"` with exact `user.type == "Bot"`; exact `app.slug == "chatgpt-codex-connector"` check/run evidence can prove only current-head post-request service start. Unknown or lookalike identities are `triple-inconclusive` and prove neither rejection, start, nor completion. When a still-eligible PR's current `headRefOid` does not equal the frozen `head_sha`, that mismatch is not an availability fallback. Publish/freeze the intended head and rerun affected lanes only when the parent separately authorized PR mutation; otherwise leave the PR unchanged and report `requested: triple`, `effective: triple-inconclusive`, with GitHub lane status `blocked-authorization`. For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue. If there is no existing PR or GitHub Codex is proved unsupported for the integration, host, or operating identity—including host `sqbu-github.cisco.com`, any other non-`github.com` host, and identity in `{hoteng, hoteng_cisco}`—do not create or mutate a PR to manufacture the lane. Report `requested: triple`, `effective: double` with the exact reason. An authenticated provider rejection may prove no-start unavailability; missing response or generic failure is `triple-inconclusive`.

## Low-Level Helper Results

A legacy `isolated_review` Codex helper result or any review driven by a supplied/pre-materialized diff is compatibility or diagnostic evidence only. It never satisfies or increments single, double, or triple, and PR readiness adds no retired extra Codex gates.
