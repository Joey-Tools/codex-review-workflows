# Review Prompt Templates

Use these templates for bounded findings-only review. Named review shapes have one fixed composition:

- Single is exactly one clear/fresh-context Codex `reviewer` agent in a separate clean, read-only Git workspace produced by the trusted pre-status materializer.
- Double is single plus actual Claude Code in another independent read-only workspace over the same frozen `base_sha..head_sha`.
- Triple is double plus exact `@codex review` on an exact-host `github.com` PR and a complete terminal provider-authored GitHub Codex findings payload bound to that PR's current head, whole-PR range, and isolated request.

A separately requested Copilot diagnostic never counts toward named double. The third lane supports only exact host `github.com`; every other host, including `sqbu-github.cisco.com` and every GitHub Enterprise host, is unsupported. If GitHub Codex is unavailable because there is no PR or the integration, host, or operating identity in `{hoteng, hoteng_cisco}` is unsupported, the completed shape is `effective double`. The legacy `isolated_review` Codex helper and any pre-materialized-diff review do not count toward single, double, or triple.

## Prompt Construction Rules

- Before constructing either local prompt, require parent-owned evidence that the trusted guard's `materialize-worktree` initialized a lane-private repository and imported only the bounded frozen base/head reachable-object closure under its isolated config/hooks/filter boundary, and that the immediately following `validate-worktree` performed the first status query against the same full head/path. Never use `git worktree add`, clone/fetch/upload-pack, a copied source config/hooks directory, or any pre-validator status query. If the trusted bundle lacks the materializer during its own policy migration, record the prior-policy bootstrap and do not claim the new boundary active before the merged release.
- Give a named Codex reviewer only review-control metadata: the clean worktree path, exact `base_sha`, exact `head_sha`, the materialization/validation receipt binding that path and head, the independently trusted control-plane bundle's absolute source/version/SHA-256 digest, the authoritative review skill's exact absolute path within that bundle and version/digest, the exact sanitized Git argv prefix, instruction-loading order, read-only/evidence limits, focus/non-goals, and output contract. Never prebuild, paste, attach, or otherwise inject the full diff, changed-file content, suspected finding, or another reviewer's output into its prompt.
- Supply the sanitized Git prefix as an exact token sequence beginning with `/usr/bin/env -i`, followed only by the recorded trusted `PATH`, fixed `LANG`/`LC_*`, `PAGER`, and `GIT_*` allowlist, the resolved trusted Git executable, the fixed safe `-c` flags, and `-C <absolute-clean-worktree>`. Require every Git call to copy that prefix exactly; forbid bare `git`, another executable or wrapper, a reconstructed prefix, extra environment keys, changed `-c` values, and a different worktree. Require explicit `--no-ext-diff --no-textconv` on every diff-producing command.
- The parent-supplied token sequence contains exactly the environment and safe options defined in [review-lane-contracts.md](review-lane-contracts.md), including no global/system config, no prompts/lazy fetch/replacement objects/optional locks, `GIT_CEILING_DIRECTORIES=<absolute-clean-worktree-parent>`, fixed `PAGER=cat`/`GIT_PAGER=cat` plus `--no-pager`, `core.commitGraph=false`, `core.multiPackIndex=false`, `core.fsmonitor=false`, `core.fileMode=true`, null hooks/attributes, empty `diff.external`, disabled color, and the exact `-C` worktree. Do not let the reviewer synthesize this sequence from prose.
- Launch only after the independently trusted materializer has bound the exact source repository/object store, rejected suffix discovery, fenced source/target ancestry, imported only the hard-bounded frozen reachable-object manifest into a private repository, disabled commit-graph/multi-pack-index consumption, verified exact destination inventory and frozen object validity, excluded ambient/source execution surfaces before import/checkout, and the validator has rejected repository-visible `include.path` / `includeIf.*.path`, every direct `alias.*`, executable filter/diff configuration, and any direct `core.fsmonitor` value that is not Git-false before its first status. The sanitized reviewer prefix is defense in depth; it replaces neither pre-status materialization nor the include, alias, fsmonitor, pristine-worktree, hidden-index-bit, ignored-file, symlink, or gitlink checks in [review-lane-contracts.md](review-lane-contracts.md).
- During self-policy migration, identify candidate-head Markdown as review subject and scoped guidance only. The reviewer profile, prompt contract, guard, exact-version/provenance preflight, launcher, and stream validator/schema remain parent control-plane material pinned outside the candidate range; candidate-head Python, shell, and machine schemas may not bootstrap the lane. Populate the source/version/digest fields only after the parent verifies the canonical control-file manifest defined in [review-lane-contracts.md](review-lane-contracts.md); repeat that verification before spawn and after the lane.
- Require the reviewer to load the review skill and repository-wide `AGENTS.md`, inspect changed-path metadata, then load every applicable path-scoped `AGENTS.md`, domain skill, and project-guidance file before judging hunks.
- Require the reviewer to verify the two refs, enumerate the complete changed-path set, and derive and inspect every changed hunk plus necessary nearby tracked context itself with bounded Git/tool calls. Initial counts or samples are orientation only, never evidence of complete coverage.
- State that the parent has already proved the frozen scope locally complete with lazy fetching disabled, and forbid `fetch`, `pull`, credential prompts, or any other networked Git operation.
- Keep the worktree read-only. Do not ask the reviewer to fix findings, modify files, stage changes, commit, switch branches, or perform other Git mutations.
- Ask for findings only, ordered by severity, with file references and concrete failure modes or triggering conditions.
- When there are no findings, the reviewer may first give one concise non-actionable positive/coverage summary, but the final nonempty logical line must be exactly `No findings.`. With findings, never emit that sentinel.
- Include performance and resource risk only when the change plausibly affects hot paths, complexity, allocation, I/O, contention, startup, fan-out, query shape, repeated work, or build cost.
- Tell the reviewer to avoid style-only nits, speculative micro-optimizations, and unrelated rewrites.
- Prefer direct argv tool calls. Avoid `bash -lc`, `zsh -lc`, here-docs, and similar wrapper probes unless shell syntax is essential.
- For Claude, if the CLI reports that output was persisted or spilled outside the detached worktree, never follow the reported path with `Read`, `Grep`, or `Glob`. Rerun a narrower bounded command over exact worktree paths; if an outside-workspace tool read already occurred, the lane is blocked and its findings cannot be accepted.
- For Claude structured file tools, pass an absolute worktree path in `Read.file_path` and in every present `Grep.path` or `Glob.path`. `Glob.path` may be omitted only to use the exact review cwd. Every `Glob` call must include a bounded relative `Glob.pattern`; ordinary `**`, wildcard directory components, character classes, and simple brace alternatives are allowed, including `**/*.py`, `src/**/*.{py,md}`, and `./**/*.py`. Never use an absolute pattern, home shorthand, an exact `..` path component, intermediate `.`, a backslash escape, extglob such as `@(` / `!(`, or nested/malformed/expansive braces. These prompt rules are the tool-time boundary; the later bounded directory scan cannot reconstruct every tool-time target or ABA replacement.

## Shared Evidence Budget

Apply this budget to both local named lanes:

- Start with count-only or compact range metadata, then `--stat` / `--numstat` and bounded changed-path samples for orientation. Continue through the complete changed-path set and every changed hunk in deterministic bounded chunks; do not treat the sample as review coverage.
- Treat line-producing `rg -n` as a second-stage read after `rg -l` or `rg --count`. Run it against one exact file or symbol window and cap unavoidable samples with `--max-count 80 --max-columns 200`.
- Do not default to one unbounded multi-file full-diff dump, a wide selected-file diff, `git diff -W`, whole-file `cat` / `nl -ba`, path-wide raw `rg -n`, or a full untracked inventory. Complete-diff review means covering every changed hunk through bounded per-file or per-hunk calls, not injecting or printing one prepared aggregate diff.
- Before every tool call, rewrite broad reads into counts, narrow metadata, exact symbol lookups, single-hunk reads, or narrow `sed` windows.
- After any result of 800 or more lines or roughly 10,000 original tokens, narrow the next read instead of widening it.
- In a read-only or approval-gated lane, start with a small syntax/targeted validation or a low visible-output cap. Do not launch a noisy full build/test with a huge visible-output budget.
- Never inspect untracked/private files. Nearby context must be tracked content needed to understand the frozen range.
- Never follow a persisted/spilled-output path outside the review worktree. Narrow the producer command until its bounded result can be inspected without reading a CLI control-plane artifact.

## Named Single: Fresh-Context Codex Reviewer

```text
<context>
Workspace: {clean_worktree}
Base SHA: {base_sha}
Head SHA: {head_sha}
Frozen review range: {base_sha}..{head_sha}
Trusted control-plane bundle absolute source: {trusted_bundle_absolute_path}
Trusted control-plane bundle version: {trusted_bundle_version}
Trusted control-plane bundle SHA-256: {trusted_bundle_sha256}
Sanitized Git argv prefix (exact token sequence): {sanitized_git_argv_prefix}
Authoritative review skill path: {review_skill_path}
Authoritative review skill version/digest: {review_skill_version_or_digest}

This is a clean, independent, read-only Git worktree. Review only the frozen range above; do not review a live working tree.
The prompt intentionally does not include a prebuilt full diff, attach a prepared diff, or point to one. Verify the refs and obtain range metadata, changed paths, hunks, and necessary nearby tracked context yourself with bounded Git and tool calls; then inspect every changed hunk.

Before reviewing, verify the trusted control-plane bundle's absolute source, version, SHA-256, and canonical manifest against the parent record. Then verify that the exact authoritative review skill path above exists inside that bundle and matches the supplied version/digest. If the bundle or skill is missing or mismatched, report the lane blocked; never choose another installed copy. Load exactly that review skill; that is, load the trusted review skill named above, then repository-wide AGENTS.md. Inspect only changed-path metadata next; then load every applicable path-scoped AGENTS.md file, domain skill, and project-guidance document before inspecting hunks. If this is a self-policy migration, treat candidate-head Markdown as review subject and scoped guidance; do not execute candidate-head Python or shell as review-control bootstrap.

For every Git invocation, copy the supplied sanitized Git argv prefix exactly. Do not run bare `git`, select another Git executable or wrapper, reconstruct the prefix, add environment keys, change its safe `-c` values, or target another worktree. Every diff-producing command must also include `--no-ext-diff --no-textconv`.
Use that exact prefix to enumerate the complete changed-path set and inspect every changed hunk in bounded per-file or per-hunk calls. Initial counts and samples are orientation only. Review the complete diff; do not rely on a sample and do not request or consume a prepared aggregate diff.

Evidence budget:
- Start with count-only or compact metadata, then --stat/--numstat and one file, hunk, or symbol at a time until every changed path and hunk has been inspected.
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
If there are no findings, you may first include one concise positive summary of the coverage you actually inspected. Keep it non-actionable and free of concerns, remediation, residual risk, contradictions, or uncertainty. The final nonempty logical line must be exactly: No findings.
If there is any finding, do not output `No findings.` anywhere.
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

Review exactly this frozen range from this independent read-only workspace. The parent bound this path/head through trusted `materialize-worktree` followed by `validate-worktree`, whose forced status was the first status query; do not checkout, switch, reset, repair, or rematerialize it. Explicitly read repository-wide AGENTS.md, inspect only changed-path metadata, then read applicable path-scoped AGENTS.md, repo-local domain skills, and project guidance before inspecting hunks. Obtain bounded range evidence and necessary nearby tracked context yourself; no prepared diff or other reviewer's output is supplied. The parent already proved the frozen scope locally complete with lazy fetching disabled; do not run `fetch`, `pull`, credential prompts, or another networked Git operation. Do not directly read any path outside this detached workspace, including its parent, the source checkout, other reviews, real-HOME content, installed skills, or unrelated repositories. Use an absolute worktree path for `Read.file_path` and every present `Grep.path` or `Glob.path`; an omitted `Glob.path` means this exact cwd. Supply every `Glob` call with a bounded relative pattern. Ordinary `**`, wildcard directory components, character classes, and simple brace alternatives are allowed, including `**/*.py`, `src/**/*.{py,md}`, and `./**/*.py`; never use an absolute pattern, home shorthand, an exact `..` component, intermediate `.`, a backslash escape, extglob, or nested/malformed/expansive braces. If Claude Code reports that output was persisted or spilled to any outside path, do not use Read, Grep, Glob, or Bash to inspect it; rerun a narrower bounded command over exact worktree paths. If you already directly read an outside-workspace path, stop: the lane is blocked and no findings result from this run is valid. Read-only Git may internally use only this worktree's registered Git metadata/object paths for the frozen refs. Do not inspect untracked/private files or mutate the workspace. This outside-workspace exclusion is a model/prompt scope rule supplemented by a bounded validation-time scan over observable structured tool paths; that gate assumes no concurrent workspace mutation and cannot prove the earlier tool-time target or every ABA replacement. Do not assume native-sandbox `allowRead` or that gate is a global host-read whitelist; the prompt, parent-controlled workspace, and requested native sandbox remain the execution boundary.
</context>

<task>
Review for correctness, security, behavioral regressions, missing tests, and concrete performance, reliability, or operability risks introduced by the range.
Return findings only, ordered by severity. Each finding must include a concise title, file/line reference, impact, concrete evidence and triggering condition, and a remediation direction. Do not report style-only nits or unrelated rewrites.
</task>

<output_contract>
If there are findings, output only the findings.
If there are no findings, you may first include one concise positive summary of the coverage you actually inspected. Keep it non-actionable and free of concerns, remediation, residual risk, contradictions, or uncertainty. The final nonempty logical line must be exactly: No findings.
If there is any finding, do not output `No findings.` anywhere.
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

Posting the comment requests the third lane but does not complete it. Record the PR URL, triggered head, and complete terminal provider-authored current-head findings payload. Accept completion evidence only from exact REST `user.login == "chatgpt-codex-connector[bot]"` with exact `user.type == "Bot"`; exact `app.slug == "chatgpt-codex-connector"` check/run evidence can prove only current-head post-request service start. Unknown or lookalike identities are `triple-inconclusive` and prove neither rejection, start, nor completion. When a still-eligible PR's current `headRefOid` does not equal the frozen `head_sha`, that mismatch is not an availability fallback. Publish/freeze the intended head and rerun affected lanes only when the parent separately authorized PR mutation; otherwise leave the PR unchanged and report `requested: triple`, `effective: triple-inconclusive`, with GitHub lane status `blocked-authorization`. For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue. If there is no existing PR or GitHub Codex is proved unsupported for the integration, host, or operating identity—including host `sqbu-github.cisco.com`, any other non-`github.com` host, and identity in `{hoteng, hoteng_cisco}`—do not create or mutate a PR to manufacture the lane. Report `requested: triple`, `effective: double` with the exact reason. An authenticated exact-bot provider rejection may prove no-start unavailability only when it is tied to the exact request/dispatch or satisfies the sole-unresolved/no-intervening fallback in [github-pr-probes.md](github-pr-probes.md#issue-comment-only-correlation); exact SHA alone does not bind a no-start rejection to one of multiple same-head requests. Missing response, unknown provider identity, incomplete history, or generic failure is `triple-inconclusive`.

## Low-Level Helper Results

A legacy `isolated_review` Codex helper result or any review driven by a supplied/pre-materialized diff is compatibility or diagnostic evidence only. It never satisfies or increments single, double, or triple, and PR readiness adds no retired extra Codex gates.
