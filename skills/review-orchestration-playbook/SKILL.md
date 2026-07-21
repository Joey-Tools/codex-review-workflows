---
name: review-orchestration-playbook
description: Orchestrate Joey's single, double, and triple code-review shapes, PR readiness, and merge-readiness. Use for fresh-context Codex review, Claude Code review, GitHub Cloud `@codex review`, helper-backed external review, PR comment or CI fix loops, and Claude Code runtime-trust changes. Single means one fresh Codex reviewer in a clean Git workspace; double adds actual Claude Code; triple adds current-head GitHub Codex when that integration is available.
---

# Review Orchestration Playbook

## Canonical Review Shapes

These are the only meanings of the named review shapes. Count completed logical reviewer lanes, never retries, model fallbacks, helper processes, or delivery gates.

| Requested shape | Required lanes |
| --- | --- |
| Single / single review / single internal review | One fresh-context Codex reviewer. |
| Double / double review / local double review | Single plus one actual Claude Code reviewer. |
| Triple / triple review | Double plus exact `@codex review` on an exact-host `github.com` PR and a trustworthy terminal GitHub Codex result bound to the current PR head. |

PR readiness means the effective review shape plus CI, unresolved-conversation, base/head, and merge-policy checks. It does not add a hidden reviewer lane.

### GitHub Codex fallback

GitHub Codex is the optional third lane, so its unavailability changes a requested triple review into an effective double review.

- Treat a missing PR, unsupported host or integration, unavailable GitHub Codex service, or unsupported operating identity as unavailable when directly known or proved by authenticated provider evidence. A missing response, timeout, generic request/HTTP failure, or guessed integration state is inconclusive rather than unavailable.
- The only supported host is exact `github.com`. Every other host is unsupported, including `sqbu-github.cisco.com` and every GitHub Enterprise host.
- PRs whose operating identity is in `{hoteng, hoteng_cisco}` are unsupported for this lane.
- Accept provider-authored review/comment evidence only from exact REST `user.login == "chatgpt-codex-connector[bot]"` with exact `user.type == "Bot"`; when app/check evidence is used, require exact `app.slug == "chatgpt-codex-connector"`. Unknown, missing, differently cased, or lookalike identities prove neither service start, terminal completion, nor authenticated no-start rejection.
- Report `requested: triple`, `effective: double`, and the concrete reason. Do not call the result a completed triple review.
- A blocked or inconclusive local lane is not a clean double merely because the GitHub lane was unavailable.

Read [pr-readiness.md](references/pr-readiness.md) for current-head evidence and the PR fix loop.

## Common Local-Lane Contract

Codex and Claude Code use the same frozen-scope and workspace scheme. Each logical lane receives its own workspace; lanes never share a checkout or reviewer context.

1. Freeze an exact `base_sha..head_sha` range. Prefer a `wip/<topic>` branch and use a merge base when the target branch moved. Never synthesize a formal named lane from an uncommitted working tree or include untracked files. If the implementation checkout is dirty and the parent request already authorizes implementation or delivery mutations, create an intentional review-anchor commit on that review branch first. For a standalone report-only named review, do not create a branch or commit. When the intended review scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization` and ask for an existing committed range or explicit authorization to create the anchor; use `blocked-input` instead for a clean checkout whose required range/PR/target selector is absent.
2. Create a separate clean Git worktree at `head_sha` for each lane. The worktree must have working Git metadata, an empty `git status --porcelain`, no task control artifacts, and access to both frozen commits. Before launch, use parent-owned read-only Git plumbing with `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0` to prove that the exact range and both endpoint trees are locally complete. Hydrate missing objects deliberately before freezing, or block the lane; never let the reviewer trigger an on-demand fetch or credential prompt.
3. Enforce read-only reviewer behavior. The reviewer may use bounded read-only Git and source-inspection tools, but must not edit files, refs, the index, configuration, the PR, or external systems. The publisher-verified canonical Claude process may update ordinary CLI-owned authentication and runtime state in trusted real `HOME`, including credential refresh and possible cache or tool-result artifacts. These accepted CLI control-plane side effects are not model-authorized review mutations and do not authorize model/tool writes or deliberate host mutations; this contract does not enumerate or attest every CLI-owned `HOME` write. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent, so the reviewer policy must forbid those actions and the parent must not authorize them. For Claude Code, native-sandbox `allowRead` is not a global host-read whitelist; the precise split between sandbox enforcement and prompt/model scope is defined below.
4. Start with no inherited conversation, parent findings, or other reviewer output. For Codex, use `fork_turns="none"`; on another platform use the equivalent zero-inherited-turn launch. Before launch, the orchestrator names the exact authoritative playbook path/version in the prompt: normally the active installed copy, or the frozen repo-local copy at the review head when a repository reviews its own policy migration. Codex must load exactly that named source before repository guidance and must never independently select another installed copy; a missing or mismatched source blocks the lane. Both local lanes follow the same discovery order: repository-wide `AGENTS.md`, changed-path metadata, applicable path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks. Claude receives the lane contract in its control prompt and reads only tracked guidance and repo-local skills from its worktree; it must not choose an installed skill outside that workspace.
5. Give the reviewer only review-control metadata: workspace path, `base_sha`, `head_sha`, exact range, authoritative instruction source/version, instruction-loading order, read-only and evidence limits, review focus and non-goals, and output contract. Do not prepare, paste, attach, or point it to a full diff, changed-file content, suspected finding, or generated diff file. This avoids front-loading a potentially million-character diff into the prompt.
6. The reviewer discovers the change itself with bounded Git/tool calls: begin with counts, `--stat`, `--numstat`, and changed paths, then inspect one file, hunk, symbol, or test at a time.
7. Keep the reviewer's raw terminal output findings-only. The orchestrator binds that verbatim output to a separate lane record containing the exact range, runtime/model, workspace identity, and terminal state. It may add commands, tests, or residual risk only when independently observable; never force that metadata into the findings-only output. Intermediate reasoning, tool traces, keepalives, and partial output are not review evidence.
8. Remove the lane worktree after the terminal artifact has been collected, unless a precise recovery reason requires temporary retention.

When repository policy requires a security scanner, or when a changed path or tracked context is known or reasonably suspected to contain a secret, credential, or unrelated private artifact, stop before provider egress and run the narrow repository-approved scan or narrow the scope. Do not turn that safeguard into a hidden universal reviewer lane, create a model-visible full-diff artifact, or inject diff content into the reviewer prompt. Credentials, untracked files, unrelated repositories, broad workspace dumps, and home-directory content remain out of scope regardless of scanner output.

Read [review-lane-contracts.md](references/review-lane-contracts.md) before launching a lane.

## Codex Lane

- Spawn the dedicated `reviewer` role with `fork_turns="none"`; do not use a default coding agent, an inherited-context child, or a parent-thread continuation.
- Give it the clean Git worktree and the common lane inputs only. The agent loads the applicable skills and project instructions itself, then uses its tools to inspect the frozen range.
- Use the configured `gpt-5.6-sol` with `xhigh` reviewer profile. If that profile is deterministically unavailable, the required Codex lane is blocked; transient failure is inconclusive. Do not silently select another profile.
- The existing frozen-diff Codex helper is not this lane and does not satisfy single review.

## Claude Code Lane

- Double and triple review require an actual Claude Code process in a second clean Git worktree under the common read-only/no-prepared-diff contract.
- The named direct lane currently requires the publisher-verified Claude Code CLI version to be exactly `2.1.212`, the only version with the reviewed init and terminal schema. Another version blocks the lane before review input is exposed.
- Before any prompt, credential, repository, range, PR, or review-workspace input reaches Claude, require [`scripts/named_claude_preflight`](scripts/named_claude_preflight) to select exact `2.1.212`. Its candidate order is an explicit absolute override (authoritative, with no fallback on error), side-by-side `$HOME/.local/share/claude/versions/2.1.212`, then the controlled active-install paths `$HOME/.local/bin/claude`, `/opt/homebrew/bin/claude`, and `/usr/local/bin/claude`; caller `PATH` is ignored. Before executing a candidate, it requires a supported native executable and exact signed-manifest size/SHA verification for `2.1.212`; only then does it probe `--version` with empty stdin in a bounded fixed credential-free environment. It emits one bounded JSON object, never downloads or installs a Claude executable, never changes an active symlink, and never executes a script/wrapper, declared wrong-version installer target, or caller-`PATH` candidate. Only `classification: accepted` supplies `<resolved-exact-claude-path>` for subsequent canonical provenance revalidation, capability verification, and direct launch. `exact-version-unavailable` and `exact-version-mismatch` are blocked. A transient native-candidate inspection failure is `candidate-inspection-inconclusive`, while publisher verification, identity, or probe uncertainty remains inconclusive; never relabel uncertainty as deterministic unavailability, and never use `2.1.216`, the helper's broader version range, another provider, or single review as a fallback.
- Acquiring a missing `2.1.212` is a separate, explicitly authorized host-mutation workflow through the official installer/version manager. A named review request alone does not authorize installation, changing the active Claude version, or repairing symlinks; until a side-by-side exact version exists and passes preflight, keep the lane blocked.
- The Claude process must start fresh and must not receive the Codex artifact or parent findings.
- In the accepted real-`HOME` native-sandbox design, the detached worktree is the review scope while real `HOME` remains the trusted CLI control plane. `Read`, `Grep`, `Glob`, and sandboxed `Bash` may be available. Launch must request global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary, while selected `allowRead` is not a global host-read whitelist. The prompt/model contract, not an OS-wide read allowlist, forbids reading outside the detached worktree.
- Claude Code 2.1.212 `system/init` and capability output cannot prove the final merged native-sandbox settings, managed permission arrays, or path-rule evaluation. Record those sandbox controls as requested configuration, never as independently verified effective enforcement.
- Accept only a strict `stream-json` envelope with exactly one leading `system/init` event as the first nonblank record and one trailing terminal `result` event as the last nonblank record. Fail closed when either event is missing, duplicated, malformed, or misordered, or when required init evidence does not match the exact clean-worktree cwd, `dontAsk`, the exact `Read`/`Grep`/`Glob`/`Bash` tool set, empty MCP/slash-command/skill/plugin surfaces, the requested model, the publisher-verified CLI version, and the parent-selected authentication source. These observable fields verify only the reported runtime surface; they do not prove the final merged sandbox, managed permission arrays, or path-rule evaluation.
- Capture bounded raw Claude stdout in parent-owned state outside the model-visible worktree and require [`scripts/validate_claude_stream.py`](scripts/validate_claude_stream.py) to return `classification: accepted` for the exact cwd, model, and authentication source before any findings count. Prose inspection, an ad hoc parser, partial output, or any validator failure cannot satisfy the lane; only accepted output contains findings, and acceptance still does not prove the merged sandbox.
- Launch `<resolved-exact-claude-path>` directly from the clean worktree with a fresh non-persistent session, inline native-sandbox settings that explicitly disable hooks and bundled skills, only `Read`/`Grep`/`Glob`/sandboxed `Bash`, no MCP/browser/edit/write/web/task tools, and the control prompt on stdin. This direct process—not `isolated_review`—is the canonical lane. Follow [canonical-claude-lane.md](references/canonical-claude-lane.md) for the executable argv, Git-metadata scope, settings, guidance loading, and structured terminal evidence.
- Use ordinary local Claude login by default with `claude-opus-4-8` and `max`; fall back to `claude-opus-4-7` with `max` only after an explicit model-entitlement or organization-policy denial.
- A Copilot, Cursor, OpenCode, or other model-family result does not satisfy the Claude Code lane. Claude Code authentication or deterministic runtime unavailability therefore leaves a requested double/triple review blocked or inconclusive; it does not silently change providers.
- Exact-version failure preserves the requested shape: double is double-but-blocked, and triple is blocked because its Claude lane is incomplete. Independently proved GitHub Codex unavailability may yield an effective double shape, but that double remains incomplete and blocked when the exact Claude lane did not complete; it never becomes single.
- Follow **Canonical Executable Provenance** and the authentication/native-sandbox contracts in [canonical-claude-lane.md](references/canonical-claude-lane.md). [claude-runtime-trust.md](references/claude-runtime-trust.md) supplies shared signed-manifest verification primitives and failure vocabulary only; its broader helper version range, executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded writeback, and recovery contracts do not apply to this direct real-`HOME` lane.

## GitHub Codex Lane

- Use only a PR on exact host `github.com` whose operating identity is not in `{hoteng, hoteng_cisco}`. Every other host, including every GitHub Enterprise host, is unsupported.
- Request the lane with the exact `@codex review` PR comment after the frozen head is current.
- Posting the request comment is not completion. An authenticated provider rejection may prove that no run started and the integration/service is unavailable. An acknowledgement, run, or review activity proves service start.
- Count provider evidence only when its exact REST bot identity or exact app slug matches the accepted identity above. Unknown or lookalike authors/apps make the lane inconclusive rather than proving rejection, start, or completion.
- Bind the accepted result to the current PR head under the request-isolation contract in [pr-readiness.md](references/pr-readiness.md): allow at most one acceptable exact request per unchanged head and never post a second one. Server timestamps prove ordering, not request/run lineage; a review/comment with no request/run identifier is triple-inconclusive whenever an older request might overlap. A qualifying check must be terminal `completed` / `success` with both non-null `started_at` and `completed_at` strictly later than the request. Any code change invalidates earlier GitHub Codex evidence and permits at most one new-head request/result.
- If the lane is unavailable, apply the explicit triple-to-double fallback above. If it ran and reported findings, the lane is available and its findings must be handled; findings are never an unavailability reason.
- If an existing supported PR's current `headRefOid` does not equal the frozen `head_sha` and the parent did not authorize publishing or changing the PR head, do not mutate the PR. Report `requested: triple`, `effective: triple-inconclusive`, and GitHub lane status `blocked-authorization`; a PR/head mismatch is not an availability fallback.
- If a supported service started but its artifact is malformed, stale, ambiguous, or transiently incomplete, report `requested: triple`, `effective: triple-inconclusive`; do not convert that uncertainty to effective double.

## Workflow

1. Classify the request.
   - A review-only child that explicitly forbids orchestration inspects its assigned range and returns findings only. It must not start other reviewers, edit code, wait for CI, or mutate the PR.
   - Resolve a standalone named review deterministically: preserve an explicit frozen range for local lanes; independently select an explicitly named PR or exactly one open PR associated with the exact current head repository/branch when PR-specific/triple work needs one. An explicit-range-only single/double is fully scoped locally and requires no PR probe. More than one required PR candidate leaves the GitHub/PR-specific lane `blocked-input` until the caller names a PR; a frozen range does not select among them, although fully scoped local lanes may run. An authenticated complete zero-candidate lookup proves the no-PR path, but does not supply a local review range: require an explicit committed range or explicitly named target/base from which to freeze `<merge_base>..HEAD`; never guess the target/base. For triple, detached HEAD or unknown head ownership without an explicit PR cannot prove no PR: run the scoped local lanes, but report the GitHub lane `blocked-input` and `effective: triple-inconclusive`, not effective double. Once a PR is selected, independently validate its current base/head metadata and unique merge base; a caller-provided range does not become whole-PR scope merely because its head matches.
   - A standalone named review request is report-only unless the user also asks to fix or deliver the change. It does not authorize branch creation, an anchor commit, push, PR creation, or PR branch/metadata changes. A clean checkout with a missing selector is `blocked-input`; reserve `blocked-authorization` for intended dirty/untracked state that would require an unauthorized anchor commit. Bare triple additionally authorizes only the scoped `@codex review` request on an already-existing supported PR. If no PR exists and an explicit committed local range is available, run the requested local lanes and reduce requested triple to effective double. If a PR exists but its host, identity, integration, or service is directly known unavailable, retain the existing-PR head-alignment preflight before running the effective double. The parent prepares the requested lanes and returns findings; it does not edit code, start delivery gates, or enter a fix loop on its own.
   - A PR/full-workflow request with no named shape defaults to single review.
2. Preserve any parent-provided frozen range before consulting PR state. Otherwise derive it only from the explicitly or uniquely selected PR's authenticated base/head metadata and unique merge base, or from an explicitly named no-PR target/base; a missing or ambiguous selector is `blocked-input`. For every selected existing PR in a PR/full-workflow request or any standalone named review request, independently read `baseRefName` as `pr_base_ref`, `baseRefOid` as `pr_base_oid`, and `headRefOid` as `pr_head_oid`; with lazy fetching disabled, require both endpoint commits locally and require `git merge-base --all pr_base_oid pr_head_oid` to return exactly one full `pr_merge_base`. Missing/ambiguous metadata, objects, or merge-base results are `blocked-input` (`scope-unverified`). A selected PR's explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, do not start or count PR-specific lanes from it, and never describe its local review results as whole-PR coverage. Then record `pr_head_oid` separately and compare it with the intended `head_sha` before creating or running any local lane or consuming PR CI/conversation/readiness state. This preflight applies to a selected PR in single, double, triple, and triple already reduced to effective double; explicit-range-only standalone single/double with no selected PR and the proven no-PR path have no PR-head comparison or selected-PR range comparison. On head mismatch, publish/freeze the intended head only when PR mutation is separately authorized; otherwise leave the PR unchanged and report readiness `blocked-authorization`. A still-eligible triple candidate also reports `effective: triple-inconclusive` with GitHub lane status `blocked-authorization`. For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
3. Freeze the exact range and create one clean worktree per requested local lane.
4. Run the fresh-context Codex lane.
5. For double or triple, run the separate Claude Code lane.
6. For triple, classify directly known no-PR/host/identity unavailability before request. On an otherwise eligible PR whose frozen range is exactly its current `pr_merge_base..pr_head_oid`, enforce one acceptable exact `@codex review` request per unchanged head: reuse the recorded request and never post a second one; overlapping or unassignable results are triple-inconclusive. Immediately before accepting a terminal result, re-read the PR base/head OIDs, recompute the unique merge base, and require that exact equality again; a changed head or merge base invalidates whole-PR lane evidence. Unknown pre-request integration/service status does not block the one request. An authenticated provider rejection may prove no-start integration/service unavailability and records effective double. Posting the request is not service start; missing response or generic failure is triple-inconclusive. Once acknowledgement or run/review activity proves start, malformed, stale, ambiguous, or incomplete evidence is triple-inconclusive, never fallback.
7. Only when the user requested fixes, delivery, or PR orchestration, apply actionable findings in the parent implementation workspace, rerun affected tests, freeze the new head, and rerun every requested lane invalidated by the fix.
8. For PR readiness, complete the remaining CI, conversation, base/head, and merge-policy checks in [pr-readiness.md](references/pr-readiness.md).
9. Report requested shape, effective shape, exact range/head, each lane/runtime/model/status, findings, fallback reason if any, and cleanup state.

## Egress Consent

Any unambiguous request classified as a named review shape authorizes scoped tracked-code review egress for exactly that shape. Examples include `single review`, `single code review`, `单重 review`, `单一 review`, `double`, `double review`, `double code review`, `双重 review`, `triple`, `triple review`, and `三重 review`:

- Single authorizes OpenAI Codex.
- Double additionally authorizes Anthropic Claude Code.
- Triple additionally authorizes, when supported, current-head GitHub Codex.
- No named shape authorizes a substitute external reviewer.

Read [egress-consent.md](references/egress-consent.md) before external egress. Approval justifications must name the exact repository, frozen range, destination, included tracked-code scope, and exclusions.

## Low-Level Helper Boundary

The `isolated_review` helper retains a frozen, `.git`-free, prepared-diff runtime for low-level compatibility and Claude runtime-security work. Its workspace and prompt contract differ from the canonical named shapes above.

- Do not use its Codex path to satisfy single review.
- Do not count a supplied-diff helper run as the Claude Code lane of a named double/triple review.
- Do not add helper preflight, fallback, or retry attempts to the review count.
- Read [helper-contract.md](references/helper-contract.md) before modifying or debugging the helper.

## Guardrails

- Do not precompute a full diff for a named local lane, even when it seems convenient or the change is small.
- Do not run formal review against a live dirty working tree. Create an explicit review anchor only when the parent request authorizes that mutation; otherwise stop as `blocked-authorization`.
- Do not claim clean review without a trustworthy terminal artifact for every required lane in the effective shape.
- Do not report a requested triple as completed triple after GitHub Codex fallback.
- Do not silently replace Claude Code with another provider.
- Do not downgrade a model for capacity, timeout, network, or other transient failure.
- Do not infer entitlement from silent model substitution.
- Do not start another reviewer from a findings-only review child.
- Do not use state-changing MCP, Plugin, Git, or GitHub actions inside a review-only lane.

## References

- [review-lane-contracts.md](references/review-lane-contracts.md): canonical workspace, prompt, bounded-read, and output contracts.
- [canonical-claude-lane.md](references/canonical-claude-lane.md): direct actual-Claude launch, native sandbox, guidance, and evidence contract.
- [claude-2.1.212-stream-schema.json](references/claude-2.1.212-stream-schema.json): machine-readable exact-model aliases and closed terminal-field allowlist for the currently reviewed Claude CLI schema.
- [validate_claude_stream.py](scripts/validate_claude_stream.py): required bounded strict raw-JSONL validator for the canonical Claude Code 2.1.212 lane.
- [named_claude_preflight](scripts/named_claude_preflight): required credential-free exact-version selector for the named Claude lane.
- [pr-readiness.md](references/pr-readiness.md): PR authorization, current-head GitHub Codex, CI/comments, fix loop, and merge-ready reporting.
- [review-prompt-templates.md](references/review-prompt-templates.md): fresh-context prompt templates.
- [github-pr-probes.md](references/github-pr-probes.md): bounded `gh` probes.
- [egress-consent.md](references/egress-consent.md): scoped review egress authorization.
- [helper-contract.md](references/helper-contract.md): low-level helper CLI, state lifecycle, and safety boundaries.
- [claude-runtime-trust.md](references/claude-runtime-trust.md): Claude Code provenance, sandbox, credential, and platform contract.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): long-running task recovery.
- [synthetic-token-fixtures.md](references/synthetic-token-fixtures.md): credential-shaped fixture policy.
