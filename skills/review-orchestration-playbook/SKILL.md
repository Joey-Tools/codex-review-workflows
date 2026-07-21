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
| Triple / triple review | Double plus exact `@codex review` on a supported GitHub Cloud PR and a trustworthy terminal GitHub Codex result bound to the current PR head. |

PR readiness means the effective review shape plus CI, unresolved-conversation, base/head, and merge-policy checks. It does not add a hidden reviewer lane.

### GitHub Codex fallback

GitHub Codex is the optional third lane, so its unavailability changes a requested triple review into an effective double review.

- Treat a missing PR, unsupported host or integration, unavailable GitHub Codex service, or unsupported enterprise identity as unavailable when directly known or proved by authenticated provider evidence. A missing response, timeout, generic request/HTTP failure, or guessed integration state is inconclusive rather than unavailable.
- `sqbu-github.cisco.com` is unsupported for this lane.
- PRs whose operating identity is in `{hoteng, hoteng_cisco}`, including their Cisco GitHub Enterprise Cloud context, are unsupported for this lane.
- Report `requested: triple`, `effective: double`, and the concrete reason. Do not call the result a completed triple review.
- A blocked or inconclusive local lane is not a clean double merely because the GitHub lane was unavailable.

Read [pr-readiness.md](references/pr-readiness.md) for current-head evidence and the PR fix loop.

## Common Local-Lane Contract

Codex and Claude Code use the same frozen-scope and workspace scheme. Each logical lane receives its own workspace; lanes never share a checkout or reviewer context.

1. Freeze an exact `base_sha..head_sha` range. Prefer a `wip/<topic>` branch and use a merge base when the target branch moved. If the implementation checkout is dirty, first create an intentional review-anchor commit on that review branch; never synthesize a formal named lane from an uncommitted working tree or include untracked files.
2. Create a separate clean Git worktree at `head_sha` for each lane. The worktree must have working Git metadata, no task control artifacts, access to both frozen commits, and an empty `git status --porcelain` after the guard's narrow absent-gitlink normalization. Before launch, use parent-owned read-only Git plumbing with `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0` to prove that the exact range and both endpoint trees are locally complete; any parent-owned diff rendering before the final guard must also use both `--no-ext-diff` and `--no-textconv`. Hydrate missing objects deliberately before freezing, or block the lane; never let the reviewer trigger an on-demand fetch or credential prompt. As the final parent-owned preflight before either Codex spawn or Claude process launch, run the shipped `scripts/named_lane_guard validate-worktree` on that exact clean worktree/head. The clean/safety-only guard forces file-mode-aware status, rejects staged or ordinary dirt, `assume-unchanged` or `skip-worktree` hidden index bits, ignored artifacts, and materialized or initialized submodules; an absent or empty uninitialized gitlink remains valid, including the exact worktree-deletion status record caused by an independently verified absent gitlink. Repository-local, per-worktree, and included submodule initialization keys are all checked even for raw gitlinks without `.gitmodules`. Before any status or reviewer Git command, effective included `core.fsmonitor` must be unset or parse as Git-false; built-in daemon (`true`), no-value, and path hook values are rejected without execution. Evaluate effective precedence only, so an earlier path value overridden by a later worktree or local `false` does not become a false finding. Effective included `filter.<driver>.clean`, `filter.<driver>.process`, `diff.external`, `diff.<driver>.command`, and `diff.<driver>.textconv` commands are also rejected before status or reviewer inspection can execute them. It allows stable in-worktree tracked source symlinks, rejects escaping or unstable/mismatched tracked symlinks, and requires every tracked `AGENTS.md` plus applicable tracked project guidance to be an ordinary in-worktree regular file. Symlink blob reads use one aggregate 30-second `git cat-file --batch` call, allow at most 4,096 tracked symlinks, cap each target at 16 KiB, and cap the batch output at 64 MiB. It compares only properties relevant to clean state and safety: it does not treat `mtime`/`ctime` churn as replacement and does not snapshot or rehash ordinary file content. Every bounded Git/preflight error from `validate-worktree` is terminal `blocked` with reason `blocked-safety`; do not launch the lane.
3. Enforce read-only reviewer behavior. The reviewer may use bounded read-only Git and source-inspection tools, but must not edit files, refs, the index, configuration, the PR, or external systems. The canonical Claude process's own ordinary credential refresh inside trusted real `HOME` is a narrow CLI control-plane exception, not a model-authorized review mutation; it does not authorize any other host write. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent, so the reviewer policy must forbid those actions and the parent must not authorize them. For Claude Code, native-sandbox `allowRead` is not a global host-read whitelist; the precise split between sandbox enforcement and prompt/model scope is defined below.
4. Start with no inherited conversation, parent findings, or other reviewer output. For Codex, use `fork_turns="none"`; on another platform use the equivalent zero-inherited-turn launch. The orchestrator identifies the authoritative active playbook version before launch. Both local lanes follow the same discovery order: repository-wide `AGENTS.md`, changed-path metadata, applicable path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks. Codex first loads the authoritative active playbook from its normal skill environment. Claude receives the lane contract in its control prompt and reads only tracked guidance and repo-local skills from its worktree; it must not choose an installed skill outside that workspace.
5. Give the reviewer only review-control metadata: workspace path, `base_sha`, `head_sha`, exact range, authoritative instruction source/version, instruction-loading order, read-only and evidence limits, review focus and non-goals, and output contract. Do not prepare, paste, attach, or point it to a full diff, changed-file content, suspected finding, or generated diff file. This avoids front-loading a potentially million-character diff into the prompt.
6. The reviewer discovers the change itself with bounded Git/tool calls: begin with counts, `--stat`, `--numstat`, and changed paths, then inspect one file, hunk, symbol, or test at a time.
7. Keep the reviewer's raw terminal output findings-only. The orchestrator binds that verbatim output to a separate lane record containing the exact range, runtime/model, workspace identity, and terminal state. It may add commands, tests, or residual risk only when independently observable; never force that metadata into the findings-only output. Intermediate reasoning, tool traces, keepalives, and partial output are not review evidence.
8. Remove the lane worktree after the terminal artifact has been collected, unless a precise recovery reason requires temporary retention.

Repository-approved preflight may validate workspace containment, frozen-scope identity, object completeness, or reviewer-sandbox safety before launch. A tracked secret delta is not a reviewer-launch gate: the trusted reviewer may inspect the original tracked diff and necessary tracked context, including repository secrets, without redaction or rewriting. Reviewer/runtime authentication credentials, untracked files, unrelated repositories, broad workspace dumps, and home-directory content remain outside the consented scope. Keep private control evidence outside the reviewer-visible workspace, and never turn a preflight into a hidden reviewer lane or inject a generated full diff into the prompt.

Read [review-lane-contracts.md](references/review-lane-contracts.md) before launching a lane.

## Codex Lane

- Run the common `validate-worktree` guard successfully on the exact frozen worktree/head immediately before spawn.
- Spawn the dedicated `reviewer` role with `fork_turns="none"`; do not use a default coding agent, an inherited-context child, or a parent-thread continuation.
- Give it the clean Git worktree and the common lane inputs only. The agent loads the applicable skills and project instructions itself, then uses its tools to inspect the frozen range.
- Use the configured `gpt-5.6-sol` with `xhigh` reviewer profile. If that profile is deterministically unavailable, the required Codex lane is blocked; transient failure is inconclusive. Do not silently select another profile.
- The existing frozen-diff Codex helper is not this lane and does not satisfy single review.

## Claude Code Lane

- Double and triple review require an actual Claude Code process in a second clean Git worktree under the common read-only/no-prepared-diff contract.
- The Claude process must start fresh and must not receive the Codex artifact or parent findings.
- In the accepted real-`HOME` native-sandbox design, the detached worktree is the review scope while real `HOME` remains the trusted CLI control plane. `Read`, `Grep`, `Glob`, and sandboxed `Bash` may be available. Launch must request global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary, while selected `allowRead` is not a global host-read whitelist. The prompt/model contract, not an OS-wide read allowlist, forbids reading outside the detached worktree.
- Claude Code 2.1.212 `system/init` and capability output cannot prove the final merged native-sandbox settings, managed permission arrays, or path-rule evaluation. Record those sandbox controls as requested configuration, never as independently verified effective enforcement.
- After successful `validate-worktree`, launch the exact revalidated actual `claude` executable through the shipped `scripts/named_lane_guard run-claude` process-only supervisor from the clean worktree. Claude must be the direct child `argv[0]`, with direct argv/no shell, a bounded control prompt whose EOF read shares the 1,800-second monotonic deadline with process supervision, and 64 MiB each for stdout and stderr (128 MiB aggregate). The CLI's test-oriented timeout, stream, and prompt overrides may equal or tighten—but never raise—the production caps of 1,800 seconds, 64 MiB per stream, and 256 KiB; the direct Python API enforces the same ceilings. For each private output path, the caller supplies a lane-unique, current-user-owned mode-`0700` canonical real parent directory outside the worktree and an absent, non-symlink leaf; the guard keeps a descriptor for that validated directory across launch and anchors publication and rollback to it. Publication and rollback remain signal-masked through an explicit commit point, and a signal observed before commit removes the complete pair before propagation. Cleanup checks the creating write's `(st_dev, st_ino)` and preserves identity drift already observed before unlink. Because POSIX/Python has no portable conditional unlink, this lightweight lane relies on cooperative same-UID exclusivity for that private directory; a non-cooperative same-UID replacement in the final check-to-unlink window is outside its guarantee. The launch environment is rebuilt from an explicit allowlist: `HOME`, `USER`, `LOGNAME`, and `SHELL` come from the current account's `pwd` record; `PATH` is trusted; only allowlisted locale/UI, proxy, and CA variables may pass through. Ambient `NODE_EXTRA_CA_CERTS` remains excluded unless the caller explicitly opts in with the value-free `--inherit-node-extra-ca-certs`; the configured value must then name an exact absolute readable non-symlink regular file that passes a stable no-follow identity check. This direct-lane path is host control-plane compatibility rather than copied or attested helper CA material. Git is forced to use no lazy fetch, prompt, replacement objects, global/system config, or optional locks. Ambient Claude/Anthropic, cloud-provider, dynamic-loader, and tool-control variables are not inherited. This remains the canonical direct actual-Claude process—not `isolated_review` or a helper reviewer. Follow [canonical-claude-lane.md](references/canonical-claude-lane.md) for the full launch, process-group cleanup, and terminal-evidence contract.
- Use ordinary local Claude login by default with `claude-opus-4-8` and `max`; fall back to `claude-opus-4-7` with `max` only after an explicit model-entitlement or organization-policy denial.
- A Copilot, Cursor, OpenCode, or other model-family result does not satisfy the Claude Code lane. Claude Code authentication or deterministic runtime unavailability therefore leaves a requested double/triple review blocked or inconclusive; it does not silently change providers.
- Follow **Canonical Executable Provenance** and the authentication/native-sandbox contracts in [canonical-claude-lane.md](references/canonical-claude-lane.md). [claude-runtime-trust.md](references/claude-runtime-trust.md) supplies shared signed-manifest verification primitives, version bounds, and failure vocabulary only; its executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded writeback, and recovery contracts do not apply to this direct real-`HOME` lane.
- Only complete structured terminal output collected after successful TERM/KILL/drain/reap cleanup of the initial supervisor process group and inherited streams may count. Every `run-claude` supervision failure, including timeout, either-stream overflow, drain/reap failure, residual members of that group, inherited-stream leaks, and malformed/partial terminal output, is `inconclusive`; never accept a partial tail or fall back to another provider/model. This process-only supervisor is not a process-tree sandbox: a descendant that deliberately uses `setsid()` or `setpgid()` and closes inherited streams is outside its cleanup guarantee, so do not claim whole-process-tree quiescence.

The shipped guard supplies only the clean/safety worktree preflight and direct-Claude process supervision. It does not prepare a diff, perform review logic, establish executable provenance, configure or attest the sandbox, authenticate Claude, scan general content/secrets, snapshot ordinary contents or timestamps, or confer any `isolated_review` helper guarantee.

## GitHub Codex Lane

- Use only a supported GitHub Cloud PR.
- Request the lane with the exact `@codex review` PR comment after the frozen head is current.
- Posting the request comment is not completion. An authenticated provider rejection may prove that no run started and the integration/service is unavailable only when it is tied to the exact request/dispatch or satisfies the sole-unresolved fallback; a full SHA alone does not bind a same-head no-start response to one request. An acknowledgement, run, or review activity proves service start.
- Bind the accepted result to the current PR head. Any code change invalidates earlier GitHub Codex evidence and requires a new request/result.
- If the lane is unavailable, apply the explicit triple-to-double fallback above. If it ran and reported findings, the lane is available and its findings must be handled; findings are never an unavailability reason.
- If a supported service started but its artifact is malformed, stale, ambiguous, or transiently incomplete, report `requested: triple`, `effective: triple-inconclusive`; do not convert that uncertainty to effective double.

## Workflow

1. Classify the request.
   - A review-only child that explicitly forbids orchestration inspects its assigned range and returns findings only. It must not start other reviewers, edit code, wait for CI, or mutate the PR.
   - A standalone named review request is report-only unless the user also asks to fix or deliver the change. It does not authorize branch creation, push, PR creation, or PR branch/metadata changes. Bare triple authorizes only the scoped `@codex review` request on an already-existing supported PR; without one, run the two local lanes and report effective double. The parent prepares the requested lanes and returns findings; it does not edit code, start delivery gates, or enter a fix loop on its own.
   - A PR/full-workflow request with no named shape defaults to single review.
2. Freeze the exact range and create one clean worktree per requested local lane.
3. Run the fresh-context Codex lane.
4. For double or triple, run the separate Claude Code lane.
5. For triple, classify directly known no-PR/host/identity unavailability before request. On an otherwise eligible PR, post exact `@codex review` after the frozen head is current. An authenticated provider rejection may prove no-start integration/service unavailability and records effective double. Posting the request is not service start; missing response or generic failure is triple-inconclusive. Once acknowledgement or run/review activity proves start, malformed, stale, ambiguous, or incomplete evidence is triple-inconclusive, never fallback.
6. Only when the user requested fixes, delivery, or PR orchestration, apply actionable findings in the parent implementation workspace, rerun affected tests, freeze the new head, and rerun every requested lane invalidated by the fix.
7. For PR readiness, complete the remaining CI, conversation, base/head, and merge-policy checks in [pr-readiness.md](references/pr-readiness.md).
8. Report requested shape, effective shape, exact range/head, each lane/runtime/model/status, findings, fallback reason if any, and cleanup state.

## Egress Consent

Any unambiguous request classified as a named review shape authorizes scoped tracked-code review egress for exactly that shape. Examples include `single review`, `single code review`, `单重 review`, `单一 review`, `double`, `double review`, `double code review`, `双重 review`, `triple`, `triple review`, and `三重 review`:

- Single authorizes OpenAI Codex.
- Double additionally authorizes Anthropic Claude Code.
- Triple additionally authorizes, when supported, current-head GitHub Codex.
- No named shape authorizes a substitute external reviewer.

The selected reviewer is a trusted processor. Consent includes the named repository's original tracked diff and necessary tracked context, including tracked repository secrets; do not redact, rewrite, or suppress reviewer-visible tracked content because a secret audit is blocked, inconclusive, or violating. It excludes automatic discovery of reviewer/runtime authentication credentials, untracked files, unrelated repositories, broad workspace dumps, and home-directory content.

Read [egress-consent.md](references/egress-consent.md) before external egress. Approval justifications must name the exact repository, frozen range, destination, included tracked-code scope, tracked-secret handling, and exclusions.

## PR/Master Secret Admission

Secret admission is independent of every named reviewer lane and never delays or blocks reviewer launch.

- For each countable candidate, use its exact raw byte value as the key and count it globally over the complete base and head tracked trees: raw Git path bytes, regular-file blob bytes, and symlink-target bytes. Gitlink entry paths count; gitlink object IDs and submodule content do not.
- Permit `head_count <= base_count`. Equality, deletion, and movement across paths, blob/symlink surfaces, modes, or byte offsets pass. Only a first appearance or global count growth blocks admission.
- Do not derive Base64, hex, URL-encoded, escaped, hashed, or other transformed variants. This is a deliberate detection limitation; a transformed byte string matters only when it independently becomes an exact scanner candidate.
- A non-exact dynamic expression does not enter the counter. Incomplete tree enumeration, unreadable bounded objects, or lost count integrity makes admission `inconclusive`.
- Report only head-side added locations for positive-delta candidates; omit unchanged occurrences. Use one-based lines for complete text evidence, `line: null` for new-path or binary fallback, and line `1` for symlink targets. Mark incomplete mapping as `location_status=inconclusive`; when endpoint trees cannot distinguish a moved occurrence from an identical new copy, omit the ambiguous locations instead of relying on heuristic rename attribution.

When the low-level helper supplies PR/master evidence, run `stateful final --state-dir <state_dir>` for its reviewer artifact and then `stateful admission --state-dir <state_dir>` on that same current-head state. These checks are independent: reviewer final may succeed while admission is violating or inconclusive. Admission exit `0` is `clean`, `1` is violations, `3` is pending, and `75` is inconclusive. A head change invalidates both.

## Low-Level Helper Boundary

The `isolated_review` helper retains a frozen, `.git`-free, prepared-diff runtime for low-level compatibility and Claude runtime-security work. Its workspace and prompt contract differ from the canonical named shapes above.

- Do not use its Codex path to satisfy single review.
- Do not count a supplied-diff helper run as the Claude Code lane of a named double/triple review.
- Do not add helper preflight, fallback, or retry attempts to the review count.
- For helper-only Claude diagnostics, use `explicit-claude-review`; use `explicit-claude-with-copilot-fallback` only after separate user consent explicitly authorizes both destinations. Named `double`/`triple` phrases and legacy `double-review`/`triple-review` values are not low-level helper consent markers.
- Read [helper-contract.md](references/helper-contract.md) before modifying or debugging the helper.

## Guardrails

- Do not precompute a full diff for a named local lane, even when it seems convenient or the change is small.
- Do not run formal review against a live dirty working tree; create an explicit review anchor first.
- Do not claim clean review without a trustworthy terminal artifact for every required lane in the effective shape.
- Do not report a requested triple as completed triple after GitHub Codex fallback.
- Do not silently replace Claude Code with another provider.
- Do not downgrade a model for capacity, timeout, network, or other transient failure.
- Do not infer entitlement from silent model substitution.
- Do not start another reviewer from a findings-only review child.
- Do not use state-changing MCP, Plugin, Git, or GitHub actions inside a review-only lane.
- Do not block trusted reviewer launch on a tracked secret delta or redact tracked reviewer input based on admission status.
- Do not count encoded variants for admission; enforce only the complete-tree global exact-raw-value non-growth rule.
- Do not treat `stateful final` as secret-admission evidence or merge the two terminal decisions.

## References

- [review-lane-contracts.md](references/review-lane-contracts.md): canonical workspace, prompt, bounded-read, and output contracts.
- [canonical-claude-lane.md](references/canonical-claude-lane.md): direct actual-Claude launch, native sandbox, guidance, and evidence contract.
- [pr-readiness.md](references/pr-readiness.md): PR authorization, current-head GitHub Codex, CI/comments, fix loop, and merge-ready reporting.
- [review-prompt-templates.md](references/review-prompt-templates.md): fresh-context prompt templates.
- [github-pr-probes.md](references/github-pr-probes.md): bounded `gh` probes.
- [egress-consent.md](references/egress-consent.md): scoped review egress authorization.
- [helper-contract.md](references/helper-contract.md): low-level helper CLI, state lifecycle, and safety boundaries.
- [claude-runtime-trust.md](references/claude-runtime-trust.md): Claude Code provenance, sandbox, credential, and platform contract.
- [cbth-agent-delivery.md](references/cbth-agent-delivery.md): long-running task recovery.
- [synthetic-token-fixtures.md](references/synthetic-token-fixtures.md): credential-shaped fixture policy.
