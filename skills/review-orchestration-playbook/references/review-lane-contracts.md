# Review Lane Contracts

These contracts apply to the canonical single, double, and triple review shapes. They intentionally keep review evidence scoped and prevent a large prepared diff from becoming the reviewer prompt.

## Shared Frozen-Range Contract

For every local logical lane:

- Select scope in this order: an explicit frozen range; otherwise an explicitly named PR; otherwise exactly one authenticated open-PR candidate for the exact current head repository/branch. Multiple candidates are `blocked-input` (the required explicit PR/range/target selector is absent) and no lane starts. A proven zero-candidate result is the no-PR path, not a range: require an explicit committed range or an explicitly named target/base before freezing `<merge_base>..HEAD`; never guess the target/base. Keep this missing-selector state distinct from `blocked-authorization`, which applies when intended dirty/untracked state would require an unauthorized anchor mutation.
- Resolve and record full `base_sha` and `head_sha`; verify that both commits exist and that the chosen range is correct for the target branch. Never derive a formal named-lane range from a dirty working tree or untracked files. When implementation or delivery mutation is already authorized, uncommitted changes may first be captured in an intentional review-anchor commit on the review branch. A standalone report-only named review does not authorize that branch or commit: when its intended scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization` and request an existing committed range or explicit anchor authorization.
- Create a lane-unique clean Git worktree at `head_sha`. Do not reuse the implementation checkout or another reviewer's checkout.
- Before launch, require `git status --porcelain` to be empty, `HEAD` to equal `head_sha`, both frozen commits to resolve, and read-only `git diff base_sha..head_sha` queries to work.
- With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, use parent-owned read-only Git plumbing to verify local object completeness for the exact range and both endpoint trees without rendering or persisting a full diff. If any required object is missing, hydrate it deliberately before freezing or report the lane blocked. Do not launch a reviewer that could trigger a promisor-remote fetch, credential helper, or interactive authentication while inspecting the frozen scope.
- Expose the workspace and Git metadata for read-only reviewer behavior. Disable writes to files, index, refs, config, hooks, remotes, PR state, and other external systems. The publisher-verified canonical Claude process may update ordinary CLI-owned authentication and runtime state in trusted real `HOME`, including credential refresh and possible cache or tool-result artifacts. Those accepted CLI control-plane side effects are not model-authorized review actions, do not authorize model/tool writes or deliberate host mutations, and do not inherit helper credential guarantees. The policy does not enumerate or attest every CLI-owned `HOME` write. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent: the reviewer policy must forbid those actions and the parent must not authorize them. This is a write/behavior contract; it is not a claim that every runtime has an OS-level global host-read whitelist.
- Keep the model-visible workspace free of generated prompts, diff files, manifests, state directories, and helper control artifacts.
- If a security preflight needs private evidence, keep it outside the reviewer-visible workspace and never project a full diff into the prompt.
- Bind the terminal artifact to the exact workspace and range, then clean up the worktree after collection.

## Prompt Contract

The reviewer prompt contains only review-control metadata:

- the absolute clean-worktree path;
- full `base_sha`, full `head_sha`, and `base_sha..head_sha`;
- the authoritative active instruction source/version, instruction-loading order, read-only and evidence limits, requested focus and non-goals, and severity/output format;
- for both local lanes, the same discovery order: repository-wide `AGENTS.md`, changed-path metadata, applicable path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks;
- for Codex, the exact authoritative playbook path/version selected by the parent: normally the active installed copy, or the frozen repo-local copy when the repository is reviewing its own policy migration. The reviewer must load exactly that source before the shared discovery sequence, never select another installed copy independently, and report the lane blocked when the named source is missing or mismatched;
- for Claude, the complete lane contract plus an instruction to read only tracked repository/path guidance and repo-local skills from the worktree during that sequence;
- an instruction to discover evidence itself with bounded Git and source-inspection tools.
- an instruction not to run `fetch`, `pull`, or any networked Git operation; the parent has already proved the frozen scope locally complete.

The parent must not:

- compute or persist a reviewer-visible full diff;
- paste diff text, changed file contents, or another reviewer's findings into the prompt;
- pass a generated diff path, stdin payload, attachment, or control artifact as the review surface;
- summarize suspected defects in a way that biases the independent reviewer;
- resume an implementation or prior review session.

This rule applies even when a direct diff would fit in the current prompt. It avoids the hard failure mode where a large change crosses an input-size boundary before the reviewer can use its own bounded tools.

## Codex Single-Lane Contract

- Use the dedicated `reviewer` agent with `fork_turns="none"`, or the platform-equivalent zero-inherited-turn launch.
- The reviewer reads the parent-named authoritative playbook source exactly, then applicable instructions and skills from the frozen worktree.
- The reviewer has read-only Git/source tools and obtains the diff itself.
- The existing `.git`-free supplied-diff Codex helper is a different low-level mechanism and cannot satisfy this lane.
- Accept only the dedicated reviewer's terminal findings artifact for the exact range.

## Claude Code Lane Contract

- Use an actual Claude Code process in a second lane-unique clean Git worktree.
- Apply the same clear-context, instruction-loading, no-prepared-diff, bounded-tool, exact-range, and read-only requirements as the Codex lane.
- Launch `claude` directly from that worktree under [canonical-claude-lane.md](canonical-claude-lane.md). The `.git`-free `isolated_review` helper is not the launcher for this lane.
- Do not give Claude the Codex artifact, parent reasoning, or suspected findings.
- Use the detached worktree as review scope and real `HOME` as the trusted Claude CLI control plane. The model may have `Read`, `Grep`, `Glob`, and sandboxed `Bash`.
- Treat the native selected-deny sandbox accurately: launch must request global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary, but `allowRead` is not a global host-read whitelist. Sandboxed Bash can technically read another host path that is not covered by `denyRead`; the prompt/model scope must explicitly forbid every outside-workspace read.
- Treat Claude Code 2.1.212 `system/init` and capability output as evidence for only the fields it reports. It cannot attest the final merged sandbox, merged managed permission arrays, or actual path-rule evaluation; record the sandbox controls as requested configuration, not independently verified effective enforcement.
- Require exactly one leading `system/init` and one trailing terminal `result` in the canonical Claude `stream-json` output. A missing, duplicate, malformed, or misordered contract event is inconclusive; a well-formed required field that mismatches the frozen launch is a deterministic blocked configuration/policy mismatch. Neither case can count as the Claude lane. The version-specific init contract must fail closed on the exact clean-worktree cwd, `permissionMode: dontAsk`, exactly `Read`/`Grep`/`Glob`/`Bash`, empty `mcp_servers`/`slash_commands`/`skills`/`plugins`, the requested model, the publisher-verified CLI version, and the parent-selected authentication source. This verifies reported init fields only, not the merged sandbox, managed permission arrays, or path-rule evaluation.
- Capture bounded raw stdout in parent-owned state outside the model-visible worktree and pass it through [`validate_claude_stream.py`](../scripts/validate_claude_stream.py) with the exact resolved cwd, requested model, and selected authentication source. Only `classification: accepted` supplies findings; prose inspection, an ad hoc parser, partial output, or any fail-closed validator result cannot satisfy the lane. Validator acceptance does not attest the merged sandbox.
- Apply **Canonical Executable Provenance** from [canonical-claude-lane.md](canonical-claude-lane.md), including its exact Claude Code `2.1.212` gate before review input is exposed. [claude-runtime-trust.md](claude-runtime-trust.md) supplies shared signed-manifest verification primitives and failure vocabulary only; its broader helper version range, executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded-writeback, and recovery rules do not apply to this direct lane.
- A different provider cannot satisfy this lane. Model fallback within Claude Code remains one lane; provider substitution does not.

## GitHub Codex Lane Contract

- The third lane exists only on exact host `github.com`, with an operating identity outside `{hoteng, hoteng_cisco}` and an available Codex integration. Every other host, including every GitHub Enterprise host, is unsupported.
- Request it with the exact `@codex review` comment after the frozen head is current.
- The request comment is not completion. Only a trustworthy terminal result bound to the current head completes the lane.
- Record PR URL, request URL/time, current head SHA, terminal artifact URL/time, and status.
- Reject stale evidence after any push.
- Host `sqbu-github.cisco.com`, every other non-`github.com` host, and any operating identity in `{hoteng, hoteng_cisco}` are unsupported for this lane; a requested triple review uses effective double and records the reason.
- Accept provider-authored review/comment evidence only from exact REST `user.login == "chatgpt-codex-connector[bot]"` with exact `user.type == "Bot"`; accept app/check evidence only from exact `app.slug == "chatgpt-codex-connector"`. Unknown or lookalike identities make the lane inconclusive and cannot prove no-start rejection, service start, or completion.
- Missing integration, unsupported host/identity, or an unavailable GitHub Codex service produces effective double only when directly known or proved by authenticated provider evidence. Findings from a running service do not.
- An existing supported PR whose current `headRefOid` does not equal the frozen `head_sha` remains a triple candidate, not an unavailable lane. If the parent did not separately authorize publishing or changing the PR head, leave the PR unchanged and report `requested: triple`, `effective: triple-inconclusive`, with GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Missing response, timeout, generic request/HTTP failure, or guessed integration state is `effective: triple-inconclusive`, not unavailable.
- Once acknowledgement or run/review activity proves service start, malformed, stale, ambiguous, or transiently incomplete evidence is `effective: triple-inconclusive`, not effective double.

## Evidence Budget

Reviewers inspect the range incrementally:

1. Start with commit/range identity, changed-path count, `--stat`, and `--numstat`.
2. List only changed paths needed for the next decision.
3. Inspect one file, diff hunk, symbol window, call site, or test at a time.
4. Use exact-path `rg -l`, `rg --count`, or bounded `rg -n --max-count 80 --max-columns 200` queries before broader reads.
5. After any 800+ line or 10k+ token result, narrow the next read.
6. Do not begin with an unbounded `git diff`, whole-file dump, broad `rg -n`, or large untracked inventory.

The reviewer may continue bounded reads until it can support a finding or a clean result. The parent does not substitute a pre-rendered diff for this process.

## Output Contract

The reviewer returns a raw findings-only terminal output:

- exactly `No findings.` when clean; or
- actionable findings ordered by severity, each with file/line, concise title, impact, evidence, and a concrete remediation direction.

The orchestrator stores that verbatim reviewer output in a separate lane record that also reports:

- logical lane and actual runtime/provider;
- requested model/effort and effective values when observable;
- full frozen range and workspace identity;
- terminal state: `clean`, `findings`, `blocked`, or `inconclusive`.

Commands, tests, or residual risk may be added when the orchestrator can independently observe them. They are optional metadata and must not be demanded from a reviewer whose raw output contract is findings-only.

Only a complete lane record with final raw reviewer output counts. Intermediate reasoning, stdout tails, tool traces, keepalives, retry attempts, and model fallbacks do not create additional lanes.

## Failure And Rerun Contract

- `blocked`: deterministic authentication, permission, configuration, policy, unsupported runtime, or missing required provider.
- `inconclusive`: transient/capacity/timeout/network failure or no trustworthy terminal artifact.
- Actionable findings invalidate a clean claim until fixed and rereviewed.
- A changed `head_sha` invalidates every artifact tied to the old head.
- Rerun every requested local lane affected by the change; rerun the GitHub lane only when it is supported and part of the effective shape.
- GitHub Codex unavailability changes only triple to effective double. It never substitutes for a failed Codex or Claude Code local lane.

## Review-Only Child Contract

A child explicitly assigned findings-only review must inspect only its frozen range and return findings. It must not start another reviewer, edit code, wait for CI, update the PR, invoke state-changing tools, or orchestrate this workflow recursively.
