# Review Lane Contracts

These contracts apply to the canonical single, double, and triple review shapes. They intentionally keep review evidence scoped and prevent a large prepared diff from becoming the reviewer prompt.

## Shared Frozen-Range Contract

For every local logical lane:

- Resolve and record full `base_sha` and `head_sha`; verify that both commits exist and that the chosen range is correct for the target branch. If implementation changes are uncommitted, create an intentional review-anchor commit on the review branch first. Never derive a formal named-lane range from a dirty working tree or untracked files.
- Create a lane-unique clean Git worktree at `head_sha`. Do not reuse the implementation checkout or another reviewer's checkout.
- Before launch, require `git status --porcelain` to be empty, `HEAD` to equal `head_sha`, both frozen commits to resolve, and read-only `git diff base_sha..head_sha` queries to work.
- With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, use parent-owned read-only Git plumbing to verify local object completeness for the exact range and both endpoint trees without rendering or persisting a full diff. If any required object is missing, hydrate it deliberately before freezing or report the lane blocked. Do not launch a reviewer that could trigger a promisor-remote fetch, credential helper, or interactive authentication while inspecting the frozen scope.
- Expose the workspace and Git metadata for read-only reviewer behavior. Disable writes to files, index, refs, config, hooks, remotes, PR state, and other external systems. The canonical Claude CLI's own ordinary credential refresh in trusted real `HOME` is the only planned host-write exception and is not a model-authorized review action; helper credential guarantees do not apply to it. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent: the reviewer policy must forbid those actions and the parent must not authorize them. This is a write/behavior contract; it is not a claim that every runtime has an OS-level global host-read whitelist.
- Keep the model-visible workspace free of generated prompts, diff files, manifests, state directories, and helper control artifacts.
- If a security preflight needs private evidence, keep it outside the reviewer-visible workspace and never project a full diff into the prompt.
- Do not use a tracked secret delta as a reviewer-launch gate. The trusted reviewer may inspect the original tracked diff and necessary tracked context, including repository secrets, without redaction or rewriting. Reviewer/runtime authentication credentials, untracked files, unrelated repositories, broad workspace dumps, and home-directory content remain out of scope.
- Bind the terminal artifact to the exact workspace and range, then clean up the worktree after collection.

## Separate PR/Master Secret Admission

Secret admission is not a named reviewer lane and does not affect whether a lane may start or whether its terminal findings artifact is valid.

- Count each exact raw secret byte value globally over the complete base and head tracked trees, including raw Git path bytes, regular-file blob bytes, and symlink-target bytes. Count gitlink entry paths, but never gitlink object IDs or submodule content.
- Require only `head_count <= base_count`. Unchanged values, deletions, and moves across paths, surfaces, modes, or offsets pass; first appearance or global count growth violates admission.
- Do not derive Base64, hex, URL-encoded, escaped, hashed, or other transformed variants. This deliberate limitation means a transformed form is related only if it independently becomes an exact scanner candidate.
- A genuinely incomplete scan or lost count integrity is `inconclusive`. Report only head-side added locations for positive-delta candidates and omit unchanged occurrences.

When low-level `isolated_review` state is used as PR/master evidence, run `stateful final --state-dir <state_dir>` for the reviewer artifact and then `stateful admission --state-dir <state_dir>` for the independent admission result on that same current-head state. Admission exit `0` is `clean`, `1` violations, `3` pending, and `75` inconclusive. A changed head invalidates both; a successful final never substitutes for admission.

## Prompt Contract

The reviewer prompt contains only review-control metadata:

- the absolute clean-worktree path;
- full `base_sha`, full `head_sha`, and `base_sha..head_sha`;
- the authoritative active instruction source/version, instruction-loading order, read-only and evidence limits, requested focus and non-goals, and severity/output format;
- for both local lanes, the same discovery order: repository-wide `AGENTS.md`, changed-path metadata, applicable path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks;
- for Codex, an instruction to load the authoritative active playbook from its normal skill environment before that shared discovery sequence;
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
- The reviewer reads applicable instructions and skills from its normal environment and the frozen worktree.
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
- Apply **Canonical Executable Provenance** from [canonical-claude-lane.md](canonical-claude-lane.md). [claude-runtime-trust.md](claude-runtime-trust.md) supplies shared signed-manifest verification primitives, version bounds, and failure vocabulary only; its helper executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded-writeback, and recovery rules do not apply to this direct lane.
- A different provider cannot satisfy this lane. Model fallback within Claude Code remains one lane; provider substitution does not.

## GitHub Codex Lane Contract

- The third lane exists only on a supported GitHub Cloud PR with an available Codex integration.
- Request it with the exact `@codex review` comment after the frozen head is current.
- The request comment is not completion. Only a trustworthy terminal result bound to the current head completes the lane.
- Record PR URL, request URL/time, current head SHA, terminal artifact URL/time, and status.
- Reject stale evidence after any push.
- Host `sqbu-github.cisco.com` and any operating identity in `{hoteng, hoteng_cisco}` are unsupported for this lane; a requested triple review uses effective double and records the reason.
- Missing integration, unsupported host/identity, or an unavailable GitHub Codex service produces effective double only when directly known or proved by authenticated provider evidence. Findings from a running service do not.
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
