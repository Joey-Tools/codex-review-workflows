# Review Lane Contracts

These contracts apply to the canonical single, double, and triple review shapes. They intentionally keep review evidence scoped and prevent a large prepared diff from becoming the reviewer prompt.

## Shared Frozen-Range Contract

For every local logical lane:

- Resolve the local range and PR selector independently. Preserve an explicit frozen range as local-lane scope. Explicit-range-only standalone single/double requires no PR probe or head comparison. When PR-specific or triple work needs a PR, use an explicitly named PR or exactly one authenticated open-PR candidate for the exact current head repository/branch. A frozen range never selects a PR. Multiple candidates leave the GitHub/PR-specific lane `blocked-input` because the required explicit PR selector is absent, while fully scoped local lanes may still run. A proven zero-candidate result is the no-PR path, not a range: require an explicit committed range or an explicitly named target/base before freezing `<merge_base>..HEAD`; never guess the target/base. For triple, an undiscoverable detached/unknown branch without an explicit PR is `blocked-input` / `triple-inconclusive`, not effective double. Keep this missing-selector state distinct from `blocked-authorization`, which applies when intended dirty/untracked state would require an unauthorized anchor mutation.
- For a selected PR, independently read authenticated `baseRefName`, `baseRefOid`, and `headRefOid`; with lazy fetching disabled, require both endpoint commits locally and require `git merge-base --all pr_base_oid pr_head_oid` to yield exactly one full `pr_merge_base`. At first freeze, persist immutable parent-owned `range_origin.kind`, `range_origin.base_sha`, and `range_origin.head_sha`; the kind is exactly `caller-supplied` or `pr-derived`, and original caller endpoints are never overwritten. A missing or ambiguous selected-PR origin is `blocked-input` (`range-origin-unverified`). A selected PR's explicit frozen range satisfies PR-specific readiness or triple completion only when `base_sha == pr_merge_base` and `head_sha == pr_head_oid`. A same-head/different-base range is `blocked-input` (`scope-mismatch`): preserve the caller's range, do not silently rewrite it, do not start or count PR-specific lanes from it, and never describe its local review results as whole-PR coverage. Explicit-range-only standalone single/double with no selected PR remains unaffected.
- Resolve and record full `base_sha` and `head_sha`; verify that both commits exist and that the chosen range is correct for the target branch. Never derive a formal named-lane range from a dirty working tree or untracked files. When implementation or delivery mutation is already authorized, uncommitted changes may first be captured in an intentional review-anchor commit on the review branch. A standalone report-only named review does not authorize that branch or commit: when its intended scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization` and request an existing committed range or explicit anchor authorization.
- Create a lane-unique clean Git worktree at `head_sha`. Do not reuse the implementation checkout or another reviewer's checkout.
- Before launch, require `git status --porcelain` to be empty, `HEAD` to equal `head_sha`, both frozen commits to resolve, and read-only `git diff base_sha..head_sha` queries to work.
- With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, use parent-owned read-only Git plumbing to verify local object completeness for the exact range and both endpoint trees without rendering or persisting a full diff. If any required object is missing, hydrate it deliberately before freezing or report the lane blocked. Do not launch a reviewer that could trigger a promisor-remote fetch, credential helper, or interactive authentication while inspecting the frozen scope.
- Expose the workspace and Git metadata for read-only reviewer behavior. Disable writes to files, index, refs, config, hooks, remotes, PR state, and other external systems. The publisher-verified canonical Claude process may update ordinary CLI-owned authentication and runtime state in trusted real `HOME`, including credential refresh and possible cache or tool-result artifacts. Those accepted CLI control-plane side effects are not model-authorized review actions, do not authorize model/tool writes or deliberate host mutations, and do not inherit helper credential guarantees. The policy does not enumerate or attest every CLI-owned `HOME` write. A filesystem read-only sandbox does not prove that state-changing MCP, Plugin, connector, or GitHub tools are absent: the reviewer policy must forbid those actions and the parent must not authorize them. This is a write/behavior contract; it is not a claim that every runtime has an OS-level global host-read whitelist.
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

Required PR/master admission uses `isolated_review secret-admission --repo <repo> --base-ref <base_sha> --head-ref <head_sha>`. The result must report `review_contract: admission-only-no-reviewer`, `reviewer_started: false`, and `temporary_cleanup_status: complete`; the command creates no review workspace, diff, prompt, state, or provider process. Exit `0` is `clean`, `1` is proved violations and remains `1` after a later location/cleanup failure, and `75` is an inconclusive scan or a clean scan whose temporary cleanup failed. A changed head invalidates the result. When an independently requested low-level helper state exists, its compatible `stateful final` / `stateful admission` pair remains helper-only evidence and never becomes a required reviewer or named lane.

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
- Launch `<resolved-compatible-claude-path>` directly from that worktree under [canonical-claude-lane.md](canonical-claude-lane.md). The `.git`-free `isolated_review` helper is not the launcher for this lane.
- Do not give Claude the Codex artifact, parent reasoning, or suspected findings.
- Use the detached worktree as review scope and real `HOME` as the trusted Claude CLI control plane. The model may have `Read`, `Grep`, `Glob`, and sandboxed `Bash`.
- Treat the native selected-deny sandbox accurately: launch must request global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary, but `allowRead` is not a global host-read whitelist. Sandboxed Bash can technically read another host path that is not covered by `denyRead`; the prompt/model scope must explicitly forbid every outside-workspace read.
- Treat capability output and `system/init` evidence—including Claude Code 2.1.212 baseline output—as evidence for only the fields each reports. Neither can attest the final merged sandbox, merged managed permission arrays, or actual path-rule evaluation; record the sandbox controls as requested configuration, not independently verified effective enforcement.
- Require exactly one leading `system/init` and one trailing terminal `result` in the canonical Claude `stream-json` output. A missing, duplicate, malformed, or misordered contract event is inconclusive; when both events report `session_id`, require the two nonempty values to match exactly or classify the stream inconclusive. A well-formed required field that mismatches the frozen launch is a deterministic blocked configuration/policy mismatch. Neither case can count as the Claude lane. The preflight-bound compatibility contract must fail closed on the exact clean-worktree cwd, `permissionMode: dontAsk`, exactly `Read`/`Grep`/`Glob`/`Bash`, empty `mcp_servers`/`slash_commands`/`skills`/`plugins`, the requested model, the exact preflight-selected CLI version, and the parent-selected authentication source. Its top-level field set is closed: only required baseline fields and optional nonempty `session_id` are allowed; any unknown init field is inconclusive. The current profile adapts only the baseline version constant and does not claim a separate audit for every in-range patch. This verifies reported init fields only, not the merged sandbox, managed permission arrays, or path-rule evaluation.
- Accept preflight evidence only from an absolute, current-user-owned, single-link regular file outside the reviewer worktree, with no group or world permission bits. Bind the compatibility-profile, audited-baseline, and capability-contract source digests before parsing the stream; workspace-local, linked, special-file, stale, or mismatched evidence is inconclusive and supplies no findings.
- Capture bounded raw stdout in parent-owned state outside the model-visible worktree and pass it through [`validate_claude_stream.py`](../scripts/validate_claude_stream.py) with the parent-private accepted `--preflight-result`, exact resolved cwd, requested model, selected authentication source, and mandatory `--process-returncode <child-returncode>`. The validator must bind the selected version and current compatibility/profile digests before parsing the stream. Only `classification: accepted` with a zero child return code supplies findings; a missing, invalid, or nonzero child return code is inconclusive when stdout contains an otherwise valid-looking success result. A nonzero code preserves deterministic structured `blocked` or `blocked-authentication` evidence, while a bare exit code creates neither. Prose inspection, an ad hoc parser, partial output, or any fail-closed validator result cannot satisfy the lane. Validator acceptance does not attest the merged sandbox.
- Advance from `claude-opus-4-8` to `claude-opus-4-7` only when that validator returns `classification: blocked` and every classified message yields machine reason `terminal.model-entitlement-denial` or `terminal.organization-policy-denial`. Resource/quota/capacity/rate-limit text, credential I/O, authentication evidence, an unclassified message, or mixed categories is inconclusive and never authorizes model fallback. A deterministic init blocker remains blocked when a non-success terminal supplies no error prose.
- The canonical compatibility range is `>=2.1.211,<3.0.0`, defined once in [`claude_version_policy.py`](../scripts/review_runtime/claude_version_policy.py). Claude Code `2.1.212` is the audited per-version stream-schema baseline, not a global eligibility pin. Before prompt, credential, repository, range, PR, or review-workspace input reaches Claude, require [`named_claude_preflight`](../scripts/named_claude_preflight) to select one compatible stable release. Its ordered candidates are an authoritative explicit absolute override, the highest compatible side-by-side install, then controlled active-install paths; caller `PATH` is ignored. Only exact absence may advance priority; inspection uncertainty stops fail closed.
- Before executing a candidate, require an in-range version declaration. Verify the native artifact against the fixed-key signed per-version manifest, size, digest, path/version/platform identity, and descriptor-bound source identity. Probe `--version` and mandatory `--help` only through a private digest-verified snapshot in the bounded credential-free environment, reverify the snapshot after each probe, then descriptor-rehash and rebind the mutable source before acceptance. The help probe verifies only the advertised capability surface; it does not prove launch semantics, the final merged sandbox, managed permission arrays, or path-rule evaluation. Persist the bounded accepted preflight JSON with selected-version, publisher, identity, capability, and stream-profile digest evidence; all unsupported, mismatched, or uncertain states fail closed as detailed in [canonical-claude-lane.md](canonical-claude-lane.md).
- Acquiring a missing compatible release is a separate host mutation requiring explicit authorization and the official installer/version manager. A named review request does not authorize installation, downgrade, active-version switching, or symlink repair. Do not install `2.1.212` merely because it is the audited baseline.
- Apply **Compatible-Version Selection Preflight** and **Canonical Executable Provenance** from [canonical-claude-lane.md](canonical-claude-lane.md). [claude-runtime-trust.md](claude-runtime-trust.md) supplies shared compatible-range, signed-manifest, capability, and failure primitives; its helper executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded-writeback, and recovery rules do not apply to this direct lane.
- A different provider cannot satisfy this lane. Model fallback within Claude Code remains one lane; provider substitution does not.
- A version, provenance, capability, or stream-contract failure does not change a requested double into single: the result is double-but-blocked. It also leaves a requested triple blocked. Independently proved GitHub Codex unavailability may make the effective shape double, but that effective double is incomplete while its Claude lane is blocked.

## GitHub Codex Lane Contract

- The third lane exists only on an authenticated selected PR with exact lifecycle `state == "open"`, `merged == false`, and `merged_at == null`, exact host `github.com`, an operating identity outside `{hoteng, hoteng_cisco}`, and an available Codex integration. Missing/contradictory lifecycle evidence is `blocked-input` (`pr-lifecycle-unverified`) and triple-inconclusive; closed-unmerged is `selected-pr-closed` and directly unavailable only before any request/service start when a separate frozen local range exists; merged is terminal `already-merged` / `selected-pr-merged`. An observed non-open lifecycle at any mandated snapshot after request/service start invalidates evidence and remains triple-inconclusive. Revalidate lifecycle at selection, before posting, before accepting a result, and before readiness/merge. These point-in-time snapshots do not prove that no intermediate close-and-reopen occurred between them. Every other host, including every GitHub Enterprise host, is unsupported.
- Before posting, inspect complete authenticated request history and the bounded audit record. For one unchanged current head, allow at most one acceptable exact `@codex review` request and never post a second one. Reuse the recorded request when it already exists. Multiple same-head requests, a second request that races with preflight, or evidence that cannot exclude an older request whose run/result might overlap makes the lane `triple-inconclusive`.
- Only when that history proves no accepted exact request exists for the unchanged head, post the one allowed exact `@codex review` comment after the frozen head is current. Otherwise reuse the one recorded request. Re-read complete authenticated request history immediately before accepting any result; a second request discovered then is an attribution race and makes the lane `triple-inconclusive`.
- The request comment is not completion. Only a complete terminal provider-authored findings payload from exact-bot review/comment evidence, bound to the current head, whole-PR range, and isolated request, completes the lane.
- Record PR URL, request URL/time, current head SHA, terminal artifact URL/time, and status.
- Reject stale evidence after any push.
- Record the exact request comment's API ID and server `created_at`. Server timestamps prove ordering, not request/run lineage. Review/comment APIs expose no request/run identifier, so review/comment evidence is `triple-inconclusive` whenever an older request might overlap, even if its trusted server `submitted_at` or `created_at` is strictly later than the current request. For a selected exact-bot review, consume the review body plus every fully paginated associated inline review comment and require exact case-sensitive state `COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`; `PENDING` continues bounded waiting, while `DISMISSED`, missing, and unknown states are `triple-inconclusive`. Preserve every finding in the combined payload. Alternatively, accept an exact-bot terminal issue-comment body only when it unambiguously reports the complete findings/no-findings outcome rather than acknowledgement or progress. Missing or ambiguous payload, terminal nature, pagination completeness, or association is `triple-inconclusive`. Same-head evidence from an earlier request is stale.
- Host `sqbu-github.cisco.com`, every other non-`github.com` host, and any operating identity in `{hoteng, hoteng_cisco}` are unsupported for this lane; a requested triple review uses effective double and records the reason.
- Accept completion evidence only from provider-authored review/comment payloads with exact REST `user.login == "chatgpt-codex-connector[bot]"` and exact `user.type == "Bot"`. Exact `app.slug == "chatgpt-codex-connector"` check/run evidence is service-start evidence only when its `head_sha` is the unchanged current head and its non-null `started_at` is strictly later than the request. It never completes triple or proves a clean/no-findings result, even when `status == "completed"` and `conclusion == "success"`. A same-App check may be unrelated to the requested review, and check success can coexist with provider review findings. Unknown or lookalike identities make the lane inconclusive and cannot prove no-start rejection, service start, or completion.
- Missing integration, unsupported host/identity, or an unavailable GitHub Codex service produces effective double only when directly known or proved by authenticated provider evidence. Findings from a running service do not.
- An existing supported PR whose current `headRefOid` does not equal the frozen `head_sha` remains a triple candidate, not an unavailable lane. If the parent did not separately authorize publishing or changing the PR head, leave the PR unchanged and report `requested: triple`, `effective: triple-inconclusive`, with GitHub lane status `blocked-authorization`.
- For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue.
- Missing response, timeout, generic request/HTTP failure, or guessed integration state is `effective: triple-inconclusive`, not unavailable.
- Once acknowledgement, exact-App current-head post-request check/run activity, or review activity proves service start, malformed, stale, ambiguous, transiently incomplete, or check-only evidence is `effective: triple-inconclusive`, not effective double, completed triple, or a clean result.

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
- A changed `head_sha` invalidates every artifact tied to the old head. For a selected PR, a changed `pr_merge_base` also invalidates every artifact previously counted as whole-PR evidence even when `head_sha` is unchanged; re-read base/head metadata and recompute the unique merge base before accepting triple or readiness completion.
- Before applying the generic same-head/different-base `scope-mismatch` branch, compare any accepted same-head request's audited request-time merge base with current `pr_merge_base` and apply [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json). The state-machine event reason for an inherited stale range is `base-changed-same-head`. A missing origin, inherited stale range, or parent rewrite of caller-owned endpoints stops before local lanes. An exact current range newly supplied by the caller recovers local lanes for caller-origin state; normal exact-current rederivation recovers them for PR-derived state. Both recovery paths proceed to local lanes while readiness remains `blocked-input` and `requested: triple`, `effective: triple-inconclusive`. Neither path unblocks the GitHub lane while `pr_head_oid` remains unchanged. Never post a replacement request or create an empty or anchor commit merely to regain eligibility.
- Otherwise rerun the GitHub lane only when it is supported and part of the effective shape.
- GitHub Codex unavailability changes only triple to effective double. It never substitutes for a failed Codex or Claude Code local lane.

## Review-Only Child Contract

A child explicitly assigned findings-only review must inspect only its frozen range and return findings. It must not start another reviewer, edit code, wait for CI, update the PR, invoke state-changing tools, or orchestrate this workflow recursively.
