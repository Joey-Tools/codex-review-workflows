# Review Lane Contracts

These contracts apply to the canonical single, double, and triple review shapes. They intentionally keep review evidence scoped and prevent a large prepared diff from becoming the reviewer prompt.

## Self-Policy Migration Trust Boundary

When the candidate range changes this playbook, its reviewer profile, prompt, guard, or launcher, candidate-head Markdown is still part of the review subject and may provide scoped repository guidance. It is not the parent control plane. Pin the reviewer profile, prompt contract, `validate-worktree`, and Claude launcher to an independently trusted bundle outside the candidate head/range, and record that bundle's absolute source path, version, and SHA-256 digest in every affected lane record. The parent and reviewers must not execute candidate-head Python or shell to bootstrap the candidate's formal review. If the prior trusted bundle cannot implement a new guard contract, apply that prior trusted policy to review the migration, merge and release it, and only then activate the new guard from the trusted release. Ordinary implementation tests may exercise candidate code separately; they do not turn it into formal-review control material.

The bundle identity is operational evidence, not a free-form label:

- Select a previously trusted installed release or frozen prior-policy checkout outside the candidate range. Its `version` is that release's publisher-provided release identifier or frozen commit ID; do not derive it from candidate-head content.
- Treat the directory that contains both `agents/` and `skills/` as the single bundle root. Build one canonical UTF-8 manifest over these exact regular, non-symlink record paths relative to that root, sorted by relative-path UTF-8 bytes. Each record is `<lowercase-file-sha256><two ASCII spaces><relative-path><LF>`: `agents/reviewer.toml`; `skills/review-orchestration-playbook/SKILL.md`; `skills/review-orchestration-playbook/references/review-lane-contracts.md`; `skills/review-orchestration-playbook/references/review-prompt-templates.md`; `skills/review-orchestration-playbook/references/canonical-claude-lane.md`; `skills/review-orchestration-playbook/references/claude-runtime-trust.md`; `skills/review-orchestration-playbook/scripts/named_lane_guard`; `skills/review-orchestration-playbook/scripts/review_runtime/__init__.py`; `skills/review-orchestration-playbook/scripts/review_runtime/named_lane.py`; and `skills/review-orchestration-playbook/scripts/review_runtime/common.py`. The recorded bundle SHA-256 is the lowercase SHA-256 of those complete manifest bytes.
- Resolve the source root and every listed path without following a symlink leaf, reject a missing/extra manifest record or type drift, and verify the same manifest digest immediately before each guard/launcher use and Codex spawn. Recompute it after each lane; any drift invalidates the artifact and is `inconclusive`.
- The selected source establishes trust; the digest binds identity only. Keep the versioned source outside the candidate worktree and deny the candidate/reviewer write access. A platform-managed reviewer profile may remain in its trusted installed location, but its exact bytes must match the manifest entry; if the parent cannot bind the active profile to that entry, the migration review is blocked rather than supplied from candidate head.

## Shared Frozen-Range Contract

For every local logical lane:

- Resolve and record full `base_sha` and `head_sha`; verify that both commits exist and that the chosen range is correct for the target branch. If implementation changes are uncommitted, create an intentional review-anchor commit on the review branch first. Never derive a formal named-lane range from a dirty working tree or untracked files.
- Create a lane-unique clean Git worktree at `head_sha`. Do not reuse the implementation checkout or another reviewer's checkout.
- Before launch, require `git status --porcelain` to be empty after the exact independently verified absent-gitlink exception below, `HEAD` to equal `head_sha`, both frozen commits to resolve, and bounded read-only range queries to work. Any parent-owned diff rendering before the final guard must use both `--no-ext-diff` and `--no-textconv`; prefer non-rendering plumbing for completeness probes.
- With `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0`, use parent-owned read-only Git plumbing to verify local object completeness for the exact range and both endpoint trees without rendering or persisting a full diff. If any required object is missing, hydrate it deliberately before freezing or report the lane blocked. Do not launch a reviewer that could trigger a promisor-remote fetch, credential helper, or interactive authentication while inspecting the frozen scope.
- As the final parent-owned preflight immediately before Codex spawn or Claude process launch, invoke `<trusted-bundle-absolute-path>/scripts/named_lane_guard validate-worktree --worktree <absolute-clean-worktree> --head <full-head-sha>`, adding one `--guidance <repo-relative-path>` for each applicable tracked project-guidance file. The lane record resolves the placeholder to the recorded absolute trusted path; never resolve a bare repository-relative guard. The guard forces `core.fileMode=true`, requires ordinary and staged Git status to be empty after the narrow gitlink exception, and separately rejects both `assume-unchanged` and `skip-worktree` hidden index bits plus every ignored artifact in the worktree. It allows stable tracked source symlinks whose materialized and tracked targets agree and whose full resolution remains inside the worktree; it rejects absolute targets, lexical escape, final or transitive escape, and unstable or mismatched tracked symlinks without reading an escaping target. The frozen targets are read through one aggregate 30-second `git cat-file --batch` call with at most 4,096 tracked symlinks, a 16 KiB per-target limit, and a 64 MiB aggregate output limit. It also requires every tracked `AGENTS.md` plus every supplied guidance path to be an ordinary non-symlink regular file inside the worktree. A gitlink is valid only when its path is absent or is an empty directory representing an uninitialized submodule; any initialized submodule, populated gitlink directory, gitfile, file, or symlink at that path is materialized reviewer-visible content and is rejected. Any repository-visible direct `include.path` or `includeIf.*.path` key is terminal `blocked-safety`, even when its condition is inactive, its target is missing or benign, or a later direct value appears to override included content. The guard enumerates the raw direct keys with includes disabled, never accepts included values as safety configuration, and blocks before `git status` or reviewer execution. The bounded Git repository-identity probes needed to locate and inspect the worktree may still parse Git's configured include before that decision; an unsafe, unreadable, or malformed target therefore fails closed, and this is not a no-read guarantee. Direct `submodule.<name>.path`, Git's per-name `submodule.<name>.active` boolean precedence, and every repeated `submodule.active` pathspec remain authoritative; global pathspecs apply to every raw gitlink even when it has no tracked `.gitmodules` or direct name/path mapping. Explicit per-name false does not become a false initialization finding, while a tracked-submodule URL remains independent registration evidence. This materialization check completes before the guard invokes `git status`, so a pre-existing gitfile cannot redirect that query into external repository metadata. Before the same status query or any reviewer Git command, direct `core.fsmonitor` must be unset or parse as Git-false. A built-in daemon (`true`), a no-value declaration, and any path hook are rejected without execution; direct local/per-worktree precedence remains effective, so a worktree `false` may override a local path. The guard also rejects direct configuration that defines executable `filter.<driver>.clean`, `filter.<driver>.process`, `diff.external`, `diff.<driver>.command`, or `diff.<driver>.textconv` commands. Smudge-only and required-only filter settings plus non-command diff metadata remain allowed. Because Git reports an absent gitlink as a worktree deletion, the guard may consume only that exact status record after the frozen tree proves mode `160000` and `lstat` independently proves the path absent; every other status record remains dirt. Every bounded Git, output-limit, deadline, drain, process, parse, race, or filesystem failure from `validate-worktree` is terminal `blocked` with reason `blocked-safety`; do not spawn or launch the lane.
- Keep the guard property-scoped (checking only the property that protects clean state or safety). It may compare Git state, hidden index flags, ignored-path presence, symlink target/containment, guidance type/location, and gitlink materialization. It must not treat `mtime`, `ctime`, or other content-derived metadata churn as object replacement, and must not snapshot or rehash ordinary file contents. Do not expand that guard into a raw-object workspace or instruction snapshots, supplied/prepared diffs, immutable guidance snapshots, or a general secret/content scan. Conditional repository-required or suspicion-driven security scanning remains a separate parent-owned decision.
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
- the independently trusted control-plane bundle's absolute source, version, and SHA-256 digest, instruction-loading order, read-only and evidence limits, requested focus and non-goals, and severity/output format;
- for Codex, the exact sanitized Git argv prefix supplied as tokens: `/usr/bin/env -i`, only recorded trusted `PATH`, fixed `LANG`/`LC_*`, `PAGER`, and `GIT_*` allowlist entries, the resolved trusted Git executable, fixed safe `-c` flags, and `-C <absolute-clean-worktree>`;
- for both local lanes, the same discovery order: repository-wide `AGENTS.md`, changed-path metadata, applicable path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks;
- for Codex, an instruction to load the trusted playbook from the external bundle before that shared discovery sequence, then treat candidate-head Markdown as review subject/scoped guidance during self-policy migration;
- for Claude, the complete lane contract plus an instruction to read only tracked repository/path guidance and repo-local skills from the worktree during that sequence;
- an instruction to discover evidence itself with bounded Git and source-inspection tools.
- an instruction not to run `fetch`, `pull`, or any networked Git operation; the parent has already proved the frozen scope locally complete.
- an instruction that every Codex Git invocation copies the supplied prefix exactly, never uses bare Git or an alternate/reconstructed prefix, and adds `--no-ext-diff --no-textconv` to every diff-producing command.

The parent materializes that prefix once in control metadata. Its environment allowlist is exactly the recorded trusted `PATH`, fixed `LANG`/`LC_ALL`, `GIT_ASKPASS=/usr/bin/false`, `GIT_ATTR_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, `PAGER=cat`, and `GIT_PAGER=cat`. After the resolved trusted Git executable, the fixed options are exactly `--no-pager -c core.fsmonitor=false -c core.fileMode=true -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c diff.external= -c color.ui=false -C <absolute-clean-worktree>`. The reviewer appends only the read-only subcommand and its arguments; it may not add an earlier `-C`/`--git-dir`/`--work-tree`, an overriding `-c`, or an environment assignment.

The parent must not:

- compute or persist a reviewer-visible full diff;
- paste diff text, changed file contents, or another reviewer's findings into the prompt;
- pass a generated diff path, stdin payload, attachment, or control artifact as the review surface;
- summarize suspected defects in a way that biases the independent reviewer;
- resume an implementation or prior review session.

This rule applies even when a direct diff would fit in the current prompt. It avoids the hard failure mode where a large change crosses an input-size boundary before the reviewer can use its own bounded tools.

## Codex Single-Lane Contract

- Complete `validate-worktree` successfully on this exact worktree/head immediately before spawn.
- Use the dedicated `reviewer` agent with `fork_turns="none"`, or the platform-equivalent zero-inherited-turn launch.
- The reviewer loads the parent-recorded trusted playbook, then reads applicable Markdown instructions and skills from the frozen worktree as review subject/scoped guidance. It never executes candidate-head Python or shell as control-plane bootstrap.
- The reviewer has read-only Git/source tools and obtains the diff itself. Every Git invocation begins with the exact supplied sanitized prefix, and every diff-producing command explicitly uses both `--no-ext-diff` and `--no-textconv`.
- The existing `.git`-free supplied-diff Codex helper is a different low-level mechanism and cannot satisfy this lane.
- Accept only the dedicated reviewer's terminal findings artifact for the exact range.

## Claude Code Lane Contract

- Use an actual Claude Code process in a second lane-unique clean Git worktree.
- Apply the same clear-context, instruction-loading, no-prepared-diff, bounded-tool, exact-range, and read-only requirements as the Codex lane.
- Complete `validate-worktree` successfully on this exact worktree/head, then launch the exact revalidated actual `claude` executable through the same parent-recorded absolute trusted guard's `run-claude` subcommand under [canonical-claude-lane.md](canonical-claude-lane.md). The guard makes Claude its direct child with direct argv/no shell; the `.git`-free `isolated_review` helper is not the launcher or reviewer for this lane. Each stdout/stderr path must have a caller-supplied lane-unique, current-user-owned mode-`0700` canonical real parent directory outside the worktree, cooperative same-UID exclusivity, and a distinct absent, non-symlink direct leaf. The guard opens and retains that validated parent directory before launch, performs temporary creation, exclusive publication, and rollback relative to the retained descriptor, and rejects parent identity or owner/mode drift before or after publication without treating directory content metadata as identity. Publication and rollback remain under a forwarded-signal mask through an explicit commit point; a signal observed before commit removes the complete pair before propagation. Final and temporary cleanup checks the `(st_dev, st_ino)` created by that write, so identity drift already observed before unlink is preserved and makes the lane inconclusive. POSIX/Python provides no portable conditional unlink; a non-cooperative same-UID replacement in the final check-to-unlink window is outside this lightweight lane's guarantee.
- Do not give Claude the Codex artifact, parent reasoning, or suspected findings.
- Use the detached worktree as review scope and real `HOME` as the trusted Claude CLI control plane. The model may have `Read`, `Grep`, `Glob`, and sandboxed `Bash`.
- Treat the native selected-deny sandbox accurately: launch must request global `denyWrite` and critical-sensitive-root `denyRead`; those requested controls define the native-sandbox enforcement boundary, but `allowRead` is not a global host-read whitelist. Sandboxed Bash can technically read another host path that is not covered by `denyRead`; the prompt/model scope must explicitly forbid every outside-workspace read.
- Treat Claude Code 2.1.212 `system/init` and capability output as evidence for only the fields it reports. It cannot attest the final merged sandbox, merged managed permission arrays, or actual path-rule evaluation; record the sandbox controls as requested configuration, not independently verified effective enforcement.
- Apply **Canonical Executable Provenance** from [canonical-claude-lane.md](canonical-claude-lane.md). [claude-runtime-trust.md](claude-runtime-trust.md) supplies shared signed-manifest verification primitives, version bounds, and failure vocabulary only; its helper executable snapshot, dependency closure, outer sandbox, credential broker/carrier/catalog, guarded-writeback, and recovery rules do not apply to this direct lane.
- `run-claude` rebuilds the child environment from an allowlist: account-derived real `HOME`/`USER`/`LOGNAME`/`SHELL`, trusted `PATH`, and only allowlisted locale/UI, proxy, and CA variables. Ambient `NODE_EXTRA_CA_CERTS` remains excluded unless the caller uses the reviewed value-free `--inherit-node-extra-ca-certs` opt-in; the configured value must then name an exact absolute readable non-symlink regular file that passes a stable no-follow identity check. The direct lane passes that original host control-plane path only to Claude Code; it does not expose the path in the guard's argv, copy or attest the material, or inherit the helper's stronger CA staging contract. It forces `GIT_ASKPASS=/usr/bin/false`, `GIT_ATTR_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_NO_REPLACE_OBJECTS=1`, no global/system Git config, `GIT_OPTIONAL_LOCKS=0`, and fixed `GIT_PAGER=cat`/`PAGER=cat`. It must not inherit ambient Claude/Anthropic, cloud-provider, dynamic-loader, or other tool-control variables; any other credential/control input needs its own reviewed interface.
- The canonical direct lane's only authentication interface is ordinary local login in trusted real `HOME`, including normal CLI refresh. It accepts no API key, OAuth-token environment interface, or helper credential carrier. If organization policy forbids normal refresh, or only API-key/OAuth-token credentials are available, the lane is `blocked-authentication`; do not widen the environment or switch providers.
- Canonical executable provenance rejects npm/NVM shebang shims and every other script/interpreter wrapper. The trusted `run-claude` `PATH` never expands to make such a shim work, and the guard's process supervision does not establish provenance.
- The process-only supervisor accepts a bounded prompt, installs structured forwarded-signal handling before prompt input, starts its 1,800-second monotonic deadline before reading that prompt through EOF, passes only the remaining budget to process supervision, caps stdout and stderr at 64 MiB each (128 MiB aggregate), caps the prompt at 256 KiB, and applies the shipped TERM/KILL/drain/reap cleanup to the initial supervisor process group and inherited streams. Test-oriented CLI timeout, per-stream, and prompt overrides may equal or tighten those production caps but may never raise them; the direct Python API enforces the same ceilings. A short prompt whose writer withholds EOF is therefore a bounded inconclusive deadline failure; SIGTERM, SIGINT, SIGHUP, or SIGQUIT during that wait is structured `inconclusive` with reason `forwarded-signal`. Only full structured terminal output accepted after cleanup may count. Every `run-claude` supervision failure—including timeout, either-stream overflow, drain/reap failure, residual members of that group, inherited-stream leak, or malformed/partial terminal output—is `inconclusive`; never accept a partial tail or use provider/model fallback. This is not a process-tree sandbox: descendants that deliberately escape with `setsid()` or `setpgid()` and close inherited streams are outside the guarantee, and the lane must not claim whole-process-tree quiescence.
- The guard supplies only clean/safety validation and process supervision. It does not prepare the diff, perform review logic, establish executable provenance, provide sandbox or authentication guarantees, scan general content/secrets, snapshot ordinary contents/timestamps, or inherit any helper-only guarantee.
- A different provider cannot satisfy this lane. Model fallback within Claude Code remains one lane; provider substitution does not.

## GitHub Codex Lane Contract

- The third lane exists only on a supported GitHub Cloud PR with an available Codex integration.
- Request it with the exact `@codex review` comment after the frozen head is current.
- The request comment is not completion. Only a trustworthy terminal result bound to the current head completes the lane.
- Record PR URL, request URL/time, current head SHA, terminal artifact URL/time, and status.
- Reject stale evidence after any push.
- Host `sqbu-github.cisco.com` and any operating identity in `{hoteng, hoteng_cisco}` are unsupported for this lane; a requested triple review uses effective double and records the reason.
- Missing integration, unsupported host/identity, or an unavailable GitHub Codex service produces effective double only when directly known or proved by authenticated provider evidence tied to the exact request/dispatch or the sole-unresolved fallback. A full SHA alone does not bind a no-start rejection to one of multiple unresolved same-head requests. Findings from a running service do not.
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

Only a complete lane record with final raw reviewer output counts. For Claude, the full structured terminal output is not eligible until the supervisor has finished inherited-stream drain, initial-process-group cleanup, and direct-child reap successfully. Intermediate reasoning, stdout tails, tool traces, keepalives, retry attempts, and model fallbacks do not create additional lanes.

## Failure And Rerun Contract

- `blocked`: deterministic authentication, permission, configuration, policy, unsupported runtime, missing required provider, or any bounded `validate-worktree` failure (`blocked-safety`).
- `inconclusive`: transient/capacity/timeout/network failure, any `run-claude` supervision failure, Claude output overflow, drain/reap or initial-process-group/inherited-stream cleanup uncertainty, malformed/partial output, or no trustworthy terminal artifact.
- Actionable findings invalidate a clean claim until fixed and rereviewed.
- A changed `head_sha` invalidates every artifact tied to the old head.
- Rerun every requested local lane affected by the change; rerun the GitHub lane only when it is supported and part of the effective shape.
- GitHub Codex unavailability changes only triple to effective double. It never substitutes for a failed Codex or Claude Code local lane.

## Review-Only Child Contract

A child explicitly assigned findings-only review must inspect only its frozen range and return findings. It must not start another reviewer, edit code, wait for CI, update the PR, invoke state-changing tools, or orchestrate this workflow recursively.
