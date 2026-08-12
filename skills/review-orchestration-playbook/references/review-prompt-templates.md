# Review Prompt Templates

This reference owns prompt skeletons, resource load order, and reviewer output shape. It deliberately omits machine fields and provider wire details. Load [review-lane-contracts.md](review-lane-contracts.md) for eligibility and budgets.

## Construction Rules

- Before constructing either local prompt, require parent-owned evidence that the trusted guard's `materialize-worktree` accepted only a full non-shallow, non-promisor, alternate-free source; proved `base_sha` is the sole merge base and an ancestor of `head_sha`; derived source commit scope `{base_sha} ∪ (base_sha..head_sha)`; and initialized a lane-private repository with exactly one materializer-owned shallow boundary at `base_sha`. It must import the complete recursive commit/tree/blob snapshot closure for every scoped commit, reject a graph that the single boundary cannot represent and any arbitrary destination shallow state, enforce the unchanged object/logical/checkout/path ceilings, the separate 250,000 parent-edge-occurrence ceiling, and the 768 MiB exact-range pack ceiling, and prove exact imported commits and total object inventory before `fsck`, completeness checks, and checkout. The formal destination has no `.git/config.worktree`; the guards bind its local config identity/content/access policy, bind owner-private `.git/info`, reject and revalidate `info/grafts`, and use `GIT_GRAFT_FILE=/dev/null` plus the fixed stat-safe configuration. Invoke candidate `validate-worktree` with that same mandatory frozen `--base` and `--head`; before its first status query it must revalidate both lane refs, exact `BASE+LF` shallow content, endpoint commits, the unique merge base, exact range topology, local config, and graft-free info state. Require both guard receipts to bind type-preserving identical `base`, `head`, `worktree`, `commit_count`, `parent_edge_count`, `parent_graph_sha256`, and `local_config_sha256`; the canonical graph digest byte-sorts commit rows and preserves parent-token order and duplicates. Never use `git worktree add`, clone/fetch/upload-pack, a copied source config/hooks directory, or any pre-validator status query. During this self-policy migration, the independently trusted prior bundle reviews the candidate through its prior interface; do not claim the candidate-only mandatory-`--base` gate active before merge and release.
- Give a named Codex reviewer only review-control metadata: the clean worktree path, exact `base_sha`, exact `head_sha`, the parent-accepted materialization/validation receipt pair binding all seven shared fields above, the independently trusted control-plane bundle's absolute source/version/SHA-256 digest, the authoritative review skill's exact absolute path within that bundle and version/digest, the exact sanitized Git argv prefix, instruction-loading order, read-only/evidence limits, focus/non-goals, and output contract. Never prebuild, paste, attach, or otherwise inject the full diff, changed-file content, suspected finding, or another reviewer's output into its prompt.
- Supply the sanitized Git prefix as an exact token sequence beginning with `/usr/bin/env -i`, followed only by the recorded trusted `PATH`, fixed `LANG`/`LC_*`, `PAGER`, and `GIT_*` allowlist, the resolved trusted Git executable, the fixed safe `-c` flags, and `-C <absolute-clean-worktree>`. Require every Git call to copy that prefix exactly; forbid bare `git`, another executable or wrapper, a reconstructed prefix, extra environment keys, changed `-c` values, and a different worktree. Require explicit `--no-ext-diff --no-textconv` on every diff-producing command.
- The parent-supplied token sequence contains exactly the environment and safe options defined in [review-lane-contracts.md](review-lane-contracts.md), including no global/system config, no prompts/lazy fetch/grafts/replacement objects/optional locks, `GIT_CEILING_DIRECTORIES=<absolute-clean-worktree-parent>`, `GIT_GRAFT_FILE=/dev/null`, fixed `PAGER=cat`/`GIT_PAGER=cat` plus `--no-pager`, `core.commitGraph=false`, `core.checkStat=default`, `core.multiPackIndex=false`, `core.fsmonitor=false`, `core.fileMode=true`, `core.ignoreStat=false`, `core.trustCtime=true`, null hooks/attributes, empty `diff.external`, disabled color, and the exact `-C` worktree. Do not let the reviewer synthesize this sequence from prose.
- Launch only after the independently trusted materializer has bound the exact full source repository/object store, rejected suffix discovery plus source shallow/promisor/alternate state, fenced source/target filesystem ancestry, created and repeatedly validated the exact base shallow boundary, imported only the hard-bounded inclusive-range snapshot manifest into a private repository, disabled commit-graph/multi-pack-index consumption, verified the destination commit set and total object inventory exactly, completed `fsck` and local completeness checks, and excluded ambient/source execution surfaces before import/checkout. The validator must then reject `.git/config.worktree`, any `info/grafts`, repository-visible `include.path` / `includeIf.*.path`, every direct stat-key override or `alias.*`, executable filter/diff configuration, and any direct `core.fsmonitor` value that is not Git-false before its first status. The sanitized reviewer prefix is defense in depth; it replaces neither pre-status materialization nor the local-config/info binding, include, alias, fsmonitor, pristine-worktree, hidden-index-bit, ignored-file, symlink, or gitlink checks in [review-lane-contracts.md](review-lane-contracts.md).
- During self-policy migration, identify candidate-head Markdown as review subject and scoped guidance only. The reviewer profile, prompt contract, guard, exact-version/provenance preflight, launcher, and stream validator/schema remain parent control-plane material pinned outside the candidate range; candidate-head Python, shell, and machine schemas may not bootstrap the lane. Populate the source/version/digest fields only after the parent verifies the [Canonical Review-Control Manifest](review-lane-contracts.md#canonical-review-control-manifest); repeat that verification before spawn and after the lane.
- Require the reviewer to load the review skill and repository-wide `AGENTS.md`, inspect changed-path metadata, then load every applicable path-scoped `AGENTS.md`, domain skill, and project-guidance file before judging hunks.
- Require the reviewer to verify the two refs, enumerate the complete changed-path set, and derive and inspect every changed hunk plus necessary nearby tracked context itself with bounded Git/tool calls. Initial counts or samples are orientation only, never evidence of complete coverage.
- State that the parent has already proved the frozen scope locally complete with lazy fetching disabled, and forbid `fetch`, `pull`, credential prompts, or any other networked Git operation.
- Keep the worktree read-only. Do not ask the reviewer to fix findings, modify files, stage changes, commit, switch branches, or perform other Git mutations.
- Ask for findings only, ordered by severity, with file references and concrete failure modes or triggering conditions.
- When there are no findings, the reviewer may first give one concise non-actionable positive/coverage summary, but the final nonempty logical line must be exactly `No findings.`. With findings, never emit that sentinel. If there is any finding, do not output `No findings.` anywhere.
- Include performance and resource risk only when the change plausibly affects hot paths, complexity, allocation, I/O, contention, startup, fan-out, query shape, repeated work, or build cost.
- Tell the reviewer to avoid style-only nits, speculative micro-optimizations, and unrelated rewrites.
- Prefer direct argv tool calls. Avoid `bash -lc`, `zsh -lc`, here-docs, and similar wrapper probes unless shell syntax is essential.
- For Claude, if the CLI reports that output was persisted or spilled outside the detached worktree, never follow the reported path with `Read`, `Grep`, or `Glob`. Rerun a narrower bounded command over exact worktree paths; if an outside-workspace tool read already occurred, the lane is blocked and its findings cannot be accepted.
- For Claude structured file tools, pass an absolute worktree path in `Read.file_path` and in every present `Grep.path` or `Glob.path`. `Glob.path` may be omitted only to use the exact review cwd. Every `Glob` call must include a bounded relative `Glob.pattern`; ordinary `**`, wildcard directory components, character classes, and simple brace alternatives are allowed, including `**/*.py`, `src/**/*.{py,md}`, and `./**/*.py`. Never use an absolute pattern, home shorthand, an exact `..` path component, intermediate `.`, a backslash escape, extglob such as `@(` / `!(`, or nested/malformed/expansive braces. These prompt rules are the tool-time boundary; the later bounded directory scan cannot reconstruct every tool-time target or ABA replacement.

## Resource Load Order

Common order:

1. the exact parent-named trusted `$review-orchestration-playbook` source, or the parent-named independently trusted external prior bundle for a self-policy migration;
2. [review-lane-contracts.md](review-lane-contracts.md) and processor-specific trusted runtime guidance from that same control source;
3. applicable repository `AGENTS.md` files from outer to inner scope;
4. repo-local domain skills and tracked project guidance;
5. task focus and any remaining repository guidance.

The first two steps establish the control plane before any candidate repository guidance is read. During a self-policy migration, candidate-head playbook, template, and machine-contract content is review subject or scoped repository guidance only; it cannot replace, reorder, or certify the parent-named trusted control source.

For GitHub triple orchestration, the parent—not a review-only child—loads:

1. [github-codex-evidence-authority.md](github-codex-evidence-authority.md);
2. [github-codex-review-epoch-state-machine.json](github-codex-review-epoch-state-machine.json);
3. [base-only-retarget-state-machine.json](base-only-retarget-state-machine.json) only for a same-head base-only retarget;
4. [github-pr-probes.md](github-pr-probes.md) for endpoint capture;
5. [pr-readiness.md](pr-readiness.md) for delivery gates.

## Named Single Skeleton

```text
You are the sole fresh-context Codex reviewer for this lane.

Repository: <absolute clean workspace>
Frozen range: <base_sha>..<head_sha>
Trusted control-plane bundle: <absolute path + version + canonical manifest SHA-256>
Authoritative review skill: <absolute path + version + SHA-256 digest>
Trusted guard receipt: <identity>
Materialize receipt: <exact accepted receipt>
Validate receipt: <exact accepted receipt>
Receipt equality: <type-preserving exact base, head, worktree, commit_count,
parent_edge_count, parent_graph_sha256, and local_config_sha256 equality>
Sanitized Git argv prefix: <exact supplied token sequence>
Instruction order: <ordered paths>
Focus: <bounded review focus>
Non-goals: <explicit exclusions>

Load the applicable instructions. Inspect the frozen diff and necessary tracked
context yourself with bounded read-only Git/tools. Do not fetch, edit, commit,
post, or start another reviewer.

Return actionable findings first, ordered by severity. Each finding must include
the affected file/line, the violated property, and why the candidate causes it.
If no actionable finding remains, return the accepted clean form required by
the trusted reviewer profile. Report any evidence or runtime blocker exactly.
```

## Named Double Claude Skeleton

```text
Review the exact frozen range <base_sha>..<head_sha> in the supplied independent
read-only workspace. Load the listed instructions in order and inspect the diff
yourself. Do not read outside the scoped workspace, mutate files, fetch, commit,
post, or contact another processor.

Focus: <bounded focus>
Non-goals: <explicit exclusions>

Return findings with severity and precise file/line evidence. If clean, use the
trusted stream/result profile's accepted clean presentation. Do not claim that
runtime or sandbox validation succeeded; the parent validates raw output.
```

The parent supplies this prompt only after trusted runtime preflight and validates the captured stream independently. Do not paste authentication values, preflight payloads, or the full diff into the prompt.

## Named Triple Parent Skeleton

```text
Requested shape: triple
Frozen local range: <base_sha>..<head_sha>
Selected PR: <owner/repo#number>

Preserve the caller range independently. Classify selected-PR lifecycle first;
only then derive base/head/merge-base scope and apply conditional retarget policy.
Run the two local lanes on the same frozen range. For the GitHub lane, load the
canonical authority and machine resources in their documented order, reconcile
complete current-scope evidence, and create only a machine-authorized request.
Never blind-retry uncertain transport or create an anchor commit.

Treat attempts as one logical lane and provider evidence artifact-first. Report
exactly six independent GitHub planes: request_policy; provider, with
evidence_basis nested only inside provider; required_action_status;
named_github_lane; reaction_audit; and readiness. Before evidence acquisition,
load the epoch machine's exact configuration into one parent-owned
composed-operation budget ledger for the complete provider/required-Action evidence
graph. Counters, retained UTF-8 bytes, and deadline are cumulative;
only the body ceiling is per body. No initial/final capture, candidate/sibling
evaluation, caller, release, or test input may reset, split, refund, borrow,
override, or reseal the ledger.
Register complete component evidence, then reduce only through one parent-owned
sealed composite coordinate binding required-status membership, final provider
validation, immutable epoch-origin clock, and current marker/attempt state; the
six planes are outputs, not separate reducer authorities. For the per-PR sole-job caller to
JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1,
floating @v1 is pre-execution trust, and dynamic post-run validation binds producer
receipt v1 and run/called-workflow identity. Bind receipt job.workflow_sha,
receipt action.ref, and unique exact-attempt referenced_workflows[].sha to W;
require its ref to be exact refs/tags/v1. Bind controlled exact-pinned checkout,
receipt action.commit_sha, provenance action.commit_oid, and
provenance tags.v1.peeled_commit_oid to selected candidate C. For every release
candidate, independently fetch and locally OpenPGP-verify its provenance-bound
release-R, derived-v1.minor, and historical-v1-T tag objects, each directly
targeting that candidate's C. Count W matches against only candidate T and C:
zero is proved-incompatible with otherwise complete valid proof, one is eligible,
and more than one is malformed ERROR. Independently authenticate and final-stably
reread current alias T_current->C_current; it is live audit/stability evidence and
never supplies W or validates historical candidate proof. Classify the complete
release-candidate vector as valid, proved-incompatible, or
malformed-or-incomplete-error; a valid signature by a different signer or zero
W matches may be proved-incompatible only with otherwise complete proof, while
missing/invalid/ambiguous/unverifiable tag proof, multiple matches, or any
integrity/cross-binding contradiction makes the whole admission ERROR. Exclude
only proved-incompatible candidates and require exactly one valid release with
all three tag proofs and one valid provenance-v2 asset. Never admit v1.5.0 or an
erratum path; v1.5.1 is first admitted. Independently authenticate the source commit and prove its
packages/action subtree equals the Action-C root tree as admission evidence.
The consumer pins neither selected called-workflow bytes/digest nor the selected
release's external Action SHA set; never substitute a Skill-pinned patch SHA,
tag object, commit, or workflow blob.
Treat any independent repository-owned scheduled dispatcher as bounded per-PR
transport into this caller only. It is not producer evidence, PASS, or an
alternate producer caller; its exact trigger, cadence, and permissions remain
repository policy rather than generic protocol or epoch-machine inputs.
A noncanonical repository-side compatibility status cannot satisfy PASS. Finish
with readiness gates and exact blockers. A +1 supplies neither PASS nor ACK. Record that the accepted
producer proof is run-level consistency rather than cryptographic job provenance
and that the contract has no post-publication revocation guarantee.
At or after 7,200 seconds, reduce any still-budgeted or other incomplete
acquisition to FAILURE before considering the narrow complete late-clean plus
canonical-success PASS arm.
```

The actual controlled request body is generated and validated by the canonical machine contract; prompt prose does not define its envelope.

## Review-Only Child Output

```text
[P0-P3] Short finding title

File: <path>:<line>
Property: <what must remain true>
Evidence: <bounded decisive facts>
Impact: <why this matters>
Repair direction: <minimal bounded direction, when useful>
```

Return no delivery plan, PR mutation, CI wait, merge action, or reviewer orchestration. If clean, use the lane's accepted clean form only.

## Parent Report Skeleton

```text
Requested/effective shape: <shape>
Repository/range: <repo> <base_sha>..<head_sha>
Selected PR/lifecycle/scope: <value or not-applicable>
Codex lane: <status/evidence>
Claude lane: <status/evidence>
request_policy: <status/warnings/evidence>
provider:
  classification: <status>
  evidence_basis: <selected provider basis or null>
required_action_status:
  decision: <PASS|FAILURE|PENDING|ERROR>
  reduction_authority: <one parent-owned sealed composite coordinate + required-status membership + final provider validation + immutable epoch-origin clock + current marker/attempt state>
  producer_binding: <caller @v1 + called-job repo/path + unique exact-attempt referenced ref refs/tags/v1 + receipt job.workflow_sha/action.ref/referenced_workflows.sha W + per-candidate provenance-bound and locally OpenPGP-verified release-R/derived-v1.minor/historical-v1-T direct-to-C proofs + candidate-local workflow_sha_resolution W-match count 0=proved-incompatible|1=eligible|>1=malformed-error + separate final-stable current alias T_current/C_current live proof that never substitutes for historical proof + complete ordered valid|proved-incompatible|malformed-or-incomplete-error release-candidate vector with missing/invalid/cross-binding global ERROR + GitHub-Releases-only immutable v1.x.y release/provenance-v2 asset/compatibility + v1.5.1 first-admitted and v1.5.0 never-admitted boundary + independently authenticated distinct source.commit_oid/packages-action-subtree-equals-Action-C-root admission proof + no consumer called-workflow-bytes/digest or external-Action-SHA-set pin + receipt/protocol/decision-schema/policy-major/policy-version evidence>
  evidence_resource_budget: <machine-owned exact-config equality + one composed-operation ledger + cumulative counters/retained-UTF-8/deadline + per-body body ceiling + no initial/final/candidate/sibling/caller/release/test reset/split/refund/borrow/override/reseal + exhaustion evidence>
named_github_lane: <disposition/evidence>
reaction_audit: <present/audit-only/PASS=false/ACK=false>
readiness: <merge-ready|pending|blocked|inconclusive + exact gates>
Findings: <summary>
Local gates: <actual commands/results>
Secret admission: <status>
CI/conversations/branch-base: <status>
Remaining risks/non-goals: <bounded list>
```

Never claim a test, reviewer, provider result, or readiness gate that was not actually completed.

## Low-Level Helper Results

Low-level `isolated_review` output remains diagnostic or compatibility evidence with `named_lane_eligible: false`. Report its backend, authentication source class, validation status, result, and recovery artifact metadata when applicable, but never present it as named single, double, or triple completion.
