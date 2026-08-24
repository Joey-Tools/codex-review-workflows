---
id: 20260822-ros001
title: Simplify Review Orchestration And Workspace Preparation
status: active
created: 2026-08-22
updated: 2026-08-24
branch: review-orchestration-simplification
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/108
supersedes: [20260807-wme001, 20260805-wpe001]
superseded_by:
---

# Simplify Review Orchestration And Workspace Preparation

## Summary

- Replace the exact-range-only local review control plane with one logical
  Codex lane that can use either a fresh-context subagent or fresh Codex CLI
  session under the same read-only, findings-only contract.
- Replace the old supplied-diff materializer with an independent-and-clean
  workspace contract. The current producer normalizes the exact review closure
  plus bounded base-history commit support into one independent pack; extra
  committed same-repository history is allowed by policy.
- Make a trustworthy terminal GitHub Codex clean result on the latest head,
  with no unresolved Codex finding, sufficient for the GitHub lane. Prefer a
  trustworthy associated merge-commit/status check when one exists.
- Keep `review-orchestration-playbook` as the single installed skill while
  splitting detailed local, workspace, Claude, GitHub, and readiness contracts
  into focused references. Global and repository `AGENTS.md` files retain only
  routing, authorization, and repository-specific exceptions.
- Treat `base_sha..head_sha` as the complete merge-inclusive commit DAG, never
  as a linear, first-parent, or `--ancestry-path` corridor. A base-to-feature
  merge is a valid branch update and creates a new head that must pass the
  complete pre-merge gate again.

## Decision Rationale

- The prior installed reviewer role resolved to GPT-5.6 Sol `xhigh`, while a
  fresh Codex CLI session supports GPT-5.6 Sol `ultra`. This candidate updates
  the role to the same `ultra` profile. The adapters are peers selected by
  verified effective capability and parent convenience, rather than by a fixed
  transport priority.
- OpenAI's API documentation names `max` as GPT-5.6 Sol's highest API
  `reasoning.effort`, while Codex exposes `ultra` as a product-level mode that
  may delegate internally. The released reviewer configuration therefore uses
  the Codex `ultra` profile and counts the resulting fresh session as one
  logical lane, without claiming that `ultra` is an API effort enum.
- Model discovery is intentionally exceptional. Query the latest eligible
  model only when the parent's effective model family or Codex mode is clearly
  stronger than the configured reviewer. A runtime rejection, downgrade, or
  mismatch instead triggers local capability diagnosis and same-profile peer
  fallback; it does not widen the lookup condition. Ordinary reviews trust the
  released role and skill defaults.
- A formal launch preflight showed that Codex CLI 0.149.0 rejects a positional
  custom prompt when `review --base` is selected, while that specialized
  surface supplies no receipt proving an stdin prompt was preserved. The CLI
  peer therefore uses fresh general `codex exec -` with the exact shared
  control prompt on stdin, and its receipt binds the prompt byte length and
  SHA-256 digest. A future specialized review entrypoint may replace it only
  after a capability probe proves both prompt preservation and frozen-range
  binding.
- The same preflight confirmed that `--ignore-user-config` suppresses the CLI
  config file, not the ambient instruction stack. Global `AGENTS.md` and any
  externally loaded skill therefore remain admissible only when their resolved
  paths and digests are parent-bound trusted guidance; an unexpected external
  read invalidates that attempt. When runtime telemetry omits effective
  model/mode, only a qualifying `accepted-pinned-launch` basis may project the
  requested pinned values as the execution-level effective profile. Without
  that basis the unproved fields are `unknown` and the lane is inconclusive; an
  observed mismatch or downgrade is likewise inconclusive.
- A subsequent PTY-based delivery visibly dropped and joined prompt bytes, so
  that process was stopped and invalidated before its output could count as a
  lane. Reliable CLI transport is direct stdin or a fixed parent-owned prompt
  file passed by one literal input redirection, with file identity, byte count,
  and SHA-256 verified before and after the process. Interactive PTY bulk input,
  pipelines, heredocs, command substitution, and prompt interpolation are not
  accepted transports.
- The prior exact-range materializer rejected shallow repositories and an
  earlier WME prototype incurred a 629,546,021-byte pack. Review correctness
  requires an independent Git namespace, an exact clean head checkout,
  complete local range objects, sanitized configuration, and a read-only
  reviewer; it does not require withholding same-repository history that is
  deliberately admitted by the workspace contract. The replacement producer
  accepts a locally complete shallow/promisor source and proved a
  626,427,312-byte normalized pack for WME's current 16,330-object snapshot.
- APFS reflinks can count as independent when a future implementation proves
  separate directory entries/inodes and copies only a validated immutable seed.
  The current producer deliberately uses one normalized pack after audit found
  that copying a live source object-store surface leaves collision, replacement,
  duplicate-pack, and traversal ambiguity. Hardlinks, alternates,
  linked-worktree common directories, shared object stores, and promisor or
  remote dependencies remain forbidden.
- This is a deterministic safety/simplicity tradeoff, not a claim that repacking
  is always fastest for very large repositories. A seed/reflink optimization is
  future-compatible with the public contract, but it must not reintroduce source
  lookup precedence or mutable-store dependencies.
- The bound pack keeps every scoped commit and that commit's complete snapshot,
  so a reviewer can inspect intermediate commits as well as the endpoint diff.
  Base ancestry contributes commit topology only; old pre-base trees/blobs that
  no scoped snapshot references do not block a partial local source.
- A fixed synthetic shallow boundary at `base_sha` is not correct for every
  merge DAG: a head-side path can re-enter pre-base history around that
  boundary, widening ordinary `git rev-list base_sha..head_sha`. Destination
  shallow state must instead represent only safely cut real missing-parent
  frontiers, preserve every scoped parent edge, and pass an ordinary-Git exact
  range comparison. An unsafe mixed frontier is `range-incomplete` and asks the
  parent for the smallest useful deepen operation.
- A shared missing frontier needs an even stronger proof. A visible path from
  an arbitrary base ancestor cannot prove that a candidate is outside
  `Reach(base)`, because an unseen bridge may make it base-reachable through a
  redundant merge. While that frontier exists, only a candidate proved to be
  a descendant of the exact base is admitted; otherwise preparation returns
  `range-incomplete` and requests the smallest useful deepen operation.
- An empty `.git/shallow` file still makes Git classify the destination as a
  shallow repository. A complete destination therefore omits that file and
  binds empty shallow bytes/digest in its receipts; a nonempty file exists only
  for a proved safe missing-parent frontier.
- Scoped commits can have a direct parent that predates the current merge base
  after the base branch moves. Those direct out-of-scope parent snapshots are
  support objects rather than review commits; importing their bounded snapshot
  closure lets the reviewer inspect each scoped parent diff without claiming a
  complete historical clone.
- A workspace producer must not copy a live checkout. It creates a fresh Git
  administration namespace from the source object authority, rebuilds safe
  config/refs/index state, checks out the frozen head, validates the range and
  clean state, and performs identity-bound cleanup.
- Workspace preparation does not fetch. A structured `range-incomplete`
  result must identify missing endpoints or objects and guide the parent to
  fetch exact refs or object scope first, without tags or submodules and with
  the smallest necessary shallow deepening instead of defaulting to
  `--unshallow`.
- For a promisor source, endpoint fetches alone may not hydrate missing blobs.
  The receipt therefore recommends bounded exact-object batches through
  `git fetch-pack --stdin`, repeats only when the reported sample is truncated,
  and refuses to recommend a whole-repository refetch or filter removal. The
  helper remains offline; the parent owns any separately authorized fetch.
- An unquiesced child process makes rollback unsafe even if publishing its
  recovery control also fails. All pack, Git-wrapper, checkout, validation, and
  streaming-integrity paths mark the workspace retained before attempting to
  seal recovery evidence. A sealed control binds PID, process group, start
  identity, root/control identities, exact bytes, and access policy.
- Exceptional recovery removes every repository/object payload but retains an
  authenticated tombstone: the same root inode is empty for a markerless
  partial workspace or contains only the original formal marker bytes, and the
  immutable control remains beside it. This deliberately small residue makes
  the same recovery argv idempotent and lets moved, missing, replaced, or
  content-drifted roots fail closed. Ordinary cleanup still removes a normal
  workspace completely.
- The existing terminal-payload policy attempted to prove provider input-base
  lineage that the GitHub OpenAI provider does not expose. Head-scoped clean
  evidence should prove only the GitHub lane; local and PR-readiness gates
  independently own base, merge-base, lifecycle, CI, and conversation state.
- A provider review binds through its native commit field, and a clean terminal
  issue comment binds through its exact reviewed-commit marker. The closed
  version-1 consumer grammar accepts no hashless terminal carrier; a stable
  request epoch is retained only for reaction fallback. This proves head
  association only and makes no claim about the provider's internal merge-base
  selection.
- GitHub names the strict freshness setting **Require branches to be up to date
  before merging**. It is distinct from **Require linear history**. When the
  former blocks a PR and a merge queue is not responsible for freshness, merge
  the current base branch into the feature branch; do not infer a rebase or
  force-push requirement. The resulting new head invalidates prior positive,
  pass, and clean evidence plus every head-bound readiness gate, so tests,
  review, GitHub/CI, conversation, policy, and final-reread gates all run again.
  An ancestry-proven unresolved provider finding that still applies to the new
  head remains blocking until a typed resolution or accepted later corrective
  artifact clears it.
- Obsolete public review entrypoints and their standalone reference are removed
  so the new skill cannot route agents back to them. Unadvertised internal
  compatibility code remains temporarily to avoid a risky one-shot deletion;
  supported secret admission and synthetic-token behavior remain intact.

## Implementation Plan

1. Reduce `SKILL.md` to review shapes, adapter selection, top-level completion
   predicates, ordered workflow, and conditional reference loading.
2. Update `agents/reviewer.toml` to GPT-5.6 Sol `ultra`, remove orchestration
   semantics from the role, and verify whether a fresh installed session
   honors the requested effort. Use the CLI peer when the role remains weaker.
3. Replace the named-lane workspace CLI with `prepare-workspace`,
   `validate-workspace`, and `cleanup-workspace`. Publish `exact-pack` as the
   current strategy while keeping the public contract implementation-neutral
   enough for a later validated immutable seed/reflink optimization.
4. Remove supported exact-range materialization and supplied-diff/stateful
   review entrypoints. Leave unreachable internals temporarily when deletion
   would add unrelated risk; keep only supported secret-admission and
   synthetic-token surfaces until their later extraction.
5. Introduce a compact GitHub lane module with latest-head terminal clean,
   unresolved-Codex-finding, preferred status-check, reconcile, retry, cost,
   and same-thread automation rules. The separate GitHub Action/status/ruleset
   workstream owns its later final revision.
6. Remove duplicated review protocol from repository/global routing text and
   adjacent skills, retaining one-line handoffs and repository exceptions.
7. Add focused runtime, contract, role-install, reference-integrity, and
   deprecation tests. Validate shell and Python entrypoints, the skill, and the
   project journal before review and commit.
8. Complete a fresh-context Codex review under the prior trusted released
   control plane, open and merge the canonical PR, and record its merge SHA and
   tree.
9. Merge a private companion that updates the overlay source-sync inventory
   and transformations, wait for that private head's release, then dispatch
   source sync. Wait for the generated sync PR to merge and for the final
   private merge SHA's immutable release; workflow success alone is not enough.
10. Run the local installer and verify the active skill, role, helper,
    source-lock provenance, and supported/deprecated command surfaces from the
    released bytes. A newly started Codex session is required to prove the
    installed reviewer role is loaded as `ultra` because this thread caches
    role metadata.

## Current State

- Design, implementation, independent runtime audit, and the first complete
  local validation are based on canonical base
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51`. Signed candidate
  `aa99912ff7bc1da1162966952be3cf3d9004d2b9` received an accepted whole-range
  fresh-context review with seven findings. All five implementation findings
  are fixed and covered by focused tests; two policy findings were adjudicated
  against Joey's explicit product decisions and are documented as intentional
  boundaries.
- The authoritative active installed release remains the prior trusted review
  control plane until this candidate is merged, released, and installed.
- The final frozen-tree canonical suite passes 3,010 tests with six conditional
  skips in 999.845 seconds with `ResourceWarning` promoted to an error under a
  controlled outer environment. The same 3,010-test run inside the restricted
  outer sandbox reached one environment-only failure when the nested macOS
  broker was rejected with `sandbox_apply: Operation not permitted`; that exact
  broker test passed independently in 1.845 seconds outside the nesting
  restriction before the complete outer-environment run passed.
- The replacement `exact-pack` producer prepared, validated, and ordinarily
  cleaned WME's locally complete current-head snapshot offline: 16,330 objects,
  one 626,427,312-byte pack and 804,700-byte index, 206.559 seconds to prepare,
  15.360 seconds to validate, and 3.089 seconds to clean. Prepare and validate
  receipts matched and the workspace was absent afterward.
- A non-empty historical WME range
  `22aa1421963330193abe00b4be6e67724f3a7363..5952543f04933eca60f9edb118e0f48a9dce58ef`
  correctly stopped offline because its partial clone lacked 49 old snapshot
  blobs. The receipt exposed 32 bounded OIDs and recommended exact promisor
  batching. A requested live Cisco hydration was rejected by the execution
  safety gate because that enterprise endpoint lacked explicit egress
  authorization; no workaround or network request was attempted. The
  current-head snapshot smoke supplied the large-repository performance check
  without that egress.
- The GitHub Action/status/ruleset implementation remains owned by the local
  Codex thread titled `评估并统一 @codex review 设计`; this workstream owns the
  skill-facing contract and handoff boundary.
- Draft PR #101 is that workstream's current implementation surface. This
  workstream lands first; PR #101 must refresh onto the resulting master and
  retain ownership of Action/status/ruleset producer details without
  redefining generic local-lane or GitHub-lane completion semantics.
- The private source-sync script currently hard-codes the old review reference
  inventory and text replacements. A private companion is a release
  prerequisite, not optional cleanup: without it, scheduled source sync will
  fail after the canonical simplification.
- The first formal CLI reviewer attempt was stopped and classified invalid
  before it could count as a lane: its specialized review entrypoint did not
  demonstrate delivery of the parent-bound control prompt. It ran read-only,
  changed no repository state, and exposed the prompt-transport contract gap
  now corrected above. The signed candidate head must be advanced and a new
  independent workspace reviewed from scratch.
- A later formal attempt also remained invalid: its PTY transport corrupted
  the already-hashed prompt in transit. The parent terminated it during
  read-only guidance inspection; it produced no accepted terminal artifact and
  changed no repository state. This second transport failure motivated the
  hash-verified file-redirection contract above.
- The first valid whole-range fresh-context CLI reviewer completed under the
  prior installed control plane and returned six actionable findings. They
  covered object-content integrity, no-follow and permission-bound control-file
  identities, uppercase skip-worktree flags, receipt-publication cleanup
  ownership, total object-store copy budgets, and precise merge-base error
  classification. All six were fixed before later whole-range reviews; no
  earlier clean result was carried forward.
- The six findings were implemented in the first post-review checkpoint. Range
  objects were canonical-content hashed; control state gained no-follow
  descriptor-bound custody; hidden index flags were strictly rejected; the
  then-current whole-store copy acquired bounded inventory, capacity, and
  monotonic deadlines; complete unrelated ranges were distinguished from
  incomplete graphs; and the CLI retained workspace cleanup ownership until
  exactly one terminal receipt had been flushed. The later normalized-pack
  design supersedes the whole-store-copy portion without discarding the other
  fixes.
- Follow-up race review also closed marker snapshot replacement, private parent
  policy, `mkdir`-to-identity acquisition, descriptor-bound quarantine removal,
  persistent signal-mask restore, and partial terminal-envelope publication
  boundaries. A successful exact-mask fallback preserves the original outcome;
  a persistently unusable process signal state terminates with the already
  published outcome instead of emitting a contradictory second result.
- A second independent runtime audit found that raw object-store copying still
  exposed mutable-source path races, duplicate pack/loose-object precedence,
  special-file and inventory ambiguities, and poor final dependency proofs. The
  supported producer now builds one bounded normalized pack from the exact review
  manifest plus base-history support commits. Raw-copy internals remain
  unreachable and explicitly deprecated rather than being deleted in the same
  migration.
- The same audit added endpoint-type classification, source-shallow replay,
  strict split-index and `ls-files` framing, checkout occurrence budgets,
  final one-pack dependency revalidation, process-group quiescence, marker/token
  and storage-identity receipts, descriptor-bound cleanup quarantine recovery,
  macOS extended-ACL checks, and signal-drain propagation. The protected
  properties are stable object/content/access-policy bindings during an
  operation; this helper does not claim an OS boundary against a continuously
  hostile same-UID ABA racer.
- The final recovery audit exercised 21 high-risk paths and found no release
  blocker. It covered retain-before-publish behavior for pack, post-root Git,
  and streaming integrity; spawn/signal assignment windows; escaped process
  groups; exact process identity; control terminal rereads; markerless and
  formal late-child injection; marker append and same-inode control drift;
  repeated recovery; ordinary-cleanup rejection; and the asymmetric shallow
  diamond. The final workspace suite passed 84 tests independently.
- Three post-fix read-only audits found no runtime release blocker. They
  independently checked Git 2.45 preflight and one-executable/no-lazy-fetch
  custody, protected-property timestamp handling, and partial recovery plus
  marker rebuild and recovery-only legacy routes. One test-strength finding
  was fixed by requiring the direct object-integrity assertion to observe the
  exact `git cat-file --batch` process rather than an arbitrary nested
  `Popen`.
- A new whole-range fresh Codex CLI review of signed head `163fa62` found five
  release blockers: descriptor custody was lost across cleanup-parent
  replacement and partial-recovery publication; source timestamp-only churn
  still failed closed as mutation; checkout attributes omitted `-ident` and a
  fallback buffered blobs below the checkout ceiling; and the retired
  independent review surface still exposed launch recipes. Independent
  reproductions confirmed all five. The old public surface will be removed
  without adding new navigation or tombstone guidance.
- Joey then clarified the merge-update invariant. The current raw scope walker
  already traverses every parent, but the destination's fixed `BASE+LF`
  shallow file makes ordinary Git range output incorrect when a feature forked
  before a moved base and later merged that base. The selected correction uses
  safe missing-frontier boundaries, exact ordinary-Git range and internal-edge
  validation, bounded direct-parent snapshot support, and minimal-deepen
  failure when a shallow graph has no safe representation.
- The completed merge-DAG implementation now derives `Reach(head) -
  Reach(base)` across every parent, separates review and parent-support object
  manifests, applies all object/pack/logical budgets to their union, omits an
  empty destination shallow file, and rejects shared-frontier ambiguity rather
  than widening a range. The workspace suite passes 117 tests after these
  corrections.
- Three timestamp-triggered revalidation paths now preserve the selected
  identity/content/access-policy property through their second proof window.
  If timestamps change again after the one allowed reread, they return
  inconclusive `revalidation-unavailable` evidence instead of accepting stale
  bytes or calling a timestamp delta a mutation.
- Signed checkpoint `2e899710950e717aaebf69480beb98cb9373704c` passed the
  complete 3,010-test suite with six conditional skips in 999.845 seconds,
  the 117-test workspace suite, policy/reference validation, Ruff, source-only
  compilation, shell checks, secret admission, and a formal whole-range CLI
  review. That review found six integration gaps introduced or exposed by the
  simplification; all six are fixed in the next checkpoint and receive fresh
  validation rather than reusing the old-head result.
- The public retired independent-review launcher and README remain absent.
  Legacy supervisor code is reachable only through a non-executable,
  test-internal harness so deterministic compatibility coverage can continue
  without restoring an agent-facing entrypoint or adding deprecation
  navigation.
- The local Codex prompt now carries one parent-owned
  `sanitized-git-argv-prefix-v1` token array and digest for either peer adapter.
  Prefix delivery, the read-only adapter boundary, and observed deviations are
  fail-closed; partial or unavailable argv telemetry is reported honestly and
  is not misrepresented as operating-system enforcement.
- GitHub terminal carriers now have a closed, versioned consumer grammar with
  data-driven fixtures for clean issue comments, clean reviews, top-level
  findings, joined inline findings, progress, stale/malformed records, actor
  near-misses, and thread resolution. Producer Actions, statuses, workflows,
  and rulesets remain owned by the separate PR #101 workstream.
- Same-head merge-base recovery now preserves an immutable parent-owned
  `range_origin`. A PR-derived range may be rederived automatically; a
  caller-supplied range requires the caller to explicitly provide or confirm
  the exact current endpoints, and missing provenance blocks PR-wide local
  coverage without invalidating separately trustworthy head-only GitHub
  evidence.
- Parent-support validation now reuses one range-commit set, reducing graph
  checks from `O(R*E)` to `O(R+E)`, and shares one 900-second monotonic phase
  deadline through subprocess, parsing, graph, snapshot, content, and final
  revalidation work. Descriptor-bound cleanup uses an iterative post-order
  stack, preserving custody and retained-marker semantics without depending on
  Python's recursion limit.
- The second audit pass bound each `range_origin` to an immutable lineage,
  append-only predecessor records, and one parent-owned active record. This
  prevents a caller-supplied same-head range from being silently replaced by a
  newly labelled PR-derived range after the merge base moves.
- The same pass made GitHub terminal evidence executable rather than
  prose-only. The closed consumer validates the parent-frozen repository, PR,
  base and head, a complete sorted ancestor projection, exact review/child
  joins, per-finding counts, and a basis-discriminated report. Terminal clean
  requires a non-null current-head artifact commit; `stable-request-epoch`
  remains reaction-only.
- GitHub's exact **Require branches to be up to date before merging** rule is
  now regression-tested as distinct from **Require linear history**. Without a
  merge queue, the authorized recovery is a signed base-to-feature merge
  commit followed by a newly frozen range and the complete validation, local
  review, GitHub review, CI, conversation, policy, and final-reread gate.
- The final integrated canonical run passed 3,028 tests with six conditional
  skips in 945.897 seconds with `ResourceWarning` promoted to an error. The
  final 33-test contract/carrier matrix, 127-test workspace module, Ruff lint
  and touched-file format checks, source-only compilation, ShellCheck, C
  syntax, core Action YAML validation, three skill validators, project-journal
  validation, JSON parsing, and whitespace checks also passed.

## Formal Review Evidence

### Review of `2e89971`

- Reviewed range:
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..2e899710950e717aaebf69480beb98cb9373704c`.
- Trusted control source: installed immutable private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`. The trusted skill, guard,
  prompt-template, and lane-contract SHA-256 values were respectively
  `76ae06111e6da1a04cab44e6fba5eb772af00b55c923e5234311edecb33449bd`,
  `2c8432731619e40cfae28a59e27d97be9cf58d48672d33a8b675141436a62cf8`,
  `4b2e05fbfc5cc79687b3cb7085a60821d5145bcd1aa29e6a895dbb6272b18bdf`,
  and
  `f16a47890bec42160703e7c0e353882df37a83dec911c0f0f93152641619a3b7`.
- Materialization and final validation agreed on two scoped commits, one parent
  edge, parent-graph SHA-256
  `d2289b62572b406e13f39ad2224c4c5589521602079f44d6f30ddfa5be0b0a8f`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- Codex CLI 0.149.0 ran a fresh ephemeral read-only review with requested
  `gpt-5.6-sol` / `ultra`. The fixed prompt was 8,573 bytes with SHA-256
  `30dece534844412617f3bab77e78d41e07bc6e031731d23343a90af0066251f0`.
  Event-stream, terminal, and stderr SHA-256 values were respectively
  `c695721900dd28f14ae5f90a902979ddb19230fc2d0016905ea3929549ad54d7`,
  `bee1247e95eb05ed8a09cb41972544a8bf5f1a6f57970d3416f5574dfc84a30a`,
  and
  `0bc8ae9bf1bf500f59bcdfcf49c026c0ebce8f6e38b42f8cfa9103e19208236e`.
- Finding disposition:
  - `deleted-supervisor-entrypoint-still-required-by-ci`: fixed with a
    non-executable test-only harness and explicit entrypoint injection; no
    public launcher or README was restored.
  - `reviewer-git-environment-not-fixed`: fixed by the shared parent-owned
    sanitized Git argv-prefix contract, lane receipt fields, adapter guidance,
    role prompt, and contract tests.
  - `github-terminal-carrier-grammar-open`: fixed with the closed version-1
    consumer grammar and reference classifier fixture matrix; hashless terminal
    comments are malformed, while stable request epochs remain reaction-only.
  - `parent-support-validation-quadratic-and-unbounded`: fixed with reused sets,
    periodic checks, and one phase-wide monotonic deadline.
  - `same-head-base-retarget-loses-range-provenance`: fixed with immutable
    parent-owned `range_origin` records and distinct caller-supplied versus
    PR-derived recovery.
  - `recursive-descriptor-cleanup-can-overflow`: fixed with iterative
    descriptor-custody post-order cleanup and deep-tree/error-unwind tests.

### Review of `163fa62`

- Reviewed range:
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..163fa62f475915c0b019c863a55da5da2e1f07fa`.
- Trusted control source: installed immutable private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`. Materialization and final
  validation agreed on seven scoped commits, six parent edges, parent-graph
  SHA-256
  `d49fcbf0071f860051d997b87287def48be525de0749f3abc6ab59d4bb7d5d57`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The fixed prompt was 5,294 bytes with SHA-256
  `705dd305bea6dcb85bc023db9e0bfc66c19a5545db98e3f9f1de074af19cc86f`.
  Reviewer thread: `01a02dad-83a9-72b0-b944-8ab1339b597a`.
  Terminal, event-stream, and stderr SHA-256 values were respectively
  `0c11c7fe16a156179e5915af7349bfb9d895d68adb77297c54c2801159dc29a5`,
  `3182ded51e1593bd05e3f152570bd7823abc0d78f4e68c8b28759645c1e7e5b8`,
  and `96577e8b89d60bdd8eea67332b497169c7540eefdc81edb99e87c504a3f0704f`.
- The requested profile was `gpt-5.6-sol` with Codex mode `ultra`. The five
  findings and the subsequent merge-DAG clarification were repaired before
  later signed heads received completely fresh whole-range reviews.

### Review of `aa99912`

- Reviewed range:
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..aa99912ff7bc1da1162966952be3cf3d9004d2b9`.
- Trusted control source: installed immutable private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`. Materialization and final
  validation agreed on six scoped commits, five parent edges, parent-graph
  SHA-256
  `d02adc14bdb11ca4da143235d9c9f45debe4c74bcffabeac24f431f3dc387043`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The fixed prompt was 4,398 bytes with SHA-256
  `e34ddb3490d33a1ccd19106956192333b930ee8c5635bb344b1654bbf443ff83`.
  Reviewer thread: `01a02d1e-52e6-74f1-a08e-185a3b4c8f10`. Terminal,
  event-stream, and stderr SHA-256 values were respectively
  `2a9359d18fbe0716d92a91ffafde198dc160f21a54a781f6c4fdca21bfbbfc23`,
  `9db47ce1c07e3f6053f41acf45d6bc5acf1150d63fa58e366872c8a847b0c8ab`,
  and `6f96394b1e4b874d650ba564a121d52d4e5d37c206a369cd5523da49c031586b`.
  The requested profile was `gpt-5.6-sol` / `ultra`; the runtime did not expose
  an authoritative effective-profile field, so no stronger claim is made.
- Finding disposition:
  - `workspace-git-version-preflight-missing`: fixed. Every workspace operation
    resolves and validates one absolute Git executable at version 2.45 or
    newer before repository Git runs, and all repository argv/environment
    paths disable lazy fetching.
  - `prepare-receipt-publication-rollback-no-recovery-capability`:
    fixed. A publication-plus-cleanup failure resolves and seals an
    owner-private external partial-recovery control before returning the
    parent-consumable capability; the owner must exit before recovery.
  - `post-validate-rollback-may-delete-marker-without-rebuild`:
    fixed. Late rollback reconstructs and verifies the exact original marker
    bytes when marker removal preceded a later failure.
  - `retired-stateful-recovery-routes-break-existing-retained-workspaces`:
    fixed through recovery-only `stateful status`, `stateful final`, and
    `stateful cleanup` migration routes. Retired review, start, wait, and
    admission entrypoints remain retired.
  - `timestamp-only-churn-treated-as-protected-property-mutation`:
    fixed. Timestamp changes trigger one full re-read but are not themselves
    mutation evidence; object identity, content, and access policy remain the
    protected properties and still fail closed on drift or unreadability.
  - `github-base-retarget-head-only-reuse`: adjudicated as intentional. GitHub
    provider evidence proves only the latest head; base and whole-PR assurance
    remain independent local/readiness responsibilities. A same-head base
    retarget may reuse qualifying provider evidence after final reread, without
    claiming the provider reviewed the new base.
  - `persistent-retry-no-terminal-ceiling`: adjudicated as intentional.
    Retryable GitHub recovery uses `1/2/4/8/16/32/60` minute backoff, reports
    at 60 minutes, then continues hourly without a retry ceiling. The state is
    caller-owned, single-flight, cancellable, cost-throttled for private repos,
    and does not enlarge mutation or egress authority.

### Earlier accepted review

- Reviewed range:
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..17b5284ce72b77787122177189ce5627eac7a918`.
- Trusted control source: installed immutable private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`; the candidate runtime was review
  subject only and no candidate executable code was used as review control.
- Materialization and final validation agreed on five scoped commits, four
  parent edges, parent-graph SHA-256
  `13d3d5d714671feba8e9ef2093f94325efbc5530b35791fe1ddea67895513b40`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The fixed parent-owned prompt was 6,257 bytes with SHA-256
  `b0e5210de9767b211fb6fcca947c83ead93f9477963f7b1232d4d6ee1895772e`;
  its path identity, size, and digest were unchanged before and after one
  literal stdin redirection into a fresh ephemeral read-only Codex CLI
  session. The reviewer thread ID was
  `01a02bf2-3da5-76d2-88c2-984664ac4596`.
- The requested profile was `gpt-5.6-sol` with Codex mode `ultra`. The runtime
  exposed no authoritative effective-profile field and no downgrade was
  observed, so effective model/mode evidence is recorded as `unknown` under
  the candidate contract rather than guessed.
- Terminal artifact SHA-256:
  `c52bbb415157754656fc677db7f352b0bf6ceec60610aabfc8414113184e7852`;
  JSON event stream SHA-256:
  `07bd7ef533af7ba350b2be3642b85e478e91c08839e448e5a35bca0589d9cf6b`;
  stderr SHA-256:
  `a8ac170844aad8ac842ae49079b7a19df97b6a7a891df237b07dd0f69400e533`.
- The task-owned review root was identity-checked and removed after the final
  trusted revalidation. The review was read-only and no repository or external
  state mutation was accepted.
- First post-fix local integration: `test_review_workspace.py` plus
  `test_named_lane.py` ran 305 tests in 187.378 seconds with
  `ResourceWarning` promoted to an error; all passed. After the second audit,
  the expanded pair ran 315 tests (`45 + 270`) in 203.750 seconds; all passed.
  The final focused suites passed `204` common-runtime tests with one
  conditional skip, `84` workspace tests, `271` named-lane tests, and `26`
  compact policy/distribution contracts. Ruff lint/format and
  `git diff --check` passed, and all three changed skills passed quick
  validation. The full suite and WME evidence are recorded above.

### Final-head formal review findings

- Reviewed range:
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..90585b6a87b4ed20fb57736c6d1724e40b1474b1`.
  The independently trusted control source remained private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`; candidate executable code was
  not used as review control.
- Materialization and the post-review trusted revalidation agreed on three
  scoped commits, two parent edges, parent-graph SHA-256
  `206e5051ebc7c8378b90d07ff0e33c2399507dbb73ad93044be48a5b463fbc14`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The parent-owned prompt was 8,858 bytes with SHA-256
  `0f52df1e9d7df4fb5e1eb5ab97eb8c7d1db981808c44c087a2999fb59b3a6fa6`.
  The findings terminal artifact SHA-256 was
  `a93a0a3e5109c33b1a3d6b1c4190591a094b98a20ebc66ccb4862c5f42746306`;
  the JSON event stream SHA-256 was
  `08287469ca9efc7c9f0a215b5c9c3edcb1eb44ddab55258bb99127a808e98319`;
  stderr SHA-256 was
  `63aab5657be324bf8ddbcbbcb2411fa6754eb5a93d0349dfeaa98e6ae428fbad`.
- The fresh GPT-5.6 Sol Ultra reviewer reported ten actionable findings. The
  accepted remediation plan is to:
  - regenerate and continuously verify the trusted Mac gate source manifest;
  - isolate the canonical CLI adapter from automatically loaded candidate and
    ambient guidance during self-policy migration;
  - make effective-profile acceptance unambiguous and fail closed on an
    unproved or mismatched runtime;
  - replace host `Path.resolve()` symlink traversal with bounded lexical and
    tracked-symlink-map containment;
  - freeze the exact repository/PR/head, Action/workflow, operation, and input
    tuple before a workflow rerun or dispatch, treat exact repetitions as
    idempotent, and still require external-mutation authority and single-flight;
  - retry only machine-classified transient infrastructure outcomes, never
    stable malformed or contradictory evidence;
  - add a closed no-selected-supported-PR report variant without weakening
    selected-PR scope requirements;
  - retain the validated repeatable synthetic-exemption compatibility
    argument without weakening secret admission;
  - include worst-case `--missing=print` frontier rows in parent-graph output
    budgeting; and
  - block only applicable unresolved provider findings, allowing typed
    same-head resolution or a trustworthy same-head provider correction.
- These findings invalidate `90585b6` as the final candidate. The next signed
  head must rerun the affected suites, the complete local gate, exact-secret
  admission, and a new fresh-context formal review.

### Final-head remediation and integrated gate

- All ten formal-review findings were fixed. Follow-up independent audits also
  closed four cross-cutting gaps before the final gate:
  - tracked-symlink chaining now follows the actual volume's case and Unicode
    alias semantics through root-relative no-follow lookups, while matching
    only double-read, inode/content-bound Git symlinks; unbound aliases fail
    closed and case-sensitive dangling targets remain valid;
  - every canonical Codex CLI lane now starts from an empty parent-owned
    neutral root, so candidate project configuration cannot inject developer
    instructions; the model-visible debug probe and exec-only capability/
    strict-launch evidence are separate, non-overclaiming receipts;
  - the always-read lane contract and prompt template now share the same
    transient-only recovery, exact-tuple intrinsic idempotency, mutation-
    authorization, and same-head typed-resolution rules as the GitHub field
    authority; and
  - the trusted Mac source-manifest generator now enforces the consumer's
    exact ASCII path grammar, no-follow ordinary-directory policy, entry,
    depth, path-byte, per-file, double-read total-byte, and manifest-byte
    ceilings, and its output is tested through the exact consumer parser.
- Focused post-remediation evidence includes 133 passing workspace tests, 304
  passing admission/workspace tests with one conditional skip, 65 passing
  combined contract/carrier/CLI/manifest tests, 13 passing symlink tests, and
  the deterministic 74-entry trusted Mac manifest regeneration/check.
- The first complete host-sandbox probe ran 3,051 tests in 1,065.851 seconds:
  3,050 passed, six were conditionally skipped, and one existing nested
  `sandbox-exec` test was rejected by the outer sandbox with return code 71.
  The exact test failed identically in isolation and did not expose a code
  assertion failure.
- The authoritative rerun outside that outer restriction used the same source,
  command, and `ResourceWarning`-as-error policy. All 3,051 tests passed with
  six conditional skips in 1,133.469 seconds. Ruff lint and format, 65 focused
  contracts, three skill validators, Action workflow syntax, JSON parsing,
  project-journal validation, and `git diff --check` also passed.

### CLI global-guidance isolation correction

- A final instruction-surface probe against signed head `0259e77` disproved
  the candidate contract's last CLI assumption. Codex CLI 0.149.0 still
  injected the probe `CODEX_HOME/AGENTS.md` marker while using a neutral launch
  root, `project_doc_max_bytes=0`, disabled skills/plugins/hooks, and the other
  supported guidance controls. The marker-free project and skill assertions
  passed, so the failure was isolated to global-home discovery rather than the
  neutral-root design.
- Official OpenAI documentation establishes both relevant boundaries: global
  `AGENTS.override.md`/`AGENTS.md` is selected from `CODEX_HOME`, while a
  file-backed login cache is `auth.json` under that same directory and may be
  copied as password-equivalent material. The chosen correction therefore does
  not trust or allowlist ambient global guidance. Every canonical CLI process
  instead receives a distinct owner-private temporary auth-only `CODEX_HOME`;
  the ordinary home remains parent-only source state, and a file-store or safe
  copy failure makes the CLI adapter unavailable so the peer subagent can be
  selected without changing the logical lane.
- The protected properties are source object identity and content stability,
  credential confidentiality, non-owner replacement exclusion, and destination
  access policy. Source `auth.json` is an owner-owned regular `0600` file;
  parent-directory traverse/read bits are benign, while group/other write is
  rejected. Parent-private no-follow identity/digest receipts bind the exact
  descriptor copy. Credential bytes are used only by the trusted Codex runtime
  and never enter prompts, events, or receipts; the contract explicitly does
  not claim that a read-only sandbox proves runtime/model-tool deny-read
  separation.
- Parent probes confirmed that an auth-only home preserved the existing
  ChatGPT login, removed all synthetic global/project/skill markers from
  `debug prompt-input`, and completed a bounded GPT-5.6 Sol Ultra sentinel
  execution. The original credential object's identity, metadata, and digest
  remained stable; no credential bytes or digest are recorded in this tracked
  journal. Runtime-created cache/tmp state is report-and-cleanup evidence only:
  no home is purged or reused, and each process-specific home is destroyed.
- Routine reviews do not pay for a second model execution. A credential-free
  prompt/capability probe plus forced-file `login status` precedes the actual
  review, and the review's own exact strict argv and structured terminal event
  provide accepted-pinned-launch evidence. A minimal model diagnostic is
  optional only when version, authentication, or flag behavior remains
  uncertain and never counts as a review.
- After this correction, the authoritative complete suite ran with
  `ResourceWarning` promoted to an error outside the outer sandbox restriction:
  all 3,052 tests passed, with six conditional skips, in 958.951 seconds. The
  48 focused policy/carrier/CLI/manifest contracts, Ruff lint/format, skill
  validation, project-journal validation, and `git diff --check` also passed.

### Auth-only CLI formal-review findings

- The frozen formal-review range was
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..3e4313c786ff431754749aaf2262056f22039ff1`.
  The independently trusted control source remained private-overlay release
  `f9e596f458a119fa88b89789c24c2290c37b4857`; candidate executable code was
  not used as review control.
- The dedicated `reviewer` role was unavailable at launch time. Because the
  accepted policy makes the fresh-context subagent and strict Codex CLI peer
  adapters for one logical Codex lane, the parent used one fresh
  `gpt-5.6-sol` Ultra CLI process rather than substituting a default child or
  starting a second reviewer.
- Materialization and post-review trusted validation agreed on five scoped
  commits, four parent edges, parent-graph SHA-256
  `482c7d50974eff31aa6c3ce4c79eac6dbffb95a39ce329257874b47802ecb68f`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The parent-owned prompt was 8,953 bytes with SHA-256
  `907d0bbe10aaf289b5a98b967c792fca69108538ee47ac3bc38385783e11596a`.
  The findings terminal artifact SHA-256 was
  `bf278c54162160d2c9faf8c86c0c95616661cb0fb3140008fe6808d36183b93f`;
  the complete JSON event stream SHA-256 was
  `4f37058370487b86df0195cbbff6b00d0f426c8e7ee50f1d158d649159c3ee7e`;
  stderr was empty with SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- The auth-only home preflight, postflight, and cleanup receipts proved the
  ordinary login file remained unchanged and the process-specific credential
  copy still matched it. The temporary review and empty-probe homes were
  destroyed after the terminal event; no credential bytes or credential
  digest are recorded here.
- The reviewer found two actionable contract defects:
  - ambiguous request delivery allowed a repeat in the GitHub probe/authority
    but prohibited it in the always-read lane contract and prompt; and
  - the lane-report validator accepted unresolved finding IDs without a
    closed, head-bound entry shape and allowed their cardinality to contradict
    the report status.
- The accepted remediation keeps the recorded Q22 recovery decision: after a
  read-before-repeat proves neither delivery nor absence, one recovery owner
  may repeat the exact request after backoff, with no concurrent POST and any
  duplicate reported as one logical-lane audit warning. The report schema must
  use closed finding entries bound to the selected PR/head and terminal
  evidence, require a non-empty list exactly for `status: findings`, and reject
  unresolved entries for `pass`, `pending`, `inconclusive`, or
  `not-applicable`.
- Both defects were remediated with a four-document ambiguous-delivery
  invariant and a closed report-entry/fixture matrix covering empty findings,
  findings in non-finding statuses, open fields, scope/evidence/head mismatch,
  resolved inline findings, and duplicate identities. The authoritative full
  suite then ran outside the outer sandbox with `ResourceWarning` promoted to
  an error: all 3,053 tests passed, with six conditional skips, in 980.329
  seconds.

### Final whole-range review and accepted boundaries

- A new fresh Codex CLI reviewer inspected the frozen range
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..ff7bc22ba6358843dbcda4939c2dfcaeab12d633`
  from an independently materialized workspace. Pre- and post-review receipts
  agreed on six scoped commits, five parent edges, parent-graph SHA-256
  `81552a554eb8c0b5ba073e82d600eee15a9860811a4a6772c8ad3fdb1fbe0e5d`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The parent-owned prompt was 9,466 bytes with SHA-256
  `0b303bc1137c69ee00ec9c844b12f4180137d27e18df3471021ed2e337023be8`.
  The complete event stream SHA-256 was
  `9bb61e848a3dfe34ec68130e718e2fea297809836434b4bdcf4b6861b3b426af`;
  the terminal findings artifact SHA-256 was
  `3c1afcd9c4f99275ffb5fc4f16b989bef6e85dd828ec68103ca7a8e54c4d0ee5`;
  stderr was empty. The auth-only review home and empty probe home were removed,
  and the ordinary authentication object remained unchanged.
- Two reviewer requests for stronger guarantees were intentionally not
  adopted because they contradict explicit product decisions rather than
  reveal internal inconsistency:
  - GitHub Codex completion is deliberately head-only. It proves the exact
    current head, not the PR base or merge base. A base change reruns local and
    readiness gates, and no report may claim that the provider reviewed the
    base.
  - After read-before-repeat remains ambiguous, one recovery owner may retry
    the exact GitHub review request with backoff. Duplicate delivery remains a
    one-lane audit warning; concurrent or uncontrolled posting is still
    forbidden.
- Five actionable findings were accepted and remediated:
  - a preferred merge/status basis now requires independent parent scope,
    exact current-head commit, stable check-run identity and URL, verified App
    and check-name contract, `completed` plus `success`, and an association to
    accepted same-head provider-clean evidence;
  - every squash, amend, base-refresh merge, or other head-changing landing
    transformation must precede final frozen review, while any later commit
    invalidates the prior exact-head result and reruns validation and review;
  - the legacy public-command test harness was removed and replaced by an
    internal-worker-only fixture that cannot forward `run` or another public
    supervisor command;
  - the exact range and parent-support object union is now counted against the
    logical-byte ceiling before pack generation, with bounded error mapping
    and post-pack integrity checks retained; and
  - an absent gitlink is accepted only through its exact NUL-framed,
    path-and-OID-bound status record, while every other deletion or dirty state
    remains blocking and materialized submodule content is rechecked.
- Two bounded combined-patch audits then found and closed five integration
  gaps without changing the selected product behavior: merge-status contracts
  are now independently parent-bound rather than report-self-authenticating;
  nested clean channel/grammar pairs are closed; in-process legacy tests
  restore `SIGPIPE` in `finally`; staged index data is read once and shared
  between link and clean validation; and every pre-pack error mapping preserves
  process-quiescence uncertainty from its complete exception graph.
- The first complete combined-tree test run executed 3,063 tests with six
  conditional skips in 947.905 seconds. Its sole failure was environmental:
  the outer execution sandbox rejected the nested Claude broker
  `sandbox-exec` with return code 71 before the code assertion could run. The
  authoritative rerun outside that outer restriction used the same tree,
  command, and `ResourceWarning`-as-error policy; all 3,063 tests passed with
  the same six skips in 984.620 seconds.

### Exact-scope review follow-up

- Signed head `a90ffc66652182d3f2d4c5caa9c7acbee3cf2b6e` received one
  fresh-context GPT-5.6 Sol Ultra CLI review over
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..a90ffc66652182d3f2d4c5caa9c7acbee3cf2b6e`
  under the independently trusted pre-migration release. Pre- and post-review
  validation receipts were byte-identical: seven scoped commits, six parent
  edges, parent-graph SHA-256
  `a34e17792f9a526f92c8eea38b97e70f9875c1a08a6aa7a359a15546d67c51e3`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
- The 10,519-byte parent-owned prompt had SHA-256
  `1f21c8aa3465e339ba5d06559ffa2d2d7ca09b1092da48537b89a05fbcf54bdf`.
  Event-stream and terminal-artifact SHA-256 values were respectively
  `6e5cca6bae213bb79864a4882be4b134fa58fd12ecd90d0944b70b7348568b8e`
  and
  `5d1efaecbf8b47f0a217be0aee9700fcb508201e87e609ce346bdc879cb7760b`;
  stderr was empty. The ordinary authentication file remained unchanged and
  the process-specific auth-only home was destroyed after review.
- The reviewer found two remaining contract defects. Direct terminal and
  reaction positive branches could accept evidence URLs whose repository, PR,
  channel fragment, evidence ID, or request ID did not match the selected
  report scope. The fix separately freezes parent-owned PR scope, terminal
  identity, and reaction/request identity before the report is parsed, then
  requires the report and exact HTTPS `github.com` channel fragment to match
  those independent closed inputs. Cross-repository, cross-PR, cross-ID,
  wrong-fragment, non-HTTPS, and coupled-mutation fixtures all fail closed; an
  independent read-only audit reproduced the rejected coupled mutations and
  accepted the issue, review, and reaction positive paths.
- The same review found that the candidate published two incompatible meanings
  of `sanitized-git-argv-prefix-v1`: documentation required a Git global
  `--no-lazy-fetch` token that the accepted adapter did not contain. The fixed
  profile uses `GIT_NO_LAZY_FETCH=1` as its sole no-lazy control and adds an
  independently trusted `codex-git-prefix` machine producer plus an exact-token
  validator. A recomputed digest cannot make an inserted, omitted, or reordered
  token conform. Self-policy migration still uses only the prior trusted guard;
  the candidate producer remains review subject until release.
- The remediation passed the nine-test carrier matrix, the 34-test combined
  contract/local-lane matrix, the complete 275-test named-lane module, Ruff
  lint and format checks, JSON parsing, the skill validator, and whitespace
  checks. These focused results do not replace the final whole-tree suite,
  secret admission, or a new fresh-context review of the advanced signed head.
- The final integrated tree then passed all 3,066 review-playbook tests with
  six conditional skips in 974.578 seconds outside the outer sandbox, with
  `ResourceWarning` promoted to an error. The first invocation used the wrong
  repository-root `tests/` discovery path and exited before loading tests; the
  authoritative run used the repository's documented
  `skills/review-orchestration-playbook/tests` discovery root.
- Signed head `bfe194cbdde87895180b2f0433b319515145fd46` then received a
  fresh-context GPT-5.6 Sol Ultra CLI review over the same frozen base. The
  independently trusted prior-release materializer and validator agreed
  before and after review on eight scoped commits, seven parent edges,
  parent-graph SHA-256
  `e6945a0331570797a33bbac96cb7398d571a1ecdb9ebf3f742061e4c45fa0c61`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The 11,658-byte prompt SHA-256 was
  `96fbc5289072cc551cb6699c4999d0aea4ae87e53b8cd5ea60aa7f6b6e9a8c1b`;
  the 580-event JSONL and terminal findings SHA-256 values were respectively
  `c9ab27bc9c81fd6a0cbde4fd9ac8c975dc9cb063dba4746c6c68c90ff0a5ccc4`
  and
  `9b1074dcc5fe6c54189fdb211c3374460749330bb9ca3f335871e29618ec925f`.
  The process exited zero with one complete turn; a single model-catalog
  refresh connection error was retained separately on stderr and was not
  silently treated as clean evidence. Because the published candidate has no
  version-bound classifier for that error and the terminal event does not
  attest the effective model/mode, the raw findings are actionable but the
  effective profile remains `unknown` and this attempt is lane-inconclusive.
  The ordinary authentication file stayed byte-identical, the actual review
  home introduced no guidance-bearing path, and that one-time home was
  destroyed after its inventory was recorded.
- That review found three remaining defects: non-positive GitHub terminal
  variants were not bound to an independent parent-owned PR-selection outcome;
  a caller could place a materialized destination inside the source, Git
  administration, common, or object-store authority; and the missing-object
  snapshot bound undercounted SHA-256 marker rows while failing to combine
  present and missing rows under one object ceiling.
- The report grammar now requires a closed parent-owned selection outcome before
  every pass, findings, pending, inconclusive, or not-applicable branch. Selected
  PR and proved-no-selected-supported-PR outcomes are mutually exclusive and
  must match the complete report repository/PR/head projection. Coupled report
  and parent mutations fail closed; the complete 12-test carrier module and an
  independent read-only audit passed.
- Workspace creation now binds the resolved source worktree, Git directory,
  common directory, and every local object-store authority, revalidates their
  descriptor identities immediately before creation, and rejects a destination
  parent equal to or below any authority through its real ancestor chain. The
  SHA-1/SHA-256-aware object snapshot reader budgets `?OID` rows correctly and
  counts every present, missing, and duplicate row before deduplication. The
  complete 144-test workspace module, a six-test focused rerun, Ruff, the skill
  validator, whitespace checks, and an independent read-only audit passed; the
  audit's one low-severity parent-fd cleanup finding was fixed and regression
  tested. A final audit then requested explicit duplicate present/missing row
  cases and all-owned-fd closure assertions; both were added and passed with
  `ResourceWarning` promoted to an error before the audit returned
  `No findings`.
- The final integrated tree passed all 3,074 review-playbook tests with six
  conditional skips in 958.714 seconds outside the outer sandbox, with
  `ResourceWarning` promoted to an error. An earlier run was intentionally
  interrupted after the audit identified the two missing regression cases and
  is not counted as validation evidence; its exact temporary directory was
  subsequently absent.
- Private-release readiness inventory confirmed the canonical reviewer role is
  copied through `personal_codex/agents/reviewer.toml` into the installed
  `agents/reviewer.toml`. It also found two downstream prerequisites: the
  companion exact inventory must use
  `scripts/independent_codex_pr_review/tests/internal_supervisor_child_fixture.py`,
  and the seven-repository default `skill-repo-codex-gate` routing must land in
  the `codex-workspace` mother-repository `AGENTS.md` before the companion can
  truthfully remove that exception from global guidance.
- A later fresh-context review of signed head
  `b9504e4b8f3ff68da67150c924f0a8423d0eefee` found four remaining policy and
  delivery defects. Self-policy review could still let candidate guidance enter
  a subagent control surface; reaction evidence could be rebound to another
  head; merge execution lacked an atomic reviewed-head precondition; and an
  all-resolved inline-finding state had no closed outcome. None of that review's
  output is reused as clean evidence for the repaired head.
- The local Codex contract now treats candidate policy Markdown only as a
  parent-enumerated, digest-bound review subject. A subagent counts only when a
  parent-verifiable receipt covers every host instruction-injection source; if
  that cannot be proved, the CLI peer is required or the lane is inconclusive.
  Role identity, zero inherited turns, and a read-only sandbox are necessary
  but not sufficient evidence for self-policy isolation.
- Reaction fallback is now bound to one independently parent-frozen exact-head
  epoch. A record for head A cannot be relabelled or coupled to producer fields
  for head B. A latest current-head inline-finding artifact whose complete
  stable thread scan proves all findings resolved is explicitly
  `resolved-inline-awaiting-clean`: it remains pending and may drive an
  idempotent Action reconcile, but it cannot pass until a later accepted
  current-head terminal clean artifact exists and the full scan still proves
  no unresolved provider finding.
- Direct merge now carries the reviewed head through GitHub CLI's
  `--match-head-commit`. Merge-queue enrollment uses the asynchronous REST
  merge endpoint with exact `sha` plus `merge_action: merge_queue`, persists
  its UUID, and requires every pending result's `expected_head_sha` to remain
  equal to the reviewed head. Long-lived `autoMergeRequest` is not equivalent;
  unavailable asynchronous queue support blocks instead of weakening the
  contract.
- The deterministic macOS supervisor inventory advanced from 847 to 848
  selected tests after a new in-process CLI signal-restoration regression was
  added. Its recomputed selected-identity SHA-256 is
  `6c7be4c1f1fe9a69c5e0af931f9f9c404bd5a7d8c9b7c0b856d5085616a02f18`;
  the exact secure runner first passed all 848 selected tests in 279.914
  seconds, an independent inventory audit returned `No findings`, and the
  final frozen-tree rerun passed the same 848 identities in 249.971 seconds.
- The final full-suite run exposed a probabilistic public-CLI defect rather
  than accepting a flaky retry: a URL-safe cleanup token has a 1-in-64 chance
  to begin with `-`, which argparse interprets as a new option in the documented
  `--token VALUE` form. New tokens now carry a fixed `rw1_` prefix while
  retaining all 32 random bytes; digest validation remains compatible with old
  receipts, including old leading-dash values supplied as `--token=VALUE`. A
  deterministic leading-dash regression and an independent diagnosis both
  confirmed the fix.
- The authoritative final outer-environment suite passed all 3,081 tests with
  six conditional skips in 982.646 seconds with `ResourceWarning` promoted to
  an error. The immediately preceding restricted-outer run is not counted as
  success: it found the cleanup-token defect above and separately hit the known
  nested macOS `sandbox_apply: Operation not permitted` limitation. The exact
  broker test then passed independently outside that nested restriction in
  1.865 seconds before the complete outer-environment run passed.
- The mother-repository routing prerequisite landed through
  `Joey-Tools/codex-workspace` PR 12 as signed squash merge
  `1c3b9c9662ef8c3ed5ddad2c3e272fb6a0eec526`. Its self-contained
  `skill-repo-codex-gate` uses one fresh local Codex processor plus exact-current-
  head GitHub Codex, leaves named single/double/triple semantics untouched, and
  keeps repository-specific exceptions out of this installed skill.
- Draft PR 108's first current-head CI run exposed two cross-platform test-
  control defects. On Linux, an `unlink`-then-recreate replacement fixture could
  immediately reuse the released inode, so its own object-identity premise did
  not hold; the fixture now allocates a distinct private object before atomic
  replacement and explicitly proves `samestat` is false. On macOS, the closed
  source-only loader did not mark its manifest-bound module spec as having a
  location, so importlib omitted `__file__`. The loader now retains its captured-
  byte execution and empty package search path while publishing the exact
  authenticated source path through standard `__file__`, `origin`, and
  `has_location` metadata.
- The stabilized Mac loader tree passed all 848 deterministic supervisor tests
  in 261.366 seconds, seven focused loader tests, and four manifest tests. An
  earlier 848-test invocation is not evidence because its task wrapper used
  `umask 077` and created synthetic Git worktree files with the wrong mode; the
  valid rerun restored `umask 022`. Four focused recovery tests and an
  independent read-only review of the combined four-file CI correction also
  passed with `No findings`.
- The corrected integrated tree passed all 3,081 review-playbook tests with six
  conditional skips in 1,028.611 seconds outside the outer sandbox, with
  `ResourceWarning` promoted to an error. A same-head CLI review attempt is
  explicitly inconclusive rather than clean: the outer sandbox prevented every
  nested model command with `sandbox_apply: Operation not permitted`. The
  trusted post-attempt workspace receipt remained byte-identical, the ordinary
  authentication file was unchanged, and the one-time auth-only home was
  destroyed. A new signed head must receive a fresh host-bound review.

### Final policy closure after `4c8636d`

- Signed head `4c8636d17e16773f6445b3ff34f1d77adb72c22a` received a fresh
  host-bound GPT-5.6 Sol Ultra CLI review under the independently trusted
  pre-migration release. The reviewer found three policy defects: the positive
  GitHub result did not bind a complete stable PR snapshot, an observed target
  base change did not invalidate all non-provider readiness gates, and the
  self-policy contract could not express Joey's selected local-Codex-only use
  of an applicable candidate `AGENTS.md` as both scoped convention and review
  subject. No clean result from that head is reused.
- The complete snapshot now closes initial and final parent-owned inventories,
  terminal selection, unresolved-finding/thread state, and the exact positive
  basis. Terminal, reaction fallback, and preferred merge/status paths each
  bind their own independently selected IDs, URLs, actors/apps, times, head,
  and producer contract before joining the lane report. Coupled report plus
  reaction/check mutation, open fields, missing projections, and initial/final
  drift all fail closed. The 61-test carrier/recovery/contract matrix and an
  independent fresh-context audit passed with `No findings.`.
- Self-policy migration now derives a closed
  `candidate-markdown-required-subject-set-v1` directly from the frozen range
  and binds its base, head, path count, and canonical ordered-path digest into
  parent, prompt, and lane-report projections. The exact candidate Markdown
  inventory must reproduce that independent set, and local Codex admission
  must reproduce the inventory. Only a parent-proved applicable candidate
  `AGENTS.md` may use `purpose: both` with
  `role: scoped-convention-and-review-subject`; every other candidate Markdown
  remains review-subject only. Claude obeys only prior trusted external
  guidance and treats every candidate file, including `AGENTS.md`, solely as
  review subject. Empty/subset/superset inventories, same-cardinality path
  substitution, coupled omission, byte drift, and open-field variants are
  rejected. The 44-test self-policy/contract matrix and two independent audits
  passed with `No findings.`.
- GitHub's exact **Require branches to be up to date before merging** setting
  remains explicitly distinct from **Require linear history**. When no merge
  queue owns freshness, a signed base-to-feature merge is the supported branch
  update. The new head reacquires tests, local review, GitHub review, CI,
  conversations, policy, and final reread. Only old-head positive/pass/clean
  evidence becomes stale; an ancestry-proven unresolved provider finding that
  still applies remains blocking. A final independent Q44 audit found and
  removed one residual merge-queue phrase that had incorrectly said all
  old-head evidence was invalidated. The contract now rejects that broad phrase
  across both the top-level skill and the complete readiness reference; the
  final audit returned `No findings.`.
- The combined focused policy matrix passed 73 tests. Ruff lint and format,
  reviewer TOML parsing, terminal-carrier JSON parsing, skill validation,
  project-journal validation, and `git diff --check` also passed. The
  authoritative complete suite then ran outside the nested macOS sandbox
  restriction with `ResourceWarning` promoted to an error: all 3,095 tests
  passed with six conditional skips in 1,148.966 seconds.

### Formal review remediation after `8d4f7b5`

- Signed head `8d4f7b50586049ff176cb061fd96cf8267670149` received one
  fresh host-bound GPT-5.6 Sol Ultra CLI review under the independently trusted
  pre-migration release. The reviewer found three implementation defects: the
  named-direct Claude guard forwarded caller-owned argv beyond the validated
  executable, candidate `.gitattributes` could hide textual hunks through
  `-diff`, and the split-index check could mistake pathname bytes containing
  `link` for a real index extension. That head did not pass local review and no
  clean evidence from it will be reused.
- The Claude named-direct lane now accepts exactly one absolute,
  preflight-bound executable after `--` and constructs the complete argument
  vector itself. The closed 4.8 profile fixes text input, maximum effort,
  `dontAsk`, stream JSON, safe mode, settings sources, an empty MCP map, the
  four read-only review tools, explicit disallowed mutation/network tools, and
  a canonical inline settings object. The launch receipt binds the selected
  executable, exact settings, guard/effective argv, environment, outputs,
  source deny roots, and guard-managed session identity. Direct 4.7 launch was
  removed; retained 4.7 stream schemas remain compatibility evidence only.
- The settings receipt deliberately says
  `requested-configuration-only`: capability probing and runtime init evidence
  do not attest that managed policy left the requested sandbox arrays
  unchanged, that the selected binary accepted every settings field, or that
  the merged native sandbox was effective. A trusted parent must independently
  reconstruct and exact-check the launch receipt before separately validating
  the raw stream. Source/materialization lineage likewise remains a parent
  comparison; the guard validates canonical source/admin/common roots for its
  deny boundary without claiming that an arbitrary caller path is authoritative.
- The independent workspace now writes the highest-precedence private
  attributes rule `* diff -text -eol -filter -ident -working-tree-encoding`.
  It therefore forces Git's built-in textual diff while retaining the existing
  checkout-transform closure. Index validation now parses DIRC v2, v3, and v4
  entries for SHA-1 or SHA-256 repositories, validates entry counts, flags,
  pathname framing, padding, prefix compression, checksum, and extension
  framing, and treats only an actual `link` extension as split-index state.
- Two final cross-contract audits found and closed runtime/resource boundary
  gaps. The Claude child fixes sanitized Git's global/system/graft paths at
  `/dev/null` while denying `/dev`; the settings now retain the broad deny but
  add the sole identity-validated exact `/dev/null` read exception required by
  those Git controls. Every other overlap, including `/dev/zero`, remains
  blocked, and the receipt revalidates and binds the character-device identity
  before publication. Separately, DIRC v4 prefix compression could amplify a
  small encoded index into repeated large pathname copies. The parser now
  computes each decoded length and applies the existing 64 MiB aggregate
  checkout path-byte ceiling before materializing the path; v2 and v3 use the
  same aggregate bound.
- The stable combined candidate passed `test_named_lane.py` (284 tests in
  177.273 seconds), `test_review_workspace.py` (150 tests in 171.047 seconds),
  `test_claude_capabilities.py` (31 tests), and `test_contracts.py` (32 tests),
  all with `ResourceWarning` promoted to an error. The final cross-contract
  read-only audit returned `No findings.`. Ruff lint/format, source-only
  compile, reviewer TOML parsing, all three affected skill validators, project-
  journal validation, and whitespace checks passed. The authoritative complete
  suite then passed all 3,112 tests with six conditional skips in 1,000.276
  seconds outside the nested macOS sandbox, with `ResourceWarning` promoted to
  an error.

### Formal review remediation after `236242e`

- Signed head `236242e212f552181dcce6aa8374caae3f46f658` received a fresh
  host-bound GPT-5.6 Sol Ultra CLI review under the independently trusted prior
  release. The terminal process completed, but the result contained three
  findings, so that head is not a local-review pass: ordinary reviews could
  silently omit candidate-head repository guidance while automatic project-
  document loading was disabled; Shared Metadata did not bind the actual
  review process's auth-only `CODEX_HOME` receipt; and the journal's profile
  rule did not make every unqualified `unknown` effective profile
  inconclusive. The post-review workspace receipts matched the frozen range,
  the source authentication file remained byte-identical, and the temporary
  review root was deleted.
- Ordinary review now uses two mutually exclusive candidate-Markdown surfaces.
  `self_policy_migration: false` requires the range-bound
  `ordinary-candidate-guidance-required-set-v1` receipt plus the closed
  `ordinary-candidate-guidance-v1` projection, while every
  `candidate_markdown_*` field is not applicable. Self-policy migration
  requires every `ordinary_candidate_guidance*` field to be not applicable and
  retains the stricter required-subject, inventory, and admission records.
  Simultaneously supplying both surfaces is inconclusive in the role and both
  model prompts.
- The ordinary required-set receipt binds the frozen base/head, the complete
  recursively enumerated endpoint-tree non-tree leaf changed-path set, the
  total guidance path set, and four
  independently parent-derived purpose partitions by exact count and canonical
  path-array digest. OpenAI's documented
  [instruction discovery order](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
  selects at most one file per directory: `AGENTS.override.md`, then
  `AGENTS.md`, then configured fallback names. This closed launch binds the
  exact fallback list as empty in parent, prompt, and report evidence because
  user configuration is ignored. The selected root file is the repository
  convention; a selected non-root file is path-scoped only when its parent
  directory is an ancestor of at least one changed path. Domain/project
  guidance cannot relabel either instruction filename. Applicability retains
  a distinct root-to-leaf stack for each changed leaf, while each purpose
  partition uses UTF-8 path-byte order only as canonical transport. The
  projection must reproduce every partition and candidate-head digest across
  parent, prompt, and report. `parent-proved-empty` therefore cannot be an
  empty-array assertion: it must bind the current changed-path scope and prove
  all four independently derived sets empty. Old-range replay, omitted
  applicable guidance, label swaps, unrelated nested conventions, non-UTF-8
  paths, and open or mismatched records are inconclusive.
- Ordinary and self-policy candidate projections now use exact compact
  canonical UTF-8 JSON as their transport. Parent, prompt, and report bind the
  encoded bytes and decoded types; the sanitized Git prefix is version 2 and
  fixes `GIT_LITERAL_PATHSPECS=1`, while each decoded candidate path is one
  exact argv token after `--`. Quoted, newline-bearing, and pathspec-shaped
  names therefore remain data rather than Git selectors; a path that is not
  losslessly representable in the closed encoding is inconclusive rather than
  an exception or an invitation to reinterpret it. Directory tree nodes are
  excluded from the changed-path inventory even when their tree OIDs change;
  tracked regular blobs, symlink blobs, and gitlinks are the endpoint leaves.
- Both ordinary model prompts now share the same closed guidance boundary:
  only enumerated candidate Markdown may be obeyed or used as guidance, each
  path is limited to its declared purpose, and candidate content cannot route
  to an unlisted control source. Unenumerated changed Markdown such as a
  `README.md` remains fully reviewable as subject code/documentation and may be
  read with necessary tracked context; it simply never becomes guidance or a
  control-plane input. The Local Codex and Claude actual prompts are each
  self-contained for the endpoint-leaf algorithm, empty proof, four exact
  purpose/path couplings, and canonical UTF-8 JSON encoder, including fixed
  non-ASCII, U+2028, backslash, NUL, and lone-surrogate behavior. Neither
  reviewer is asked to prevalidate a future report-only equality field.
- The exact boolean `self_policy_migration` discriminant is bound between
  parent and prompt before launch and among parent, prompt, and report after
  termination. Its inactive route has one closed `not-applicable` shape, so a
  coupled route reinterpretation, non-boolean value, or later discriminant
  drift is inconclusive. Executable oracles also reject malformed endpoint
  modes/object IDs, tree/leaf contradictions, unhashable status fields, and
  omitted changed leaves rather than raising or manufacturing evidence.
- Candidate guidance and self-policy subject records accept only exact regular
  Git blob modes `100644` and `100755`, bind the blob bytes without filesystem
  dereference, and reject symlink, gitlink, tree, or other modes as
  inconclusive. Because adding `git_mode` changes two already published closed
  self-policy record shapes, the active profiles are
  `candidate-markdown-subject-inventory-v2` and
  `candidate-markdown-admission-v2`; their old v1 forms cannot satisfy the new
  candidate control plane. `candidate-markdown-required-subject-set-v1`
  remains v1 because its endpoint/count/path-digest shape did not change, and
  the newly introduced ordinary-guidance profiles remain v1 because they have
  not previously shipped. Bootstrap review still runs under the independently
  trusted prior policy rather than executing candidate-head control code. For
  self-policy Local Codex admission, the parent-selected applicable
  `AGENTS.override.md` shadows same-directory `AGENTS.md`; Claude treats either
  filename solely as review subject.
- The actual CLI review process receives a prelaunch opaque parent-private
  auth-home receipt identity and the final lane report must repeat that identity
  after post-run validation and cleanup.
  The effective-profile rule now permits
  requested-value projection only under a qualifying
  `accepted-pinned-launch`; otherwise missing runtime telemetry is `unknown`
  and inconclusive, as is any observed mismatch or downgrade.
- GitHub's official protected-branch documentation confirms the exact strict
  setting name [Require branches to be up to date before merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
  It remains separate from `Require linear history`. When strict freshness
  blocks and no merge queue owns it, this workstream authorizes a signed merge
  of the current base into the feature branch, followed by a new frozen range
  and the complete test, local-review, GitHub-review, CI, conversation, policy,
  and final-reread gate. No new guidance routes reviewers toward the retired
  supplied-diff helper.
- The post-remediation focused contract, recovery, terminal-carrier, and local-
  lane matrix passes all 77 tests in 3.608 seconds. Ruff lint and format, the
  skill validator, and `git diff --check` pass, and the final independent
  stable-snapshot contract audit returned `No findings.`. This is focused
  evidence only; the complete authoritative suite and fresh whole-range review
  must be rerun after the candidate snapshot is frozen.
- The first complete post-remediation probe ran 3,116 tests in 1,137.817
  seconds: 3,115 passed, six were conditionally skipped, and the existing
  nested macOS keychain-broker test was rejected by the outer sandbox with
  `sandbox_apply: Operation not permitted` and return code 71. The exact test
  then passed independently outside that nesting restriction in 1.990 seconds.
  The authoritative complete rerun used the same source and
  `ResourceWarning`-as-error policy outside the outer restriction; all 3,116
  tests passed with six conditional skips in 1,118.931 seconds.

### Formal review remediation after `5a924cf`

- Signed head `5a924cf9292a07abc2314a55fe858e1346eea8fe` received a fresh,
  non-resumed, ephemeral GPT-5.6 Sol Ultra Codex CLI review in a newly
  materialized host-bound workspace. The reviewer found one P1 cleanup defect:
  `_verify_range_object_contents()` called `selector.close()` before entering
  the mandatory `OwnedProcessLease.settle()` path. A selector-close exception,
  including a main-thread forwarded-signal control-flow exception, could
  therefore leave the lease worker waiting forever, orphan the verifier's
  `git cat-file --batch` process, and let ordinary rollback remove a workspace
  whose process-group quiescence had not been proved. That head did not pass
  local review and none of its review evidence will be reused for a later head.
- The review attempt itself passed its post-run evidence gates. The prior
  trusted bundle manifest remained
  `d12328d7a2da38c7c2edc58287a194faedbc4a37587ca047dbd48db34ac0a5b9`;
  materialization and revalidation retained 14 commits, 13 parent edges,
  parent-graph digest
  `b416e281d9e09760ee15c226770038f9441aaab84fd159f2c2ef1daa1d3f6784`,
  and local-config digest
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The 606-event JSON stream ended in `turn.completed`; all 58 Git calls used
  the exact parent-bound sanitized prefix and no bare Git invocation appeared.
  Prompt bytes retained SHA-256
  `95614a8df2639bd3340bf9f072ca5dc12f3bd284630af935e23734b7c0b413ce`.
  The source authentication object remained exact, no guidance-bearing path
  appeared in the temporary auth home, the neutral launch root remained empty,
  and the temporary auth home was removed after verification.
- Selector teardown now captures its own `BaseException` inside an outer
  `finally` whose mandatory action is lease settlement. A close-only failure is
  the cleanup primary; an earlier verification failure remains primary and
  receives close failure as a secondary diagnostic. Quiescence-unproven
  settlement raises the synthetic process-leak result from that exact primary
  and retains the recovery control/workspace. A later control revalidation
  failure remains the safety-primary result but explicitly retains the prior
  selector/verification failure as its cause.
- Four new fault-injection cases cover close-only control flow, close-only plus
  forced process-group non-quiescence and retained recovery state,
  verification-plus-close dual failure, and close-plus-control-revalidation
  dual failure. Together with the adjacent release-publication regression, the
  five exact tests passed in 13.120 seconds. The complete
  `test_review_workspace.py` file then passed all 154 tests in 188.564 seconds.
  An independent read-only audit found no remaining blocker in this P1 scope;
  the broader problem of masking asynchronous signals around every cleanup
  opcode would require a separate lease-API redesign and is not part of this
  remediation.
- The authoritative post-fix complete suite ran outside the nested macOS
  sandbox with `ResourceWarning` promoted to an error. All 3,120 tests passed
  with six conditional skips in 1,128.061 seconds.

### Formal review remediation after `a6782e6`

- Signed head `a6782e6ceea6ac1d6d02e0bd229f22d7550fe768` received a new
  non-resumed, ephemeral GPT-5.6 Sol Ultra Codex CLI review in another clean
  host-bound workspace. The reviewer found one P1 teardown defect that
  superseded the prior audit's narrower conclusion: selector closure and lease
  settlement were protected, but a forwarded signal could still interrupt
  after settlement and before process-control release, stderr zeroization,
  control revalidation, and `_PartialRecoveryControl.close()`. The same signal
  class could also arrive at the `OwnedProcessLease.settle()` entry opcode
  before its settlement latch was published. Either path could leave an armed
  or process-bound control without a sealed recovery receipt, and the latter
  could leave child quiescence unproved while ordinary rollback removed the
  workspace. This head did not pass local review and none of its review result
  is reusable for a later head.
- The review attempt itself passed its post-run evidence gates. The prior
  trusted bundle manifest remained
  `d12328d7a2da38c7c2edc58287a194faedbc4a37587ca047dbd48db34ac0a5b9`;
  materialization and post-run validation retained 15 commits, 14 parent
  edges, parent-graph digest
  `db5ba7d5f459666be834250ac59d72e6e7fe9dfaee7de7498776b0f3ce547eb4`,
  and local-config digest
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The 515-event JSON stream ended in `turn.completed`; all 63 Git calls used
  the exact parent-bound sanitized prefix and no bare Git invocation appeared.
  Prompt bytes retained SHA-256
  `e81806c8ab7fbf10a56c000b580d60e1ce59ce0e738658973352c3ddb0abd54a`,
  stderr was empty, the neutral launch root remained empty, the source
  authentication object retained exact identity, and the temporary auth-only
  home was removed after post-run verification.
- Forwarded signals are now blocked before any verifier lease worker or child
  can exist and remain blocked in the worker and child. Spawn waits and the
  selector loop check pending signals at bounded intervals and convert them to
  an explicit `ForwardedSignal`; the outer owner restores and propagates only
  after lease settlement, close-or-seal recovery-control disposition,
  revalidation, and sensitive-buffer clearing. A mask-restore failure inherits
  quiescence, retention, and recovery metadata from the primary error instead
  of making a retained workspace look ordinarily cleanable.
- Real-signal tests cover a process-directed signal during select, a normal
  pre-settlement signal, a post-release signal, and the decisive combined
  sequence: an ordinary verification primary with a live `/bin/sleep 60`
  child followed by process-directed SIGTERM at the real settle entry. The
  combined case proves the exact primary object survives with a deferred-signal
  diagnostic, the child exits, the process group disappears, and no partial
  control sidecar remains. The stable focused signal/restore/selector matrix
  passed 9 tests in 19.942 seconds; seven adjacent assignment,
  process-leak, and recovery tests passed in 14.546 seconds. A later complete
  workspace-file run after all teardown remediations and cross-version test
  corrections passed 166 tests in 188.164 seconds.
- A separate independent audit found another P1 in the candidate-only
  `codex-git-prefix` v2 issuer. The old implementation could produce a
  `complete` token-template receipt for a nonexistent workspace and caller-
  supplied Git path even though the contract claimed a binding to a validated
  workspace receipt and accepted Git identity/version. Its final Parent
  Classification also could not carry or compare that composite evidence.
- The candidate v2 command now requires the frozen base and head, reruns the
  trusted workspace validator, binds the complete closed validation receipt,
  captures the selected Git executable's lexical and resolved identities,
  runs the exact bounded clean-environment version probe, and publishes a
  one-field-exclusion canonical-JSON composite digest. Its public validator
  repeats the real Git identity/version probe and fresh workspace validation,
  then requires exact semantic equality rather than merely accepting
  self-consistent recomputed hashes. Process-control exceptions from the Git
  probe, including an unquiesced process leak, propagate unchanged. Shared
  Metadata and Parent Classification carry the same raw composite, schema,
  digest, workspace receipt, executable identity, and type-preserving
  cross-field equalities while keeping prompt delivery, read-only enforcement,
  and argv observation as separate outer-lane evidence.
- This strengthened v2 interface is deliberately fail closed and requires
  `--base` and `--head`. It cannot approve its own self-policy migration: the
  independently trusted prior installed bundle remains the control plane for
  this candidate review, and the new composite issuer activates only after the
  reviewed release is installed. No production repository caller still uses
  the retired two-argument route. The final focused prefix matrix passed 13
  tests in 30.538 seconds, and the complete `test_named_lane.py` passed all 294
  tests with `ResourceWarning` promoted to an error in 198.967 seconds. Ruff,
  format, contract, local-lane, guard-entrypoint, and diff checks passed on the
  same stable implementation.
- A late independent teardown audit found that the revalidation path could
  replace its own explicit low-level `OSError` cause with one selected teardown
  failure. The same single-selection logic could omit the lease-settlement
  source of a synthesized process leak or a concurrent process-release
  failure. The corrected ordering preserves an existing revalidation cause,
  links `process leak -> settlement -> primary`, and records every unselected
  release or control-finalization failure as a stable secondary diagnostic.
  The top-level revalidation failure still inherits the exact quiescence,
  retention, and recovery payload of an unquiesced process leak; no diagnostic
  change authorizes ordinary cleanup.
- That follow-up also exposed a control-finalization defect: the first
  descriptor-close failure in `_PartialRecoveryControl.close()` could skip the
  remaining owned descriptors and obscure an earlier unlink, fsync, or
  retention failure. Finalization now attempts each owned control, workspace-
  root, and workspace-parent descriptor independently. An existing operation
  failure remains primary; otherwise the first close exception retains its
  identity, and every close failure is labeled in visible diagnostics. Focused
  verification passed 20 object-integrity tests in 44.739 seconds and 16
  signal tests in 21.592 seconds. The final 166-test workspace-file run passed
  in 188.164 seconds; Ruff format/check and `git diff --check` also passed.
- A closing audit found that newly added diagnostics assertions initially read
  Python 3.11 exception notes directly even though Python 3.10 carries the
  same secondary diagnostics through the explicit cause/context fallback. The
  tests now traverse both representations with cycle protection and exercise
  `add_note = None`, an existing explicit cause, and visible context. The
  process-leak recovery regression also verifies the actual postcondition:
  ordinary payload is removed while the exact formal marker tombstone and
  external control tombstone remain authenticated. Ten focused closing tests
  passed in 14.406 seconds, followed by the final workspace-file run above.
- The post-prefix, pre-late-remediation full playbook baseline passed 3,135
  tests with six conditional skips in 1,098.645 seconds. It is retained as a
  baseline only. The final stable tree then passed the authoritative 3,142-test
  whole suite with the same six conditional skips in 1,147.173 seconds, and
  the independent closing audit reported `No findings.`

## Next Steps

- Sign the corrected head, rerun exact-head secret admission and one fresh
  whole-range GPT-5.6 Sol Ultra Codex review under the prior trusted release,
  and push that stable candidate without merging it.
- Refresh the private companion's immutable candidate/tree anchors, merge the
  current private base with a signed merge commit, rerun its complete gates,
  merge the companion, and confirm the pre-activation private release.
- Complete PR 108's current-head GitHub lane, CI, final reread, and squash
  merge. Then merge the generated source-sync PR, confirm the activated
  private-overlay release, run the local installer, and record the final merge,
  release, and installation identities here.

## Evidence

- Active pre-migration skill:
  `/Users/hoteng/.codex/skills/review-orchestration-playbook/SKILL.md`.
- Prior WME materialization record:
  `docs/project_journal/2026/08/2026-08-07-large-repo-range-materialization-wme001.md`.
- Prior terminal-payload completion record:
  `docs/project_journal/2026/08/2026-08-05-whole-pr-completion-evidence-wpe001.md`.
- Final post-fix full
  `python3 -B -W error::ResourceWarning -m unittest discover` review-playbook
  suite (`3,142` tests, `6` conditional skips, `1,147.173` seconds) outside the
  nested macOS sandbox restriction. The post-prefix, pre-late-remediation tree
  passed `3,135` tests with the same six skips in `1,098.645` seconds; the
  earlier signal-remediation tree passed `3,120` tests with the same six skips
  in `1,128.061` seconds. The preceding stable tree passed `3,116` tests with
  the same six skips in `1,118.931` seconds. Its corresponding restricted probe
  reached one environment-only nested-broker failure, whose exact test passed
  separately in `1.990` seconds before that authoritative full rerun. The
  earlier stable tree passed `3,112` tests with the same six skips in
  `1,000.276` seconds; the prior signed `2e89971` checkpoint passed `3,010`
  tests with the same six skips in `999.845` seconds.
- Combined `test_contracts`, `test_github_terminal_carriers`,
  `test_github_recovery_contracts`, and `test_local_codex_lane_contracts`
  matrix (`77` focused policy, distribution, carrier, report, and self-policy
  contracts).
- Skill quick validation for `review-orchestration-playbook`,
  `change-delivery-workflow`, and `synthetic-token-fixtures`; reviewer TOML
  parse; source-only Python compile; Ruff lint; Markdown relative-link check;
  `git diff --check`; and project-journal validation.
- Offline WME exact-pack smoke at
  `971977069e6e0ec430529eab4cdb835695f1eeaa` with the exact object/pack/timing
  evidence in Current State, followed by verified ordinary cleanup.
