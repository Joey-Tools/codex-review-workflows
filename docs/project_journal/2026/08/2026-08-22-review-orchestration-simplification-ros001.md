---
id: 20260822-ros001
title: Simplify Review Orchestration And Workspace Preparation
status: active
created: 2026-08-22
updated: 2026-08-23
branch: review-orchestration-simplification
pr:
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

- The current dedicated reviewer profile resolves to GPT-5.6 Sol `xhigh`,
  while a fresh Codex CLI session supports GPT-5.6 Sol `ultra`. The adapters
  should therefore be peers selected by verified effective capability and
  parent convenience, rather than by a fixed transport priority.
- OpenAI's API documentation names `max` as GPT-5.6 Sol's highest API
  `reasoning.effort`, while Codex exposes `ultra` as a product-level mode that
  may delegate internally. The released reviewer configuration therefore uses
  the Codex `ultra` profile and counts the resulting fresh session as one
  logical lane, without claiming that `ultra` is an API effort enum.
- Model discovery is intentionally exceptional. Query the latest eligible
  model only when the parent is clearly stronger than the configured reviewer
  or the reviewer runtime rejects, downgrades, or mismatches the requested
  model/effort. Ordinary reviews trust the released role and skill defaults.
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
  read invalidates that attempt. A runtime that accepts the strict requested
  profile but does not report effective model/mode records `unknown`; only an
  observed mismatch or downgrade makes profile evidence inconclusive.
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
  force-push requirement. The resulting new head invalidates all prior
  head-bound test, review, CI, conversation, and final-reread evidence.
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

## Next Steps

- Use the final signed squash candidate head for secret admission and obtain a
  clean whole-range fresh-context Codex review under the prior trusted release.
- Merge the canonical PR, complete the private companion and generated sync
  release chain, install locally, and update this entry with final merge,
  release, and installation evidence.

## Evidence

- Active pre-migration skill:
  `/Users/hoteng/.codex/skills/review-orchestration-playbook/SKILL.md`.
- Prior WME materialization record:
  `docs/project_journal/2026/08/2026-08-07-large-repo-range-materialization-wme001.md`.
- Prior terminal-payload completion record:
  `docs/project_journal/2026/08/2026-08-05-whole-pr-completion-evidence-wpe001.md`.
- Final full `python3 -B -m unittest discover` review-playbook suite (`3,028`
  tests, `6` conditional skips, `945.897` seconds) with `ResourceWarning`
  promoted to an error. The prior signed `2e89971` checkpoint passed `3,010`
  tests with the same six skips in `999.845` seconds.
- `python3 -B -m unittest skills.review-orchestration-playbook.tests.test_contracts`
  plus `test_github_terminal_carriers` (`33` focused policy, distribution,
  carrier, and report contracts).
- Skill quick validation for `review-orchestration-playbook`,
  `change-delivery-workflow`, and `synthetic-token-fixtures`; reviewer TOML
  parse; source-only Python compile; Ruff lint; Markdown relative-link check;
  `git diff --check`; and project-journal validation.
- Offline WME exact-pack smoke at
  `971977069e6e0ec430529eab4cdb835695f1eeaa` with the exact object/pack/timing
  evidence in Current State, followed by verified ordinary cleanup.
