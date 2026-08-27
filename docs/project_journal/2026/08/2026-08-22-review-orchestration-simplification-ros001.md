---
id: 20260822-ros001
title: Simplify Review Orchestration And Workspace Preparation
status: completed
created: 2026-08-22
updated: 2026-08-27
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
- PR #110's macOS read-only-install job then failed twice at the same
  test-only opcode-offset injection even though the production subtree was
  unchanged from its passing base. The owner-persistence test now interrupts
  the real deletion API at its semantic successful-return profile event, after
  the aggregate proof has been published but before the caller can store or
  transfer it. All original recovery-owner assertions remain intact, while the
  test no longer depends on CPython specialization, superinstructions, or a
  particular `STORE_FAST` offset. The focused test passes under both local
  CPython 3.13.0 and the workflow's exact CPython 3.13.13.

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

### Formal review remediation after `cd5ccd2`

- Signed head `cd5ccd2ddd2a0975db6c5286765d4aab838bc736` received a
  fresh, non-resumed GPT-5.6 Sol Ultra Codex CLI review in a newly materialized
  host-bound workspace over
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51..cd5ccd2ddd2a0975db6c5286765d4aab838bc736`.
  The reviewer found one P1 signal-custody defect. Partial-recovery controls
  could be created and finalized without one surrounding forwarded-signal
  mask, and `codex-git-prefix` validated its workspace outside the structured
  workspace-command handoff. A SIGTERM delivered after an armed control was
  created but before unlink, sealing, or final descriptor closure could leave
  a sidecar that neither ordinary cleanup nor `recover-partial-workspace` could
  safely consume. That head did not pass local review; none of its positive
  evidence is reusable for the replacement head.
- The failed review attempt itself passed its evidence-integrity gates. Its
  stream contained 833 events and 409 command events; 79 Git command events
  represented 80 Git invocations because one event contained two invocations.
  Every Git invocation used the exact parent-bound sanitized prefix. The
  subcommand inventory was 69 `diff`, one `log`, one `ls-files`, three
  `rev-list`, three `rev-parse`, and three `show` invocations. Prelaunch and
  post-run trusted validation remained type-preserving equal at 16 commits,
  15 parent edges, the same parent-graph digest, and local-config digest
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The source authentication object retained exact identity and the temporary
  auth-only home was removed. One bounded websocket connection-limit warning
  appeared on stderr, but the process reached its terminal finding and the
  finding-mode audit accepted the complete run.
- The candidate workspace helper was also exercised against the actual private
  companion merge DAG from
  `284f0f54daba1e9e17e922e4fa87aa6b586e37a4` through
  `6d6bf6a51c6f448f1d2be077b50fdeb0516eca05`. The prior installed materializer
  failed closed with `materializer review graph cannot be represented by the
  sole shallow boundary`. Candidate `prepare-workspace` succeeded with
  `strategy: exact-pack`, seven scoped commits, 172 parent-support objects, 420
  range objects, no shallow boundary, and independently owned object
  identities; its paired cleanup receipt reported complete removal. This was
  an ordinary implementation proof of merge-DAG support, not authorization to
  use candidate-head control code as the formal bootstrap for its own review.
- The correction places every production partial-control owner under complete
  forwarded-signal custody: per-Git controls in `_run_git_raw`, owner-exit
  recovery retention, exact-pack object-store construction, and range-object
  verification. Each owner acquires the mask before control creation can
  return and retains it through process settlement, revalidation, unlink or
  durable sealing, every owned descriptor close, and recovery-metadata
  attachment. A queued signal propagates only after that interval. If an
  operation already failed, the exact primary remains primary and the deferred
  signal is a secondary diagnostic.
- Publication rollback now passes its active signal-mask owner into owner-exit
  recovery rather than opening an interruptible caller/helper handoff. Record
  fsync followed by parent-directory fsync is the durable seal commit point;
  the executable recovery payload is cached immediately. Post-commit binding
  revalidation remains mandatory, but its failure and any later unlock,
  mask-restore, or descriptor-close failure inherit that exact cached route.
  Before the commit point, an armed control is never advertised as executable
  recovery. Failed creation durably removes it when possible or reports a
  bounded, identity-bound locator with `argv_ready: false`.
- Control creation, path revalidation, snapshot reads, stream and descriptor
  retirement, process release, control finalization, and recovery cleanup now
  use all-attempt teardown. The first active operation error remains primary;
  otherwise the first teardown error in fixed ownership order is selected, and
  every later failure remains visible with inherited quiescence, retention,
  and recovery metadata. The exact-pack stream owner closes both streams even
  when both close operations fail. A replaced parent path can no longer turn a
  descriptor-bound armed sidecar into a false path locator: the public
  `control_file` becomes null and only an identity-bound, unverified expected
  locator remains. Revalidation retains its original low-level cause while
  concurrent process-leak, settlement, operation, release, and control-close
  failures remain labeled diagnostics.
- `codex-git-prefix` now uses the same structured workspace-command dispatcher
  as prepare, validate, cleanup, and partial recovery. Validation, final
  identity reread, receipt flush, signal-mask restoration, and terminal
  return-code commitment share one cleanup path. Once a success or failure
  receipt is durably flushed, a later cleanup fault exits with that committed
  return code rather than emitting a traceback or contradictory second result.
- Final verification of the replacement candidate passed 12 focused signal,
  recovery, publication, locator, stream-close, and cause-chain tests; the
  parent independently reran the six newly decisive cases. The complete
  `test_review_workspace.py` file passed 185 tests in 222.698 seconds and the
  complete `test_named_lane.py` file passed 297 tests in 222.965 seconds. The
  77-test contract matrix passed in 3.661 seconds. Ruff 0.13.2 default
  E4/E7/E9/F checks and format checks passed for all four modified Python
  files, along with source compilation, reviewer TOML parsing, skill quick
  validation, and `git diff --check`. The authoritative host-side whole suite,
  with `ResourceWarning` promoted to an error, passed 3,164 tests with six
  conditional skips in 1,181.076 seconds. A new signed head, exact-head secret
  admission, and one fresh whole-range GPT-5.6 Sol Ultra review remain the next
  immutable gates; this entry intentionally does not predict their outcome.

### Formal review remediation after `8ae797d`

- Signed head `8ae797d80fae998637fb55d19a486c34a55a17af` received a
  new, non-resumed GPT-5.6 Sol Ultra Codex CLI review over the same frozen base.
  The reviewer found one P1 contract/implementation mismatch: policy required
  the live sanitized-Git-prefix consumer to validate the exact issued receipt
  immediately before launch, but `named_lane_guard` exposed only the issuer
  route that created a different receipt. Direct Python imports used by tests
  were not a conforming orchestration path, so that head remained
  inconclusive and none of its positive review evidence is reusable.
- The finding run itself remained auditable. Its 654 events contained 320
  completed command events and 47 Git invocations across 46 events; all Git
  invocations used the exact parent-bound sanitized prefix. Prelaunch and
  post-run trusted validation were type-preserving equal at 17 commits, 16
  parent edges, parent-graph digest
  `4437ea070269afc3bd4614aa4713ad3c370911e12dcf78fdf631fedcc7cbb8b6`,
  and the unchanged local-config digest. One sampling reconnect, one analytics
  503, and one recorded sandbox denial were bounded diagnostics; the complete
  stream reached its terminal P1. Auth-home verification passed, and the
  temporary review home and materialized workspace were removed.
- The correction adds the guard-bound
  `validate-codex-git-prefix-receipt` consumer. Its caller must supply the
  issued receipt file, an independently retained expected receipt digest, the
  frozen worktree/base/head, and the selected Git executable. The consumer
  never invokes the issuer. It retains owner-private parent and single-link
  leaf descriptors across strict bounded parsing and live workspace/Git
  validation, rejects a receipt inside the model-visible worktree, separates
  parent object/access policy from benign child-entry metadata churn, and
  revalidates the same descriptor bytes plus path identity before publication.
  Success re-emits the exact original v2 receipt object rather than introducing
  a second acknowledgement schema.
- Focused verification passed 11 live-consumer tests, 16 existing prefix tests,
  two contract tests, and an additional unsafe-path/access-policy test. The
  matrix covers the real source-only guard route, issuer non-use, wrong frozen
  scope or expected digest, stale/tampered receipts, bounded strict JSON,
  hardlinks, in-worktree paths, unsafe parent/leaf policy, benign sibling
  churn, in-place mutation, name replacement, and structured signals. An
  initial independent focused audit reported `No findings`, after which the
  parent found a reachable P2 in descriptor teardown: the first close failure
  could replace an active validation primary and skip the parent descriptor.
  Follow-up audit confirmed the defect. Both descriptors now use the existing
  all-attempt teardown path; an active primary retains its object and cause
  while every close failure remains diagnostic, and a standalone forwarded
  signal retains its exact terminal meaning. Three new real-close fault tests
  passed in 17.752 seconds, and the expanded live-consumer matrix passed 14
  tests in 86.974 seconds. Ruff 0.13.2, formatting, source compilation, skill
  validation, and `git diff --check` passed. The pre-P2 complete
  `test_named_lane.py` run passed 308 tests in 254.194 seconds but is baseline
  evidence only. The post-fix complete file passed 311 tests in 299.528 seconds
  with `ResourceWarning` promoted to an error, and the final focused audit
  reported `No findings.` The restricted-host whole suite reached 3,178 tests
  with six conditional skips; its only failure was the known nested macOS
  `sandbox-exec` denial, whose exact test passed outside the host sandbox in
  1.926 seconds. The authoritative unrestricted whole suite then passed all
  3,178 tests with the same six skips in 1,165.556 seconds and
  `ResourceWarning` promoted to an error. A new signed head, exact-head
  admission, and a new whole-range fresh review remain mandatory next gates.

### Formal review remediation after `4420739`

- Signed head `4420739070522ae7e9598298424b0e54ac824886` received a
  new, non-resumed GPT-5.6 Sol Ultra Codex CLI review under the prior trusted
  release. The reviewer found one P2 teardown defect: both
  `_remove_bound_directory()` and `cleanup_workspace()` still retired owned
  root and parent descriptors sequentially. A first close fault could skip the
  second descriptor, replace an active cleanup primary, discard its recovery
  route, or permit a reused descriptor number to be closed twice. That head did
  not pass and none of its positive review evidence is reusable for a later
  head.
- The finding run was complete and auditable. Its 815 events contained 401
  paired command executions and 36 Git invocations; every Git invocation used
  the exact parent-bound sanitized prefix. Materialization, initial validation,
  and post-run validation remained type-preserving equal at 18 inclusive
  commits, 17 parent edges, parent-graph digest
  `f1bd18cb70ac681924225c80ccf240370c4168fd9d73543a579d9a114839b58a`,
  and the unchanged local-config digest. Auth-home verification passed. The
  only stderr was an analytics 503 and one WebSocket reset followed by a
  successful bounded sampling retry; the stream reached its terminal P2.
- Both paths now transfer descriptor ownership to local teardown state and set
  the owner fields to `-1` before attempting closure. Root and parent
  descriptors are always attempted in fixed order. An active operation error
  retains the same object, explicit cause, status, details, retention state,
  and recovery payload while every unlock or close fault remains diagnostic;
  without an active primary, the first teardown fault is selected and every
  later fault remains visible. A proved completed deletion is not mislabeled as
  an incomplete payload-removal recovery merely because descriptor retirement
  later failed.
- `cleanup_workspace()` now follows the same terminal funnel as partial
  recovery: it keeps forwarded-signal custody through unlock and every
  descriptor-close attempt, selects or annotates the terminal error, and only
  then restores the signal mask. Deferred handoff returns an active mask only
  after descriptor custody is fully retired; a teardown fault first completes
  that handoff and then propagates.
- Eight new regression tests cover active-primary and standalone dual-close
  faults for both paths, the real cleanup wrapper with its exact cause and
  recovery argv, root-open failure with parent-only retirement, deferred
  handoff failure, and a real pending SIGTERM that is delivered only after both
  descriptors close. The 14-test focused matrix passed, the complete
  `test_review_workspace.py` file passed 193 tests in 232.932 seconds, and a
  fresh-context focused read-only review returned `No findings.` Ruff 0.13.2
  default checks, format checks, source compilation, and `git diff --check`
  passed. The authoritative whole suite, a new signed head, exact-head secret
  admission, and a new whole-range fresh review remain mandatory next gates.

### Formal review remediation after `3d080de`

- Signed head `3d080deb582d3d77509e1847652336a564de1589` received a new,
  non-resumed GPT-5.6 Sol Ultra Codex CLI review under the independently trusted
  pre-migration release. The reviewer found one P1 in GitHub negative-evidence
  authority: a findings report could change both its evidence commit and finding
  entry to the same arbitrary non-ancestor SHA because the old validator checked
  only report-internal agreement. That head did not pass, and none of its
  positive review evidence is reusable.
- The finding run remained complete and auditable. Materialization and trusted
  post-run validation agreed on 19 inclusive commits, 18 parent edges,
  parent-graph SHA-256
  `81ab28ac3adcbd6d9ed80e0eb35ed3e1b452b94b593c04fb114dbce8841195af`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The 7,031-byte parent-owned prompt had SHA-256
  `fa5acba5506f470ea01cf0bfd12b1297c61a44a52dc9bccd673dc753b27c8514`;
  event-stream, terminal-artifact, and stderr SHA-256 values were respectively
  `dc434422a936ce1aba4c9c43e11c806873bbe4f822f0a45e81a4f236f85fef0e`,
  `a0cf50f7d6b77a7c9417ec0d8c5106139721437ba3a176233362a1172d434a2d`,
  and `77b9f24fcd54fcba377dab347617fbf5b2a65b9d7252bb9080323a1a4dd95a62`.
  The 1,068-event stream contained 525 completed command events and 58 Git
  invocations across 52 events; every Git invocation used the exact
  parent-bound sanitized prefix. The source authentication object remained
  unchanged, and the process-specific auth home and review workspace were
  removed after their final checks.
- Blocking findings now require three independent, closed parent inputs. A
  `finding_page_receipt` freezes complete current-scope provider acquisition,
  its five pagination-completeness/count pairs, and a consumer-recomputed
  canonical digest of every issue-comment and review record including inline
  children and GraphQL thread joins. A separate `finding_range_receipt` freezes
  repository, PR, unique merge base, exact head, and the complete sorted
  `base..head` ancestor set. The `finding_carrier_snapshot` supplies the actual
  closed observation from which the consumer replays classification,
  applicability, semantic-time precedence, supersession, thread resolution,
  evidence, and the exact unresolved-finding projection. Report, snapshot, and
  embedded carrier fields cannot create or repair either independent receipt.
- The range receipt uses the complete Git DAG. Merge commits and side history
  are included; first-parent, `--ancestry-path`, and linear-history projections
  are rejected. Changing either base or head invalidates all three inputs and
  requires a fresh acquisition, range proof, replay, and final reread. This
  preserves the Q44 branch-refresh design: **Require branches to be up to date
  before merging** authorizes a signed base-to-feature merge, then the new head
  reruns the full pre-merge gate; it never implies a rebase or linear history.
- Independent adversarial passes closed four follow-on gaps before the local
  gate: coupled deletion of a later clean result, coupled page-count or thread-
  state mutation, cross-channel latest-bucket conflicts, and partial retention
  of a superseded top-level finding beside an unresolved inline child. The
  final same-channel rule follows the authority exactly: at the same semantic
  time, findings outrank clean or resolved-inline-only within one channel;
  equal-priority ambiguity and conflicting channel winners remain
  inconclusive.
- On the final uncommitted bytes, the carrier module passed all 28 tests and
  the combined carrier, recovery, and distribution matrix passed all 67 tests;
  the adjacent local-lane module passed all 14 tests. JSON parsing, Ruff, skill
  validation, and whitespace checks passed. Two independent read-only
  adversarial audits returned
  `No findings.` One restricted outer-environment discovery ran 3,190 tests;
  3,183 passed, six were conditionally skipped, and the sole failure was the
  known nested `sandbox-exec: sandbox_apply: Operation not permitted` denial
  in the Claude keychain-broker test. The authoritative host-side whole-suite
  rerun then passed all 3,190 tests with the same six conditional skips in
  1,287.393 seconds with `ResourceWarning` promoted to an error. This result
  freezes the implementation, schema, reference, and test bytes; the following
  journal-only evidence update receives its own journal and contract checks
  before signing.

### Formal review remediation after `3e29262`

- Signed head `3e2926293aa6a2f3c09898cb45c7023f67d50736` received a new,
  non-resumed GPT-5.6 Sol Ultra Codex CLI review under the independently trusted
  pre-migration release. It did not pass. The reviewer found one P1 access-
  policy omission and one P2 portability defect: the temporary Codex
  authentication-home and neutral-root contract treated owner/mode/no-follow
  evidence as complete on Darwin even though an extended ACL can grant another
  principal access while `0600`/`0700` remains unchanged; the active Git object
  verifier also constructed repository-mandated SHA-1 without
  `usedforsecurity=False`, so a FIPS-enabled Python could reject every ordinary
  SHA-1 repository.
- The run reached a complete terminal findings result with successful trusted
  post-run workspace validation. Materialization and both validation receipts
  agreed on 20 inclusive commits, 19 parent edges, parent-graph SHA-256
  `b366428be4209f2a9a46dfa5b73f11242362100d4312f9a61396524790c2e56b`,
  and the unchanged local-config digest. The source authentication object
  remained stable, the process-specific auth home passed its post-run
  inventory check, and both that home and the materialized workspace were
  removed. The CLI cask advanced from 0.149.0 to 0.149.1 while the review was
  running, so its vanished old binary path could not supply a post-run binary
  rehash; this is an additional reason not to reuse the attempt even apart from
  its findings.
- The Darwin contract now distinguishes the protected property from benign ACL
  metadata. Source and temporary `auth.json`, each process-specific auth home,
  every neutral launch root, and task-created private control directories must
  have no extended ACL. Every complete absolute custody chain is opened from
  the filesystem root through descriptor-relative no-follow operations;
  pre-existing ancestors reject every allow/grant entry but may retain
  deny-only ACLs, which grant no access and commonly appear on macOS home
  directories. ACL inspection failure, unknown entries, protected-object ACLs,
  ancestor grants, or a transition outside the admitted policy is
  `blocked-safety`. The checks repeat before and after copying, immediately
  before launch, after exit, and before cleanup. Receipts bind the access-policy
  class with object identity and content/inventory evidence; directory
  timestamps, size, and link count are not treated as mutation, and a file
  timestamp merely triggers full content/access-policy revalidation. Two
  boundary observations explicitly do not claim detection of a complete
  between-observation ACL ABA.
- This ACL detail stays in `local-codex-lane.md`, with one cross-lane receipt
  summary in `review-lane-contracts.md`. It is not added to the reviewer role or
  model-visible prompt, which retain only the opaque parent-private receipt
  identity. No new canonical runtime helper or old supplied-diff entrypoint is
  introduced: expanding the candidate self-policy control surface would not
  help the candidate approve itself. The replacement formal review instead
  uses a parent-owned, candidate-external, digest-bound task guard that enforces
  the new auth-home and neutral-root boundary.
- The active object-integrity stream now marks only Git SHA-1 construction as
  non-security use; SHA-256 retains its prior constructor semantics. A FIPS
  simulation rejects default/security SHA-1 while the complete real
  `validate_workspace` path succeeds and proves every SHA-1 constructor
  received `usedforsecurity=False`. The ACL policy and FIPS focused matrix
  passed 15 tests, the complete `test_review_workspace.py` module passed all
  194 tests in 344.014 seconds, and both independent remediation audits returned
  `No findings.`
- The corrected final bytes then ran the complete 3,191-test discovery suite
  with `ResourceWarning` promoted to an error. In the restricted outer sandbox,
  3,190 tests passed, six were conditionally skipped, and the sole failure was
  the known nested `sandbox-exec: sandbox_apply: Operation not permitted`
  denial in the Claude keychain-broker test after 1,771.015 seconds. The exact
  denied test passed on the host in 2.058 seconds, and the authoritative
  host-side whole-suite rerun passed all 3,191 tests with the same six skips in
  1,265.683 seconds. Signed-head admission and another fresh whole-range Ultra
  review remain mandatory before this remediation can be called clean.

### Formal whole-range findings after `64291d9`

- Signed candidate `64291d9411af370d7577596e0f977ae1dc0d9632`
  received a fresh-context GPT-5.6 Sol Ultra whole-range review over exact base
  `c8df0f5d17e93a7b22d5fe5294baf9884ab2ba51`. The independently materialized
  workspace and repeated validation receipts agreed on 21 inclusive commits,
  20 parent edges, parent-graph SHA-256
  `31b53b786a6222d0de9c710852062f92c3c7e2de35e3be4a9fcc06b72c6c0572`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The parent-owned prompt was 7,050 bytes with SHA-256
  `90b1bf8b6f7ab6ec41671f0be0a2a37f212fbbc649ed67913b23fc851c30df31`.
  The reviewer inspected all 60 changed paths and returned three findings.
- The P1 source-authority finding exposed a mismatch between the new workspace
  helper and the Claude read boundary: local Git alternates were accepted and
  imported, but an alternate object store outside source/admin/common was not
  included in Claude `denyRead`. An external or symlinked primary objects
  directory is the same class of bypass. The remediation intentionally chooses
  direct primary storage instead of expanding the closed receipt and CLI:
  `<common>/objects` must be canonical and real, and local/HTTP alternate
  metadata is rejected. Ordinary clones, linked worktrees, shallow/promisor
  sources, and filesystem reflink/COW clones remain supported; reference/shared
  clones must be dissociated first. This is a point-in-time bind/revalidate
  contract and does not claim resistance to an unobserved same-UID ABA.
- The second P1 finding corrected a durable Q22 interpretation error. Repeating
  the same authorized repository-Action tuple is idempotent, but GitHub's
  create-issue-comment POST has no applicable idempotency key. Each exact
  repository/PR/head epoch therefore permits at most one possibly delivered
  `@codex review` comment POST. An ambiguous response consumes that mutation
  budget; complete rereads may prove delivery, otherwise request policy remains
  `unknown` and observation/retryable Action reconciliation continues until a
  stable pending or `request-delivery-unproven` inconclusive result. A visible
  duplicate is audit evidence and never authorizes another POST. This
  supersedes the earlier journal text that incorrectly preserved comment-POST
  replay as part of Q22.
- The P2 finding established that self-policy Markdown inventory cardinality
  may legitimately be zero when the range changes only non-Markdown control
  files or deletes all changed Markdown. Exact `path_count: 0`, canonical JSON
  `[]` digest, and exact empty parent/prompt/report inventory are accepted;
  local Codex admission is likewise exact empty, while Claude admission remains
  `not-applicable`. Empty records only the absence of candidate-head Markdown
  bytes and never removes deleted Markdown, another hunk, a merge commit, or
  side history from the complete frozen-range review. A nonempty required set
  projected as empty and every stale, digest, type, subset/superset, or
  projection mismatch remain inconclusive.
- The integrated remediation passed the 82-test policy/carrier/recovery/
  self-policy matrix, full `test_named_lane.py` (317 tests), full
  `test_review_workspace.py` (198 tests), and full `test_contracts.py` (32
  tests). The final direct-primary source/profile/remediation deltas also
  received focused race, lexical-entry, CLI-payload, and exact-profile reruns,
  Ruff lint/format, `git diff --check`, and a fresh follow-up review with
  `No findings.` The authoritative host-side whole suite then passed all 3,205
  tests with six conditional skips in 1,169.329 seconds with
  `ResourceWarning` promoted to an error. The system quick skill validator was
  unavailable because its interpreter lacked PyYAML; repository contract tests
  plus a Ruby-standard-library YAML frontmatter fallback validated the skill
  instead.

### Cross-phase source-authority finding after `7cc9f270`

- A later fresh review found that the direct-primary repair still had a
  cross-phase authority gap. `prepare-workspace` did not publish the source
  authority it had used, while `run-claude` derived a new binding only from the
  current lexical path. A persistent rename/replacement could therefore move
  the original source outside requested `denyRead` and let both Claude point
  checks accept the replacement; for a linked worktree the replacement could
  retain the same admin, common, and object directories.
- The remediation uses a direct parent handoff rather than a standalone mutable
  file. The unchanged shared marker/validator schema remains
  `review-workspace-v1`; prepare success separately declares
  `review-workspace-prepare-v2` and publishes a closed
  `review-source-authority-binding-v1` object plus canonical-JSON SHA-256.
  Immediately before constructing it, preparation revalidates the source; the
  binding is then projected only from the originally captured worktree,
  `.git` marker, linked `gitdir` back-pointer, admin, `commondir`, common,
  direct objects, object-info, and alternate-absence authorities.
- The `admin/commondir` state is explicit. Absence requires `admin == common`;
  presence binds the exact regular-file identity, size, content digest, and
  resolved common path. Ordinary `marker == admin == common` remains valid.
  Binding paths use `utf8-only-canonical-absolute-v1`; non-UTF-8 filesystem
  bytes represented through surrogate escapes return structured
  `source-authority-path-encoding-unsupported` evidence instead of being
  rewritten or raising an unhandled encoder exception.
- `run-claude` now requires the exact canonical JSON and digest as guard-parent
  argv, verifies and detaches them before source probing or executable snapshot
  creation, compares each independently resolved live authority projection at
  initial binding, pre-spawn, and pre-terminal acceptance, and fully echoes the
  exact parent values in `named-direct-claude-argv-v3`. The binding arguments
  are not forwarded to Claude. Local process inspection may see their
  non-secret control metadata (paths, identities, sizes, and control digests),
  but they carry no cleanup token, credentials, prompt, or repository content.
- This closes persistent replacement and cross-phase lineage mismatches under
  the observed same-UID host TCB. It does not claim resistance to an
  instantaneous or wholly between-check ABA rename/restore.
- The final adversarial matrix passed five preparation/workspace cases and ten
  Claude handoff cases, including missing CLI inputs, tampered digest, strict
  JSON/schema variants, structured non-UTF-8 rejection, persistent ordinary
  and linked replacements, same-content `commondir` replacement, exact v3
  echo, pre-spawn alternate injection, and pre-terminal object replacement.
  A fresh schema audit then found one test-only provenance blind spot: shared
  helpers silently synthesized a current-source binding for unrelated tests.
  The helpers now accept only the exact object/digest pair from a real cached
  preparation receipt, created before test mocks. A raw helper-bypassing CLI
  matrix covers digest mismatch, duplicate JSON keys, non-canonical JSON, and a
  non-UTF-8 path and proves rejection before any worktree, preflight, source,
  prompt, or snapshot probe. Its focused closure run passed five tests in
  12.134 seconds, and the schema re-audit returned no findings. The separate
  persistent ordinary/linked replacement audit also returned no findings after
  eight directed tests passed.
- Final full evidence: `test_review_workspace.py` passed 202 tests in 283.200
  seconds; `test_named_lane.py` passed 326 tests in 639.969 seconds; and
  `test_contracts.py` passed 32 tests in 3.796 seconds. Ruff lint and format,
  project-journal validation, and the focused matrices were clean. The system
  quick skill validator remained unavailable because its interpreter lacked
  PyYAML; the repository contract module supplies the skill/frontmatter
  fallback evidence.
- The final warning-strict whole-skill discovery reached 3,215 tests in
  1,769.189 seconds with six conditional skips. Its only failure was the known
  host restriction that prevents the nested `sandbox-exec` broker test from
  applying its child sandbox (`sandbox_apply: Operation not permitted`); the
  other 3,214 tests passed. That exact broker test then passed alone outside
  the host sandbox in 2.473 seconds with `ResourceWarning` still promoted to an
  error. This paired result is the final whole-suite evidence for the dirty
  candidate before its signed commit.

### Frozen resource-ceiling finding after `565cf252`

- The required fresh-context whole-range reviewer confirmed one resource-bound
  regression. The replacement workspace runtime had silently raised the active
  ceilings from the independently trusted 250,000 objects, 250,000 parent-edge
  occurrences, and 2 GiB of logical object bytes to 1,000,000, 1,000,000, and
  32 GiB. Neither the user decisions nor this journal supplied a basis for the
  fourfold and sixteenfold increases.
- The historical WME probe reached only 16,689 objects and 1,528,979,578
  logical bytes. The trusted limits therefore still cover the measured large
  repository while keeping malicious or accidental range expansion bounded.
  The active runtime restores the 250,000 / 250,000 / 2 GiB contract; the
  complete-DAG, merge-side-history, range-plus-parent-support, 768 MiB pack,
  256 MiB index, and 15-minute preparation behavior remain unchanged.
- Error messages now derive their displayed counts from the enforced constants,
  the routed workspace reference publishes the same limits, and a direct
  regression test freezes all four active range ceilings. Retained unreachable
  raw-copy constants and retired supplied-diff helper paths are intentionally
  unchanged and receive no new routing or documentation.
- The direct four-test ceiling/budget matrix passed in 1.610 seconds. The full
  warning-strict `test_review_workspace.py` module passed all 203 tests in
  444.645 seconds, and `test_contracts.py` passed all 32 tests in 5.059
  seconds. Ruff lint/format, `git diff --check`, and project-journal validation
  also passed for the remediation.
- The post-remediation warning-strict whole-skill discovery ran 3,216 tests in
  1,781.643 seconds with six conditional skips. Its only failure was the known
  host restriction that prevents the nested `sandbox-exec` broker test from
  applying its child sandbox (`sandbox_apply: Operation not permitted`); all
  other 3,215 tests passed. That exact broker test then passed alone outside
  the host sandbox in 2.127 seconds with `ResourceWarning` still promoted to an
  error.

### Python 3.10 exception-diagnostic compatibility after `6f40453`

- The first GitHub Actions run on the signed candidate exposed four Python
  3.10-only failures across both Linux and macOS. Two tests incorrectly assumed
  `BaseException.__notes__` existed, while two production paths appended a
  diagnostic and then used a late `raise ... from ...`; on Python 3.10 that
  final cause assignment replaced the compatibility fallback chain and hid the
  diagnostic from the rendered exception.
- The tests now inspect the complete formatted exception rather than a
  Python-3.11-only field. Production diagnostic attachment uses one preserving
  helper: native notes remain the Python 3.11+ representation, while Python
  3.10 appends a diagnostic node below the existing explicit-cause chain.
  Settlement-to-primary binding is completed before diagnostics are attached,
  and selector, recovery-publication, identity, deferred-signal, rollback, and
  object-revalidation paths no longer overwrite that chain with a late
  `raise ... from ...`.
- The focused Python 3.10 compatibility matrix passed all six repaired cases;
  the same six passed on Python 3.13. A broader Python 3.10 two-module run
  passed 528 of 529 tests; its only failure was a host-local uv-managed
  temporary virtual environment whose copied interpreter could not load its
  relocated `libpython3.10.dylib`, outside the exception logic and unlike the
  GitHub `setup-python` environment. The authoritative Python 3.13
  warning-strict two-module run passed all 529 tests in 900.243 seconds.
- A fresh focused audit found no remaining overwritten primary cause,
  diagnostic loss, cause cycle, or process-leak/recovery precedence regression.
  The active `prepare-workspace` full-DAG tests continue to cover a feature
  branched from a pre-base commit and refreshed by merging the current base:
  the resulting current-base-to-head range retains the feature commit and merge
  commit, exact diff, commit patches, and parent-support evidence. The retired
  internal materializer has no CLI entrypoint and receives no new routing or
  documentation.
- The final warning-strict whole-skill discovery ran all `3,216` tests in
  `1,522.718` seconds. It reproduced only the known restricted-host nested
  `sandbox-exec` denial; the other `3,215` tests passed with six conditional
  skips. That exact broker test then passed alone outside the host sandbox in
  `2.277` seconds with `ResourceWarning` still promoted to an error.

### Codex CLI shell-environment capability correction after `0c58178`

- The final fresh-context whole-range reviewer found that the normalized Codex
  CLI launch still used `shell_environment_policy.filters`, which is not a key
  accepted by the version-bound Codex CLI 0.149.0 configuration schema. A
  strict-config launch would therefore fail before the reviewer process could
  start, potentially leaving a self-policy review without an eligible local
  adapter.
- The normalized argv now uses exact
  `shell_environment_policy.exclude=["CODEX_HOME"]`. The companion test parses
  the complete documented argv, validates option arity, TOML-decodes every
  `-c` override, checks the version-bound config and shell-policy key/type
  schema, and proves that substituting the retired `filters` spelling is
  rejected. It no longer treats presence of one literal as capability proof.
- All `15` local Codex lane contract tests and all `32` general contract tests
  passed. Ruff lint/format and `git diff --check` also passed. No runtime helper
  or retired supplied-diff entrypoint changed.

### Fail-closed multi-carrier finding projection after `929cfc8`

- The second fresh-context whole-range reviewer found that the version-1
  finding-report test consumer accumulated every active provider finding but
  then selected only the newest carrier. Because the closed version-1 evidence
  projection binds one raw carrier, that behavior could omit an older
  unresolved carrier from the reported actionable findings.
- Version 1 now fails closed whenever more than one finding carrier remains
  active. A later clean does not clear an unresolved inline child; resolving
  the older inline thread permits the unique newer carrier, and a strictly
  later trustworthy clean may still supersede only an older top-level finding.
  The JSON authority and prose authority state the same single-carrier limit.
- Four regressions cover two active inline carriers, a later clean that cannot
  hide either inline finding, explicit resolution of the older inline carrier,
  and top-level supersession that leaves one independent active carrier. All
  `28` terminal-carrier contract tests passed, JSON parsing, Ruff lint/format,
  and `git diff --check` passed, and the original reviewer found no findings in
  its targeted recheck of the complete three-file repair.

### Workspace no-lazy-fetch documentation correction after `713e296`

- The final fresh-context whole-range reviewer found one P3 contract mismatch:
  `review-workspace.md` said the workspace helper had no global Git
  `--no-lazy-fetch` option even though every helper-owned Git argv and its
  regression test already require that option.
- The runtime remains unchanged. The contract now records its actual dual
  control: workspace-helper subprocesses receive both
  `GIT_NO_LAZY_FETCH=1` and `--no-lazy-fetch`, while the separate closed
  `sanitized-git-argv-prefix-v2` for a local Codex reviewer intentionally uses
  only the environment token. A contract regression preserves that distinction
  without relaxing either exact token profile.
- All `32` general contract tests passed. Ruff lint/format and
  `git diff --check` also passed.

### Canonical UTF-8 source-authority correction after private activation review

- The private-overlay activation's fresh GPT-5.6 Sol Ultra reviewer found that
  `review-source-authority-binding-v1` declared
  `canonical-json-utf8-v1` while its encoder still used ASCII escaping. A
  locally valid source path containing non-ASCII text could therefore produce
  bytes that disagreed with the cross-phase canonical encoding contract and
  leave a local Codex or Claude lane inconclusive.
- The source-authority encoder now emits literal UTF-8 with
  `ensure_ascii=False`, matching the already published canonical encoder
  definition. The strict UTF-8 path check remains fail closed for surrogate or
  otherwise non-UTF-8 filesystem paths; no path is replaced or omitted.
- Regression coverage binds exact bytes, digest, and strict round-trip for a
  source path containing both `é` and U+2028. Parser and CLI tests continue to
  reject an ASCII-escaped surrogate fixture as non-canonical input. This is a
  canonical source fix; the private overlay must advance its source lock and
  regenerate rather than carrying a hand-edited runtime copy.

### Canonical follow-up after private-overlay whole-range review

- Canonical PR #110 squash-merged as
  `a439793df9483943991c258e16f4ddf705736643` with tree
  `76633f7ac00736ab8309a8f22413839dea04267` after its current-head local and
  GitHub Codex gates passed. The private overlay then bound that exact source
  identity and generated PR #181 instead of carrying a divergent copy.
- A fresh ephemeral GPT-5.6 Sol Ultra review of private PR #181 range
  `58e44edb8aa57bfe8e18adceac01489f85f2bf19..5f78907def147c231a09a5ff39a705d9d0c8eafa`
  ran from an independent clean workspace under installed immutable control
  release `f9e596f458a119fa88b89789c24c2290c37b4857`. Its terminal artifact
  SHA-256 was
  `93dbff2dd357d33e8a96da65718dcedba8192cce6df7d2967a75768d16fb768a`.
- That review found three cross-repository contract gaps, so no private-head
  clean result is carried forward. First, equality of an Actions
  repository/PR/head/workflow/ref/operation/input tuple identifies a repeat
  but cannot make an arbitrary workflow idempotent. Automatic mutation is now
  limited to the exact Codex reconcile operation that a candidate-range-
  external, parent-owned closed contract explicitly declares idempotent or
  reentrant, in addition to current authorization and single-flight. The
  agreed recovery cadence remains 1, 2, 4, 8, 16, 32, and 60 minutes, then
  hourly without a fixed attempt limit; at 60 minutes the active thread is
  informed, Automation wakes that same thread when available, cancellable
  sleep remains the fallback, and private repositories retain the lower-cost
  cadence.
- Second, a merge/status check cannot establish GitHub Codex provider-clean
  merely because candidate-head bytes introduce a contract that calls an
  ordinary success clean. The reference schema now requires a separately
  frozen parent trust anchor outside the candidate range. Its source and
  stable producer identity join the dynamic App/workflow/run/check evidence;
  a parent-owned candidate-range commit receipt also prevents a non-head
  candidate commit from masquerading as an installed trusted release. This is
  a normative machine-readable reference plus a test consumer; the separate
  GitHub Action/status/ruleset workstream still owns the production consumer.
- Third, the published sanitized-Git-prefix receipt consumer checked UID,
  mode, link count, identity, and content but omitted Darwin extended ACLs.
  Its protected access-policy property is now owner-private access: the bound
  parent and receipt descriptors reject allow/grant ACL entries on acquisition
  and both revalidation passes, while deny-only ACLs remain acceptable and
  non-Darwin POSIX mode behavior remains unchanged. Real Darwin ACL tests cover
  initial grants, drift before the first revalidation, drift before the final
  revalidation, and deny-only entries.
- The first warning-strict whole-skill run exposed one additional stale copy of
  the old retry policy in `review-prompt-templates.md` and its matching exact-
  text test. Both now require the same trusted recovery contract as the active
  lane/authority documents; no model-facing prompt says that tuple equality
  creates idempotency. That restricted run otherwise passed 3,220 of 3,222
  tests with six conditional skips; its other failure was the known outer-
  sandbox rejection of a nested `sandbox-exec` broker. The exact broker test
  passed outside that nesting restriction in 2.455 seconds. After the prompt
  correction, the authoritative non-nested warning-strict run passed all
  3,222 tests with six conditional skips in 1,650.381 seconds. The 330-test
  named-lane module, 83-test GitHub/local-contract matrix, Ruff lint/format,
  JSON parsing, skill validation, project-journal validation, and whitespace
  checks also passed.
- Signed checkpoint `8d62cbc22c6078f3f3b5e8b5f7ac29dd2a2790a0`
  then received a completely fresh, ephemeral GPT-5.6 Sol Ultra review of
  `a439793df9483943991c258e16f4ddf705736643..8d62cbc22c6078f3f3b5e8b5f7ac29dd2a2790a0`
  from an independent workspace prepared by immutable control release
  `f9e596f458a119fa88b89789c24c2290c37b4857`. Materialize and every
  pre/post validation agreed on two commits, one parent edge, parent-graph
  SHA-256
  `e89fcd746f44d76afc770661daccd6e414c246e08a166e0281ea21f379f774b2`,
  and local-config SHA-256
  `07990c1d83a78ea34a87e3f51883e3164c3098b21770082207e00a3a898ab24f`.
  The 8,343-byte prompt SHA-256 was
  `632ca52e7a3215e8f798900c850eeb4c9ef7522052a44478ed8746e88399e3a3`;
  the terminal artifact SHA-256 was
  `6bd08a31a31ce5911cd126e43a1f72143327be139e36cfec595571778b7f497c`
  after 497,693 reviewer tokens. A first outer-sandbox launch failed before
  model startup because Codex could not open its state database; it produced
  no terminal artifact and does not count as a lane.
- The valid review found three more GitHub contract gaps, so `8d62cbc` is not
  a clean checkpoint. A merge-status pass still bound a trusted declaration
  without proving which workflow revision and transitive producer code the
  actual run executed. The guarded recovery text still illustrated
  `workflow_dispatch` against a mutable feature-branch ref, which cannot
  atomically bind the frozen head. Finally, `recovery_operation_contract`
  remained prose rather than a versioned closed schema and reference consumer.
  The remediation therefore binds actual producer implementation evidence,
  removes automatic new dispatch from authoritative recovery, admits an
  existing-run rerun only after its original head and implementation are
  bound, and adds a closed machine-readable recovery contract plus
  candidate-range exclusion and negative tests. A manually confirmed dispatch
  and its receipts remain status-only because branch/tag dispatch has no
  documented atomic expected-SHA or `If-Match` precondition; a later run/check
  can count only through an independent ordinary producer/status contract.
  GitHub's documented
  maximum of 50 reruns limits state-changing rerun attempts; monitoring itself
  may continue hourly without a fixed limit.
- The exact GitHub rule name remains **Require branches to be up to date before
  merging**, distinct from **Require linear history**. If freshness blocks and
  no merge queue owns the update, merge the current base into the feature
  branch with a signed merge commit and rerun the complete test, review,
  GitHub, CI, conversation, policy, and final-reread gates. Intermediate merge
  commits are valid members of `base..head`; neither this recovery nor the
  workspace contract requires linear history.
- The `8d62cbc` findings were closed through parent-owned evidence rather than
  another candidate assertion. A preferred merge/status pass now joins the
  exact dynamic App/workflow/run/check identities to platform-authenticated
  run and job workflow identities, parsed workflow references, and a complete
  immutable implementation closure. A separately anchored dependency resolver
  records one exact source-resolution result for every canonical
  repository/commit/path/kind/blob entry, including an explicit empty
  reference list, and derives the complete edge set in both directions. The
  stable PR snapshot binds both implementation and resolution receipt digests.
  Candidate-range workflow or dependency bytes, root-only closure omission,
  self-declared `complete`, forged raw references, and identical blobs at
  distinct paths all fail closed. An external App without equivalent
  provider-authenticated immutable implementation identity cannot use the
  merge/status basis and falls back to terminal provider evidence.
- Resolver source trust is relation-specific rather than merely "not in the PR
  range." A target-branch baseline must be the exact current base tip, a
  parent-fixed external source must be in another repository, and an installed
  trusted release must carry an independent parent-owned manifest/provenance
  receipt. This prevents a same-repository off-range commit created by a
  candidate author from becoming its own resolver authority.
- GitHub authoritative recovery is a closed two-phase contract whose accepted
  union contains only full and failed-jobs reruns of an exact existing run. The
  preflight binds the repository, PR, frozen head, operation intent,
  repeat-safety declaration, trusted producer implementation, resolved
  dependency closure, and original platform run observation. The rerun joins
  the original `GITHUB_SHA`, `GITHUB_REF`, workflow SHA/ref, and job workflow
  identity; GitHub preserves those values. The completion receipt cannot
  authorize a mutation retroactively and is accepted only when separate
  parent-owned authenticated exact-attempt/current-run observations join the
  accepted preflight and operation identity.
- A new workflow dispatch remains outside that accepted union even when the
  REST response returns a run ID and URLs: the branch/tag ref still has no
  documented pre-POST atomic expected-SHA comparison, so post-creation identity
  checks cannot prevent an already-started substituted workflow from causing
  side effects. A separately caller-confirmed manual dispatch and its receipt
  are status-only; any later current-head check must qualify independently
  through the ordinary producer/status contract.
- The final fresh-context review exposed four additional recovery-boundary
  gaps that focused self-tests had not found: target repository identity did
  not cross every receipt boundary; the recovery resolver could still omit a
  dependency edge or supply its own trust anchor; an existing-run rerun could
  reuse an older run snapshot; and failed-job versus full reruns shared an
  ambiguous operation kind. The repaired contract now carries exact target
  repository equality through producer, operation, delivery, observation, and
  completion; freezes resolver anchor, provenance, and full-entry resolution
  independently from the candidate preflight; and maps failed-job/full reruns
  to separate GitHub REST operations with distinct operation identities.
- Existing-run recovery now joins a mutation-before authenticated current-run
  observation, an exact HTTP 201 no-body delivery receipt, an exact-attempt
  observation, a mutation-after current-run observation, and a closed
  acquisition transaction. Both post observations must describe attempt
  `n + 1` with the same immutable run identity and platform start time, while
  the start must follow the POST boundary. A stale historical attempt, an
  intervening rerun, a cross-mode endpoint, or a coupled digest rewrite is
  status-only. Exact-attempt and current-run `updated_at` values are validated
  against their own response windows rather than compared across endpoints;
  live GitHub samples showed that those endpoint projections may differ by one
  second even for the same attempt.
- Repeat safety and mutation authority remain separate. Equality of an
  operation tuple identifies a requested repeat but does not make arbitrary
  Actions idempotent or reentrant. Only a candidate-range-external closed
  recovery contract may declare repeat safety, and the current task must still
  authorize the mutation. Mutation attempts stop at provider or contract caps,
  including GitHub's total rerun maximum of 50; read-only monitoring continues
  on the `1/2/4/8/16/32/60` minute then hourly schedule without a terminal time
  ceiling. Private repositories retain cost throttling, public repositories may
  retry more freely within the same authority, Automation wakes the active
  thread when available, and cancellable hourly waiting remains the fallback.
- No new instruction, tombstone, or navigation points at the retired
  supplied-diff review helper. The active skill describes only the clean
  independent workspace and current local/GitHub lane contracts; unadvertised
  compatibility internals remain outside named review shapes.
- Multiple rounds of coupled-mutation audit progressively rejected forged
  producer references, root-only and empty-edge closure claims, fake source
  anchors, arbitrary existing-run refs, unbound gate entries, pre/post phase
  conflation, substituted dispatch runs, incomplete REST response envelopes,
  the internal-list-versus-API-object request-body mismatch, cross-repository
  receipt substitution, a candidate-controlled installed-release resolver,
  stale historical attempts after a new rerun POST, and cross-mode rerun
  substitution. The first focused audit returned `CLEAN`, but the later formal
  fresh-context review correctly found four stronger coupled attacks; each
  original attack author then re-ran its probe against the repaired contract
  and returned `CLEAN`. A later formal pass additionally established that
  recovery consumes the canonical closed producer-entry profile (`action`, not
  an invented kind), and the external-App union nulls both raw and parsed
  workflow identities. The subsequent formal review removed automatic new
  dispatch from the accepted recovery union and bound the trusted root workflow
  repository to the operation/contract repository; cross-repository reusable
  workflow identity remains valid only as the job identity. Coupled
  final-window, malformed-entry, provider-union, root-repository, and manual-
  dispatch authority attacks now fail mechanically. The focused
  contract/carrier/recovery/local-lane matrix passes all 90 tests after this
  downgrade and repository-binding revision.
- The same formal review found that the Darwin published-receipt ACL check had
  implemented a stricter property than its owner-private contract by rejecting
  a redundant allow entry for the exact file owner. The live descriptor-bound
  check now resolves an owner UUID only when an allow entry exists, accepts
  deny entries and exact-owner allows, and rejects any allow for another
  principal plus every unknown, malformed, or uninspectable entry. Stronger
  control-object contracts that intentionally require an empty ACL remain
  unchanged.
  The GitHub Action/status/ruleset thread remains
  responsible for the production producer and consumer; this workstream
  supplies its closed skill-facing evidence contract and test-only reference
  validators without claiming they are the deployed integration.

### Final follow-up review findings after `a1e034a`

- A fresh-context GPT-5.6 Sol Ultra reviewer inspected the complete signed
  `a439793df9483943991c258e16f4ddf705736643..a1e034a18c7c1deacce42c3fc3dc3f46b50c975a`
  range in an independently prepared clean workspace. It found three remaining
  fail-closed gaps; that result is findings-only and does not count as a clean
  local lane.
- GitHub documents different dependency behavior for the two accepted rerun
  modes: a full rerun re-resolves a non-SHA reusable-workflow reference, while
  a failed-jobs rerun reuses the reusable-workflow commit from the first
  attempt. Version 1 now applies one conservative rule to both modes because
  its platform evidence does not prove every external action dependency. Every
  external reusable-workflow or action selector must name the target closure
  entry's canonical repository identity, exact workflow path or action-manifest
  directory, and lowercase full commit SHA. Same-repository reusable workflows
  may instead use GitHub's `./.github/workflows/...` form or the contract's
  `$/...` running-commit form when source and target are at the same commit;
  `$/...` may likewise bind an action-manifest directory from workflow,
  reusable-workflow, or action content. Branches, tags, expressions, mismatched
  SHAs, unbound workflow `./`/`../` actions, bare untyped action-to-script
  paths, and unknown forms are status-only. This closes the coupled
  receipt-rehash attack without pretending the two GitHub modes behave
  identically.
- The external-App merge/status branch is disabled in version 1. A provider
  implementation ID plus a self-digested closure does not authenticate the
  provider-owned ID-to-root-to-transitive-closure relation; therefore the
  accepted external-App binding-profile set is empty and such repositories use
  ordinary terminal-clean fallback. A future profile must introduce separate
  provider-authenticated binding and graph-reachability evidence before this
  branch can become positive.
- RFC 8785 digests use the closed version-1 numeric profile
  `-9007199254740991..9007199254740991`, with non-Boolean integers, fixed ASCII
  keys, and no floating-point values. Public reference validators reject
  out-of-domain reports and parent inputs before digesting, so distinct JSON
  integers cannot alias through an IEEE-754 implementation. A future GitHub ID
  outside that range requires a new grammar carrying the value as a decimal
  string.
- The first repaired focused carrier/recovery run passed all 48 tests. The
  next independent implementation audit then found six stronger boundary
  cases that those tests did not exercise. GitHub resolves a workflow's
  `./path/to/action` against the checked-out runner workspace, so matching only
  the declaring workflow's repository and commit could bind different bytes.
  Recovery and ordinary merge-status now accept canonical exact-SHA external
  reusable-workflow and action selectors, map action selectors to the
  action-manifest directory, accept exact same-commit local reusable-workflow
  `./` and `$/` edges, and accept an exact same-commit `$/` action edge from a
  workflow, reusable workflow, or action. They reject unbound workflow-local
  `./` or `../` action edges and every bare untyped action-manifest-to-script
  path; a future typed metadata-field and resolution-base schema is required
  before such script edges can become positive.
- The same audit showed that an external non-root `job_workflow_ref` could
  remain branch-like while a different dependency edge claimed an exact SHA.
  Both contracts now require every closure entry to be reachable from the
  authenticated root and count all inbound edges to the non-root job identity:
  exactly one is allowed, its source must be workflow or reusable-workflow
  content, and it must semantically match the raw job ref. An external edge
  therefore forces the raw selector to use the resolved full SHA. A
  same-repository `./` or `$/` reusable-workflow edge may retain the
  platform-reported branch-like raw job identity because its separately bound
  resolved commit and target entry equal the source running commit. A root job
  identity must equal the complete root workflow identity and have no inbound
  edge.
- Canonical input validation now rejects lone Unicode surrogate code points,
  cyclic containers, nesting beyond 256 containers, more than 100,000 JSON
  value nodes, a string value or object key beyond 1 MiB of UTF-8, aggregate
  string-plus-key UTF-8 beyond 16 MiB, and invalid JSON-like shapes before
  canonicalization. A code-point-count precheck rejects an already over-limit
  string before bounded UTF-8 encoding, followed by the exact encoded-byte
  check. The
  iterator-frame walk rejects an over-wide list or object before allocating a
  child-frame fan-out, and parent inputs are bounded before defensive copying.
  All four public reference entrypoints and their constructor boundary map
  malformed Python objects to `malformed` or false rather than leaking
  `UnicodeEncodeError`, `RecursionError`, or `TypeError`.
- The next fresh-context audit found two remaining coupled-selector ambiguity
  families. A closure could carry the same repository/commit/path with a
  different kind or blob, and one action directory could carry both
  `action.yml` and `action.yaml` while the same raw selector named either one.
  The closed grammar now requires direct `.github/workflows/*.yml` or
  `.github/workflows/*.yaml` targets, one kind/blob per canonical repository
  identity/commit/path, one target per source-entry/raw-selector identity, and
  at most one action-manifest entry per canonical repository
  identity/commit/directory. Both
  ordinary merge-status and recovery apply those constraints before selector
  resolution; targeted terminal and recovery regressions cover different-blob,
  alternate-manifest, wrong-directory, nested-workflow, and wrong-suffix
  variants.
- The following independent audit found that the GitHub repository component
  was still treated byte-exact in some semantic keys. GitHub's REST API says
  [`owner` and `repo` names are not case
  sensitive](https://docs.github.com/en/rest/repos/repos#get-a-repository), so a
  case alias could otherwise evade candidate-range exclusion, closure
  uniqueness, action-directory uniqueness, selector joins, or reachability.
  The contract now accepts only valid ASCII `owner/name` and applies one
  case-insensitive canonical repository identity to every repository-semantic
  join, including repository-scoped URL/ref joins. Workflow/action paths,
  commits, refs, URL suffix/query/fragment fields, and the original raw records
  remain exact and type-preserving in their digests. GitHub also says Actions
  and reusable workflows [do not follow rename
  redirects](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#limitations-of-reusable-workflows),
  so the correction deliberately does not infer rename continuity or an
  immutable repository ID.
- The same audit observed that node/depth caps alone still allowed very large
  strings to be encoded and copied. The closed canonical-JSON profile therefore
  adds the 1 MiB per-string/key and 16 MiB aggregate UTF-8 limits above.
- Two final targeted audits exposed lexical normalization gaps rather than a
  new policy branch. `PurePosixPath(".")` has no parts and had passed the
  vacuous component check, while NUL is not representable in a Git tree path.
  Safe canonical paths now require at least one component and explicitly reject
  `.` and NUL. Separately, Python's URL parser can strip tab/newline/control
  bytes, normalize scheme parsing, and discard an empty `?` or `#` delimiter.
  GitHub web/API URLs now require raw ASCII without C0/space/DEL, the exact
  lowercase field-specific scheme/host prefix, and byte-identical
  parse/recomposition; only the `owner/name` segment receives case-insensitive
  semantic comparison. Fully rehashed terminal and recovery regressions cover
  dot/NUL paths, mixed-case repositories, trailing tab, uppercase scheme, empty
  delimiters, and endpoint/ref variants.
- After those repairs and documentation synchronization, the main orchestrator
  independently passed the focused carrier/recovery matrix at `52/52`, the
  four-module contract matrix at `98/98`, Ruff format/check, JSON parsing,
  `git diff --check`, skill validation, and project-journal validation. The
  first full review-playbook suite then passed `3,243` tests in `1,657.587`
  seconds with six conditional skips under CPython 3.13 and
  `ResourceWarning` promoted to an error.
- A committed-range exact-secret admission for
  `a439793df9483943991c258e16f4ddf705736643..dacb26847dad27f219dab26c794c7baf20bdcd77`
  was clean with complete temporary cleanup. The installed specialized
  `reviewer` role was temporarily unavailable at launch, so the parent used the
  contract's peer-adapter fallback: one zero-inherited-context
  `gpt-5.6-sol` / `ultra` subagent over an exact-pack detached workspace from
  the installed trusted release. Prepare and validation agreed on seven
  commits and 360 range objects; the issued and live-consumed sanitized Git
  prefix receipts were byte-identical. Post-review trusted validation remained
  clean and the guard completed workspace cleanup.
- That review found three remaining fail-closed gaps. The recovery validator
  did not bind each source trust-anchor kind to its required repository/base
  relation; Python Boolean/integer equality could satisfy implementation run
  and dependency-count bindings; and the candidate grammar used permissive
  `json.loads` without duplicate-key, non-finite-number, whole-resource, or
  closed top-level checks. The repairs now apply kind-specific source
  relationships, exact non-Boolean integer domains plus type-preserving
  equality, and one strict whole-grammar loader. Fully rehashed regressions
  reach each intended check rather than failing on stale digest evidence.
- Recovery and terminal focused modules passed `18/18` and `37/37`; the joined
  four-module matrix passed `101/101`. Two independent closure audits returned
  clean for exact file SHA-256 values
  `364680bdec20adbd9bb8ac84f5fef9176f0f4cc6c79a1bce99c38fdbb448434b`
  and
  `274737adb251de68c7fe224f5f3b588e16c41ac4aa2c0662a4f384a00b7445eb`.
  The post-fix full review-playbook suite passed `3,246` tests in `2,027.495`
  seconds with six conditional skips under the same strict warning profile.
  Because the repairs advance the head, the earlier admission and review are
  evidence for the repair loop only; final-head admission and fresh review are
  rerun rather than reused.

## Next Steps

- Keep final-head delivery evidence—exact-secret admission, fresh local Codex,
  current-head GitHub Codex, CI, conversation, and ruleset readiness—in the PR
  rather than advancing the reviewed head for journal-only status prose.
- Let the private overlay consume the canonical merge through its generated
  sync workflow. Do not hand-edit the generated overlay; release and installed
  verification remain downstream delivery evidence.

## Evidence

- Post-activation canonical UTF-8 correction: `3,217` review-playbook tests
  completed in `1,948.651` seconds with six conditional skips. The aggregate
  process reported three environment-only artifacts: a test-supervisor
  `RLIMIT_FSIZE` collision, one transient macOS ACL command failure, and the
  known outer-sandbox rejection of nested `sandbox-exec`. Each exact test
  passed after removing only its demonstrated environmental blocker, including
  the broker test outside the outer sandbox. Five focused source-authority
  tests, the broader `source_authority` selection, Ruff lint/format, skill and
  project-journal validation, and `git diff --check` also passed.
- Active pre-migration skill:
  `/Users/hoteng/.codex/skills/review-orchestration-playbook/SKILL.md`.
- Prior WME materialization record:
  `docs/project_journal/2026/08/2026-08-07-large-repo-range-materialization-wme001.md`.
- Prior terminal-payload completion record:
  `docs/project_journal/2026/08/2026-08-05-whole-pr-completion-evidence-wpe001.md`.
- Final post-`cd5ccd2` remediation
  `python3 -B -W error::ResourceWarning -m unittest discover` review-playbook
  suite (`3,164` tests, `6` conditional skips, `1,181.076` seconds) outside the
  nested macOS sandbox restriction. The post-`3d080de` final candidate passed
  `3,190` tests with the same six skips in `1,287.393` seconds. The prior stable
  tree passed `3,142` tests
  with the same six skips in `1,147.173` seconds; the post-prefix,
  pre-late-remediation tree passed `3,135` tests with the same six skips in
  `1,098.645` seconds; the earlier signal-remediation tree passed `3,120` tests
  with the same six skips in `1,128.061` seconds. The preceding stable tree
  passed `3,116` tests with the same six skips in `1,118.931` seconds. Its
  corresponding restricted probe reached one environment-only nested-broker
  failure, whose exact test passed
  separately in `1.990` seconds before that authoritative full rerun. The
  earlier stable tree passed `3,112` tests with the same six skips in
  `1,000.276` seconds; the prior signed `2e89971` checkpoint passed `3,010`
  tests with the same six skips in `999.845` seconds.
- Combined `test_contracts`, `test_github_terminal_carriers`,
  `test_github_recovery_contracts`, and `test_local_codex_lane_contracts`
  matrix (`90` focused policy, distribution, carrier, report, recovery, and
  self-policy contracts). Signed head `65a36ce` passed the complete
  `3,227`-test suite with six conditional skips in `1,562.494` seconds; the
  final repaired head will be validated and reported as PR evidence before
  publication.
- Skill quick validation for `review-orchestration-playbook`,
  `change-delivery-workflow`, and `synthetic-token-fixtures`; reviewer TOML
  parse; source-only Python compile; Ruff lint; Markdown relative-link check;
  `git diff --check`; and project-journal validation.
- Offline WME exact-pack smoke at
  `971977069e6e0ec430529eab4cdb835695f1eeaa` with the exact object/pack/timing
  evidence in Current State, followed by verified ordinary cleanup.
