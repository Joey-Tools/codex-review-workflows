---
id: 20260730-gea001
title: GitHub Codex Provider-Evidence Authority
status: active
created: 2026-07-30
updated: 2026-08-02
branch: wip/github-codex-evidence-authority
pr:
supersedes: []
superseded_by:
---

# GitHub Codex Provider-Evidence Authority

## Summary

- The GitHub Codex lane now separates request-orchestration compliance from
  provider-authored result evidence.
- Duplicate or early requests produce stable warning codes without
  invalidating otherwise complete current-scope provider-result evidence.
- The latest trustworthy terminal artifact has precedence; unresolved
  thread-backed findings remain blocking, while a later clean artifact may
  supersede a top-level finding on the same or a proved successor head.
- Dynamic provider profiles define a narrowly gated `+1` clean fallback while
  preserving terminal-payload priority and treating `eyes` as liveness-only.

## Current State

- The canonical profile names are `terminal-payload`, `mixed`,
  `thumbs-up-clean`, and `unknown`.
- A strong current terminal clean/findings result defaults to
  `terminal-payload`. Missing declaration or failure confined to historical
  traversal, pagination, endpoint/artifact budget, or sidecar validation blocks
  only `mixed` and weak reaction authority; current endpoint/artifact and
  whole-PR/lifecycle/final-stability failures still block the strong result.
- Reports keep `request_policy`, `provider_profile`, and `evidence_basis`
  independent. `request_policy` is a record whose stable warning codes include
  `early-request-observed` and `duplicate-observed`. A lone compliant pending
  request is not a warning. `provider_profile` is `null` only before an
  eligible provider plane exists. `evidence_basis` may also be `null` for an
  eligible waiting or inconclusive lane when no stable artifact is selected;
  an inconclusive lane with a stable unresolved-thread or selected malformed
  blocker records that complete blocker basis instead.
- Existing duplicate requests do not require request/run attribution before a
  complete, independently ordered provider result can count. The orchestrator
  still does not create another same-scope request.
- Result-present acceptance applies even when request history overlaps the
  provider result: `R1 -> clean1 -> R2 pending`,
  `R1 -> clean1 -> R2 -> clean2`, and
  `R1 -> R2 -> clean1 -> clean2` may all pass from the latest stable
  current-scope clean artifact when every historical finding is resolved.
  `R2 pending` is audit/liveness state, not contrary verdict evidence.
  Duplicate request history remains visible as `duplicate-observed`; it does
  not manufacture `triple-inconclusive`, does not require a request/run join,
  and does not authorize an agent-created third request.
- Reaction-only authority now uses a parent-owned request-time scope receipt
  sidecar. Its closed raw pre/post PR-detail and compare receipts plus exact
  request-comment response bind the eight request fields—including closed
  `user: {login, type}` actor identity—to the immutable
  repository/PR/merge-base/head scope. The raw discovery transcript remains
  schema version 3; final PR metadata can never regenerate or relabel an older
  request receipt. Missing or malformed receipts close only the weaker
  request/reaction plane and make `request_policy` unknown; they do not veto an
  independently valid terminal provider payload. Complete raw request/reaction
  pages remain audit input, but stable or changing duplicate/pending requests
  and reactions affect only their own policy/profile plane and never overturn
  an independently stable terminal verdict.
- Terminal payload authority now has a separate parent-owned artifact-time
  whole-PR scope receipt. Every terminal-looking artifact admitted to current
  precedence is wrapped by one closed `artifact_scope_receipt` of kind
  `parent-recorded-terminal-artifact-scope-v1`, with exactly
  `kind`, `pre_artifact_scope_receipts`, `artifact_get_receipt`, and
  `post_artifact_scope_receipts`. Raw pre/post pull+compare responses bind head
  and merge base; the exact artifact GET binds repository/PR, channel/native
  ID, provider identity, semantic time, body/digest, grammar, and artifact
  commit. The required time envelope is `pre Date <= artifact semantic time <=
  artifact GET Date <= post Date`; lifecycle remains independently re-read.
  A previously persisted identical receipt may be reused, but an artifact that
  predates every trustworthy pre observation is inconclusive because current
  metadata cannot prove its creation-time whole-PR scope retroactively.
  Missing request sidecars still close only request/reaction authority;
  missing or unstable artifact receipts block the wrapped terminal artifact.
  Neither receipt supplies request/run/artifact lineage, and their point reads
  do not exclude an intermediate ABA transition.
- Normalized current scope and artifact commit are now explicitly separate.
  `scope.head` always remains the exact current PR head. Clean must bind it;
  a finding keeps its own current-or-proved-ancestor commit and remains in the
  complete projection through the parent-owned local Git ancestry receipt. A
  later current-head clean may supersede an older projected top-level finding,
  and a resolved ancestor target thread may cease blocking under the thread
  rule, but an unresolved applicable target thread still blocks. The
  implementation must not rewrite an ancestor finding to current head or omit
  it merely to make raw and normalized projections agree.
- The authenticated provider declaration PR is itself part of the complete
  repository seed/detail traversal. Declaration authority and terminal
  classification are orthogonal: one exact receipt-bound comment may prove the
  declaration and independently classify as clean, findings, or malformed.
  Only an independently nonterminal declaration record is audit-only and, by
  itself, `confirmed-non-candidate`; arbitrary exact-provider prose is still
  fail-closed, while the existing progress grammar remains nonterminal audit
  evidence and in-window terminal-looking malformed payloads remain candidates.
  A fully parsed provider outcome at or before the exclusive lower boundary
  remains `confirmed-non-candidate` audit evidence for that frozen interval
  instead of entering candidate entries or count.
- Terminal comments/reviews count only under the authority's fixed
  clean/finding/inline-parent grammar. Clean issue comments carry one full-SHA
  `Reviewed commit` marker; clean reviews are exact `APPROVED` / native
  current-head `commit_id` / `No findings.` records whose fully paginated
  exact-provider selected-review target-child set is present and empty. A valid
  target child is findings; an unread, incomplete, malformed, or conflicting
  target join is never clean. Non-target replies remain audit context.
  Every other terminal-looking exact-provider payload is malformed. Review
  terminal-looking detection is independent of state admissibility:
  `PENDING` remains nonterminal; `DISMISSED`, or a missing/unknown state with a
  nonempty body or associated inline child, is a whole-snapshot inconclusive
  blocker. Its original `submitted_at` is not a trusted state-transition time,
  so a later-looking clean cannot supersede it. A single uniquely observed
  blocker may be reported as the stable inconclusive basis. With two or more,
  the snapshot proves only that the lane is inconclusive: IDs, list order,
  channel, and original submission times do not authorize a selector, so
  `candidate_basis`, raw source selection, and report `evidence_basis` remain
  `null` while every blocker stays in the complete audit. This is the same
  evidence-authority principle used for result-present acceptance: report only
  what the provider evidence actually proves, and do not manufacture missing
  lineage or ordering.
- `+1` can count only for `thumbs-up-clean` after a directly fetched,
  finally stable exact-bot/App GitHub declaration artifact containing the
  predeclared `If Codex has suggestions, it will comment; otherwise it will
  react with 👍.` line. Generic issuer/source strings, copied prose, local
  paraphrases with self-consistent hashes, and caller-synthesized records are
  not declaration authority. The profile also requires a GitHub
    initial-response-receipt-anchored exact `(as_of - 2592000, as_of]`
    same-repository history window and exact request/bot identity. The closed
    receipt binds method, canonical URL, integer status, canonical `Date`, raw
    response body, and body digest; the declaration snapshot is projected from
    that body. A later final receipt proves stability but never moves the
    initial window.
  The complete historical candidate universe excludes the exact current scope:
  3–10 selected historical outcomes establish the profile, while the current
  outcome separately proves this review. Every historical sample and the
  separate current outcome bind one selected exact `@codex review` parent
  request to its individual child exact-bot `+1` by positive ID, canonical
  parent endpoint, immutable scope, server times, and strict ordering. GitHub's
  reaction-list response has no reaction self URL, so the playbook never
  synthesizes one: `(parent_reactions_api_url, reaction.id)` is the stable
  native identity. Every reaction also records `parent_request_id`; it and the
  exact fully paginated parent reactions endpoint must match the enclosing
  audited request, so local nesting cannot move an R1 reaction under R2. They
  also record every accepted same-scope request and
  fully paginated reaction so a later duplicate request or cross-parent
  `eyes`/conflict cannot be hidden. The record binds the
  authenticated provider declaration identity/digest. Every historical
  candidate's complete pagination and initial/final snapshot are checked before
  sorting, including candidates that later rank outside the newest 10, and its
  ordering basis is derived from the scope-final outcome after terminal
  precedence. Candidates outside the selected newest-10 window remain
  completeness, ordering, and audit inputs, but do not themselves select the
  provider profile. A newer terminal/finding artifact, later `eyes`, or
  incomplete page therefore cannot be hidden by an older reaction-only basis.
  Once terminal precedence selects a terminal/finding artifact, every later
  legal exact-provider reaction remains visible audit evidence but does not
  replace or reorder that stronger basis. Only reaction-only classification
  restricts content to `+1` plus compatible earlier `eyes`. Current
  initial/final snapshots bind exact
  open/unmerged lifecycle, complete
  pagination, stable whole-PR scope, no trustworthy current-scope terminal
  payload or conflicting finding/thread evidence, and an unchanged final
  re-read. Those normalized snapshots are now explicitly derived views, not
  terminal or reaction-clean authority. Every accepted terminal clean/findings
  or reaction-clean basis additionally embeds independent initial/final raw
  current endpoint inventories and parent-owned initial/final local Git
  ancestry receipts for every raw-derived finding commit. The complete
  applicable artifact/thread projection from those inventories must
  type-preservingly equal the normalized current record. Object resolution
  must return exact `0`; ancestry must return exact
  `0` for current/ancestor or exact `1` for proved non-ancestor. Missing
  receipts, any other return code, commit-set mismatch, or initial/final drift
  selects `unknown`. The basis also records independently derived
  `finding_commits.initial/final`. Any raw-derived top-level finding or
  unresolved exact-provider selected-review target-thread finding whose
  `ancestry_return_code` is exact `0` blocks reaction clean.
  The reaction report embeds independently fetched initial/final
    schema-version-3 discovery transcripts, raw-derived source-authority
    inventories, and independently validated complete candidate arrays, not
    just the selected samples or a caller-adjustable count. Each transcript
    begins with a fully paginated repository-wide
    `state=all&sort=created&direction=asc&per_page=100` PR seed and drives one
    complete detail traversal for every seeded PR, including current and
    confirmed non-candidates. Current is excluded from historical candidates
    only after full parsing. Version 2 cannot prove fallback, and any
    seed/detail/page/count/byte/time budget overflow selects `unknown`. Each
    inventory entry binds scope/order plus carrier, channel, semantic result,
    native identity, and canonical source-record digest; same time/ID cannot
    substitute a reaction for a terminal artifact. Pull scope uses a canonical
    compare fetch, and only `merge_base_commit.sha` supplies `pr_merge_base`.
    Repository discovery uses the closed
    `github-codex-evidence-resource-budget-v1` profile: at most 512 seeded pull
    requests, 512 controlled requests, 8,192 fetch attempts, 4,096 retained
    pages, 20,000 records, 8,388,608 UTF-8 bytes in one page, 67,108,864
    retained UTF-8 bytes in one traversal, and 900 monotonic seconds. Every
    overflow selects `unknown`; no prefix may be treated as complete.
    Actor identity is validated before applying the frozen as-of projection.
    A fully new post-cutoff issue comment, review, or reaction from a confirmed
    different human or clearly unrelated bot remains in the raw transcript but
    may be excluded from the semantic projection only after its carrier schema,
    canonical URL, commit/scope fields, and actor all validate. A controlled
    exact `@codex review` request is always policy-relevant and must be within
    the cutoff. Any post-cutoff exact-provider or identity-ambiguous record,
    cross-cutoff issue-comment edit, or unproved carrier selects `unknown`.
    Schema version 3 has no per-inline-child server timestamp, so it cannot
    infer that a human reply attached to an in-cutoff provider review is a
    safely excludable suffix. A provider terminal artifact can form a candidate
    without an observed request, while reaction-only evidence always requires
    its exact controlled parent. `mixed` always requires terminal payload for
    a clean result.
- A no-start rejection would be availability evidence, not clean evidence, but
  the fixed authority baseline has no accepted no-start body grammar. Free-form exact-bot
  prose therefore remains inconclusive. A future policy may activate
  `evidence_basis.kind: no-start-rejection` only with an immutable
  provider-backed grammar and regression tests, while preserving the actually
  recomputed profile.
- At this fixed baseline, the accepted structured capability/installation
  schema set is empty. Integration/service state therefore cannot currently
  reduce requested triple to effective double. A future policy must pin the
  authoritative API/issuer, schema ID/version, fields,
  repository/installation binding, enum values, authentication,
  normalization, and positive/near-miss tests. Absence, timeout, permission or
  generic transport/HTTP failure, and free-form provider prose remain
  inconclusive.
- The new evidence-authority reference is part of the formal trusted-bundle
  manifest, so future self-policy reviews bind its exact bytes instead of
  treating it as an untracked explanatory side document.

## Decision Rationale

- A provider-authored terminal payload carries the actual finding/no-findings
  decision and commit scope; a request comment carries only intent to start.
  Provider evidence is therefore the verdict authority, while requests remain
  producer controls and audit records.
- The controlled request projection has exactly eight top-level fields:
  `id`, `url`, `created_at`, `updated_at`, `request_server_time`,
  `request_server_time_field`, `normalized_body`, and closed
  `user: {login, type}`. Actor identity belongs in the normalized request and
  every digest/report/sidecar comparison so an actor change cannot preserve a
  superficially identical request record. The machine-readable base-only
  retarget state machine carries the same eight-field projection and closed
  two-field user schema. The reaction projection remains its separate
  seven-field schema; the two cardinalities must not drift together.
- Declaration matching is a role, not an exclusive artifact class. A canonical
  terminal comment may contain the provider declaration line while also
  carrying a clean/finding payload; consuming it as declaration-only would hide
  the provider result and violate result-present authority. The same artifact
  is therefore evaluated independently for declaration authority and ordinary
  clean/findings/malformed terminal classification. Only a declaration record
  that independently classifies as nonterminal is audit-only, and only that
  declaration-only nonterminal scope is `confirmed-non-candidate`.
- Dynamic adaptation is subordinate to strong current evidence. Missing
  declaration, incomplete historical traversal or pagination, historical
  endpoint/artifact budget exhaustion, and historical request-sidecar failure
  may prevent `mixed` or the weak `+1` fallback, but they do not contradict an
  independently complete current terminal result; that result defaults to
  `terminal-payload`. Failures in the current endpoint/artifact receipt plane,
  current identity/scope/lifecycle/thread/ancestry/grammar, selected artifact,
  or final stability still block. This is the direct operational consequence
  of the pinned `codex-review-gate` / released Action “result present is
  sufficient verdict evidence” baseline, not a relaxation of triple's
  whole-PR proof.
- Resource deadlines are plane-local, not a global wall-clock veto. Optional
  history runs before the final current reread; fresh current trackers start
  afterward, completed phases retain their failure state without being aged by
  another phase's work, and the fresh final-current deadline is rechecked
  immediately before success. Otherwise a history timeout could incorrectly
  expire an earlier current tracker and recreate the same weak-plane veto that
  result-present authority forbids.
- Result-present acceptance does not imply retroactive scope assignment. The
  provider payload supplies the verdict, while the independent artifact-time
  receipt supplies evidence that its semantic server time was bracketed by the
  same whole-PR head/merge-base scope. Keeping those authorities separate
  preserves the Action-aligned no-request/run-binding decision without
  accepting an old clean after an unobserved base-only retarget.
- Individual reactions carry less information than terminal comments/reviews:
  notably, they have no native commit-head binding. They are therefore a
  bounded fallback only when recent eligible outcomes show reaction-only
  provider behaviour. A later `+1` or `eyes` cannot demote an already selected
  terminal payload; newer `eyes` blocks only the weaker reaction-only fallback.
- GitHub review and issue-comment APIs do not expose a general request/run
  lineage. Requiring that unavailable binding would permanently classify valid
  current-head results as inconclusive. Duplicate or mistimed requests are
  still actionable orchestration defects, but they do not contradict what the
  provider reported; they remain visible as warnings.
- This follows the fixed source regressions
  `valid current-head clean passes without creating a review marker`,
  `current-head clean passes regardless of marker timing or deadline`, and
  `marker and audit history cannot reject stable current-head clean` at the
  source baseline below. The released Action's complete 15-file tree has the
  same relative paths and Git blob identities as the source repository's
  complete `packages/action/` tree, including the full runtime closure
  `src/gate.mjs`, `src/core.mjs`, and `src/evidence-budget.mjs`. The comparison
  is therefore release-backed rather than an unreleased design inference or a
  partial-file spot check. Both trees have exact Git tree ID
  `d03de9035d20f285e6a93986d436403b4a30e9bc`; the authority reference records
  the complete 15-path blob manifest so a future baseline change cannot hide
  behind a partial comparison.
- Drift prevention is intentionally immutable: future policy changes must name
  a new source commit, released Action commit, full release-tree identity, and
  changed regression evidence. A moving branch, “latest” release, or partial
  runtime-file comparison does not silently replace this baseline.
- The Action alignment is intentionally asymmetric. Provider-result authority,
  duplicate-result consumption, and early-result consumption are inherited.
  Exact whole-PR lifecycle/scope, the artifact-time scope receipt,
  ancestor-finding projection, local-lane sequencing, warning codes, explicit
  clean payloads, the narrower full-SHA terminal grammar, and the conditional
  `+1` fallback are deliberate playbook extensions. Future edits must preserve
  that split instead of mechanically copying either implementation into the
  other. The machine-readable base-only-retarget contract is now version 2;
  version 1 request-sidecar event semantics are unchanged, and version 2 adds
  only the independent terminal-artifact scope plane.
- Future provider behaviour may change, but adaptation must select one of the
  predeclared profiles from complete bounded evidence. It must not invent a new
  reaction meaning, declaration authority source, or time-window definition, or
  silently weaken identity, scope, pagination, finding, or final-stability
  gates.
- Dynamic history is deterministic and independent: collapse to one final
  outcome per repository/PR/`pr_merge_base`/head scope. Exclude the exact
  current scope from the exact GitHub-server-time-anchored 30-day historical
  candidate universe and validate it separately. The interval is
  `(as_of - 2592000, as_of]`; the lower boundary is excluded, the upper
  boundary is included, post-cutoff policy-bearing artifacts remain invalid,
  and only the fully validated confirmed-different raw-only suffix described
  below is excluded without moving that window. The source URL, boundaries,
  and complete universe count are recorded. If that historical
  universe has at least ten candidates, take exactly the newest ten; otherwise
  take the complete historical candidate set without skipping an incomplete or
  unfavourable outcome. A moving
  `baseRefOid` does not create a second outcome when the merge base and head are
  unchanged. The three-scope minimum belongs only to historical reaction-only
  `thumbs-up-clean` evidence; it cannot downgrade terminal-payload behaviour
  inside the selected newest-10 window. A terminal payload outside that window
  remains validated audit/order evidence but does not itself select the
  profile. Each historical reaction-only outcome and the separate current
  outcome are eligible only when their selected request-comment parent, exact
  child `+1`, every same-scope request/reaction page, trusted
  request-before-reaction times, and authenticated declaration artifact/digest
  are independently recorded. Every candidate's complete scope evidence and
  ordering basis are rebound to the final scope-local outcome before sorting,
  even when that candidate later falls outside the newest-ten window. The
  selected `+1` must belong to the unique latest request by semantic time and be
  later than every same-scope request, so a later duplicate request cannot be
  mistaken for a completed weak result.
- Historical-universe candidate arrays, inventories, and counts are derived
  views, not their own completeness proof. The authoritative input is the
  parent-fetched, fully paginated raw endpoint transcript with its endpoint and
  cursor/`Link` chain. A fixed projector derives the complete source-authority
  entry, while the closed candidate evaluator separately validates every
  normalized candidate and requires its authority projection to match. Removing
  a candidate while synchronizing every derived array, inventory, and count must
  still fail because the raw transcript continues to disclose the missing
  scope.
- Issue-comment body edits use `updated_at` as semantic server time, while
  unedited comments and reactions use `created_at` and reviews use
  `submitted_at`. Review-thread joins use current GitHub GraphQL
  `fullDatabaseId: BigInt`, normalized with REST IDs as canonical positive
  decimal text. The join target set contains only exact-provider
  selected-review REST children. Every target maps exactly once; human,
  unrelated-bot, null-parent, and unrelated-only records remain fully fetched
  audit context and cannot supply resolution.
- Raw REST receipts keep GitHub timestamps as canonical whole-second RFC3339
  `Z` text. A fixed policy projector strictly converts them to positive Unix
  seconds before ordering and source hashing; numeric, offset, fractional, or
  invalid substitutes fail closed, while unrelated transport fields do not
  change the policy projection.
- Review-thread resolution comes only from fully paginated raw GraphQL
  `isResolved` evidence. First derive the exact-provider selected-review target
  subset from the fully paginated raw REST inline-comment set; only each target
  in that subset must join exactly once to raw GraphQL evidence. Non-target
  records remain audit context. Synthesized `thread_id` or `thread_resolved`
  fields on REST records are not authority; duplicate, orphaned, conflicting,
  noncanonical, or incompletely paginated target joins fail closed.
  `isOutdated` never substitutes for `isResolved`.
- Historical discovery transcript v3 records the real nested GraphQL
  `comments { nodes pageInfo }` response shape. It accepts nested comments only
  when the first connection is complete; a child cursor is fail-closed until a
  later schema version can bind that separate request instead of fabricating
  normalized pages inside a raw response. Version 3 additionally roots
  discovery in the independent repository-wide PR inventory above; version 2
  is no longer sufficient for `thumbs-up-clean`. A missing top-level GraphQL
  `errors` member or `errors: []` is admissible; `null`, a non-array value, or
  a nonempty array fails closed. A nonempty array makes each affected page
  partial even when usable-looking `data` is also present.
- Every raw declaration, request-scope receipt, REST page, and GraphQL page
  crosses one strict JSON decoder before projection. Duplicate object keys at
  any depth, nonstandard or decoded non-finite numbers, and surrogate code
  points fail closed. Endpoint objects remain forward compatible only after
  this syntax/scalar gate. Terminal body normalization separately accepts
  Unicode scalar format characters such as ZWJ, maps the grammar's declared
  line separators, and rejects other disallowed remaining controls. Progress
  detail separately rejects every C0/C1 control, including HT.
- The reaction-history as-of is frozen from the closed receipt of the initial
  direct REST GET of the exact provider declaration issue comment.
  `as_of_receipt` is that exact receipt, `as_of_api_url` is its request URL, and
  `as_of_server_time` is parsed from its canonical `Date`. A final receipt
  validates the same declaration resource but does not move the 30-day window.
  A PR, repository, final-read time, or caller-selected integer cannot replace
  that time authority.
- Reaction identity follows the documented GitHub REST data model rather than
  a locally invented URL. A future endpoint or schema change must update the
  pinned documentation reference and the executable closed-schema tests
  together; adding a caller-supplied or derived self URL is not a compatible
  extension.

## Final Named-Single Review Corrections

The formal named-single review of the then-current frozen range identified four
anti-drift gaps. These are required corrections to the evidence contract, not a
change to result-present acceptance:

1. **Raw history universe.** Preserve independently fetched, fully paginated
   endpoint transcripts as authority. Derive scope/order/source-evidence
   inventories and counts from them, validate complete candidate arrays
   independently against those projections, then perform scope collapse and
   newest-ten selection. Self-consistent derived collections cannot prove that
   the upstream universe was complete.
2. **Raw review-thread association.** Preserve both raw REST inline-comment
   pages and raw GraphQL review-thread/comment pages, normalize GraphQL
   `BigInt` IDs to canonical positive decimal text, require every exact-provider
   selected-review target child to join exactly once, and take its resolution
   only from raw GraphQL `isResolved`. Human, unrelated-bot, null-parent, and
   unrelated-only records remain audit context.
3. **Issue-comment terminal carrier.** Give provider-authored terminal issue
   comments the same closed-schema, history, current-selection, report, and
   cross-channel ambiguity coverage as pull-request reviews. Edited comments
   order by `updated_at`; unedited comments order by `created_at`.
4. **Frozen declaration as-of.** Bind the history window to the initial direct
   declaration issue-comment REST response `Date` and exact declaration
   `api_url`, then freeze both through the final declaration reread.

These corrections strengthen the independence, association, carrier, and time
provenance of evidence. They do not restore request/run lineage as a verdict
gate: producer requests still trigger and audit; the latest trustworthy
provider terminal result still decides; duplicate requests still warn rather
than automatically negate a clean result.

## Post-Review Adversarial Hardening

A second independent audit intentionally tested whether the new evidence
contract could prove itself from synchronized summaries. It found additional
anti-drift gaps, all closed without changing result-present acceptance:

- Schema-version-3 discovery retains realistic pull plus compare responses and
  adds an independent fully paginated repository-wide PR seed that closes the
  scope universe. Every seeded PR receives one complete detail traversal;
  current and confirmed non-candidates remain present through parsing. Pull
  `base.sha` and `head.sha` bind the compare URL, and only
  `compare.merge_base_commit.sha` supplies the immutable merge base. Endpoint
  objects may contain unrelated GitHub fields; the fixed projector validates
  policy fields while the raw page digest binds all bytes.
- Each raw-derived entry now includes `source_evidence`, so a reaction cannot be
  replaced by an issue comment with the same time/ID, and `+1` cannot be replaced
  by `eyes`, without a projection mismatch. Complete candidate arrays remain
  closed and stable, but their source-authority projection must match the raw
  entry rather than relying on self-consistent summaries.
- Confirmed human/unrelated-bot comments, reviews, inline threads, and reactions
  are audit-only. Provider-like ambiguous identities fail closed. Terminal
  artifacts can be consumed without an observed request; reaction fallback
  still requires the exact controlled parent.
- Raw REST inline IDs are positive JSON integers, while only GraphQL BigInt
  values use canonical decimal strings. Every admitted GraphQL thread has at
  least one comment that joins one-to-one to REST; an unresolved empty thread
  cannot disappear into a clean result.
- The declaration as-of now uses closed initial/final GET receipts. The initial
  canonical IMF-fixdate alone anchors history; a later final Date cannot move
  the window, and a correct URL/label plus an invented integer is rejected.
- The older issue-comment report envelope was removed. The unified closed
  candidate-artifact evaluator is the only issue-comment report path, and
  terminal-looking malformed fixtures must actually contain the exact
  case-sensitive `Codex Review` marker.
- Equal-time clean/clean ambiguity is exercised across the review and
  issue-comment channels, not by two artifacts from one channel.

## Final Formal-Review Authority Hardening

The latest formal review reported three authority gaps. The documentation fixes
and executable regressions are now present and validated:

1. **Repository-wide discovery root.** The prior schema-version-2 transcript
   could validate only scopes already present in the transcript and therefore
   could not prove that a whole PR scope had not been omitted. Schema version 3
   adds independent initial/final, fully paginated repository-wide
   `GET /repos/<owner>/<repo>/pulls?state=all&sort=created&direction=asc&per_page=100`
   seeds. Every seeded PR drives exactly one complete detail traversal,
   including current and confirmed non-candidates; current is excluded from
   historical candidates only after full parsing. Version 2 cannot prove
   fallback, and any evidence-budget overflow is `unknown`, never truncation.
2. **Independent current reaction authority.** Matching normalized current
   snapshots did not independently prove current endpoint completeness or
   local commit ancestry. Current `+1` clean now requires independent initial
   and final raw current endpoint inventories plus parent-owned initial/final
   local Git receipts for every raw-derived finding commit. Exact object return
   code `0` and ancestry return code `0` / `1` are the only accepted results.
   Missing receipts, another return code, commit-set mismatch, or drift is
   `unknown`. The basis records independently derived
   `finding_commits.initial/final`. Any raw-derived top-level finding or
   unresolved exact-provider selected-review target-thread finding whose
   ancestry return code is `0` blocks reaction clean. The reaction
   `evidence_basis` embeds all authority records.
3. **Target-only thread joins.** Requiring every raw REST and GraphQL comment
   to join could let unrelated replies affect the resolution decision. The
   mandatory exactly-once join now targets only exact-provider
   selected-review REST children. Fully fetched human, unrelated-bot,
   null-parent, and unrelated-only records remain audit context and cannot
   contribute resolution. Orphaned, duplicate, conflicting, or otherwise
   malformed target joins still fail closed.
4. **Terminal raw-current binding.** The terminal reference path previously
   selected from the normalized current record before validating raw current
   authority. Every terminal and reaction profile now requires a complete
   initial/final raw-current projection match. A raw-only applicable artifact
   or unresolved target thread therefore makes the profile `unknown`; the
   terminal report embeds `current_raw_authority`.
5. **Exact REST/report ID types.** Request, reaction, reaction-parent,
   selected, and artifact IDs are positive JSON integers. Quoted decimal
   strings, booleans, and floats are rejected. Canonical decimal text remains
   limited to GraphQL BigInt-to-REST joins.
6. **Schema-version-3 nested pagination.** Version 3 paginates the outer
   `reviewThreads` connection only. A nested comments connection must be
   complete in its first response; `hasNextPage == true` is `unknown` until a
   future schema version defines a bound child-cursor fetch.
7. **Resolved-child semantic stability.** A valid exact-provider target child
   keeps its parent review classified as findings even after the thread is
   resolved. Resolution controls only whether that finding still blocks a
   later clean result; it cannot rewrite the immutable provider artifact into
   clean.
8. **Nonterminal audit stability.** Exact-provider `PENDING` reviews and
   progress-only issue comments remain in a canonical initial/final raw
   authority audit projection while staying outside terminal ordering. Their
   presence does not negate a valid terminal result, but any final-reread
   change in their bound source projection fails closed.
9. **Raw-derived scope classification.** Every repository-wide discovery seed
   now has exactly one closed, raw-derived `scope_classifications` item:
   `current`, `historical-candidate`, or `confirmed-non-candidate`. The
   recorded list must equal the independently parsed transcript and the
   historical-candidate scopes must equal the complete candidate arrays;
   missing, duplicate, or relabelled seeds are `unknown`.
10. **Request-time scope receipts.** The formal review of
    `0f77fb7b1dd59f5eed522fa9699497aa013695fc..f64f149aa27399bdd37d99b5acf42a1b825266d9`
    proved that deriving historical request scope from the final PR detail
    could relabel an old request and its child `+1` onto a new head or merge
    base. The reaction plane now requires a separate parent-owned sidecar with
    closed raw pre/post PR-detail and compare responses, the exact POST
    response, canonical response dates and body digests, and a one-to-one join
    to every request field. A same-head/different-merge-base receipt remains a
    base-only-retarget blocker; an older-head receipt is an older epoch and
    does not count as a current duplicate. Receipt absence, drift, or malformed
    bytes make reaction fallback and request policy unknown but do not weaken
    or veto independently authoritative terminal evidence. The receipt proves
    no request/run lineage, and point-in-time pre/post reads do not prove the
    absence of an intervening ABA transition.
11. **Declaration discovery reachability.** The same formal review found that
    the authenticated declaration was used to select `thumbs-up-clean` but its
    PR was absent from the supposedly complete repository traversal, while the
    parser rejected the exact nonterminal declaration before its audit path.
    The declaration PR is now seeded and fully traversed, its exact
    independently authenticated raw record must appear once, and it is
    classified `confirmed-non-candidate` without changing candidate counts when
    that record is independently nonterminal.
    Only that exact declaration and the closed progress grammar are
    nonterminal audit exceptions; other free-form provider prose remains
    inconclusive and terminal-looking malformed evidence keeps fail-closed
    precedence.

These are stricter playbook evidence extensions. They do not change the fixed
`codex-review-gate` / released Action commits, common tree, 15-path manifest,
provider-result authority, result-present acceptance rationale, request/result
plane separation, or warning-only treatment of early/duplicate requests.

## Final Consistency-Audit Corrections

Two independent read-only audits then checked the request/result boundary and
the request-time retarget proof:

1. **Projection-scoped final stability.** Stable or changing duplicate,
   pending, and reaction records remain audit-only and never contradict a
   selected terminal verdict. Their raw pages must remain complete and
   parseable, but the terminal decision projection excludes their complete
   collections rather than only the request-scope sidecar. Request/reaction
   changes, request-scope-sidecar-only drift, or bounded historical
   profile-input drift can change or close request policy and reaction
   authority without erasing an independently stable terminal result. The
   strict reaction path retains the complete sidecar when comparing raw
   endpoint authority with the normalized record.
2. **Receipt-proved scope epochs.** The dedicated
   `base-changed-same-head` branch is reachable only from exactly one valid
   `parent-recorded-request-scope-v1` sidecar bound one-to-one to the request
   being revalidated. Missing, malformed, duplicate, extra, or unmatched
   sidecars do not prove retarget; they leave request policy unknown, forbid a
   new POST while request history is unproved, and preserve independent local
   and terminal gates. A valid old-head receipt is audit-only and returns the
   new head to ordinary producer-policy evaluation. A valid same-head,
   different-merge-base receipt proves the blocker and forbids a replacement
   request.

These clarifications preserve result-present acceptance. They keep request and
reaction transport changes outside terminal verdict authority, and they prevent
a derived or unbound audit record from manufacturing the base-only-retarget
state.

## Exact-Head Named-Single Regression Corrections

The formal named-single review of
`0f77fb7b1dd59f5eed522fa9699497aa013695fc..284b6ace42ffa4d53d1b1b2cf6932a50ad466cb0`
found the first five final contract-model gaps below. Three follow-up
adversarial audits added items 6–8. All eight fixes preserve the same
provider-result authority decision while making its failure boundaries
executable and auditable:

1. **Terminal/reaction plane separation.** Every legal exact-provider GitHub
   reaction remains in the raw terminal audit projection. `heart`, `confused`,
   and other legal content no longer invalidate a stable terminal payload;
   non-`+1`/`eyes` content still makes reaction-only fallback `unknown`.
2. **GraphQL partial responses.** Every outer thread page rejects a nonempty
   top-level `errors` array even when `data` is present, including failures on
   later cursor pages. Unrelated valid response extensions remain forward
   compatible.
3. **Stable inconclusive basis.** An unresolved exact-provider target thread
   supplies the blocking basis ahead of clean or malformed terminal artifacts;
   multiple stable unresolved blockers select the greatest server-time/ID pair
   independently of input order. Without an unresolved thread, only the
   ordinarily selected malformed terminal artifact supplies a blocker basis.
4. **Strict JSON authority boundary.** Declaration and request-scope receipts,
   REST pages, GraphQL pages, and the declaration rediscovery join use one
   decoder that rejects recursive duplicate keys, nonstandard/non-finite
   numbers, and surrogate-containing strings or member names before policy
   projection.
5. **Unicode scalar/control distinction.** Terminal normalization rejects all
   surrogate code points. Progress detail rejects C0/C1 controls, including
   HT, while retaining legitimate format scalars such as ZWJ and astral emoji.
6. **Terminal/request-plane isolation.** Complete terminal carriers are
   selected before reaction-only timing and selected-ID constraints. Legal
   request/reaction records remain raw audit context, but a same-time reaction,
   a reaction before a later request edit, or an unselected audit `+1` cannot
   veto the terminal result.
7. **Blocker-specific unresolved projection.** A stable unresolved target
   thread is selected by greatest server-time/ID from the same complete raw
   inventories before ordinary terminal channel arbitration. Equal-time
   cross-channel clean or malformed evidence keeps the verdict inconclusive
   while preserving that unresolved blocker in `evidence_basis`; ordinary
   terminal acceptance remains fail-closed.
8. **Operational decoder parity.** The PR probe procedure now requires the
   same strict recursive JSON decoder as the authority reference before any
   declaration, receipt, REST, or GraphQL projection. A raw-body digest does
   not make permissive duplicate-key, non-finite-number, or surrogate parsing
   acceptable.

These corrections were discovered by reviewing the exact signed candidate
head rather than by changing the decision baseline. The immutable
`codex-review-gate` source commit, released Action commit, common tree, complete
15-path manifest, and result-present acceptance rationale remain unchanged.

## Second Exact-Head Named-Single Corrections

The formal named-single review of
`0f77fb7b1dd59f5eed522fa9699497aa013695fc..3468090c9a3f81765d8401487d36dad61bd96b7c`
found two remaining consumer-side completeness errors:

1. **Frozen-window candidate boundary.** Repository discovery must still seed,
   traverse, parse, and classify a provider-bearing scope whose final result is
   older than or exactly on the exclusive lower boundary. Once proved valid,
   that scope remains raw audit evidence and is classified
   `confirmed-non-candidate` for the frozen interval, but it does not enter
   `entries`, `candidate_universe_count`, or the 3–10 eligible-outcome sample.
   Treating every discovered provider result as a candidate would make one old
   result permanently disable an otherwise valid reaction-only fallback.
   Post-as-of, ambiguous, schema-invalid/unparseable, or incomplete evidence is
   still fail-closed and cannot use this temporal exclusion.
2. **Semantic final-reread stability.** Initial and final repository discovery
   are independent traversals. Each raw body digest, REST Link chain, GraphQL
   cursor chain, and seed/detail closure must validate on its own, but GitHub's
   opaque cursor tokens and therefore raw page bytes/digests may legitimately
   differ. Stability compares the fixed semantic projection,
   classifications, candidate entries/arrays, count, and selected source
   evidence—not transport-token byte identity. Parent-owned request-time
   sidecars remain type-preserving identical because they are immutable write
   receipts, not independently refetched endpoint transport. Node, membership,
   or semantic drift remains fail-closed.

Two corrective read-only audits then exposed the remaining consequences of
that semantic-stability rule:

3. **Complete scope-authority audit.** Selected entries alone cannot establish
   semantic stability. The fixed projector now derives an audit-only
   `scope_authority_audit` for every provider-bearing seeded scope, retaining
   lifecycle, every controlled request and sidecar binding, every individual
   reaction including confirmed-different actors, every selected or unselected
   provider artifact/source digest, and provider pending/progress records. It
   is compared across traversals but never enters candidate entries/count.
   Reaction candidates are also rebound to their matching raw audit, so a
   final-only earlier `eyes` cannot hide behind the same selected `+1`.
   Terminal-determined candidates keep request/reaction-plane isolation while
   still binding lifecycle and every provider artifact. This also makes an old
   audit-only scope changing clean/findings/malformed fail closed.
4. **Actor-independent as-of bound.** The frozen server-time upper bound is
   checked before actor filtering. In particular, a future submitted review
   from a human or unrelated bot is impossible in the frozen observation and
   selects `unknown`; it cannot be discarded as ordinary audit noise.
5. **Final request-plane policy.** A final reread may legitimately discover a
   second controlled request after a stable terminal result. The terminal
   verdict remains unchanged, while `request_policy` is derived from the
   complete independently parsed final raw request plane and preserves
   `duplicate-observed`. Initial/final request-plane drift cannot erase a
   duplicate that the final snapshot proves; malformed or unbound final
   request evidence still makes only that plane `unknown`.
6. **Artifact multiplicity binding.** A normalized candidate may not insert a
   second copy of one native `(channel, artifact ID)` and rely on map
   de-duplication to match a single raw artifact. Candidate-to-raw authority is
   one-to-one and preserves occurrence count; any repeated native identity is
   rejected.
7. **Old-epoch and audit-only sidecars.** Each request derives its own immutable
   scope from its pre/POST/post sidecar. An old-head request and reaction remain
   old-epoch audit evidence even when their timestamps are newer than the
   current-scope request; they do not enter current reaction ordering,
   duplicate warnings, or `same_scope_request_audit`. Conversely, a final-only
   sidecar change on an expired audit-only scope still invalidates the weak
   reaction profile because the immutable write receipt changed.
8. **Cross-document plane terminology.** Entrypoint, readiness, prompt, lane,
   interface, and probe documents now reserve provider `unknown` for
   provider-artifact/thread/finding or ancestry-authority failure. A
   request/reaction/sidecar-only failure closes its own plane without erasing
   an independently stable terminal result. Historical malformed terminal
   evidence is a candidate only inside the frozen window; a fully parsed
   expired record remains audit-only `confirmed-non-candidate` evidence.

These are corrections to sampling and reread mechanics, not changes to the
provider-evidence decision. They preserve the pinned alignment with
`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`
and the released
`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`
whose common Action tree is
`d03de9035d20f285e6a93986d436403b4a30e9bc`. “Result present means pass” still
means that a trustworthy current-scope provider result is verdict authority;
it never meant that every fully traversed historical scope must count as a
current profile sample, or that transport-specific opaque cursors are verdict
semantics.

## v7 Named-Single Superseding Corrections

The formal v7 named-single review of
`0f77fb7b1dd59f5eed522fa9699497aa013695fc..1774f12e180b88193c0b88568b3895a2760393b5`
found three P2 gaps. This section deliberately preserves the earlier
“Actor-independent as-of bound” and old-epoch entries above as review history,
but supersedes them wherever they conflict with the rules below.

1. **Old-epoch-only poisoning.** A fully validated request-scope sidecar bound
   to the same repository and PR but a genuinely different head is old-epoch
   audit evidence. It does not enter current-scope request ordering, duplicate
   warnings, reaction fallback, or candidate count. When the traversed endpoint
   is the selected current PR but every controlled request is old-head, the
   scope remains classified `current` with no candidate entry; for another
   fully traversed historical PR scope it is `confirmed-non-candidate`, also
   with no entry. This exception requires closure over every request receipt.
   A same-head/different-merge-base receipt is not an old epoch; missing,
   malformed, duplicate, extra, or unmatched sidecars remain fail-closed.
2. **Actor-first raw-only suffix.** The former actor-independent rule could
   never converge after a legitimate human or unrelated bot wrote a record
   after the frozen cutoff. Identity is now validated first. A fully new
   post-cutoff non-request issue comment, review, or reaction may remain
   raw-only and be excluded from the semantic projection only when it is proved
   to come from a confirmed different human or clearly unrelated bot and its
   complete carrier schema, canonical URL, commit/scope fields, and actor all
   validate. A controlled exact `@codex review` request is always
   policy-relevant and must be within the cutoff. A post-cutoff exact-provider
   or identity-ambiguous record, a cross-cutoff edit to an issue comment, or an
   invalid/incomplete carrier remains fail-closed. Schema version 3 exposes no
   per-inline-child server timestamp, so it cannot infer that a reply attached
   to an in-cutoff provider review is a safely excludable later human suffix.
3. **Executable repository-wide resource budget.** Every initial and final
   traversal now uses the exact closed
   `github-codex-evidence-resource-budget-v1` profile: 512 seeded pull requests,
   512 controlled requests, 8,192 fetch attempts, 4,096 retained pages, 20,000
   records, 8,388,608 UTF-8 bytes per page, 67,108,864 retained UTF-8 bytes per
   traversal, and a 900-second monotonic deadline. Attempts, pages, bytes, and
   records are charged before their corresponding request, decode, retention,
   or accumulation step; exceeding any cap selects `unknown` without accepting
   a truncated prefix. Initial and final traversals receive independent
   budgets and deadlines.

Implementation hardening while closing those findings made the bounds and
plane separation explicit. Endpoint evidence, request-scope sidecars, and
terminal-artifact scope receipts use three non-borrowing ledgers under the same
inventory start/deadline; each sidecar or artifact wrapper is pre-counted and
its five raw responses are byte- and record-bounded before digesting or
decoding. The artifact ledger is created once for an inventory decision pass;
each immutable wrapper is charged and validated once, and candidate ordering,
audit, profile, outcome, and report consumers reuse that memoized result.
Per-candidate/scope/recomputation resets and repeated charging are forbidden.
Sidecar overflow closes request/reaction authority but does not erase a
complete terminal result; aggregate artifact-ledger overflow invalidates the
complete terminal projection and cannot accept a validated prefix. A current
raw inventory parses its single retained detail fetch set once—without a
synthetic repository seed, duplicate pull parse, second deadline, or
post-budget byte rewrite. Known
GraphQL nested-record counts are charged before cloning/serialization. The
semantic projection also retains in-cutoff confirmed-different and
null-parent/unrelated audit context, while only fully validated post-cutoff
confirmed-different suffixes may converge as raw-only noise. The result digest
for a review stays target-only; a separate scope-level `review-thread-audit`
digest in `nonterminal_records` binds every non-excluded semantic GraphQL
thread, so associated-human, unrelated-parent, and null-parent thread drift is
visible without granting those threads provider result or resolution
authority. Invalid-state terminal signals are also checked before the history
window: their original `submitted_at` cannot turn a later dismissal or unknown
state into an expired `confirmed-non-candidate`.

The memo cache is deliberately outside those retained-evidence counters, but
it is not outside the resource boundary. The fixed
`github-codex-memo-fingerprint-guard-v1` rejects non-JSON values, cycles,
depth above 64, more than 20,000 entries in one container, more than 2,000,000
value/key occurrences (each object key and each value counts once), an integer
above 128 bits, a scalar above 8 MiB UTF-8, or more than 64 MiB of scalar UTF-8
in one memo input. A no-hash iterative preflight runs first. On a
miss, the endpoint, sidecar, or artifact producer then completes its ordinary
ledger validation before a sorted-key, type-tagged streaming fingerprint is
created; on a hit, summary drift rejects before hashing and equal-summary
content is rehashed. This ordering is intentional: memo identity must still
detect equal-size nested edits, but it must not serialize or hash the complete
untrusted tree before the evidence budget that gives the result authority.
Periodic zero-charge deadline checks keep that temporary work inside the same
plane without double-charging fingerprint bytes as retained GitHub evidence.
The cache key also binds the owning tracker. Endpoint transcripts/fetches,
request-scope sidecars, and artifact wrappers are separate memo subjects;
composite normalized inventory envelopes are rechecked from those plane-local
results rather than scanned under one plane's budget.

Two outcome boundaries are likewise explicit. A valid same-head/different-base
sidecar blocks even when a terminal clean exists, because it proves that the
whole-PR scope changed. Conversely, a new receipt-bound R2 observed only during
the final reread after a stable clean changes request policy (normally to
`duplicate-observed`) but not terminal outcome authority. A missing or malformed
R2 sidecar makes request policy unknown; it still cannot delete the already
proved stable result. This is the direct implementation of the producer-policy
versus consumer-verdict split below.

The decision itself is unchanged and is recorded here explicitly to prevent
future drift: **a trustworthy result being present is sufficient verdict
evidence**. In concrete terms, a stable current-scope clean provider artifact
may pass when every historical finding is resolved and no newer finding,
malformed terminal artifact, unresolved thread, lifecycle/scope change, or
incomplete snapshot contradicts it. A request records producer intent and
orchestration compliance; it is not the consumer verdict. Therefore
`duplicate-observed` and early-request warnings remain visible, and the agent
must not produce another same-scope request, but those producer-policy defects
do not veto an independently valid provider result or require a fabricated
request/run join.

This decision remains pinned to
[`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`](https://github.com/JoeyTeng/codex-review-gate/commit/16366aa81270ad2c875d2ceb8ce194f5b2308af6)
and the released
[`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`](https://github.com/JoeyTeng/codex-review-gate-action/commit/2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6),
with common Action tree
`d03de9035d20f285e6a93986d436403b4a30e9bc`. Provider-result authority and
consumption despite duplicate or early request timing are inherited from that
baseline. The 20,000-item, 8-MiB-response, and 64-MiB-run magnitudes align with
its pinned `src/evidence-budget.mjs`; the playbook maps those bounds to records,
per-page UTF-8 bytes, and retained traversal bytes. The 512 seeded-PR, 512
controlled-request, 8,192 fetch-attempt, 4,096 retained-page, and 900-second
limits are playbook-specific extensions. This is an evidence-authority
alignment, not a claim that the Action and playbook have identical scope or
runtime policy.
Any future change must update the pinned source/release/tree evidence and state
which inherited decision or playbook extension changed; it must not silently
restore request/run binding or erase this rationale.

## Implementation Intent

- Use
  `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`
  as the detailed normative source for GitHub Codex evidence consumption.
- Keep entrypoint surfaces concise and link to the authority reference instead
  of duplicating the full decision matrix.
- Preserve the stricter playbook requirements for exact PR lifecycle and
  whole-PR base/head scope.
- Require schema-version-3 repository-wide raw discovery, full seed-to-detail
  coverage, post-parse current exclusion, and fail-closed budget handling
  before reaction fallback.
- Preserve the report matrix for unsupported/no-PR, waiting, terminal,
  reaction-fallback, reserved authenticated no-start, and inconclusive states,
  including channel-specific `server_time_field` values.
- Terminal-payload reports embed identical initial/final selection and selected
  artifact snapshots plus independent initial/final raw-current inventories,
  raw-derived finding-commit sets, and parent-owned ancestry receipts. Review
  snapshots include exact actor/state/body/commit plus fully paginated
  associated inline children and target-only thread joins; non-target replies
  remain audit context. Issue comments include exact actor/App/body/time/commit
  marker inputs. Sparse summaries cannot prove the closed grammar or final
  reread.
- Reaction reports embed the same raw-current authority. Normalized current
  snapshots cannot replace its complete applicable artifact/thread projection.
- Keep REST/report IDs as exact positive JSON integers. Keep GraphQL BigInt
  canonical decimal text only at the join boundary.
- Under schema version 3, fail closed when a nested thread-comments connection
  needs another page; do not claim or fabricate a child-cursor traversal.
- Require an explicit commit-bound clean payload for terminal-payload
  completion; an empty `APPROVED` review does not count, and an exact
  `No findings.` review is clean only after its complete exact-provider
  selected-review target-child set is proved empty.
- Treat the dynamic `+1` fallback as a playbook-specific policy extension, not
  as behaviour inherited from the fixed Action release.
- This workstream defines documentation and policy contracts only; a runtime
  GitHub evidence evaluator or API is outside its scope.

## Next Steps

- After the canonical repository change merges, manually dispatch
  `scheduled-sync-release.yml` in `Joey-Tools/codex-private-workflows` with
  `force=true`.
- Confirm the matching private-workflows sync PR merged or was explicitly
  unnecessary, then confirm the default-branch Private Overlay Release ran.
  If the release needs a manual rerun, dispatch `release.yml` on `master`.
- Any future runtime evaluator must implement the reference without collapsing
  request warnings, provider outcome, profile, and evidence basis into one
  status.

## Validation

- The named-single review of
  `0f77fb7b1dd59f5eed522fa9699497aa013695fc..7c57e1ee14c996c79b9df9cc30e9df8ce95f4a4e`
  found two P1 evidence gaps. First, final current metadata could retroactively
  assign a new merge-base scope to an older terminal artifact when request
  sidecars were absent. Second, normalized current records required every
  finding commit to equal current head even though raw authority deliberately
  retains proved-ancestor findings. The artifact-time receipt and
  scope-head/artifact-commit separation recorded above are the corrections;
  they preserve result-present/request-run independence rather than reversing
  it. This remains aligned to the immutable source
  `JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`,
  released Action
  `JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`,
  and common tree `d03de9035d20f285e6a93986d436403b4a30e9bc`;
  artifact-time whole-PR proof and ancestor-finding projection remain stricter
  playbook extensions. A new exact-head review is required before completion.
- The v7 named-single review of head
  `1774f12e180b88193c0b88568b3895a2760393b5` reported the three P2 findings
  recorded in “v7 Named-Single Superseding Corrections”: old-epoch-only scope
  poisoning, non-convergent actor-independent as-of filtering, and the absence
  of an executable numeric repository-wide budget. The current candidate
  contains the corresponding policy and contract corrections. Its final full
  validation gate and successor exact-head named-single review remain pending;
  this journal does not claim either result in advance.
- The final candidate gate reruns the focused 102-test contract module, the
  complete review-orchestration suite, Ruff format/lint, the skill validator,
  the project-journal validator, JSON parsing when changed JSON exists, and
  `git diff --check` after the candidate bytes stop changing. The focused
  command is
  `python3 -B -m unittest skills.review-orchestration-playbook.tests.test_contracts -q`.
- The complete suite runs outside the filesystem sandbox because provider tests
  require temporary Unix and loopback socket binds:
  `/usr/bin/env PYTHONDONTWRITEBYTECODE=1 /Users/hoteng/.pyenv/versions/3.13.0/bin/python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py' -q`
  The exact final command results and final named-single receipt remain
  parent-owned outside the candidate head: writing observed durations or the
  review result back here would move the byte range they attest. A historical
  pre-correction run completed 2,822 tests with 6 expected skips; it is useful
  regression evidence but does not substitute for the final frozen-byte run.
- Read-only consistency audits covered request/reaction exclusion from terminal
  equality, strict reaction-sidecar equality, duplicate/pending requests,
  final-reaction drift, receipt-proved retarget paths, terminal reaction-plane
  isolation, strict JSON/GraphQL/Unicode parsing, and blocker-specific
  unresolved projection. Their corrections are recorded above; the final
  exact-head named-single result remains parent-owned for the same reason.
- The workstream remains `active` only until this exact snapshot receives its
  signed commit and final fixed-range named-single review. Validation through
  head `f64f149aa27399bdd37d99b5acf42a1b825266d9` and all earlier per-head timing
  receipts are historical evidence and do not substitute for this final gate.
- An earlier named-single review found two P2 contract gaps: a synthesized
  reaction self URL and a self-consistency-only report classifier. Both were
  removed and replaced by parent-endpoint-plus-ID reaction identity and a
  report validator rebuilt from authoritative inputs.
- The first final-range named-single review found one P1 reference-evaluator
  gap: a newer clean terminal artifact could bypass an older unresolved review
  thread. The report derivation now preserves the latest provider terminal
  outcome while globally refusing completed-clean until every applicable
  thread-backed finding is resolved, with an executable regression for the
  older-unresolved-thread plus newer-clean case.
- Prior follow-up independent audits completed clean after probing accepted terminal
  clean/findings reports, later-reaction terminal precedence, every
  missing/false/numeric request-completeness combination, closed schemas, JSON
  type identity, cross-scope native-ID collisions, selected provenance,
  terminal child/thread joins, newest-10 ordering, fixed Action provenance,
  and the result-present decision rationale.
- The final cross-document audit found no remaining P1/P2 after verifying
  heading-bounded schema-version-3 markers in all five authority/consumer
  documents and v3-to-v4 drift regressions.
- The named-single review of
  `0f77fb7b1dd59f5eed522fa9699497aa013695fc..249978b846c108cd3d9ac98fddf54475b8a92504`
  found the one P1 and two P2 follow-up gaps recorded above. Its receipt is
  parent-owned evidence. The corrected exact-head review will likewise remain
  outside the candidate head because writing it back would change the reviewed
  range.
- The later named-single review of
  `0f77fb7b1dd59f5eed522fa9699497aa013695fc..a1403a4f3b0bd63603591dc33c09583f8a8a69e0`
  found three P2 authority gaps: resolved target children could be
  reclassified as clean, nonterminal provider records could reject an
  otherwise valid terminal inventory instead of remaining audited, and the
  historical inventory lacked a closed raw-derived classification for every
  seeded PR. Items 7–9 in “Final Formal-Review Authority Hardening” record the
  fixes. Independent follow-up audits of resolved-child semantics, nonterminal
  coexistence and final-reread drift, and raw-derived scope classification all
  returned no findings.
- Two final targeted audits then checked the corrective diff. The raw-current
  authority projection audit returned no findings. The ID/pagination audit
  found one remaining P2: the issue-comment schema example still quoted
  `id` and `stable_artifact_id`. The example now uses positive JSON integers,
  and executable review/issue-comment regressions reject string terminal
  artifact IDs.
- The subsequent final-range named-single review found one P2 resource-ordering
  gap: artifact and inventory memo keys called full-tree `json.dumps` and
  SHA-256 before their uncached validators charged the evidence ledgers. The
  bounded two-stage guard above is the correction. Its regressions prove that
  over-budget and over-depth inputs reach neither the unbounded serializer nor
  the hasher/producer, while an equal-summary nested edit still invalidates a
  successful cached result. The successor exact-head review remains required;
  this entry records the reason and correction, not a future verdict.
- Two focused follow-up audits then found that a bounded fingerprint could
  still be assigned to the wrong ledger: the current endpoint path scanned its
  composite inventory, while historical endpoint/artifact paths scanned
  envelopes containing request sidecars. That would let a deep unused sidecar
  fail the endpoint or artifact tracker and erase an otherwise complete
  terminal result. Memo subjects are now the exact plane-owned transcript or
  fetch list, sidecar list, or artifact wrapper; cache identity also binds the
  owning tracker, and composite envelopes are rebuilt from those independent
  results. The same audits fixed the integer conversion boundary at 128 bits,
  clarified that the 2,000,000 limit counts every value and every object key,
  and added probes proving that producer, canonical serialization,
  `json.dumps`, and SHA-256 are not reached before a guard rejection. The
  declaration/ancestry policy namespace now uses the same bounded preflight and
  streaming digest instead of canonical JSON. Artifact caches bind the exact
  tracker and exact-type PR scope, the root coordinator cannot own a memo, and
  narrowed current-fetch memoization validates the complete excluded scaffold.
  Healthy negative cache results carry and recheck a content digest; mutation
  of an immutable negative remains fail-closed until the next fresh context.
  Finally, a truthy partial producer result cannot survive a failed owning
  ledger. These details prevent Python equality aliases, cross-ledger reuse,
  and stale summary-only negatives from weakening the authority boundary.
  A final focused audit found one remaining accounting path: complete history
  could validate wrapper responses before the wrapper-array record precharge,
  then fall back sidecar-blind and reuse the cached artifact. Complete,
  sidecar-blind, and candidate-ordering paths now call one tracker-bound
  exact-list/dict precharge before wrapper iteration. The regression asserts
  the closed six-record cost for every wrapper (one wrapper record plus five
  responses), including an accepted
  `unused-sidecar-unavailable` fallback.
  The next independent pass closed two adjacent aliases: ancestry filtering now
  precharges the original exact arrays before iteration and can bind a filtered
  view only when it is an identity-preserving subsequence, while current raw
  parsing requires an exact object/fetch-list scaffold and exact positive
  integer PR number. Thus a list subclass cannot run before admission, and JSON
  `true` or `1.0` cannot be washed into PR `1` by the synthesized narrow
  transcript. The final memo audit extended the same rule to every narrowed
  transcript container and to repository/head text: equality-compatible dict,
  list, or string subclasses are rejected before cold-cache or cache-hit reuse.
  It also locked the filtered ledger contract directly: a retained wrapper must
  be the identical ordered source object with no extra multiplicity, and a valid
  projection reuses the already charged array entries without charging them a
  second time. These checks prevent the synthetic current-scope envelope from
  laundering foreign outer metadata or uncharged cloned evidence into provider
  authority.

## Post-Review Artifact Receipt Hardening

The later fixed-range review and focused follow-up audits clarified why
provider-result authority needs an independent artifact-time scope proof in
the stricter triple lane:

- The pinned Action baseline still supplies the primary consumer rule: a
  complete trustworthy provider result is verdict evidence even when request
  count, request timing, or request/run lineage is unavailable. Duplicate and
  early requests remain producer-policy warnings, not a veto. This preserves
  the earlier “result present is sufficient” decision instead of silently
  restoring request/run coupling.
- The playbook additionally claims exact current whole-PR coverage. A current
  head alone cannot prove that an older terminal result predates a same-head
  base retarget, so every terminal-looking artifact now needs its own
  pre/artifact-GET/post scope receipt. This extension establishes artifact-time
  repository, PR, merge base, head, identity, body, and semantic time without
  inventing request/run/artifact lineage.
- Receipt validators strictly parse, retain, digest, and finally re-read the
  complete raw GitHub bodies, but compare only their closed authority
  projection. Real REST resources legitimately carry additional fields; full
  equality with a synthetic minimal fixture would reject all production
  evidence, while ignoring a projected identity/scope/time/body field would be
  unsafe.
- Artifact scope derives the real base/head OIDs from each retained pull body,
  constructs the canonical compare URL from those values, and requires the
  compare body to repeat both OIDs plus the unique merge base. Fixture-derived
  or PR-number-derived synthetic SHAs cannot stand in for production scope,
  and a compare body for another head cannot lend its merge base.
- Evidence time and observation time are separate. The frozen reaction-history
  as-of constrains eligible historical artifact semantic time. It does not
  prohibit collecting the exact artifact GET or post-scope receipt later in
  the same bounded decision/final reread, provided the required time envelope
  and final stability hold. Nor does it cap a strong current terminal result's
  semantic time: `terminal-payload` or `mixed` evidence may arrive during the
  bounded provider wait after declaration discovery. Only historical samples
  and the current reaction-only fallback basis use that cutoff.
- An ancestor finding may vary only the artifact-time head. Repository, PR,
  and merge base remain equal to the evaluated whole-PR scope, and normalized
  `scope.head` remains current. A proved non-ancestor is raw audit-only; placing
  it in normalized active or unresolved finding lists is a projection mismatch
  and selects `unknown`.
- Review completeness is cardinality-independent. Validate every associated
  exact-provider inline child and its unique target-thread join. Any applicable
  unresolved child blocks; a later strong clean may supersede the older review
  only after all applicable children are resolved.
- Endpoint, request-sidecar, and artifact-receipt validation have three
  non-borrowing ledgers sharing one inventory start/deadline. Create one
  artifact decision context, charge and validate each immutable wrapper once,
  and reuse that result through ordering, audit, profile, outcome, and report
  construction. Per-candidate/scope/recomputation resets, pre-charge
  serialization of untrusted wrappers, repeat charges, and validated-prefix
  acceptance are forbidden.

These corrections remain part of the active candidate until the final focused
and complete suites, validators, signed commit, and successor exact-range
named-single review complete. Their eventual receipts remain parent-owned so
recording them cannot move the bytes they attest.

## Evidence

- `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`
- Source baseline:
  [`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`](https://github.com/JoeyTeng/codex-review-gate/commit/16366aa81270ad2c875d2ceb8ce194f5b2308af6)
- Released Action baseline:
  [`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`](https://github.com/JoeyTeng/codex-review-gate-action/commit/2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6)
- Complete source/release tree baseline:
  `d03de9035d20f285e6a93986d436403b4a30e9bc`.

| Relative path | Git blob ID |
| --- | --- |
| `COOKBOOK.md` | `70784aed0869504d85cd9b95710b2dea427841e5` |
| `COOKBOOK.zh-CN.md` | `f7dc955b8ebd1673883d38352f37b58099b1227d` |
| `DESIGN.md` | `8de87334a37bd85a6b3f3d1a4362933eeacbab25` |
| `DESIGN.zh-CN.md` | `45026f208847f1385780ffe9904b58b98903fb44` |
| `EULA.md` | `eeaeb240bb31e35e2d7c574c044d3ddcbb64ea30` |
| `LICENSE` | `d9a10c0d8e868ebf8da0b3dc95bb0be634c34bfe` |
| `README.md` | `c43aeded90def8d5876dec6d67e07a7cdcfac038` |
| `README.zh-CN.md` | `c66a93b90a3354269f2f91135103490cc949a81e` |
| `SECURITY.md` | `ae8b45461e2f41350b1e6fc7343504fc4c9dcd8b` |
| `SUPPORT.md` | `4378a1e3377ee0fb58fcaa7a2ad715a4d53e814f` |
| `action.yml` | `2169ca33d1cb8c698805513768e6a5c34887fe35` |
| `package.json` | `b554018df447543590a0f732968892ccc22050f3` |
| `src/core.mjs` | `7270586bced68f0faca15ebe844f0517dc7b1ec3` |
| `src/evidence-budget.mjs` | `b2a07e9a4dd33dc60d138d97a59444b3fc537677` |
| `src/gate.mjs` | `e0b974b27ebd64e412eaef1d069789b5f6bd76ba` |

This exact 15-path manifest, rather than a branch name or partial runtime-file
comparison, is the immutable alignment anchor. The inherited baseline is
provider-result authority plus duplicate/early-result consumption. The
playbook extensions are stricter whole-PR lifecycle and scope, explicit
terminal-payload grammar, local-lane sequencing, warning/report fields, raw
history and thread completeness, final stability, and the conditional `+1`
fallback. Future changes must state which side of this boundary changed and pin
a new source commit, release commit, complete tree ID, and full manifest.
- GitHub REST reaction model:
  [List reactions for an issue comment](https://docs.github.com/en/rest/reactions/reactions#list-reactions-for-an-issue-comment)
  returns the reaction ID from the parent-scoped collection and does not
  define a reaction self URL.
- Authenticated GitHub GraphQL schema introspection on 2026-07-30 returned
  `fullDatabaseId: BigInt` for both `PullRequestReviewComment` and
  `PullRequestReview`, with no `databaseId` field in either selected field set.
- The fixed source `packages/action/` tree and released Action root share the
  same 15 relative paths and Git blob identities: the ten shipped documentation,
  license, support, and security files; `action.yml`; `package.json`; and the
  complete runtime closure `src/gate.mjs`, `src/core.mjs`, and
  `src/evidence-budget.mjs`.

## Generative AI Disclosure

This workstream was implemented with OpenAI Codex assistance.
