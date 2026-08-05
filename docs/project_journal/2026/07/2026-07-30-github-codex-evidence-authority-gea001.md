---
id: 20260730-gea001
title: GitHub Codex Provider-Evidence Authority
status: completed
created: 2026-07-30
updated: 2026-08-05
branch: wip/github-codex-evidence-authority
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/87
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
- A newer fully receipted current-head terminal result can restore decision
  authority while two exact, strictly older pre-v1 carrier shapes remain
  complete audit-only history; this prevents old transport limitations from
  defeating the recorded result-present decision without accepting arbitrary
  legacy prose.

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
  repository/PR/merge-base/head scope. The raw discovery transcript uses
  schema version 4; final PR metadata can never regenerate or relabel an older
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
  commit. The required time envelope is `pre Date < artifact semantic time <=
  artifact GET Date <= post Date`; lifecycle remains independently re-read.
  A previously persisted identical receipt may be reused, but an artifact that
  does not strictly follow every trustworthy pre observation is inconclusive
  because current metadata cannot prove its creation-time whole-PR scope
  retroactively.
  Missing request sidecars still close only request/reaction authority;
  missing or unstable artifact receipts block the wrapped terminal artifact.
  Neither receipt supplies request/run/artifact lineage, and their point reads
  do not exclude an intermediate ABA transition.
- The v1 receipt is intentionally an **artifact-publication scope** contract.
  A complete pre/artifact/post envelope authorizes the whole-PR tuple observed
  around publication even if request history is unbound or a caller reports
  that provider work began under an earlier merge base. It does not attest the
  provider's internal input merge base. Only a valid
  same-head/different-merge-base request sidecar proves
  `base-changed-same-head`; a missing or malformed sidecar is `not-proved`,
  makes request policy unknown, and cannot veto an independently trustworthy
  terminal result. Requiring unavailable launch-time scope would restore the
  rejected request/run/artifact binding. A future provider-authenticated
  input-base marker governed by a predeclared provider profile may change this
  policy explicitly; caller narrative and inferred timing may not.
- Reports describe this assurance as `artifact-publication-only`. They may say
  that a terminal result is independently trustworthy for the selected
  publication-time evidence scope, but they must not claim that GitHub Codex
  reviewed the current whole-PR range or that its internal input merge base was
  attested. `Result present` does not make an unreceipted historical artifact
  current-scope evidence.
- Legacy receipt migration never adopts an old artifact retroactively and
  never lets the agent POST a replacement same-scope request. Recovery is
  limited to an ordinary substantive change that creates a new head, or one
  explicitly caller-owned manual exact `@codex review` trigger on the unchanged
  head after the parent persisted the standard pre-artifact pull/compare scope
  pair. The agent neither performs nor repeats that POST and creates no request
  sidecar for it; request policy remains `unknown`, and reaction-only evidence
  is unavailable. Only a later terminal artifact that strictly follows the pre
  boundary and completes the normal version-1 artifact receipt/final-stability
  contract can decide without request/run attribution. Otherwise the lane
  remains `triple-inconclusive`. A proved `base-changed-same-head` event cannot
  use the manual path and requires a real new head; empty or anchor commits are
  not recovery mechanisms.
- The tolerated legacy member is now closed to exactly two raw-internal
  migration-only carriers; an ordinary unreceipted current-grammar clean or
  finding cannot enter. `legacy-finding-native-review-v1` reports role
  `finding` only for an exact-provider
  `COMMENTED`/`CHANGES_REQUESTED` native review with the exact
  `### 💡 Codex Review` layout, one same-repository full-SHA blob URL
  equal to native `commit_id`, one fixed `P0/red`, `P1/orange`, `P2/yellow`,
  or `P3/lightgrey` shields badge, and bounded title/prose containing neither
  `www.` nor a URI-scheme prefix whose colon is immediately followed by a
  non-whitespace character. After newline normalization, every physical
  disclosure line is trimmed and blank lines are dropped; the remaining lines
  exactly equal the closed nine-line disclosure. It is separated by either no
  padding line or exactly one line of four ASCII spaces, with no other
  title/prose trailing whitespace or blank line before it, and the review has
  no associated inline child. This grammar is raw-migration-only and never
  becomes receipt-bound current/provider authority. An exact
  old short clean issue comment remains role `clean-pending-resolution` with
  its raw lowercase 10-hex ref. A non-current prefix requires the exact stable
  parent-owned initial/final local Git prefix-resolution receipt arrays; an
  ancestry array cannot self-attest it. The receipts completely cover every
  raw-derived prefix, are unique and sorted by `raw_prefix`, enumerate exactly
  one prefix-matching full commit with disambiguation/commit/ancestor return
  codes `0`, and remain type-preservingly identical. They prove only ancestor
  applicability, and the report still retains the raw 10 hex. Neither becomes a provider carrier, candidate
  basis, or superseding evidence. Both must be strictly older than both
  selected-result pre-scope `Date` receipts and stable in the initial/final raw
  projections. A near-miss, unresolved thread, bad ancestry, equal/newer
  legacy time, missing selected-artifact scope/resolution receipt, incomplete
  pagination, or scope/lifecycle/final-read drift still fails closed.
- Unrecoverable old request sidecars may leave `request_policy` `unknown`; that
  producer/audit status forbids another same-head POST and disables reaction
  authority, but it does not independently null a newer complete provider
  clean. The selected result requires no fabricated request/run binding.
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
  clean/finding/inline-parent grammar. Clean issue comments carry one exact
  lowercase 10- or 40-hex `Reviewed commit` marker. A 10-hex marker additionally
  remains raw `clean-pending-resolution` and non-authoritative until the stable
  exact-repository commit-resolution companion introduced by the 2026-08-05
  live-provider compatibility follow-up joins its artifact ID, scope, ref, and
  resolved current full SHA. Current, complete-history, and sidecar-blind
  historical paths all require that same join; sidecar-blind may ignore request
  sidecars but never the resolution companion. The receipt dates prove
  `artifact GET <= initial resolution <= post-scope snapshot(s) <= final resolution`
  with same-second equality allowed, so authority does not rest on a prose claim
  about invocation order. Clean reviews are exact
  `APPROVED` / native
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
  schema-version-4 discovery transcripts, raw-derived source-authority
  inventories, and independently validated complete candidate arrays, not
  just the selected samples or a caller-adjustable count. Each transcript uses
  the updated-desc pull boundary, the fully paginated since-cutoff controlled
  request-comment feed, and exact current/declaration anchors, then drives one
  complete detail traversal for every PR in their deduplicated union. Current
  is excluded from historical candidates only after full parsing. Version 3
  cannot prove reaction fallback, and any source/union/detail/page/count/byte/
  time budget overflow selects `unknown`. Boundary witnesses and cumulative
  old PRs consume endpoint budgets but do not consume the 512 union/detail cap.
  Each inventory entry binds scope/order plus carrier, channel, semantic result,
  native identity, and canonical source-record digest; same time/ID cannot
  substitute a reaction for a terminal artifact. Pull scope uses the canonical
  bare pull-detail request plus an exact pull-derived compare URL; the response
  body's `base_commit.sha` and `merge_base_commit.sha` bind the remaining exact
  scope fields.
  Discovery uses the closed `github-codex-evidence-resource-budget-v1`
  profile: at most 512 union-seeded pull requests, 512 controlled requests,
  8,192 fetch attempts, 4,096 retained pages, 20,000 records, 8,388,608 UTF-8
  bytes in one page, 67,108,864 retained UTF-8 bytes in one traversal, and 900
  monotonic seconds. Every overflow selects `unknown`; no prefix may be treated
  as complete. Actor identity is validated before applying the frozen as-of
  projection. A fully new post-cutoff issue comment, review, or reaction from a
  confirmed different human or clearly unrelated bot remains in the raw
  transcript but may be excluded from the semantic projection only after its
  carrier schema, canonical URL, commit/scope fields, and actor all validate. A
  controlled exact `@codex review` request is always policy-relevant and must
  be within the cutoff. Any post-cutoff exact-provider or identity-ambiguous
  record, cross-cutoff issue-comment edit, or unproved carrier selects
  `unknown`. Schema version 4 has no per-inline-child server timestamp, so it
  cannot infer that a human reply attached to an in-cutoff provider review is a
  safely excludable suffix. A provider terminal artifact can form a candidate
  without an observed request, while reaction-only evidence always requires
  its exact controlled parent. `mixed` always requires terminal payload for a
  clean result.
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
- GitHub gives the receipt's semantic timestamps and HTTP `Date` values only
  whole-second authority. A pre `Date` equal to the artifact semantic time
  cannot order “old-base artifact first” against “same-head retarget and pre
  read later in the same second.” The artifact is therefore inconclusive at
  equality; only a strictly earlier pre boundary can bind it to the observed
  scope. This closes retroactive scope assignment without restoring
  request/run coupling or weakening result-present authority.
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
- The Action alignment is intentionally asymmetric and remains pinned to source
  `JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`
  and released Action
  `JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`.
  Provider-result authority, duplicate-result consumption, and early-result
  consumption are inherited. Short-marker parity is limited to 10/40 carrier
  lengths and the short carrier's fail-closed exact-repository REST resolution
  outcome. Lowercase-only refs, exact marker spacing, the exact-two-LF/nonblank
  boundary, closed lead/tagline/disclosure/native grammar, and independent
  parent-recorded initial/final receipt evidence remain stricter playbook rules;
  complete grammar parity with the Action is not claimed. Exact whole-PR
  lifecycle/scope, the artifact-time scope receipt, ancestor-finding projection,
  local-lane sequencing, warning codes, explicit clean payloads, and the
  conditional `+1` fallback are further playbook extensions. The earlier
  full-SHA-only clean issue-comment rule was superseded after PR 91 live evidence
  demonstrated the provider's 10-hex carrier and the fixed Action baseline
  proved its fail-closed REST resolution outcome; finding URLs and native
  review/inline commit IDs remain full-SHA-only. Future edits must preserve that
  split instead of mechanically copying either implementation into the other.
  The machine-readable base-only-retarget
  contract is now version 2;
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

## Latest Formal-Review Disposition

- The artifact-publication/internal-input-base finding is an accepted trust
  boundary, not a state-machine defect. The policy intentionally authorizes a
  receipted terminal result for its publication-time evidence scope without
  claiming the provider's internal input merge base or inventing
  request/run/artifact lineage. Report wording now names this assurance
  `artifact-publication-only` and forbids the stronger claim that GitHub Codex
  reviewed the current whole-PR range. Changing that boundary requires a new
  predeclared provider-authenticated input-base profile, not inferred timing.
- The legacy-receipt finding first exposed an operability/documentation gap,
  then a later evaluator audit proved that the documented manual recovery path
  was not executable: a pre-receipt artifact could neither enter the normalized
  record nor be omitted from the raw projection. The evaluator now proves the
  closed partition `raw = receipt-bound ⊎ legacy-unreceipted-audit` by native
  identity. Only old clean and non-unresolved finding roles that are strictly
  earlier than both selected-artifact pre-scope boundaries enter the audit-only
  member; unresolved, malformed, unknown, equal-boundary, later, overlapping,
  or omitted evidence fails closed. A selected completion remains independently
  receipt-bound, and reports expose the stable audit list without adding a
  fourth top-level key. This makes the two recovery paths executable while
  preserving the rule that the agent never POSTs a replacement request, old
  artifacts are never scoped retroactively, and the base-retarget state machine
  is unchanged.
  A follow-up regression now constructs the raw legacy member with its
  `artifact_scope_receipt` truly absent, proves that copying that wrapper into
  the normalized receipt-bound member remains `unknown`, and covers later v1
  clean/findings recovery plus only-legacy, newer-finding, and unresolved-thread
  fail-closed cases. Operational summaries now state the same partition
  exception explicitly so the ordinary raw/normalized equality rule cannot be
  misread as a permanent lane-wide veto.
- The large reference matrix remains exhaustive, but its report-only negative
  variants no longer recompute the full evidence oracle. A pure matcher reuses
  an already independently generated and positively round-tripped expected
  report for 34 near misses and for unchanged-input null-status variants,
  removing 90 redundant `expected_report_from_inputs` evaluations without
  deleting fixtures. The focused Python 3.13 run improved from 93.805 seconds
  to 72.056 seconds (about 23%).
- An attempted single-pass cache-hit optimization was rejected because it
  weakened the protected property: content stability across validation, not
  merely object identity or container shape. Deterministic inventory and
  artifact regressions now mutate equal-length content between the no-hash
  preflight and digest observations and require fail-closed rejection. The
  race-safe two-observation contract remains normative even though it costs
  more than a single traversal.
- A later cold-cache audit found that the two-observation guarantee had only
  been enforced on hits: a miss took its sole digest after the uncached
  validator or producer, so an equal-length mutation during that work could be
  cached. Cold admission now takes a bounded, non-authoritative baseline digest
  after the no-hash guard, runs the owning ledger, then requires an equal
  confirmation summary and digest before returning or caching. Ledger failure
  discards the baseline. Deterministic inventory and artifact regressions make
  equal-length changes during the producer/validator and require no stale cache
  with a healthy tracker. This protects exact content stability between the two
  digest observations; it does not detect an `A -> B -> A` transition between
  them or mutation after the final confirmation hash, so snapshot immutability
  and fresh rereads remain part of the boundary.
- A report-contract audit found that the documented publication-scope boundary
  was prose-only. Every accepted terminal or stable receipt-bound terminal
  blocker basis now carries the exact nested field
  `scope_assurance: artifact-publication-only`; reaction and `null` bases do
  not. Missing, wrong, null, or reaction-injected values fail exact report
  validation. This records why result-present evidence is sufficient without
  overstating what it proves: the provider artifact attests its trustworthy
  publication-time scope, but not the provider's internal input merge base or
  whole-PR review coverage. Any future stronger interpretation requires a
  predeclared provider-authenticated input-base profile rather than inferred
  request/run timing.

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
inventory start/deadline. Each request sidecar or ordinary artifact wrapper is
pre-counted with its five raw responses, for six records including the wrapper;
a lowercase 10-hex clean wrapper adds two independent resolution responses, for
seven raw responses and eight records. Every response is byte- and record-bounded
before digesting or decoding. The artifact ledger is created once for an
inventory decision pass;
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

The paired base-retarget regression fixes that evidence boundary rather than
trusting a launch narrative. With the same current-scope artifact receipt, a
valid same-head/different-base request sidecar blocks; removing that sidecar
makes the retarget `not-proved`, leaves request policy unknown, and allows the
artifact-publication scope result to decide. This preserves result-present
authority and records why unavailable provider input scope is not inferred.

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
- Require schema-version-4 bounded dual-source discovery before reaction
  fallback: retain updated-desc pull pages through the first
  `updated_at <= window_start_exclusive` boundary or natural end; combine those
  rows with the fully paginated controlled-request comment source and exact
  current/declaration anchors; fully traverse and parse every union-seeded PR
  before excluding the exact current scope.
- Count the 512 seeded-PR cap only against that deduplicated union and its
  detail traversals. Boundary witnesses and cumulative old PRs consume endpoint
  budgets but not that cap; incomplete sources, projection drift, and all
  budget overflow fail closed. A version-3 transcript cannot prove reaction
  fallback.
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
- Under schema version 4, accept a nested thread-comments connection only when
  its first response is complete (`hasNextPage == false`); terminal
  `endCursor` may be null or a non-empty string and never triggers a later
  fetch. Only `hasNextPage == true` requires a separately bound child-cursor
  schema; until then the profile is `unknown`, and normalized or fabricated
  child traversal is forbidden.
- Classify issue-comment provider identity jointly: only the exact Bot actor
  plus exact `performed_via_github_app.slug == "chatgpt-codex-connector"` is
  exact. If either half claims the provider while the other is absent or
  conflicts, treat it as ambiguous/provider-like and fail closed, never as a
  removable confirmed-different suffix.
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
- The final candidate gate reruns the focused 109-test contract module, the
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
- The successor named-single review of head
  `49bd5067fc01de814be72dcf6a8ef7cf639da400` found two final anti-drift
  gaps. An exact provider App combined with a conflicting non-provider actor
  could be misclassified as removable third-party noise, and the older
  `Implementation Intent` section still prescribed schema version 3. The
  corrected contract jointly classifies issue-comment Bot/App identity and
  fails closed on either-half conflicts across historical, current, and
  post-as-of paths. The intent now prescribes schema-version-4 bounded
  dual-source discovery and its closed nested-comment rule. Heading-scoped
  documentation assertions plus executable regressions preserve both decisions;
  the corrected exact-head review remains parent-owned evidence.
- The exact-head named-single review of
  `0f77fb7b1dd59f5eed522fa9699497aa013695fc..0a019ad7db49c109ee5f18c5fa8c65976133a053`
  raised one P1 about a provider run reportedly beginning before a same-head
  base retarget when request scope was unproved. Two independent read-only
  audits classified that scenario as the explicit v1 artifact-publication
  scope boundary, not an implementation defect: the artifact receipt attests
  publication scope, not the provider's hidden input merge base, and an
  unbound narrative cannot recreate the request/run/artifact binding this
  workstream deliberately removed. The cross-document anchors and paired
  valid-sidecar-versus-missing-sidecar regression above record that disposition.
  A fresh exact-head review after this documentation/test correction remains
  parent-owned evidence and must not be claimed here in advance.
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
  the closed ordinary six-record cost (one wrapper record plus five raw
  scope/artifact responses), including an accepted
  `unused-sidecar-unavailable` fallback. A lowercase 10-hex clean wrapper instead
  adds two independent resolution responses and therefore carries seven raw
  responses for eight records total.
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
  binds both in the canonical compare request URL, and requires the compare
  body to repeat the base plus the unique merge base. Fixture-derived or
  PR-number-derived synthetic SHAs cannot stand in for production scope, and a
  compare response fetched through another head URL cannot lend its merge base.
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

## Bounded Dual-Source Discovery Superseding Decision

The final review exposed a separate availability failure in the weak `+1`
adaptation plane: schema version 3 enumerated every PR ever created and applied
`max_seeded_pull_requests: 512` to that cumulative list. A repository's 513th
historical PR would therefore disable the fallback forever, even when the
frozen 30-day evidence window contained only a few eligible outcomes. That is
not a protective bound on the decision scope; it is an accidental repository
lifetime limit.

Schema-version-4 bounded dual-source discovery supersedes that model with two
independent bounded sources plus exact anchors. Version 3 cannot prove reaction
fallback under the new completeness contract:

- An updated-desc pull-list traversal retains complete pages through the first
  `updated_at <= window_start_exclusive` boundary. A boundary page may still
  carry `rel="next"`; the canonical descending order then proves that later
  pages cannot re-enter the window. Without either that witness or a natural
  terminal page, the traversal is incomplete and fails closed.
- A fully paginated repository issue-comment feed uses the exact cutoff and
  selects only strict controlled `@codex review` parents. This second source is
  necessary because adding a reaction does not imply that GitHub advances the
  PR's `updated_at`; a recent request on an otherwise old PR must remain
  discoverable. Every retained request is raw-equal joined back to the complete
  PR-detail issue-comment inventory before it can seed or support evidence.
- The exact current PR and authenticated provider-declaration PR are explicit
  anchors. The current reaction-only basis is validated by its independent
  current-scope traversal and is not counted among the 3–10 historical
  outcomes; historical reaction samples require both their parent request and
  reaction to fall inside the frozen interval.

The detail scope is the deduplicated union of recent pull rows, recent
controlled-request PRs, and the two anchors. The 512 cap now counts only this
union and its detail traversals. Old boundary witnesses still consume endpoint
page/record/byte budgets, but neither they nor cumulative repository history
consume the seeded-PR cap. A real 513-member union, an incomplete source,
initial/final union drift, or any budget overflow remains `unknown`; prefix
acceptance and caller-selected truncation remain forbidden.

This correction does not weaken the earlier result-authority decision. The
pinned `codex-review-gate` source and released `codex-review-gate-action`
baseline establish that a stable provider result can be consumed without
request/run attribution. Duplicate or pending requests remain producer-policy
warnings and reaction-plane audit state, not contrary verdict evidence. The
schema-v4 discovery machinery is a conditional playbook extension used only to
prove the lower-information reaction fallback; failure in that historical
adaptation plane cannot veto an independently trustworthy current terminal
payload.

The same review also closed the pull-detail URL mismatch: canonical pull-detail
requests use the bare `/pulls/{number}` URL, while collection endpoints retain
their explicit pagination query. A later live pre-request probe against
`github.com` exposed a separate fixture-only assumption before any request was
posted: the real REST Compare object has `base_commit` and
`merge_base_commit`, but no `head_commit`. The corrected authority chain derives
the exact full base/head OIDs from the pull detail, requires that pair in the
exact Compare request URL, and validates the response body's base and unique
merge base. It deliberately ignores an unknown `head_commit` extra and never
uses `commits[-1]`, because that array can be paginated or empty.

This correction is a playbook-only receipt-schema fix. It does not change the
pinned `codex-review-gate` / released `codex-review-gate-action` consumer rule
that a stable provider result is authoritative without request/run lineage.
The exact pinned `src/gate.mjs` blob also binds head from PR detail and the
exact Compare URL without reading `head_commit`. Its separate ancestry helper
validates a larger closed status/count/commit-list contract; the playbook does
not inherit only a fragment of that helper. Future changes to this decision
must update the schema, all agent/lane/readiness mirrors, executable anti-drift
contracts, and this journal together, and must state whether the pinned Action
baseline or a playbook-only extension changed.

## Schema-v4 Pre-Commit Audit Corrections

The stable pre-commit audit found six additional fail-closed obligations that
the first schema-v4 implementation did not yet enforce:

- Historical reaction selection ranges over every exact-epoch controlled
  request in the recent request feed, not only parents that already have a
  reaction. A pending-only scope is not a confirmed non-candidate, and a newer
  pending request prevents an older parent's `+1` from proving the unique latest
  request outcome. The sidecar-blind audit path applies the same rule.
- Sidecar failure cannot make discovery semantics disappear. The sidecar-blind
  endpoint result carries the raw-derived `scope_discovery_projection`; each
  phase requires the stored projection to match it, and initial/final stability
  includes that projection before returning an adaptation-plane-unavailable
  result.
- REST transport shape is part of evidence authority. Pull detail and compare
  are single-page, null-`Link`, direct-object responses. Collection pages have
  array roots; Link relations preserve the fixed HTTPS host, path, and decoded
  non-page query map, use one literal canonical `page=N` token, treat omitted
  page and `page=1` as the same first page, and follow the exact raw `rel=next`
  URL through consecutive page numbers. An empty first page cannot redirect
  scope authority to an arbitrary second URL.
- Updated-desc pull discovery accepts only exact integer status `200`. Its
  canonical `last` relation remains consistent across retained pages, equals the
  current page at a natural no-`next` end, and never precedes the next page.
- GraphQL thread completeness is scope-bound, not endpoint-bound. Every raw
  response page repeats exact `repository.nameWithOwner` and typed positive
  `pullRequest.number`, and both must match the selected transcript scope before
  an empty or nonempty connection can count. The shared `/graphql` URL plus a
  cursor and stable body digest cannot by themselves distinguish an empty
  response collected from another owner, repository, or PR.

These are not new provider policy. They make the retained bytes prove the
already-declared discovery, ordering, and scope properties instead of allowing
fixture/parser self-consistency to substitute for the real GitHub endpoint
contract. Regression tests cover pending-only and newer-pending histories,
sidecar-blind projection drift, arbitrary pagination URLs, multi-page
direct-object substitution, contradictory `last`, numeric type aliases, and
cross-scope GraphQL empty-response substitution on first and later pages.

These corrections are part of the completed landing contract. Test, validator,
signed-commit, exact-range review, CI, and merge receipts remain parent-owned
delivery evidence rather than mutable authority data in this journal, so
recording those receipts cannot move the bytes they attest.

## v10 Discovery-Classification Corrections

The fresh named-single review of
`b807cf90a2c8235ea79ef5013655bd7c52e4c886..db538424a1e5aa1731ddb3eddd70b541c2f84557`
found two related cases where repository-wide discovery made a semantic verdict
too early:

1. The recent issue-comment feed kept strict `@codex review` records only when
   they already looked like ordinary user comments with no App. That actor
   filter could omit an otherwise old PR whose only discovery seed was an
   untrusted, App-authored, or ambiguous strict request. The corrected rule is
   actor-independent at discovery: every exact-body `@codex review` record
   seeds its PR regardless of actor or App. Complete detail, raw-equal join,
   actor classification, and request-scope sidecar validation then accept it or
   select `unknown`; discovery never turns lack of trust into lack of scope.
2. The fully paginated `since` feed is a live traversal, not an as-of snapshot.
   A final reread may legitimately contain an ordinary human non-request comment
   created wholly after the frozen `as_of_server_time`. The corrected parser
   first validates schema, body, actor, canonical ordering, and timestamps. It
   keeps such a confirmed-different non-request as a raw-only suffix, while a
   future strict request, exact-provider or ambiguous record, or cross-cutoff
   edit remains policy-bearing and fails closed.

The decision reason is completeness before trust: a record's existence decides
which PR must be inspected, while its fully validated identity and sidecars
decide whether it can contribute authority. This preserves the established
“result exists means pass” provider-result rule and the pinned
`codex-review-gate` / `codex-review-gate-action` baseline. The Action alignment
still says trustworthy provider results outrank request/run attribution;
actor-independent historical discovery and the raw-only future suffix are
playbook-only safeguards for the lower-information conditional `+1` fallback,
not new Action behavior.

## Final Reviewer P2: Future-Prefix Semantic Convergence

The final formal reviewer reported P2 against the schema-v4 stability rule.
Disposition: accepted and corrected. The raw updated-desc pull traversal is a
live observation made after the provider-declaration receipt froze
`as_of_server_time`; treating a pull row's live `updated_at`, raw row digest, or
endpoint position as fixed semantic state caused an unrelated human comment to
make otherwise identical initial/final histories disagree and select a false
`unknown`.

The corrected contract separates raw discovery closure from fixed semantic
convergence:

- The frozen as-of bounds historical outcome semantics, not raw endpoint
  observation time. Rows later than as-of form a validated contiguous future
  prefix. They remain in retained raw pages, consume the ordinary attempt,
  page, record, byte, deadline, and 512-seed budgets, and seed the complete
  pull/compare/comments/reviews/inline/thread/reaction traversal.
- The fixed `scope_discovery_projection` uses deterministic positive-number
  `{pull_number, base_oid, head_oid}` retained-seed identities. It does not bind
  volatile pull-list `updated_at`, raw row digests, or endpoint row order. An
  existing retained seed can therefore converge across unrelated post-as-of
  confirmed-different activity when its scope, lifecycle, semantic evidence,
  classification, and authority audit remain unchanged.
- The closed `retained_pull_scope_audit` additionally records
  pull/base/head/merge-base/lifecycle for every retained semantic-union PR,
  including request/anchor-only and record-free confirmed non-candidates, and
  requires identical audit identity for every PR present in both traversals.
  Complete initial/final arrays may differ only by an identically audited,
  eligible PR present in exactly one local union; the joint coordinator handles
  that difference. When the recent pull list also contains a PR, its typed
  `state` must equal pull-detail lifecycle state. This closes the reviewer-found
  gap where a shared scope without a separate policy record could hide base or
  lifecycle drift without rejecting a valid one-sided future-prefix scope.
- A seed present only because of the future pull prefix can enter the closed
  `future_prefix_omission_eligibility_audit` only after its complete detail
  traversal proves no record in the frozen interval, no request-feed or anchor
  co-seed, no controlled request or exact/ambiguous provider/policy-bearing
  semantic record, and only already authorized removable confirmed-different
  post-as-of suffix forms, if any. An empty future-prefix scope can be eligible.
  The eligibility audit is a closed subset of the
  `retained_pull_scope_audit` identities. No raw record, normalized scope,
  detail traversal, or budget charge is skipped by the per-traversal parser.
- Effective omission is a joint initial/final decision, not a single-snapshot
  classification. The joint coordinator removes a scope only from the derived stable
  comparison and only when that PR appears in exactly one complete local union
  and is eligible there. A PR observed in both traversals always remains in the
  exact retained comparison, even when later unrelated human activity makes
  one side locally eligible. Eligibility items shared by both traversals must
  have type-preserving identical pull/base/head/merge-base/lifecycle identity.
- Controlled requests, exact or ambiguous/provider-like evidence, exact or
  ambiguous children, cross-cutoff edits, base/head/lifecycle drift, incomplete
  pagination, broken joins, and overflow remain fail-closed. The exception is
  therefore convergence of irrelevant live repository activity, not prefix
  acceptance or a weaker completeness rule.

The regression rationale is narrow: initial/final evidence should agree when
only unrelated repository activity happened after the frozen semantic cutoff,
while every raw discovery candidate still receives full detail validation.
Coverage must distinguish an already retained seed with a future metadata bump,
an already retained record-free seed that later receives only removable human
activity, a new empty or noisy one-sided future seed that is fully traversed
then omitted only by joint coordination, and the fail-closed
request/provider-like/drift/incomplete variants. It must also prove that the raw
512-seed cap and every detail fetch apply before coordination, that
request/anchor co-seeds stay retained, and that any scope observed in both
traversals cannot change base, head, merge base, or lifecycle. Coverage must
also bind every retained scope, including anchor-only and record-free scopes,
and reject pull-list/detail lifecycle disagreement.

The first formal named-single review of commit `4e760b6f25487b269fb3ba164e7e66eb1fd098de`
found the prior single-traversal omission bug: it could not distinguish a newly
observed empty future PR from an already retained record-free PR that later
received removable human noise. The joint-coordination rule above is the
accepted correction; it prevents future drift back to per-snapshot omission.

The second formal named-single review of commit
`65e1c329f2514818503d0f29e175909a45ce620f` found one residual prose
contradiction: the authority still required the complete
`retained_pull_scope_audit` arrays to be identical before coordination. That
would reject the exact one-sided eligible scope that the joint coordinator is
defined to normalize. The corrected rule requires exact identity only for PRs
present in both traversals and permits complete-array difference solely for a
fully validated one-sided eligibility-audit item. A contract assertion now
forbids the obsolete unconditional-equality wording.

The third formal named-single review of commit
`8700073a41a1fa1930a1865a1d438e84b2b8071f` found a transport-level
convergence gap: adding one fully eligible future-prefix PR can move the first
old boundary witness from a page that still has `rel="next"` to the natural
last page. Both traversals are independently complete, but their exact stored
stop reasons then differ between `window-boundary-complete` and
`natural-end-complete`. After both traversals independently prove complete,
the joint stable comparison treats `window-boundary-complete` and
`natural-end-complete` as equivalent complete termination forms. The exact
reason remains in each raw-derived and stored projection; only that transport
label is removed from the derived comparison, and incomplete or malformed
pagination still fails closed. The regression uses 99 in-window rows, two old
boundary witnesses, and one final-only eligible future PR to force the boundary
from page one to page two while proving the coordinated semantic view remains
stable.

The fourth formal named-single review of commit
`5e1be7e100beb375b10dff235ec21666a02aabd9` found that the repository-wide
issue-comment endpoint also returns comments on ordinary issues. Treating every
exact-body `@codex review` record as a PR request made one canonical ordinary
issue comment invalidate the entire adaptive history and could consume the
seeded-PR budget. Canonical ordinary-issue `@codex review` comments are
validated, retained, and budget-charged as raw-only non-seeds; mismatched or
ambiguous PR-like routing fails closed. The classifier jointly binds the
canonical issue API URL, comment API URL, ordinary-issue or PR HTML route,
shared issue number, and comment ID; controlled-comment IDs remain unique
across both routes. A future ordinary-issue comment remains irrelevant to PR
scope after the same raw validation, while a future canonically routed PR
request continues to fail closed under the frozen as-of policy. Positive,
future, duplicate-ID, route, issue-number, comment-ID, and issue-URL fixtures
lock the distinction. Route and comment IDs stay inside the 128-bit native-ID
envelope; a 5,000-digit route fixture proves rejection occurs before Python
integer conversion can raise instead of returning a fail-closed result.

The fifth formal named-single review of commit
`16af13eafceb0f6a84981bc887c0a6a556dd13d8` generalized that same exception
boundary: an updated-desc `rel="last"` page number and GraphQL
`fullDatabaseId` could still pass a decimal regex and then send a 5,000-digit
value directly to Python `int()`. Canonical decimal page and native-ID tokens
are limited to 39 digits and 128 bits before integer conversion; overlong
values fail closed without raising. The shared canonical-decimal helper now
establishes that property for every GraphQL child/parent ID consumer, while the
pagination parser uses the same helper before interpreting `last`. Dedicated
5,000-digit `last` and future-review parent-ID fixtures prove both paths return
`None` rather than escaping the reference evaluator.

The sixth formal named-single review of commit
`ad391afe6a6b2ac1d3fcebaca0edb049e589b439` found two transport-compatibility
errors after its exact full suite had passed 2,827 tests with six skips.
GitHub's GraphQL contract uses typed `hasNextPage == false` as the terminal
signal while `endCursor` may still identify the last returned edge, and
GitHub's documented REST `Link` examples use an explicit `page=1` for `first`
and `prev`. A terminal GraphQL page requires typed
`hasNextPage == false`; `endCursor` may be null or a non-empty string, and a
retained terminal cursor never triggers another fetch. The raw response and
digest retain that opaque cursor, while the semantic projection canonicalizes
a terminal cursor away so an otherwise identical initial/final reread remains
stable. A nested v4 connection still fails closed when
`hasNextPage == true` because this schema has no child-cursor fetch shape.

REST Link page relations are validated semantically against the fixed HTTPS
host, path, and non-page query map; omitted page and a literal canonical
`page=1` are equivalent, while each raw `rel=next` URL is followed exactly.
Only the page key/value must remain literal canonical text before the existing
39-digit/128-bit conversion bound; non-page query order and valid percent
encoding may vary without changing endpoint semantics. Duplicate, missing,
extra, cross-host, cross-path, noncanonical-page, contradictory relation, and
broken raw-next-chain evidence still fails closed. This division follows the
provider's opaque traversal tokens without weakening scope binding.

The first hosted CI pass after that review exposed two environment-specific
test-contract gaps rather than provider-policy regressions. Python 3.10 treats
an empty query as malformed when `urllib.parse.parse_qsl()` is called with
`strict_parsing=True`, while newer Python accepts it as an empty parameter
set. The REST authority parser now handles an absent query explicitly before
strictly parsing every non-empty query, so canonical unpaged pull-detail and
compare endpoints remain page 1 on every supported Python version. Dedicated
bare-URL fixtures cover omitted page, literal `page=1`, and later canonical
pages without weakening the fixed host, path, or query-map checks.

The hosted macOS job also created unrelated same-UID processes while a fixture
was verifying real process-group settlement after leader exit. Account-wide
same-UID census protects exact process identity and remains mandatory in the
production isolated-account lane; it is not a property of those group-only
fixtures. After integrating the newer trusted-source-custody baseline, those
fixtures explicitly replace only their account-wide census calls, assert the
non-dedicated closure invocation, and retain the real process-group absence
proof. The trusted macOS gate separately exercises the unfiltered production
census under its dedicated-UID custody receipt, so a caller-controlled marker
is neither needed nor accepted as isolation evidence. The combined baseline
keeps the reviewed 847-test deterministic identity with digest
`93cbe4c702f25d1cf3c5fdc1170f55df5217f6dad4ba170085b4aae63621a897`.

This disposition preserves the earlier “result exists means pass” decision and
the pinned `codex-review-gate` / released `codex-review-gate-action` alignment:
trustworthy provider results remain authoritative without request/run
attribution. Future-prefix discovery convergence is a conditional `+1`
adaptation-plane playbook extension, not behaviour attributed to the Action.
Any future change to the as-of meaning, stable seed identity, eligibility or
joint-omission predicate, retained-scope audit, eligibility-overlap audit,
raw/detail budget closure, or Action attribution must update the versioned
transcript/projector contract,
agent/readiness/probe mirrors, regression coverage, and this journal together;
changing the Action side also requires a new pinned
source/release/tree/manifest baseline.

## Live REST Compare Schema Correction

The final pre-request probe for public PR #91 deliberately read the real
current PR detail and Compare endpoint before posting `@codex review`. At
GitHub server time `2026-08-05 14:48:07 GMT`, the Compare object exposed
`ahead_by`, `base_commit`, `behind_by`, `commits`, `merge_base_commit`,
`status`, `total_commits`, and link fields, but no `head_commit`. No provider
request had been posted for that head, so the candidate contract was corrected
before it could create unconsumable live evidence.

The authority decision is therefore deliberately split:

In each receipt pair, the pull body supplies base/head, the exact derived
Compare request URL binds that pair, and the Compare body repeats base and
supplies merge base.

- Pull detail supplies the exact lowercase full base/head OIDs.
- Those OIDs form the exact authenticated
  `/compare/<base>...<head>` request URL, whose raw receipt binds head.
- The Compare body must repeat `base_commit.sha` and supply the unique
  `merge_base_commit.sha`; an extra `head_commit` member is an ignored unknown
  field and cannot strengthen or contradict the projection.
- `commits[-1]` is not a replacement head signal because Compare commits may
  be paginated and an identical comparison has no final commit.

This remains a local whole-PR receipt extension rather than a new Action
inheritance claim. The exact pinned `src/gate.mjs` blob
`e0b974b27ebd64e412eaef1d069789b5f6bd76ba` (109,096 bytes; raw SHA-256
`5b25faa7336e3b53603df42d15e52853d4de039e755c9ed5338c51fd528b9415`)
is shared by the source and released Action manifests below. Its ancestry
helper binds the exact Compare URL and validates a complete closed combination
of status, ahead/behind/total counts, bounded commit-list shape, final commit,
and identical-range behavior; it does not read `head_commit`. The playbook
receipt intentionally takes only its own smaller closed scope projection. It
must not copy a bare `commits[-1]` check without the Action helper's complete
count, pagination, and identical-range constraints.

## Live Legacy Provider Recovery

PR #91 exposed a second live anti-drift boundary after the real Compare schema
was fixed. Its complete provider history contained three relevant exact-bot
artifacts:

- pull-request review `4863163875`, submitted on
  `832edd60e50392c7f000d67ed856d20959c0d5b2`, used the provider's older native
  `### 💡 Codex Review` URL/badge/title/prose/disclosure finding form;
- issue comment `5191165370` carried the raw short clean marker `9abfd559e9`
  for `9abfd559e955503fdd3233ecd16073918423fc7a`, before version-1 artifact and
  dual short-marker receipts existed; and
- issue comment `5195502331` carried the current-head marker `06264ac0a0` for
  `06264ac0a06240634f896e606b5744f747dd825f` and had the complete current
  artifact-scope and independent initial/final full-SHA resolution evidence.

The pre-correction contract treated the first record as arbitrary malformed
review prose and the second as a malformed unresolved short clean. That made
the complete old raw history veto the third record even though the third was a
newer, independently complete current-head No-findings result. The correction
does not discard or retroactively receipt those old records. It recognizes the
first only through the closed migration-only
`legacy-finding-native-review-v1` grammar and the second only as raw role
`clean-pending-resolution`; both remain in the stable
`legacy_unreceipted_artifacts` audit projection and neither can become result
authority, provider profile carrier, candidate basis, or superseding evidence.
The old 10-hex prefix is admitted only because the history-top-level
`initial_legacy_short_commit_resolution_receipts` and
`final_legacy_short_commit_resolution_receipts` completely cover the
raw-derived pending-prefix set, uniquely enumerate the same prefix-matching
full commit, prove commit type and ancestry with return codes `0`, and remain
type-preservingly identical. An ancestry array cannot self-attest that mapping.
The terminal report retains both arrays under
`evidence_basis.current_raw_authority.local_git_prefix_resolution_receipts`;
a reaction report uses
`evidence_basis.current.local_git_prefix_resolution_receipts`. That local
mapping is not a REST resolution companion and the audit item continues to
preserve only `9abfd559e9`. Multiple legacy short refs are supported: each
phase is unique and sorted by `raw_prefix`; after the next substantive head,
the expected raw-derived set includes both `9abfd559e9` and `06264ac0a0` as
ancestor-era clean markers. A selected current-head short clean remains on its
separate dual REST resolution path.
The newer artifact decides only because both older semantic times are strictly
earlier than both of its pre-scope `Date` receipts and every identity, grammar,
ancestry, thread, pagination, scope, lifecycle, receipt, and final-stability
gate closes.

This is the intended “result exists means pass” behavior, not a broad legacy
allowlist. The old native finding grammar requires exact state, provider,
same-repository full-SHA URL/commit match, one fixed severity/color badge,
bounded title/prose containing neither `www.` nor a URI-scheme prefix whose
colon is immediately followed by a non-whitespace character, and the
normalized closed disclosure. Newlines are normalized, every physical
disclosure line is trimmed, blank lines are dropped, and the remaining lines
must exactly equal the nine-line block. Only no padding or one line of four
ASCII spaces may precede it, with no other title/prose trailing whitespace or
blank line, and the review has no associated inline child. The old
short clean remains unresolved and keeps its raw 10-hex value; it never borrows
the current selected artifact's dual full-SHA resolution. Any near-miss,
unresolved thread, unknown identity/role, bad ancestry, equal/newer contrary or
malformed artifact, missing current receipt/resolution, incomplete page, or
scope/lifecycle drift remains fail-closed. Only newer/equal malformed evidence
participates in ordinary terminal precedence; an older recognized audit-only
carrier cannot control, while a truly malformed older near-miss still prevents
the migration partition from closing.

The legacy badge mapping is pinned from exact REST Bot evidence, independently
of the Action: `P0/red` in `openai/openai-cookbook#2915` inline comments
`3707792981`/`3707792985`; `P1/orange` in `ykylee/Devhub_example#592`
`3409533388`/`3409533389` (also `andreame-code/netrisk#154` `3140609225`);
`P2/yellow` in PR #91 review `4863163875`; and `P3/lightgrey` in
`Joey-Tools/codex-debug-triage#5` `3676232685`/`3676232690`. Each observed
record used exact `chatgpt-codex-connector[bot]` / `Bot` REST identity. The
pinned `codex-review-gate` Action does not parse badge colors, so this is a
separate provider-payload provenance baseline rather than claimed Action
parity.

Old request sidecars were not fabricated. Their absence may leave
`request_policy: unknown`, which forbids another same-head request and closes
reaction-only authority, but that producer/audit field alone does not negate
the complete current provider result. This exactly preserves the fixed
`codex-review-gate` source and released `codex-review-gate-action` baseline:
provider-result evidence decides without unavailable request/run lineage, while
the playbook keeps its stricter scope, thread, lifecycle, pagination, grammar,
and stability extensions. The repository still has no production live
evaluator CLI; this PR #91 adjudication therefore remained manual and
receipt-backed, while the embedded executable contract locks the same three
live carrier shapes and their near-miss regressions for future automation.

## Private Release Portability

The first private release validation exposed distribution-contract gaps, not a
provider-evaluator regression. Repository-owned README and project-journal
anti-drift assertions belong only to the canonical profile; the private
profile keeps the shared skill/reference checks without requiring the pending
private `AGENTS.md` authority-pointer migration or mirroring the complete
canonical policy corpus. Canonical-only repository policy files are not opened
under the private profile; a missing-file regression preserves that boundary.
Private release transport materializes the reviewed private CI fixture as the
live workflow. Installed-supervisor validation
requires exact Python 3.13 rather than treating later minor releases as
compatible. The deep fallback cleanup success-path test now allows five
seconds for runner-load variance, while the dedicated timeout tests retain
their strict budgets; no cleanup runtime semantics changed.

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
