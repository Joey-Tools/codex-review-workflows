---
id: 20260730-gea001
title: GitHub Codex Provider-Evidence Authority
status: completed
created: 2026-07-30
updated: 2026-07-30
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
- Reports keep `request_policy`, `provider_profile`, and `evidence_basis`
  independent. `request_policy` is a record whose stable warning codes include
  `early-request-observed` and `duplicate-observed`. A lone compliant pending
  request is not a warning. `provider_profile` is `null` only before an
  eligible provider plane exists. `evidence_basis` may also be `null` for an
  eligible waiting or inconclusive lane when no stable artifact is selected.
- Existing duplicate requests do not require request/run attribution before a
  complete, independently ordered provider result can count. The orchestrator
  still does not create another same-scope request.
- Terminal comments/reviews count only under the authority's fixed
  clean/finding/inline-parent grammar. Clean issue comments carry one full-SHA
  `Reviewed commit` marker; clean reviews are exact `APPROVED` / native
  current-head `commit_id` / `No findings.` records whose fully paginated
  associated inline-child set is present and empty. A valid child is findings;
  an unread, incomplete, malformed, or conflicting child set is never clean.
  Every other terminal-looking exact-provider payload is malformed. Review
  terminal-looking detection is independent of state admissibility:
  `PENDING` remains nonterminal; `DISMISSED`, or a missing/unknown state with a
  nonempty body or associated inline child, is a whole-snapshot inconclusive
  blocker. Its original `submitted_at` is not a trusted state-transition time,
  so a later-looking clean cannot supersede it.
- `+1` can count only for `thumbs-up-clean` after a directly fetched,
  finally stable exact-bot/App GitHub declaration artifact containing the
  predeclared `If Codex has suggestions, it will comment; otherwise it will
  react with 👍.` line. Generic issuer/source strings, copied prose, local
  paraphrases with self-consistent hashes, and caller-synthesized records are
  not declaration authority. The profile also requires a GitHub
  response-`Date`-anchored exact `(as_of - 2592000, as_of]` same-repository
  history window and exact request/bot identity.
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
  Once terminal precedence selects a terminal/finding artifact, a later `+1`
  or `eyes` remains visible audit/liveness evidence but does not replace or
  reorder that stronger basis. Current initial/final snapshots bind exact
  open/unmerged lifecycle, complete
  pagination, stable whole-PR scope, no trustworthy current-scope terminal
  payload or conflicting finding/thread evidence, and an unchanged final
  re-read. The reaction report embeds identical initial/final discovery
  inventories and complete candidate arrays, not just the selected samples or
  a caller-adjustable count. Every raw historical/current server time must be
  at or before the GitHub response-time as-of, including confirmed-different
  actors excluded from provider ordering. Confirmed different-user and clearly unrelated-bot
  reactions remain in the audit but do not enter provider ordering; missing
  identity, exact-login/wrong-type, and differently cased or other
  `codex`-containing bot identities make the reaction profile unknown. `mixed`
  always requires terminal payload for a clean result.
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

- A provider terminal payload contains the review verdict and commit scope; a
  request comment contains only the intent to start work. Provider evidence is
  therefore the verdict authority, while requests remain producer controls and
  audit records.
- Individual reactions carry less information than terminal comments/reviews:
  notably, they have no native commit-head binding. They are therefore a
  bounded fallback only when recent eligible outcomes show reaction-only
  provider behaviour. A later `+1` or `eyes` cannot demote an already selected
  terminal payload; newer `eyes` blocks only the weaker reaction-only fallback.
- GitHub review and issue-comment APIs expose no general request/run lineage.
  Requiring that unavailable binding would permanently classify valid
  current-head results as inconclusive. Duplicate or mistimed requests remain
  visible as warnings without contradicting the provider's result.
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
  Exact whole-PR lifecycle/scope, local-lane sequencing, warning codes, explicit
  clean payloads, the narrower full-SHA terminal grammar, and the conditional
  `+1` fallback are deliberate playbook extensions. Future edits must preserve
  that split instead of mechanically copying either implementation into the
  other.
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
  boundary is included, future artifacts are impossible, and the source URL,
  boundaries, and complete universe count are recorded. If that historical
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
- Issue-comment body edits use `updated_at` as semantic server time, while
  unedited comments and reactions use `created_at` and reviews use
  `submitted_at`. Review-thread joins use current GitHub GraphQL
  `fullDatabaseId: BigInt`, normalized with REST IDs as canonical positive
  decimal text.
- Reaction identity follows the documented GitHub REST data model rather than
  a locally invented URL. A future endpoint or schema change must update the
  pinned documentation reference and the executable closed-schema tests
  together; adding a caller-supplied or derived self URL is not a compatible
  extension.

## Implementation Intent

- Use
  `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`
  as the detailed normative source for GitHub Codex evidence consumption.
- Keep entrypoint surfaces concise and link to the authority reference instead
  of duplicating the full decision matrix.
- Preserve the stricter playbook requirements for exact PR lifecycle and
  whole-PR base/head scope.
- Preserve the report matrix for unsupported/no-PR, waiting, terminal,
  reaction-fallback, reserved authenticated no-start, and inconclusive states,
  including channel-specific `server_time_field` values.
- Terminal-payload reports embed identical initial/final selection and selected
  artifact snapshots. Review snapshots include exact actor/state/body/commit
  plus fully paginated associated inline children and thread joins; issue
  comments include exact actor/App/body/time/commit-marker inputs. Sparse
  summaries cannot prove the closed grammar or final reread.
- Require an explicit commit-bound clean payload for terminal-payload
  completion; an empty `APPROVED` review does not count, and an exact
  `No findings.` review is clean only after its complete associated inline set
  is proved empty.
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

- Focused contract suite:
  `python3 -B -m unittest skills/review-orchestration-playbook/tests/test_contracts.py`
  passed 102 tests in 8.252 seconds.
- Full review-orchestration suite:
  `python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py'`
  passed 2,822 tests in 1,539.069 seconds with 6 expected skips. It ran outside
  the filesystem sandbox because loopback socket tests require local `bind`.
- System `skill-creator` validation passed for
  `review-orchestration-playbook` and `change-delivery-workflow`.
- The bundled project-journal validator passed.
- Ruff lint and format checks for `tests/test_contracts.py` passed.
- `git diff --check` passed.
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
- Follow-up independent audits completed clean after probing accepted terminal
  clean/findings reports, later-reaction terminal precedence, every
  missing/false/numeric request-completeness combination, closed schemas, JSON
  type identity, cross-scope native-ID collisions, selected provenance,
  terminal child/thread joins, newest-10 ordering, fixed Action provenance,
  and the result-present decision rationale.

## Evidence

- `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`
- Source baseline:
  [`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`](https://github.com/JoeyTeng/codex-review-gate/commit/16366aa81270ad2c875d2ceb8ce194f5b2308af6)
- Released Action baseline:
  [`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`](https://github.com/JoeyTeng/codex-review-gate-action/commit/2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6)
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
