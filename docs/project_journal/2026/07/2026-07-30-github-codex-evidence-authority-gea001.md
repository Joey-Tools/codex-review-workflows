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
- `+1` can count only for `thumbs-up-clean` after explicit provider semantics, a
  bounded 30-day same-repository history, exact request and bot identity,
  complete pagination, stable whole-PR scope, no trustworthy current-scope
  terminal payload or conflicting finding/thread evidence, and an unchanged
  final re-read. `mixed` always requires terminal payload for a clean result.
- A no-start rejection would be availability evidence, not clean evidence, but
  the fixed baseline has no accepted provider body grammar. Free-form exact-bot
  prose therefore remains inconclusive. A future policy may activate
  `evidence_basis.kind: no-start-rejection` only with an immutable
  provider-backed grammar and regression tests, while preserving the actually
  recomputed profile.
- At this fixed baseline, the only integration/service-unavailable proof that
  can reduce requested triple to effective double is authenticated structured
  capability or installation metadata whose defined schema identifies the
  selected repository/integration and explicitly encodes unavailable or
  not-installed. Absence, timeout, permission or generic transport/HTTP failure,
  and free-form provider prose remain inconclusive.
- The new evidence-authority reference is part of the formal trusted-bundle
  manifest, so future self-policy reviews bind its exact bytes instead of
  treating it as an untracked explanatory side document.

## Decision Rationale

- A provider terminal payload contains the review verdict and commit scope; a
  request comment contains only the intent to start work. Provider evidence is
  therefore the verdict authority, while requests remain producer controls and
  audit records.
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
  partial-file spot check.
- The Action alignment is intentionally asymmetric. Provider-result authority,
  duplicate-result consumption, and early-result consumption are inherited.
  Exact whole-PR lifecycle/scope, local-lane sequencing, warning codes, explicit
  clean payloads, and the conditional `+1` fallback are deliberate playbook
  extensions. Future edits must preserve that split instead of mechanically
  copying either implementation into the other.
- Future provider behaviour may change, but adaptation must select one of the
  predeclared profiles from complete bounded evidence. It must not invent a new
  reaction meaning or silently weaken identity, scope, pagination, finding, or
  final-stability gates.
- Dynamic history is deterministic and independent: collapse to one final
  outcome per repository/PR/`pr_merge_base`/head scope, then take the newest
  ten distinct scopes in the 30-day window. A moving `baseRefOid` does not
  create a second outcome when the merge base and head are unchanged. The
  three-scope minimum belongs only to reaction-only `thumbs-up-clean`; it
  cannot downgrade observed terminal payload behaviour.
- Issue-comment body edits use `updated_at` as semantic server time, while
  unedited comments and reactions use `created_at` and reviews use
  `submitted_at`. Review-thread joins use current GitHub GraphQL
  `fullDatabaseId: BigInt`, normalized with REST IDs as canonical positive
  decimal text.

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
- Require an explicit commit-bound clean payload for terminal-payload
  completion; an empty `APPROVED` review does not count.
- Treat the dynamic `+1` fallback as a playbook-specific policy extension, not
  as behaviour inherited from the fixed Action release.
- This workstream defines documentation and policy contracts only; a runtime
  GitHub evidence evaluator or API is outside its scope.

## Next Steps

- Downstream private-overlay releases should consume the aligned canonical
  policy after the repository change lands.
- Any future runtime evaluator must implement the reference without collapsing
  request warnings, provider outcome, profile, and evidence basis into one
  status.

## Validation

- Focused contract suite:
  `python3 -B -m unittest skills.review-orchestration-playbook.tests.test_contracts`
  passed 100 tests.
- Full review-orchestration suite:
  `python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests -p 'test_*.py'`
  passed 2,820 tests in 1,107.983 seconds with 6 expected skips. It ran outside
  the filesystem sandbox because loopback socket tests require local `bind`.
- System `skill-creator` validation passed for
  `review-orchestration-playbook` and `change-delivery-workflow`.
- The bundled project-journal validator passed.
- Ruff lint and format checks for `tests/test_contracts.py` passed.
- `git diff --check` passed.
- Independent cross-document policy audit completed clean after closing the
  structured no-start metadata and bounded-wait boundary findings.

## Evidence

- `skills/review-orchestration-playbook/references/github-codex-evidence-authority.md`
- Source baseline:
  `JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`
- Released Action baseline:
  `JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`
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
