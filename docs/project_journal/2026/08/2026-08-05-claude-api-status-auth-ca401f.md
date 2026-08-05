---
id: 20260805-ca401f
title: Claude Numeric API Error Status Authentication
status: completed
created: 2026-08-05
updated: 2026-08-05
branch: codex/claude-api-status-auth
pr: 91
supersedes: []
superseded_by:
---

# Claude Numeric API Error Status Authentication

## Summary

- Accept a true integer `api_error_status` from `100` through `599` as bounded error metadata on Claude failure envelopes.
- Classify numeric `401` authentication evidence as `blocked-authentication` through the canonical direct lane while keeping successful envelopes with numeric status fail closed.
- Align only the clean-marker carrier lengths and fail-closed short-ref REST resolution outcome with the pinned Action while retaining the playbook's stricter lowercase, spacing, boundary, grammar, and independent-receipt rules.
- Keep the generated private CI fixture responsible for running the canonical project-journal suite as well as the review-orchestration suite.

## Current State

- The provider compatibility classifier accepts exact login text plus numeric `401` only when the failure envelope and requested-model `modelUsage` binding are otherwise verified; `_record_attempt` records `auth` with `structured-authentication`. Any other bounded numeric status conflicts with that authentication fallback and remains inconclusive unless its own recognized category controls.
- The canonical stream validator maps bounded integer status metadata into the existing strict failure classifier. Numeric `401` produces `terminal.authentication-error`; other bounded statuses remain classified evidence, while booleans, non-integer numbers, objects, and values outside `100..599` are malformed.
- Success still accepts only absent, `null`, or whitespace-only `api_error_status`; a numeric status contributes `terminal.success-with-error` and yields `inconclusive`.
- The aggregate runtime profile and its validator mirror use `null_or_whitespace_string_or_http_status_integer`. The audited Claude Code 2.1.212 baseline remains unchanged.
- Clean GitHub Codex issue comments retain a full `parsed_commit`. A 40-hex marker must already equal the current head; a raw lowercase 10-hex live-provider marker remains `clean-pending-resolution` and non-authoritative until the exact companion joins its artifact ID, scope, ref, and full current head through independent initial and final exact-repository commit receipts. Current, complete-history, and sidecar-blind historical paths use the same join; sidecar-blind may ignore request sidecars but never the resolution companion. The receipt dates prove `artifact GET <= initial resolution <= post-scope snapshot(s) <= final resolution`, with same-second equality allowed. Findings URLs, native review commit IDs, and inline comment commit IDs remain full-SHA-only.
- GitHub Compare scope receipts now match the real REST response schema. Pull detail supplies full base/head OIDs, the exact derived Compare request URL binds that pair, and the Compare body repeats base and supplies the unique merge base. The parser does not require the nonexistent `head_commit` field, ignores any unknown field with that name, and never derives head from a possibly paginated or empty `commits` array.

## Decision Rationale

- HTTP status is bounded transport metadata rather than a free-form error payload, but its value still constrains classification: only `401` may corroborate the exact authentication result, while a different numeric status cannot be ignored in favor of stderr authentication prose.
- Exact `type(value) is int` checks exclude JSON booleans even though Python booleans are integer subclasses; inclusive `100..599` bounds preserve the HTTP status domain and reject unreviewed numeric shapes.
- Numeric metadata is admitted only into failure classification. Success retains its stronger empty-error invariant, preventing a contradictory success envelope from supplying findings.
- The 10-hex clean-marker rule is not an optimistic prefix comparison. The fixed `JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6` and released `JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6` baselines establish only the 10/40 carrier lengths and the fail-closed repository-commit resolution outcome used here. The playbook intentionally remains stricter on lowercase-only refs, exact marker spacing, the exact-two-LF/nonblank boundary, closed lead/tagline/disclosure/native grammar, and independent parent-recorded initial/final raw receipt evidence; it does not claim complete grammar parity with the Action. Those raw receipt fields, digests, joins, and temporal comparisons are contract evidence, while a prose assertion that the parent performed the calls is not.
- The private CI fixture is canonical source, so project-journal validation belongs there rather than as a private-only workflow edit that the next overlay sync would erase.
- A live PR #91 pre-request probe proved that GitHub's Compare response has `base_commit` and `merge_base_commit` but no `head_commit`. The minimal receipt projection therefore binds head through pull detail plus the exact Compare URL. The pinned Action's exact shared `src/gate.mjs` blob `e0b974b27ebd64e412eaef1d069789b5f6bd76ba` likewise does not read `head_commit`; its separate ancestry helper validates a complete status/count/pagination/identical-range contract. Copying only its conditional final-commit check would be unsound, so the playbook keeps its own smaller closed scope-receipt extension.

## Review Finding Provenance

- A named single review of `Joey-Tools/codex-private-workflows` PR 146 reported that generated overlay `providers.py` downgraded exact login text plus numeric `401` to `unverified-auth-failure-envelope`.
- Canonical-source adjudication assigned the fix to `Joey-Tools/codex-review-workflows` and identified the direct stream validator as a second independent rejection point; fixing only the provider compatibility layer would not have changed the complete named Claude lane outcome.
- GitHub Codex review of canonical PR 91 identified the converse conflict: a non-401 numeric status could be ignored when stderr supplied authentication prose. The provider compatibility layer now rejects that combination while retaining numeric `401` and recognized transient-status behavior.
- A fresh whole-range named single review identified that `docs/PROJECT_STATE.md` still pointed to the older 2026-08-03 workstream. The recovery pointer and its contract assertion now select this completed workstream.
- Live revalidation of PR 91 produced exact-provider issue comment `5191165370` for head `9abfd559e955503fdd3233ecd16073918423fc7a` with the provider's 10-hex marker `9abfd559e9` and whitespace-varied official disclosure. The then-current playbook classified the live carrier as malformed even though the pinned Action resolved it to the exact full head. This observable anti-drift failure triggered the narrow carrier/resolution compatibility correction. The playbook's closed disclosure handling remains an independently reviewed local rule, and no complete grammar parity or widening of finding/review-native grammar is claimed.
- GitHub Codex review of private overlay PR 146 identified that generated CI omitted the project-journal suite. The canonical private CI fixture now owns that check so resync cannot reintroduce the omission.
- The final PR #91 pre-request scope probe exposed the synthetic `compare.head_commit.sha` assumption before any `@codex review` request was posted for head `f481ee35cbdbb3f54eb9433a1a610b7048c8df97`. Request, artifact, and history receipt parsers plus their fixtures and documentation were corrected together; anti-drift assertions now require all authority mirrors to state the pull-body / exact-URL / Compare-body division.

## Next Steps

- Downstream private-overlay sync and release consume the canonical squash merge.

## Evidence

- Focused provider regression: 2 tests passed in 0.986 seconds.
- Complete stream-validator suite: 109 tests passed in 6.584 seconds.
- Focused stream schema/authentication/bounds regression, including float, object, and blank-string cases: 3 tests passed in 0.329 seconds.
- Canonical documentation contract anchor: 1 test passed in 0.008 seconds.
- Floating aggregate schema contract case: 1 test passed in 0.003 seconds.
- PR 91 non-401 conflict regression, canonical documentation anchor, and unchanged direct-stream numeric-status regression passed.
- Complete review-orchestration suite on the final Compare-schema, short-reference history, and receipt-ordering state outside the restricted sandbox with `/opt/homebrew/bin/python3.13` 3.13.12: 2,842 tests passed in 1,358.116 seconds; skipped=6.
- Complete contract suite on the final journal snapshot after the Compare parser/fixture correction with Python 3.13.12: 111 tests passed in 83.451 seconds. The focused Compare authority anti-drift contract passed in 0.159 seconds.
- The restricted sandbox's Unix-socket `EPERM` and the relocatable uv Python 3.14.2 test copy's missing relative `libpython3.14.dylib` were environment-only diagnostics; both affected tests passed under the final host Python 3.13.12 configuration.
- Ruff lint, aggregate-schema JSON parsing, skill validation, project-journal validation, independent read-only audit, and `git diff --check` passed.
