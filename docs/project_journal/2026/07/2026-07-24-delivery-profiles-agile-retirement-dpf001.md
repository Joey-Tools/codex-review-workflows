---
id: 20260724-dpf001
title: Unify Delivery Profiles And Retire Standalone Agile Delivery
status: completed
created: 2026-07-24
updated: 2026-07-24
branch: codex/delivery-profiles-agile-retirement-20260724
pr:
supersedes: []
superseded_by:
---

# Unify Delivery Profiles And Retire Standalone Agile Delivery

## Summary

- `change-delivery-workflow` is the thin active orchestrator for
  `focused-checkpoint`, `local-gate`, and `pr-readiness-handoff`.
- `agile-delivery-workflow` is a compatibility alias that maps legacy
  MVP/agile/scout triggers to `focused-checkpoint`.
- `synthetic-token-fixtures` routes authoring through the existing review
  helper's authoritative catalog CLI through a trusted exact runtime manifest,
  without defining a second pool or broad executable runtime.

## Current State

- Focused checkpoints and local landing commits are created automatically with
  the repository signing policy after their gates pass, unless the user
  explicitly requests a report-only, probe-only, or no-commit result.
- Commit mode is resolved before profile selection or any review anchor. A
  no-commit run may reuse an already-correct committed range, but it never
  creates history merely to satisfy a formal lane.
- Explicit local-only, report-only, probe-only, read-only, and no-remote
  constraints are resolved before terminal-outcome signals. The result records
  local and remote mutation independently. Report/probe/read-only requests
  short-circuit implementation, journal, commit, generated-result, and
  mutation/cache-writing validation steps.
- A request that explicitly asks for PR-readiness evidence while forbidding
  remote mutation routes through the review orchestrator's
  `pr-readiness-read-only-probe` handoff. It can read only PR selection,
  lifecycle, CI, conversation, and base/head evidence; it cannot comment,
  request GitHub Codex, start local lanes or secret admission, wait, write
  cache or state, fix, commit, push, release, or merge. The receiver is
  classified before every generic PR/review route and returns one closed
  terminal report whose action fields and merge-ready claim are fixed false.
- Read-only report schema v7 represents selection and range failures directly.
  Every target state binds provider, immutable repository identity, and exact
  current query-head repository/ref/OID. `pre-target` and
  `pre-target-blocked` omit only PR/base, while `target-resolution-blocked`
  retains the selected PR and current head but omits unresolved base evidence.
  Every report uses fresh independent report/target/snapshot/observation IDs.
  Every selection, lifecycle, CI, and conversation observation repeats the
  applicable target identity exactly, including PR Node ID/base ref and current
  head, so cross-PR splicing, head races, and stale-green CI fail closed. The
  standalone semantic validator equality-binds every evidence record to that
  instance and requires the exact canonical URL derived from the structured
  repository and PR number. It preserves GitHub `statusCheckRollup` as an exact
  provider-discriminated union: `CheckRun` binds its Node/database IDs, name,
  GitHub App Node/database IDs and slug plus complete raw status/conclusion
  enums, while legacy `StatusContext` binds its Node ID, context, and creator
  identity plus complete raw state enum. Stable type/provider/object
  identities, rather than display names, determine uniqueness. Non-null GitHub
  App and CheckRun database IDs map one-to-one to Node IDs in both directions.
  Every legacy `StatusContext` Node ID also maps globally to exactly one
  creator Node ID and context; state changes do not change that immutable
  binding.
  One explicit fail-closed mapping normalizes those provider values to success,
  failure, pending, or cancelled aggregates.
  CI pagination now binds the GraphQL connection and every page to the exact
  repository Node ID, PR Node ID, and observed head OID. Server `totalCount`,
  page counts, the complete flat rollup, and aggregate total must agree. Every
  page repeats the report snapshot binding, observation ID, and server total,
  and binds those fields plus its exact ordered flat-list slice with the
  domain-separated canonical JSON SHA-256; cursor chaining is
  contiguous and the final page proves `hasNextPage=false`. The
  bounded complete profile admits at most 1,000 entries across at most ten
  100-item pages, subject to the tighter independent report-byte ceiling.
  Over-cap, incomplete, hidden-later-page, count-mismatched, or
  identity-drifted results are unavailable/blocked rather than truncated
  observed evidence.
  Conversation evidence independently exhausts
  `pullRequest.reviewThreads`, preserves unique thread Node IDs and raw
  `isResolved` values, binds every page with the same canonical digest
  contract, and recomputes total and unresolved counts from the complete list.
  A hidden later-page unresolved thread, incomplete cursor chain, content
  drift, or mid-pagination total change fails closed.
  Base/head evidence records the exact observed endpoint OIDs and must match
  the target byte-for-byte before object-existence or merge-base results count.
  The validator also rejects lifecycle, selector, CI-rollup,
  conversation-count, and endpoint contradictions that JSON Schema cannot
  express. The schema embeds its complete closed delivery-v3 receiver
  definition and has no external `$ref`. The schema and semantic helper remain
  direct records in the canonical control manifest, so the release digest
  binds the complete v7 receiving closure without loading an external or
  candidate-head delivery schema. Its binding generator
  retries collisions, while file input uses no-follow/nonblocking/close-on-exec
  descriptor admission, regular-file and byte ceilings, exact identity/size
  revalidation, and two identical complete reads. Strict UTF-8 JSON parsing
  rejects duplicate keys, non-finite numbers, oversized integers, excessive
  depth/node counts, and non-object roots; every rejection is one bounded,
  control-free machine record.
- Every terminal result or permitted handoff carries a closed delivery-v3
  record with the selected profile, immutable constraint list, mutation modes,
  terminal outcome/reason/evidence, handoff target, and handoff profile. A
  blocked PR-readiness run retains its requested profile but forces both
  handoff fields to `none`. A commit-allowed PR handoff requires a succeeded
  local gate, satisfied build/tests/docs/journal, a present clean range, a
  verified signature bound to the exact head by
  `signature_verified_head_oid`, and satisfied authorization/input. A
  commit-forbidden
  PR handoff uses a distinct existing-range reason, checked local gate, present
  clean range, and read-only verification of that exact frozen head. Unsigned,
  unverifiable, or differently bound heads stop with `signing-failed`; no
  commit is induced. Missing range, findings, signing
  failure, and authorization/input blockers all stop before handoff.
  Conflicting or widened records fail closed.
- The delivery schema now owns an exact 18-row success-reason matrix and a
  finite blocker matrix. Every success reason
  fixes its profile, local/commit/formal/remote modes, complete local
  gate/build/tests/docs/journal/range/review/signature/authorization/input
  evidence, and handoff. Cross-profile, cross-mode, and cross-evidence
  combinations fail both schema and semantic checks. A successful result
  cannot contain blocked, failed, findings, or not-started evidence.
  Implementation, earliest validation failure, journal, and formal-review
  blockers each have closed evidence rows; contradictory later-stage evidence
  is rejected.
- `review-findings` is terminal only for a required formal review whose commit
  mode is forbidden and whose existing range is preserved. Under allowed
  commit mode, findings have no terminal record: repair, affected validation,
  journal work, a new signed head, and exact-range review must repeat.
- Terminal-outcome precedence makes a combined MVP-plus-PR request run the
  focused slice, full local gate, and PR handoff in that order. A clean signed
  review checkpoint is already the landing commit; the workflow never creates
  an empty relabeling commit or rewrites history for that purpose.
- Version-sensitive validation loads a dedicated reference that deterministically
  selects single- or multi-version authority and isolates checkout, cache,
  ports, and persistent state before concurrent execution.
- The journal automation gate updates repositories that already adopted the
  convention, repositories whose policy requires it, and durable cross-session
  or PR handoffs with an existing tracking product. A short checkpoint does not
  introduce first-time tracking by itself.
- Formal review details remain in `review-orchestration-playbook`. When commit
  mode allows fixes, the workflow reruns affected validation and journal work,
  creates a new signed review checkpoint, and reviews the new exact range. When
  commit mode forbids fixes, it preserves the existing committed range, reports
  the findings as a blocker, and stops without creating or requiring history.
- The formal-review terminal matrix now distinguishes a clean pre-existing
  range from missing-range and findings blockers under forbidden commit mode.
  A clean range is reported and proceeds directly to the selected profile's
  stop or permitted handoff; no row asks for, implies, or manufactures a commit.
- When formal review is not required, forbidden commit mode now terminates with
  the uncommitted checked result and exact validations; it does not invent a
  missing-range blocker or handoff.
- Synthetic fixture authoring binds its sibling review runtime from the same
  active immutable release. The resolver admits imports only after an absolute
  Python interpreter starts it with `-I -B -S`, rejects a raw resolver leaf or
  parent-chain symlink before resolution, and binds the loaded-skill and
  co-release identity through the release `sync-manifest.json`.
- Each catalog bind, validation, metadata listing, or single-ID retrieval is
  one in-process transaction. It retains and revalidates the resolver,
  interpreter, trusted runtime manifest, dedicated catalog entry, four source
  modules, catalog, and parent-directory descriptors through snapshot
  execution, result validation, namespace cleanup, and final close. The
  trusted guard pins the manifest SHA-256; that manifest pins every executable
  source and data byte in the exact import closure. The closed loader rejects
  unlisted modules and imports, while candidate changes require explicit
  manifest rotation reviewed under the previous trusted release. No validated
  mutable pathname is executed later.
  `CODEX_HOME`, `HOME`, repository shadows, caller-selected catalog paths, and
  same-byte inode replacement cannot select or release a result.

## Next Steps

- No code follow-up is required for this workstream.

## Evidence

- `python3 -B -m unittest discover -s skills/change-delivery-workflow/tests
  -p 'test_*.py'` passed (`42` tests). The suite keeps the exact 18-success
  matrix and now also covers the finite blocked-reason matrix, exact frozen-head
  signature verification for no-commit existing-range handoff, snapshot- and
  ordered-content-bound CI pages, complete paginated review threads, global
  `StatusContext` creator/context identity, and fail-closed delivery-v2/report-v6
  migration.
- `python3 -B skills/synthetic-token-fixtures/tests/test_skill_contract.py -v`
  passed (`13` tests), including co-release binding, isolated-import shadows,
  raw-leaf and intermediate cross-release symlinks, unsafe parent modes,
  bound validate/list/get operations, manifest/source/catalog tampering,
  unlisted modules and import substitution, parent replacement, same-byte
  entry inode replacement, valid trusted manifest rotation, and fail-closed
  source/layout drift.
- `python3 -B skills/review-orchestration-playbook/tests/test_synthetic_tokens.py -q`
  passed the complete `190`-test synthetic runtime suite.
- `python3 -B skills/review-orchestration-playbook/tests/test_contracts.py -q`
  passed (`88` tests), including the semantic helper's canonical-manifest
  binding, self-contained receiver schema closure, and absence of an external
  delivery-schema dependency without widening a formal named-lane source
  closure.
- `python3 -B -m unittest discover -s
  skills/review-orchestration-playbook/tests -p 'test_*.py'` passed the complete
  review-helper suite outside the filesystem sandbox (`2,401` tests, `5`
  platform skips). The unsandboxed run was required only for existing
  loopback-broker tests that bind an ephemeral `127.0.0.1` port.
- `python3 -B skills/review-orchestration-playbook/tests/test_cli.py -q`
  passed (`17` tests).
- Both the system `quick_validate.py` and Joey
  `codex_skill_validate.py` passed the two modified skills.
- `jq empty` passed for both schemas and all three changed fixture files.
  Draft 2020-12 `jsonschema` validation accepted both schema definitions;
  the delivery suite validated all `13` profile-selection cases, all `8`
  formal-review terminal cases, and all four terminal read-only report states.
- `python3 -B /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .`
  passed.
- Ruff checks, `ruff format --check`, and `py_compile` passed for the three
  modified Python runtime/test files.
- `git diff --check` passed for tracked changes.
