---
id: 20260724-dpf001
title: Unify Delivery Profiles And Retire Standalone Agile Delivery
status: completed
created: 2026-07-24
updated: 2026-07-29
branch: codex/delivery-profiles-agile-retirement-20260724
pr: 83
supersedes: []
superseded_by:
---

# Unify Delivery Profiles And Retire Standalone Agile Delivery

## Summary

- `change-delivery-workflow` is the thin active orchestrator for
  `focused-checkpoint`, `local-gate`, and `pr-readiness-handoff`.
- `agile-delivery-workflow` is a compatibility alias that maps legacy
  MVP/agile/scout triggers to `focused-checkpoint`.
- `synthetic-token-fixtures` routes authoring only through the active immutable
  release's manifest-bound `catalog-bootstrap` guard. The low-level helper and
  repo-local catalog entry reject direct authoring, so no mutable checkout can
  publish catalog metadata or a raw value.
- The post-#53 integration removes the deprecated exemption flag and legacy
  list/audit commands. Historical catalog records remain automatic exact-value
  admission inputs, not caller-selectable authority.

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
  record with the selected profile, immutable constraint list, exact full
  `head_sha`, mutation modes, terminal outcome/reason/evidence, handoff target,
  and handoff profile. A verified `signature_verified_head_oid` must
  byte-for-byte equal `head_sha` for both SHA-1 and SHA-256; the ordinary and
  read-only PR-readiness receivers enforce that equality through the
  same-release semantic helper, and the read-only report additionally binds
  the delivery head to its exact target head. A
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
  26-row blocker matrix. Mutable commit, mutable no-commit existing-range, and
  read-only formal blockers are distinct closed rows that fix
  `local_mutation`, `commit_mode`, local-gate state, and mutable versus
  read-only phase evidence. The six no-commit/read-only formal-review,
  missing-range, and findings rows contain a second closed profile branch:
  policy-promoted `focused-checkpoint` blockers use
  `local_gate: not-required`, while full local/PR gate blockers use `checked`.
  Cross-profile, cross-mode, and cross-phase relabeling fails closed, and no
  no-commit or read-only blocker can claim a fake succeeded local gate. Every
  success reason
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
- The catalog bootstrap and active resolver now protect the release's effective
  access policy in addition to owner/mode. macOS descriptors reject mutating
  extended ACL entries for non-owner UUIDs and bind selected BSD security
  flags, while harmless metadata/ACL churn remains outside the protected
  property. Linux descriptors admit only an explicit local POSIX ACL
  filesystem set through `fstatfs`; NFS/NFSv4, CIFS/SMB, FUSE, ZFS, 9P,
  overlayfs, and unknown models fail closed instead of treating mode bits as
  complete access evidence.
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
- `isolated_review synthetic-tokens ...` now rejects every action before
  catalog loading. Direct `scripts/synthetic_catalog_entry` execution also
  rejects before output; the entry remains executable only as a retained
  manifest-bound source snapshot inside the active-release resolver. Its
  internal `catalog_main` additionally requires resolver-injected bound catalog
  bytes. Repository tests exercise those internal bytes explicitly and use a
  test-only catalog read for credential-shaped supervisor fixtures rather than
  advertising a mutable authoring CLI.
- The authoring catalog exposes only `validate`, metadata-only `list`, and
  exact single-ID `get`, with one shared result implementation. The deprecated
  exemption-selection flag, exemption-list command, pinned-master audit
  command, audit runtime, and handwritten ID table are absent. Historical
  schema-v1 state can still be parsed for bounded status/cleanup recovery, and
  historical catalog values still participate automatically in the same
  complete-tree `head_count <= base_count` admission rule.
- Linux hosted CI runs the synthetic catalog contract with the root-owned
  system `/usr/bin/python3`. The setup-python interpreter lives below the
  hosted runner's group/world-writable `/opt`, so the catalog binder correctly
  rejects that mutable parent chain instead of adding a CI-only trust bypass.
  On macOS, setup-python resolves through the fixed
  `/Library/Frameworks/Python.framework/Versions` parent. Immediately after
  setup-python completes, and before the first workflow `run:` step, Python
  invocation, or repository-code execution, the workflow proves that exact
  path is an ordinary directory and removes only its group/world write bits;
  the catalog transaction still validates the full interpreter parent chain,
  executable bytes, identity, access policy, and terminal stability. A changed
  path, symlink, unsafe ACL, or other unsafe ancestor still fails closed.
  Review-helper and delivery tests continue to use the requested setup-python
  version. Both reviewed CI profile snapshots carry the same macOS sealing
  order and Linux system-interpreter branch.
- `master` at `b3d593315b2b6e9310914bd8b2af8a41aa46e08b` (including PR #53)
  was integrated with the signed merge commit
  `bd9266dec9cae76de662795368c6080b8909b3c5`. Conflict resolution preserved
  GitHub-request ordering, Trusted Mac evidence, and complete CI/conversation
  pagination contracts.

## Next Steps

- No code follow-up is required for this workstream.

## Evidence

- The 2026-07-29 access-policy follow-up passed the synthetic fixture contract
  (`20` tests, `1` Linux-only skip), focused review contracts (`99` tests),
  delivery contracts (`45` tests), and the complete module-bounded
  review-helper suite (`2,820` tests, `8` platform skips). The provider module
  passed outside the outer sandbox (`947` tests, `3` skips) because its local
  identity socket is intentionally unavailable inside that sandbox. The
  workspace module passed outside the outer sandbox (`286` tests, `1` skip)
  without the log runner's process-wide file-size limit, which otherwise
  blocked its intentional 256 MiB+1 sparse-file boundary fixture.
- Joey's installed skill validator accepted both changed skills; the project
  journal validator, Ruff check/format, and `git diff --check` passed. A second
  independent implementation review reported no findings after overlayfs was
  removed from the Linux POSIX ACL allowlist.
- `python3 -B -m unittest discover -s skills/change-delivery-workflow/tests
  -p 'test_*.py' -q` passed (`45` tests).
- `python3 -B -m unittest` over the synthetic skill contract, synthetic runtime,
  and Claude Linux credential tests passed (`455` tests, `1` platform skip).
  This includes the catalog-value non-duplication contract and exact
  metadata-bound fixture selection.
- `python3 -B -m unittest tests/test_auth_carrier.py -q`, from the independent
  supervisor root, passed (`37` tests). Its test-only fixed catalog read
  validates a unique ID, role, state, and nonempty ASCII value without exposing
  a public authoring command; the full synthetic contract separately validates
  the catalog digests and raw-value non-duplication.
- Six directly affected provider authentication and egress tests passed.
- `python3 -B -m unittest
  skills/review-orchestration-playbook/tests/test_contracts.py -q` passed
  (`99` tests).
- `python3 -B -m unittest discover -s
  skills/review-orchestration-playbook/tests -p 'test_*.py' -q` passed the
  complete review-helper suite outside the outer workspace sandbox (`2,818`
  tests, `6` platform skips). Native macOS `sandbox-exec` coverage required
  that environment; the exact previously sandbox-blocked test also passed in
  isolation before the full rerun.
- Joey's installed `codex_skill_validate.py` accepted
  `change-delivery-workflow`, `synthetic-token-fixtures`, and
  `review-orchestration-playbook`; the latter two were revalidated after direct
  authoring dispatch was removed.
- `jq empty` passed for the catalog and trusted runtime manifest.
- `python3 -B /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .`
  passed.
- Ruff checks passed for every modified Python file. Ruff format checks passed
  for the modified files that were not already part of the inherited #53
  formatting baseline; the repository-wide check still identifies seven
  inherited files from that baseline.
- `git diff --check` passed for tracked changes.
- PR #83's first Ubuntu run proved the setup-python `/opt` rejection. The
  workflow now preserves that fail-closed production property and selects
  `/usr/bin/python3` only for the stdlib-only synthetic catalog contract on
  Linux. A fresh-context review then found the canonical and private CI
  snapshots had not yet inherited that branch; both snapshots and the explicit
  profile contract are now updated. `actionlint`, the byte-for-byte canonical
  workflow comparison, and the focused profile contract passed locally.
- PR #83's `93adea2` macOS run then failed closed because
  `/Library/Frameworks/Python.framework/Versions` was group/world writable on
  the hosted runner. The canonical workflow and both reviewed CI snapshots now
  seal that exact non-symlink directory before the macOS synthetic contract;
  they do not copy the interpreter or relax catalog admission. The focused
  review contract passed (`99` tests), and the local macOS synthetic contract
  passed (`20` tests, `1` Linux-only skip) with a secure interpreter chain.
- A fresh Codex finding on `0f09650` identified that the seal still followed
  earlier Python and repository-code execution, including a complete review
  suite in the private snapshot. The canonical workflow and both snapshots now
  make the seal the first `run:` step after setup-python. The profile contract
  slices each `platform_tests` job and asserts
  `setup-python < seal < first Python/repository-code execution`; the focused
  contract passed (`99` tests), the synthetic contract passed (`20` tests,
  `1` Linux-only skip), `actionlint` accepted all three workflows, the
  canonical snapshot remained byte-for-byte equal to the workflow, all three
  related skills passed the installed validator, and Ruff check/format passed.
- The subsequent whole-range review found that the mutable-commit
  `formal-review-blocked` and `signing-failed` schema rows unconditionally
  labeled the full local gate as blocked. Both rows now share a profile-bound
  rule: a `focused-checkpoint` keeps `local_gate: not-required`, while
  `local-gate` and `pr-readiness-handoff` retain `local_gate: blocked`.
  Cross-combination tests reject either gate value under the wrong profile and
  reject relabeling focused evidence as a full gate. The complete delivery
  schema suite passed (`46` tests), and the review contract suite passed
  (`99` tests).
