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
  helper's authoritative catalog CLI without defining a second pool or runtime.

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
- Read-only report schema v3 represents selection and range failures directly:
  `pre-target` and `pre-target-blocked` omit PR/base/head, while
  `target-resolution-blocked` retains only the selected PR. Every report uses
  fresh independent report/target/snapshot/observation IDs. The standalone
  semantic validator equality-binds every evidence record to that instance and
  rejects lifecycle, selector, CI/check, conversation-count, and endpoint
  contradictions that JSON Schema cannot express. Its binding generator
  retries collisions, while file input uses no-follow/nonblocking/close-on-exec
  descriptor admission, regular-file and byte ceilings, exact identity/size
  revalidation, and two identical complete reads. Strict UTF-8 JSON parsing
  rejects duplicate keys, non-finite numbers, oversized integers, excessive
  depth/node counts, and non-object roots; every rejection is one bounded,
  control-free machine record.
- Every terminal result or permitted handoff carries a closed, versioned record
  with the selected profile, immutable constraint list, local mutation mode,
  commit mode, remote mutation mode, handoff target, and handoff profile.
  Conflicting or widened records fail closed.
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
  interpreter, catalog CLI, catalog, and parent-directory descriptors through
  snapshot execution, result validation, namespace cleanup, and final close.
  The CLI and its closed `review_runtime` imports execute only from captured
  source and catalog bytes; no validated mutable pathname is executed later.
  `CODEX_HOME`, `HOME`, repository shadows, caller-selected catalog paths, and
  same-byte inode replacement cannot select or release a result.

## Next Steps

- No code follow-up is required for this workstream.

## Evidence

- `uv run --offline --with jsonschema python -B skills/change-delivery-workflow/tests/test_delivery_profiles.py`
  passed (`28` tests), including deterministic local-mutation short circuits,
  the independent mutable-`no-commit` control, constrained-scope conflicts,
  staged read-only PR-probe terminals, fresh instance bindings, cross-report
  splice rejection, collision recovery, descriptor-safe input admission and
  revalidation, hostile JSON/resource caps, bounded machine-safe errors, closed
  delivery and terminal report records, and the clean-range, missing-range,
  findings, and review-not-required terminals under forbidden commit mode.
- `python3 -B skills/synthetic-token-fixtures/tests/test_skill_contract.py -v`
  passed (`7` tests), including co-release binding, isolated-import shadows,
  raw-leaf and intermediate cross-release symlinks, unsafe parent modes,
  bound validate/list/get operations, same-byte CLI inode replacement, and
  fail-closed source/layout drift.
- `python3 -B skills/review-orchestration-playbook/tests/test_synthetic_tokens.py SyntheticTokenCliTest -v`
  passed (`6` tests), including the explicit exact-bytes catalog hook used only
  by the bound transaction.
- `uv run --offline --with pyyaml python skills/review-orchestration-playbook/tests/test_contracts.py`
  passed (`87` tests), including the semantic helper's canonical-manifest
  binding without widening a formal named-lane source closure.
- `python3 -B skills/review-orchestration-playbook/tests/test_cli.py -q`
  passed (`17` tests).
- `uv run --isolated --with pyyaml python3 /Users/hoteng/.codex/skills/joey-skill-authoring/scripts/codex_skill_validate.py --report /tmp/delivery-binding-review-fixes.TIcfwF/skill-validation-escalated.json skills/change-delivery-workflow skills/agile-delivery-workflow skills/synthetic-token-fixtures skills/review-orchestration-playbook`
  passed for all four affected skills after the constrained-scope review-fix
  round.
- `python3 /Users/hoteng/.codex/skills/joey-skill-authoring/scripts/codex_skill_validate.py skills/change-delivery-workflow skills/review-orchestration-playbook`
  passed for both helper-owning skills after the final hostile-input hardening.
- `python3 -m json.tool` passed for both schemas and the read-only probe fixture;
  Draft 2020-12 `jsonschema` validation accepted all `13` delivery records and
  all four terminal read-only report states through the registered cross-schema
  reference.
- `python3 -B /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .`
  passed.
- Ruff `E9,F,I` checks passed for the new semantic helper and delivery contract
  tests; `E9,F` passed for the manifest contract test, and `ruff format --check`
  passed for all three touched Python files.
- Broader review-playbook discovery was bounded and manually interrupted after
  six silent minutes in unchanged `test_providers` signal-mask setup; it
  produced no assertion failure and left no process behind. The affected
  targeted modules above completed.
- The validator's task-local `uv` cache and test-created Python bytecode were
  removed after validation; the final ignored-cache scan passed.
- `git diff --check` passed for tracked changes.
