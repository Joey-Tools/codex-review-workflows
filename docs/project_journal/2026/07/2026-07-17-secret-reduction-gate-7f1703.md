---
id: 20260717-7f1703
title: Trust Reviewers and Gate Exact-Secret Growth
status: active
created: 2026-07-17
updated: 2026-07-20
branch: codex/secret-reduction-review
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/60
supersedes: []
superseded_by:
---

# Trust Reviewers and Gate Exact-Secret Growth

## Summary

- Codex, Claude Code, and the consent-gated Copilot fallback are trusted processors for the frozen tracked review scope.
- Tracked secret deltas do not block reviewer launch or trigger reviewer-input rewriting.
- PR/master admission allows every existing exact raw secret whose global tracked count does not grow and blocks only first appearance or growth.

## Decision

### Trusted Reviewer Boundary

After the consented egress boundary passes, the reviewer receives the frozen tracked diff, necessary tracked context, and explicitly supplied prompt in their original form, including repository secrets. Secret scanning is not an egress filter. A secret-admission violation or inconclusive count must not prevent the reviewer from starting or invalidate its terminal artifact.

This authorization remains scoped. It does not permit automatic discovery or collection of reviewer/runtime authentication credential sources, untracked private files, unrelated repositories, broad workspace dumps, or unrelated host-local artifacts.

### Unified Exact Raw Counter

Every tracked exact secret outside the approved authoring pool uses one rule, whether it was previously cataloged as legacy or discovered dynamically:

```text
head_count <= base_count
```

Count one exact raw byte value globally over each actual tracked surface in the complete base and head Git trees:

- raw Git path bytes, including gitlink/submodule entry paths without reading submodule content;
- regular-file blob bytes, including executable blobs; and
- symlink-target bytes.

The rendered diff and prompt are reviewer input, not additional count surfaces.

| Range outcome | PR/master admission |
| --- | --- |
| `head_count < base_count` | Pass |
| `head_count = base_count` | Pass |
| Value moves across path, content, blob/symlink surface, mode, or offset without global growth | Pass |
| Copy is balanced by another removal | Pass |
| `base_count = 0` and `head_count > 0` | Block |
| `head_count > base_count` | Block |
| Complete bounded scanning or count integrity cannot be established | Inconclusive |

There is no unembedded counter, per-occurrence provenance requirement, path-specific absolute deny, or separate stricter legacy policy. Occurrences are intentionally fungible across paths, surfaces, and offsets.

### Exactness And Scan Completeness

The counter consumes exact raw candidates only. It does not derive canonical Base64, URL encoding, hexadecimal, escaping, hashing, or any other representation.

This creates a deliberate limitation: an encoded or transformed form is not linked to the raw secret unless that byte string independently becomes an exact scanner candidate. Evidence must state this limitation without generating the missing variants.

A dynamic expression that cannot produce one stable exact byte value does not enter the counter and is not itself an admission violation. This is not the same as an incomplete scan. A scanner-recognized shape that is unextractable only in base is treated as a permitted deletion; an unextractable head-side shape is `inconclusive`. If the helper cannot completely enumerate or read the bounded base/head trees, loses counter integrity, or otherwise cannot finish counting an exact candidate, admission is also `inconclusive` and records a bounded failure class without exposing the raw diagnostic.

### Violation Reporting

A violation report contains only detectable additions for a candidate whose global count grows. Text evidence carries raw path plus one-based head line; new tracked paths and binary fallbacks use `line: null`; symlink targets use line `1`. It does not enumerate unchanged residual or base-only occurrences. If bounded diff evidence cannot map every detected local growth to a line, `location_status` is `inconclusive` rather than inventing one.

### Catalog Compatibility

Approved authoring-catalog values remain exact safe-fixture exceptions under their declared scanner rule.

Historical `legacy_exemptions` no longer select a different admission policy. Their exact raw values receive the same complete-tree baseline automatically, without explicit selection, unembedded counts, provenance, encoded-variant checks, or path denial. `--synthetic-secret-exemption`, `list-exemptions`, and `audit-master` may remain temporarily for CLI compatibility, but they are deprecated and must not alter admission.

### Review Lanes

The fresh local Codex CLI review is the independent local lane:

- single review: fresh local Codex;
- double review: fresh local Codex plus one Claude-family lane;
- triple review: double review plus current-head GitHub Codex.

PR readiness reuses that Codex artifact. It does not add separate `offline-frozen-diff-review` or `independent-codex-pr-review` gates. Retries, helper implementations, and the clean-context fallback remain one logical Codex lane.

### Workspace Scope

This decision does not redesign the frozen workspace, materialization, symlink handling, control artifacts, process supervision, cleanup, retention, or accounting. Do not import a separate detached-worktree or supervisor design as part of this policy update.

## Current State

This note supersedes its earlier strict-reduction design, which required raw-count decrease, unembedded non-growth, same-location provenance, encoded-variant denial, and two extra Codex PR-readiness gates. Those requirements are no longer the target contract.

Implementation and local validation now match this decision. The workstream remains `active` only while the fixed-range review and PR delivery gates are in progress. Historical test counts and prior fixed-range review claims in earlier revisions of this note are not validation evidence for the new semantics.

## Validation Criteria

- Trusted reviewer launch succeeds with unchanged, moved, newly added, and growing tracked exact secrets when the egress boundary itself is valid.
- PR/master admission passes unchanged counts, reductions, and cross-path/surface/offset moves.
- PR/master admission blocks first appearance and global growth.
- Former legacy values receive the same baseline without explicit exemption selection.
- Authoring-catalog safe fixtures retain exact declared-rule acceptance.
- Base64 and other encoded variants are neither derived nor scanned as aliases.
- Non-exact dynamic expressions are excluded from the counter.
- Base-only unextractable shapes may be deleted, while head-side or otherwise genuinely incomplete scans report `inconclusive`.
- Violation diagnostics include only newly added `path:line` locations.
- Single/double/triple review counting remains Codex / Codex+Claude / Codex+Claude+GitHub Codex.
- PR readiness has no additional offline/independent Codex double gate.
- Existing workspace behavior remains unchanged.
- Skill and journal validation pass.

## Next Steps

- Commit the validated whole-range review anchor.
- Run one fresh local Codex review over the fixed base/head range and resolve actionable findings.
- Deliver PR #60 through current-head CI/review, squash merge, private-overlay release, installation sync, and remote-task handoff.
- Mark this journal `completed` once the reviewed implementation and its verified evidence are final in this change.

## Delivery TODO

- [x] Align the exact-secret policy, reviewer trust boundary, lane model, and encoded-form limitation.
- [x] Update the canonical design and workflow contracts.
- [x] Finish the exact raw counter, added-line evidence, and reviewer-egress separation.
- [x] Update focused scanner, workspace, provider, state, CLI, and contract tests.
- [x] Run Python 3.13 validation, contract checks, skill validation, and journal validation.
- [ ] Run one fresh local Codex review over the fixed whole range and resolve actionable findings.
- [ ] Push the branch, update PR #60, and wait for current-head CI and review completion.
- [ ] Squash-merge PR #60 after every merge-readiness gate is clean.
- [ ] Trigger and verify the private-overlay sync/release, then update the local and `BL-mac-mini-m4-hoteng` installations with the installed synchronizer.
- [ ] Notify Codex task `019f17fc-5756-7fb2-8d9f-34c0330bd59b` on `BL-mac-mini-m4-hoteng` to resume its Claude Code review with the updated personal review skill.

The detached-worktree versus reflinked snapshot workspace design is intentionally deferred until every item above completes.

## Evidence

- `AGENTS.md`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/egress-consent.md`
- `skills/review-orchestration-playbook/references/helper-contract.md`
- `skills/review-orchestration-playbook/references/pr-readiness.md`
- `skills/review-orchestration-playbook/references/review-lane-contracts.md`
- `skills/review-orchestration-playbook/references/synthetic-token-fixtures.md`
- Python 3.13.0: `1260 tests`, `OK (skipped=4)`, 327.283 seconds.
- Focused contract suite: `41 tests`, `OK`.
- Focused base-only deletion and head-side incomplete-scan boundary: `2 tests`, `OK`.
- Ruff checks, changed-file format checks, and `git diff --check`: passed.
- Official skill validator: `Skill is valid!`.
- Project journal validator: `Project journal validation passed.`.
