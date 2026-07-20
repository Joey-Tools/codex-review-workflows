---
id: 20260717-7f1703
title: Trust Reviewers and Gate Exact-Secret Growth
status: completed
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
- Stateful review evidence and secret admission are separate current-head checks: harvest `stateful final` first, then run `stateful admission` on the same state.
- The frozen reviewer launch boundary uses safe modes, prepared runner-lock identity checks, and descriptor-bound workspace, prompt, sandbox, attempt-output, and verdict/control I/O.

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

### Stateful Admission Evidence

PR/master/merge-ready evaluation first harvests the terminal reviewer artifact with `stateful final --state-dir <state_dir>`, then evaluates the bounded public secret summary with `stateful admission --state-dir <state_dir>` on that same current-head state. Admission exit `0` means `clean` and is the only permitting result; exit `1` means violations, exit `3` means pending, and exit `75` means inconclusive. The reviewer final is independent and may remain successful when admission blocks or is inconclusive. Foreground review never supplies admission evidence. A head change invalidates both checks and requires a new frozen current-head state. None of these admission outcomes may delay, suppress, or redact the trusted reviewer launch.

### Workspace Scope

Targeted launch-boundary hardening is part of this delivery: frozen workspace and control artifacts use safe owner-only modes, cleanup is bound to the prepared runner-lock identity, and reviewer workspace, prompt, sandbox mount, attempt output, and verdict/control I/O remain attached to validated descriptors. This does not adopt a detached-worktree or reflinked-snapshot architecture; that broader redesign remains deferred.

## Current State

This note supersedes its earlier strict-reduction design, which required raw-count decrease, unembedded non-growth, same-location provenance, encoded-variant denial, and two extra Codex PR-readiness gates. Those requirements are no longer the target contract.

Implementation and final combined code validation now match this decision, including the explicit stateful final-then-admission split. This tracked implementation workstream is `completed`; the final fixed-range Codex review, PR merge, private-overlay release, installation sync, and remote-task notification remain delivery operations tracked by the active PR/task rather than transient project state. Historical test counts and prior fixed-range review claims in earlier revisions of this note are not validation evidence for the new semantics.

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
- PR/master/merge-ready requires `stateful final` followed by same-state, current-head `stateful admission`; only admission exit `0` is permitting.
- Admission exits `1`, `3`, and `75` remain distinct violations, pending, and inconclusive outcomes; reviewer final success is independent, foreground output is insufficient, and a head change invalidates both checks.
- Frozen workspace/control creation and runner-lock cleanup fail closed under permissive umasks, symlinks/FIFOs, path swaps, and identity/mode/link-count/owner mismatches.
- Reviewer cwd, frozen prompt, Linux sandbox workspace mount, attempt output, and terminal verdict/control artifacts remain bound to the prepared container across pathname swaps; descriptor handoff and close failures surface before a result is accepted.
- Skill and journal validation pass.

## Next Steps

- Deliver PR #60 through current-head CI/review, squash merge, private-overlay release, installation sync, and remote-task handoff.
- Keep the detached-worktree versus reflinked snapshot redesign out of this delivery and revisit it only after the operational checklist completes.

## Delivery TODO

- [x] Align the exact-secret policy, reviewer trust boundary, lane model, and encoded-form limitation.
- [x] Update the canonical design and workflow contracts.
- [x] Finish the exact raw counter, added-line evidence, and reviewer-egress separation.
- [x] Harden frozen review launch modes, runner-lock cleanup identity, and descriptor-bound workspace, sandbox, prompt, attempt, and verdict I/O.
- [x] Update focused scanner, workspace, provider, state, CLI, descriptor-launch, and contract tests.
- [x] Separate current-head reviewer final evidence from the explicit stateful secret-admission decision and document its exit-code contract.
- [x] Run Python 3.13 validation, contract checks, skill validation, and journal validation.
- [ ] Run one fresh local Codex review over the final signed fixed range and resolve actionable findings.
- [ ] Push the branch, update PR #60, and wait for current-head CI and review completion.
- [ ] Squash-merge PR #60 after every merge-readiness gate is clean.
- [ ] Trigger and verify the private-overlay sync/release, then update the local and `BL-mac-mini-m4-hoteng` installations with the installed synchronizer.
- [ ] Notify Codex task `019f17fc-5756-7fb2-8d9f-34c0330bd59b` on `BL-mac-mini-m4-hoteng` to resume its Claude Code review with the updated personal review skill.

The detached-worktree versus reflinked snapshot workspace design is intentionally deferred until every item above completes.

The remaining unchecked items are post-commit delivery operations. They are intentionally not pre-marked in tracked history before they occur; their current state belongs in PR/task coordination.

## Evidence

- `AGENTS.md`
- `skills/review-orchestration-playbook/SKILL.md`
- `skills/review-orchestration-playbook/references/egress-consent.md`
- `skills/review-orchestration-playbook/references/helper-contract.md`
- `skills/review-orchestration-playbook/references/pr-readiness.md`
- `skills/review-orchestration-playbook/references/review-lane-contracts.md`
- `skills/review-orchestration-playbook/references/synthetic-token-fixtures.md`
- Python 3.13.0 pre-admission anchor: `1285 tests`, `OK (skipped=4)`, 252.878 seconds.
- Python 3.13.0 final merged code anchor `95b34b7`: `1325 tests`, `OK (skipped=4)`, 270.621 seconds.
- Post-admission focused suites: state plus CLI `153 tests`; workspace `135 tests`; synthetic-token `165 tests`; contracts `42 tests`; all passed.
- Focused runtime suites: `test_common.py` 38 tests; `test_claude_linux.py` 153 tests with 3 skipped; `test_providers.py` 479 tests with 3 skipped; all passed.
- Descriptor-bound runtime patch review: two actionable findings were fixed; follow-up result `No findings.`.
- Admission/final follow-up review: one malformed-JSON fail-closed finding was fixed; follow-up result `No findings.`.
- Latest `master` cleanup-directory identity fix `202ef98` was merged; the stable directory identity and descriptor-bound runtime-artifact contracts were both retained, and their focused concurrency/path-replacement regressions passed.
- Ruff checks, changed-file format checks, and `git diff --check`: passed.
- Official skill validator: `Skill is valid!`.
- Project journal validator: `Project journal validation passed.`.
- The final immutable whole-range review result is recorded in PR #60 after the signed implementation anchor exists; it is not pre-claimed by this commit.
