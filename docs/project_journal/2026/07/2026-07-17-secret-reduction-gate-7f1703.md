---
id: 20260717-7f1703
title: Trust Reviewers and Gate Exact-Secret Growth
status: completed
created: 2026-07-17
updated: 2026-07-21
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
- Stateful review evidence and secret admission are separate current-head checks: harvest `stateful final` first, then run `stateful admission` on the same state and require its schema-v5 runner-sealed preflight receipt.
- The frozen reviewer launch boundary uses safe modes, prepared runner-lock identity checks, trusted child argv for reviewer/egress policy, and descriptor-bound workspace, prompt, sandbox, attempt-output, and verdict/control I/O.

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

A violation report contains only detectable additions for a candidate whose global count grows. Text evidence carries raw path plus one-based head line; new tracked paths and binary fallbacks use `line: null`; symlink targets use line `1`. It does not enumerate unchanged residual or base-only occurrences. If bounded diff evidence cannot map every detected local growth to a line, `location_status` is `inconclusive` rather than inventing one. Git endpoint trees do not preserve `git mv` operation identity, so a move plus an identical copy is deliberately reported with ambiguous locations omitted when the local positive candidates exceed the authoritative global delta; heuristic rename attribution is not admission evidence.

The authoritative violation list retains every positive-delta candidate that fits the bounded catalog and complete-preflight capacity. If optional secondary accepted/legacy/reduction audit rows would make the public evidence exceed its fixed byte limit, those rows may be removed after the underlying manifest has been completely validated; the complete digest and base/head/delta proof plus bounded additions remain `violations` and admission remains blocked. Location omission likewise does not weaken a proved global-count violation. The secondary synthetic-token section retains its 64 KiB compact bound. The complete preflight retains a separate 128 KiB bound and switches from pretty to equivalent compact JSON only when required by that limit.

### Catalog Compatibility

Approved authoring-catalog values remain exact safe-fixture exceptions under their declared scanner rule.

Historical `legacy_exemptions` no longer select a different admission policy. Their exact raw values receive the same complete-tree baseline automatically, without explicit selection, unembedded counts, provenance, encoded-variant checks, or path denial. `--synthetic-secret-exemption`, `list-exemptions`, and `audit-master` may remain temporarily for CLI compatibility, but they are deprecated and must not alter admission.

Declared rules still govern authoring-fixture acceptance. At the counting layer, exact raw bytes are the unique key: if the same cataloged legacy bytes are rediscovered through a different scanner rule, the legacy descriptor takes precedence and the helper creates one counter, one violation, and one set of added locations rather than an ambiguous duplicate.

A large catalog-only manifest may use the existing public and helper-private files as complementary 64 KiB shards. Their fixed metadata must match, their combined rows must be complete and duplicate-free, and a unique SHA-256 commitment carried by the public control-state-bound shard commits to the canonical private rows. The loader verifies the commitment and reruns normal catalog/count/violation consistency checks after merging; missing, duplicated, mutated, or incomplete private rows fail closed.

### Review Lanes

Canonical named lanes use separate clean Git worktrees, clear reviewer context, and no injected full diff:

- single review: fresh local Codex;
- double review: fresh local Codex plus one Claude-family lane;
- triple review: double review plus current-head GitHub Codex.

The stateful supplied-diff/no-Git helper remains a low-level compatibility, security-maintenance, and admission-audit tool. Its reviewer artifact is trusted but never satisfies or replaces a named lane. PR readiness does not add the former `offline-frozen-diff-review` or `independent-codex-pr-review` lanes; the explicit low-level helper final/admission pair is a non-lane merge gate.

### Stateful Admission Evidence

PR/master/merge-ready evaluation first harvests the terminal reviewer artifact with `stateful final --state-dir <state_dir>`, then evaluates the bounded public secret summary with `stateful admission --state-dir <state_dir>` on that same current-head state. Before releasing its inherited lock, the stateful runner exact-reads and validates `preflight.json` through the preparation-bound container and advances the schema-v5 marker with the artifact's exact size and SHA-256. Receipt publication is not itself terminal: every admission query remains pending while the runner lock is held, even when a clean receipt is already readable. After lock release, admission re-reads the artifact under the same bounded no-follow rules and trusts it only when those bytes match the runner-sealed receipt. Admission exit `0` means receipt-bound `clean` and is the only permitting result; exit `1` means violations, exit `3` means pending, and exit `75` means inconclusive. A terminal unsealed state, malformed or mismatched receipt, replaced preflight, or schema-v4 marker is inconclusive. Receipt-only missing fields, malformed values, excessive nesting, and inner or top-level duplicate keys produce structured `preflight-invalid` / exit `75`, cannot be overwritten by sealing, and do not invalidate the separately verified reviewer final or lifecycle cleanup. Excessive nesting or other corruption in non-receipt lifecycle fields remains a hard state error. Schema v4 remains compatible with `status`, `wait`, `final`, and cleanup; it simply cannot authorize admission. The reviewer final is independent and may remain successful when admission blocks or is inconclusive. Foreground review never supplies admission evidence. A head change invalidates both checks and requires a new frozen current-head state. None of these admission outcomes may delay, suppress, or redact the trusted reviewer launch.

### Runner Policy Binding And Host Boundary

The trusted parent passes the selected reviewer and exact optional egress-consent value to the terminal child as argv alongside the inherited runner-lock descriptor. The child validates the lock before loading state, requires the path-loaded reviewer and consent to match those argv values exactly, and launches only with the argv-bound policy. A replacement `state.json` therefore cannot switch a Codex-only run into Claude or Copilot egress.

The receipt and argv bindings close helper-controlled path-replacement and cooperative-writer races; they do not claim hostile same-euid isolation. A malicious process running as the same account can mutate owner-private namespaces and is part of the host trusted computing base (host TCB, meaning software with equivalent host-account authority). This limitation also applies to cleanup identity binding and is not broadened into a container/security redesign in this delivery.

### Workspace Scope

Targeted launch-boundary hardening is part of this delivery: frozen workspace and control artifacts use safe owner-only modes, a newly created bound `attempts` directory is forced to `0700` before reopening, newly created runtime/control/attempt/credential-update files are descriptor-forced to `0600` even under an owner-masking umask, runner stdout/stderr descriptors are forced to exact `0600` before child spawn, existing lock and artifact files are never chmod-repaired, cleanup is bound to the prepared runner-lock identity, reviewer/egress policy is child-argv-bound, and reviewer workspace, prompt, sandbox mount, attempt output, preflight receipt, and verdict/control I/O remain attached to validated descriptors or exact digests. Canonical named lanes now use #68's separate clean Git worktree contract. This delivery does not redesign the low-level helper's `.git`-free frozen snapshot into a detached worktree or reflinked snapshot; that separate architecture decision remains deferred.

## Current State

This note supersedes its earlier strict-reduction design, which required raw-count decrease, unembedded non-growth, same-location provenance, encoded-variant denial, and two extra Codex PR-readiness gates. Those requirements are no longer the target contract.

Implementation and final combined code validation now match this decision, including the explicit stateful final-then-admission split, schema-v5 runner-sealed preflight receipt, reviewer/egress child-argv binding, and #68 named-lane/low-level-helper separation. This tracked implementation workstream is `completed`; the final fixed-range Codex review, PR merge, private-overlay release, installation sync, and remote-task notification remain delivery operations tracked by the active PR/task rather than transient project state. Historical test counts and prior fixed-range review claims in earlier revisions of this note are not validation evidence for the new semantics.

## Validation Criteria

- Trusted reviewer launch succeeds with unchanged, moved, newly added, and growing tracked exact secrets when the egress boundary itself is valid.
- PR/master admission passes unchanged counts, reductions, and cross-path/surface/offset moves.
- PR/master admission blocks first appearance and global growth.
- Former legacy values receive the same baseline without explicit exemption selection.
- The counter creates one legacy-preferred descriptor for the same raw bytes rediscovered across scanner rules, while authoring acceptance remains declared-rule-specific.
- Catalog-only clean, mixed, and all-growth evidence can use integrity-bound complementary 64 KiB shards; the complete bounded violation list remains blocked even when optional secondary rows or addition locations must be omitted, and the complete preflight stays within 128 KiB.
- Authoring-catalog safe fixtures retain exact declared-rule acceptance.
- Base64 and other encoded variants are neither derived nor scanned as aliases.
- Non-exact dynamic expressions are excluded from the counter.
- Base-only unextractable shapes may be deleted, while head-side or otherwise genuinely incomplete scans report `inconclusive`.
- Violation diagnostics include only newly added `path:line` locations.
- Ambiguous move-plus-copy or cross-surface endpoint mappings never overstate addition locations; they retain the proved global violation while reporting location evidence as `inconclusive`.
- Single/double/triple review counting remains Codex / Codex+Claude / Codex+Claude+GitHub Codex, each local named lane using its own clean Git worktree without an injected full diff.
- The low-level supplied-diff helper is never counted as a named lane, and PR readiness has no additional offline/independent Codex double gate.
- PR/master/merge-ready requires low-level `stateful final` followed by same-state, current-head `stateful admission`; only receipt-bound admission exit `0` is permitting.
- Admission exits `1`, `3`, and `75` remain distinct violations, pending, and inconclusive outcomes; a held runner lock always wins as pending even after receipt publication, reviewer final success is independent, foreground output is insufficient, and a head change invalidates both checks.
- A schema-v5 runner-sealed receipt binds admission to the exact bounded `preflight.json` bytes; replacement, mutation, terminal non-sealing, malformed receipt, and schema-v4 admission all fail closed, while schema-v4 `status` / `wait` / `final` / cleanup remain compatible.
- Receipt-only corruption, including excessive nesting, maps to structured inconclusive admission without masking a valid reviewer final or cleanup; non-receipt marker corruption stays a hard lifecycle error.
- Terminal child argv binds the reviewer and egress consent independently of path-loaded state, and the documented same-euid host-TCB limitation remains explicit.
- Frozen workspace/control creation and runner-lock cleanup fail closed under permissive umasks, symlinks/FIFOs, path swaps, and identity/mode/link-count/owner mismatches.
- Frozen head paths that exceed the cleanup recursion capacity are rejected before materialization, including the additional directory level created for gitlinks.
- Non-UTF-8 Git path bytes remain reversible in bounded violation evidence and still participate in raw-value leak checks; invalid non-filesystem surrogate strings fail as typed review errors.
- Reviewer cwd, frozen prompt, Linux sandbox workspace mount, attempt output, and terminal verdict/control artifacts remain bound to the prepared container across pathname swaps; descriptor handoff and close failures surface before a result is accepted.
- The bound attempts-directory creator forces `0700` before reopening, and bound runtime/control/attempt and credential-update file creators plus runner stdout/stderr force exact owner-only mode before publication or child spawn even when the caller umask masks owner bits, while unsafe existing locks are rejected without chmod repair.
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
- [x] Separate current-head reviewer final evidence from the explicit stateful secret-admission decision, bind admission to a schema-v5 runner-sealed preflight receipt, bind reviewer/egress policy to trusted child argv, and document compatibility plus host-TCB limits.
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
- Python 3.13 final pre-commit discovery after integrating master `3134c1c`: `1359 tests` in 409.464 seconds, `OK (skipped=5)`, in the narrow environment that permits the loopback-bind lifecycle test.
- Python 3.13 post-review location-evidence discovery: `1361 tests` in 337.678 seconds, `OK (skipped=5)`, in the loopback-capable environment. Move-plus-copy and cross-surface cancellation retain the authoritative global violation while omitting ambiguous locations, and the summary validator rejects any reported occurrence total above `delta` or an incomplete `location_status=complete` claim.
- Python 3.13 post-review lifecycle discovery: `1362 tests` in 531.863 seconds, `OK (skipped=5)`, in the loopback-capable environment. A sealed clean receipt remains pending while the runner lock is held and becomes clean only after release; first launch under `umask 0777` creates an accessible exact-`0700` attempts directory and exact-`0600` attempt log.
- Final focused Python 3.13 suites: state `163 tests` in 174.817 seconds; workspace `145 tests` in 139.507 seconds with one platform skip; contracts `41 tests`; all passed.
- Ubuntu CI exposed an inode-reuse race in one runner-lock replacement fixture; retaining the original inode via rename makes the replacement identity deterministic without changing production behavior.
- Final-review boundary regressions: deepest cleanable blob path passed and cleaned completely, the next depth and equivalent gitlink depth failed before materialization without residue, reversible non-UTF-8 evidence serialization passed, and the APFS-incompatible raw-filename end-to-end case skipped explicitly on macOS.
- Final-review P2 regressions: receipt-only missing/malformed/duplicate evidence maps to structured inconclusive admission while real `final` and cleanup remain usable; atomic runtime, control, attempt-log, compatibility-lock, and credential-update writers force `0600` under a local restrictive-umask boundary without repairing unsafe existing files.
- Final receipt-parser and complementary-manifest-sharding audits found no bypass after exact-`null`, duplicate-order, mixed clean/growth, and exact shard-commitment regressions were added; follow-up result `No findings.`.
- The next whole-range review found a provisional-receipt admission race and an owner-masking attempts-directory launch failure; both were fixed with runner-lock-first pending semantics and create-only `0700` normalization before descriptor reopening, with focused and full-suite regressions passing.
- Official skill validator: `Skill is valid!`.
- Project journal validator: `Project journal validation passed.`.
- The final immutable whole-range review result is recorded in PR #60 after the signed implementation anchor exists; it is not pre-claimed by this commit.
