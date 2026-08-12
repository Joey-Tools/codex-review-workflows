# PR Readiness

This reference owns authorization, gate ordering, CI and conversation checks, fix-loop behavior, and readiness outcomes. It links rather than restates GitHub evidence schemas. Load [github-codex-evidence-authority.md](github-codex-evidence-authority.md) for provider evidence and [github-pr-probes.md](github-pr-probes.md) for endpoint capture.

## Authorization

A bare named-review request is report-only and authorizes no mutation except the bare-triple request-comment flow: on an eligible existing PR it may post the scoped `@codex review` comment and only those serial attempts permitted by the canonical epoch machine. It still does not authorize branch creation, commits, push, PR creation, PR metadata mutation, an anchor commit, fixes, delivery, or merge. A separate delivery request may authorize the ordinary branch/PR actions it names. Merge requires explicit authorization unless the governing request already grants it.

Use:

- `blocked-input` for a missing or ambiguous range, PR selector, lifecycle, or scope;
- `blocked-authorization` when the intended operation needs an ungranted mutation;
- `blocked-safety` when the trusted runtime or isolation boundary cannot be established;
- `blocked-authentication` when an authorized processor cannot authenticate through its supported interface.

Never manufacture an empty or anchor commit to make a lane eligible.

## Gate Order

Preserve this order:

1. Preserve the caller's explicit committed `base_sha..head_sha`, if any.
2. Select an explicitly named PR or exactly one authenticated open-PR candidate for PR-specific work. Explicit-range-only single or double review bypasses all selected-PR gates.
3. Classify selected-PR lifecycle first. Require exact `state == "open"`, `merged == false`, and `merged_at == null`. Closed-unmerged and merged are terminal short-circuits; missing or contradictory evidence is `pr-lifecycle-unverified`.
4. Only after lifecycle passes, read base ref name/tip and head, prove locally complete endpoints, derive exactly one merge base, and compare PR scope with the preserved range. `base_ref_oid` and `pr_merge_base` are separate authorities that may be equal or different.
5. Apply the canonical base-only-retarget machine before generic scope mismatch. A same-head retarget remains blocked when prior provider evidence binds only head and cannot prove coverage of the new merge base.
6. Freeze the range, materialize and validate independent local-lane workspaces, and run the requested named shape. Repair actionable findings on a new head only when a separate delivery or fix request authorizes that mutation.
7. For an eligible triple, reconcile complete provider evidence before any POST, then post only the scoped `@codex review` request comment and machine-authorized serial attempts; reconcile again and dynamically validate the hosted reusable-workflow producer before populating the six independent GitHub report planes. For a bare triple, this request-comment flow is its only mutation authority.
8. Require canonical current-head Action-status `PASS`, then run local delivery gates, exact-secret admission, all other current-head CI, unresolved-conversation checks, branch/base protection, and final lifecycle/scope/head revalidation.
9. Report merge-ready only when every required gate is independently current-head clean and the intended mutation remains authorized.

Revalidate lifecycle before POST, before accepting provider evidence, before readiness, and immediately before merge. Once a mandated post-start observation is non-open, later reopen cannot repair that epoch.

## Effective Review Shape

- Single requires exactly one accepted fresh-context Codex lane.
- Double requires that Codex lane plus one accepted actual-Claude lane on the same frozen range.
- Triple requires double plus the eligible GitHub Codex lane on the selected PR.

No PR or a directly unsupported GitHub host/identity may reduce requested triple to effective double only when the local range is independently valid. Once exact provider activity has started, malformed, stale, ambiguous, or incomplete GitHub evidence is `triple-inconclusive`, not a silent double fallback. Helper and Copilot runs never count.

## Exact-Secret Admission

Exact-secret admission is independent of named review and never suppresses a trusted reviewer launch. The parent Skill's [canonical admission section](../SKILL.md#prmaster-secret-admission) owns extraction, schema, budget, and evidence details. For readiness, count each exact raw secret byte value globally across the complete base and head tracked trees and require `head_count <= base_count`; do not derive Base64, hex, URL-encoded, or other encodings. A proved violation reports only head-side added locations.

Run `isolated_review secret-admission --repo <repo> --base-ref <base_sha> --head-ref <head_sha>` directly. It uses `review_contract: admission-only-no-reviewer` and starts no reviewer, review workspace, diff, prompt, or provider. Only exit `0` with `temporary_cleanup_status: complete` admits the range; exit `1` proves a violation and remains `1` even if later location mapping or cleanup is incomplete; exit `75` means the scan is inconclusive or a clean scan's temporary cleanup failed. A separately requested low-level helper's `stateful final` or `stateful admission` result is compatibility-only: do not start that reviewer for admission or substitute it for this direct gate.

## Required Action Status, CI, And Conversation

Consumer setup is one-time: preserve the repository's existing event triggers, permissions, and concurrency, and make the per-PR caller workflow's only job use exact `JoeyTeng/codex-review-gate-action/.github/workflows/codex-review-gate.yml@v1`. The reusable workflow's called path is the same `.github/workflows/codex-review-gate.yml`. Do not add a compatibility job to this caller or pin a patch-release SHA/blob in the Skill; compatible v1.x producer changes ship through the Action source and its signed immutable release provenance. For initial activation, first merge only the producer source/packages change without switching any root caller/template, publish the immutable release, move `v1`, and pass the live canary; merge the separate consumer/Skill activation PR only afterward.

Keep scheduled reconciliation outside that sole-job producer caller. A separate repository-owned dispatcher may boundedly select PR targets and transport targeted runs into the caller, but it is not producer evidence, Action-status `PASS`, or an alternate producer caller. Repository-specific trigger, cadence, and permission choices do not enter the generic readiness protocol.

Floating `@v1` is the accepted pre-execution trust boundary: GitHub resolves and executes it before this Skill can evaluate the result. Post-run validation can withhold Action-status `PASS`, but cannot undo code already executed with the caller's permissions. Keep caller-workflow SHA, run/event head, PR/status head, exact-attempt workflow value `W`, each candidate's release-`R`/historical-`T`/commit-`C`, and the separate current alias `T_current/C_current` as distinct roles. For every candidate required status, validate producer receipt v1; keep its caller `environment` identity separate from the receipt's called-job repository/path/ref identity, and structurally cross-bind that called identity with the unique exact-attempt `referenced_workflows` repository/path/ref fields and the canonical caller. Require exact `job.workflow_sha == action.ref == referenced_workflows[].sha == W`, exact referenced ref `refs/tags/v1`, and fail closed on a missing or null ref.

For each release candidate, independently fetch and locally OpenPGP-verify its provenance-bound immutable release tag object `R`, derived `v1.minor` tag object, and historical provenance-`v1` tag object `T`; require all three to directly target that candidate's `C`. Its closed `workflow_sha_resolution` compares `W` with only `T` and exact `C`: zero matches is `proved-incompatible` only when every other proof is complete, valid, and unambiguous; one is eligible; more than one is malformed `ERROR`. Independently authenticate and final-stably reread the current floating alias as signed `T_current -> C_current`; it never validates a historical candidate or replaces `W`. If `W == T_current`, additionally require `C_current == C`; otherwise a valid later alias move may differ. Fetch the reusable workflow and released Action tree/critical-file bytes at candidate `C`.

Select the admitted release only from GitHub Releases after exactly one valid candidate has all three independent tag proofs and exactly one valid provenance-v2 asset whose GitHub digest binds its bytes. `v1.5.0` is never admitted and has no erratum path; `v1.5.1` is the first admitted release. Provenance `source.commit_oid` remains the distinct source-repository commit; prove source-to-Action subtree equality separately rather than equating it to `C`. Require producer protocol major 1, decision schema 1, decision policy major 1, and provenance schema version 2; retain exact SemVer `policy_version` as audit evidence, require major 1, and require type-sensitive equality only across provenance `compatibility.decision_table.policy_version`, provenance `critical_files.decision_table.policy_version`, and `policy_version` parsed from the authenticated released decision-table raw bytes. Receipt v1 remains a separate closed shape and supplies no `policy_version`. Never supply `W`, candidate `R/T/C`, current `T_current/C_current`, a release, or workflow bytes from a Skill pin. This is authenticated run-level consistency plus signed release admission, not cryptographic job provenance. The contract defines no online or retroactive post-publication revocation guarantee.

Derive and final-stably rederive the complete ordered release-candidate vector as `valid`, `proved-incompatible`, or `malformed-or-incomplete-error`. A complete, well-typed, authenticated, internally unambiguous candidate with a valid OpenPGP signature from one unambiguous nontrusted primary signer or zero `W` matches is `proved-incompatible`. Missing, invalid, ambiguous, or unverifiable tag/signature evidence, multiple `W` matches, and every integrity or cross-binding contradiction are errors. Any such candidate makes the whole admission `ERROR`; otherwise exclude only proved-incompatible candidates and require exactly one valid candidate. The source-to-Action subtree equality above is independently authenticated admission proof rather than audit-only evidence. The consumer pins neither selected called-workflow bytes/digest nor the selected release's complete external Action SHA set.

`PASS` in this reference means exactly one thing: the sealed canonical reduction selects the exact current-head required Commit Status context `codex/review-gate == success` after the same coordinate binds the accepted producer, final provider validation, and epoch/marker clocks. Do not infer that binding from context, head, state, description, creator, or apparent workflow identity. A noncanonical repository-side compatibility publisher is deliberately non-authoritative and cannot satisfy `PASS`, even when it publishes the same context and `success` on the same head.

Action-status `PASS` is a required-check result, not a provider artifact, named-triple completion claim, or merge-ready result. It remains necessary but insufficient: every other required CI context and each independent authorization, local-validation, exact-secret, conversation, lifecycle, scope, base/head, and branch-protection gate must also pass on the same current head.

Consume only the one parent-owned sealed composite reduction coordinate that binds required-status membership, final provider validation, the immutable epoch-origin clock, and current marker/attempt state; the six report planes are independent outputs, not separate reducer inputs. At or after the overall deadline, apply the canonical ordered reduction before this projection: any still-budgeted or other incomplete acquisition becomes overall-timeout `FAILURE` before the narrow late-`PASS` arm, and only with no incomplete acquisition may an actual complete, final-stable, exact-current-head late clean plus canonical Action `success` become `PASS`.

Project that sealed result with this closed readiness mapping:

| Canonical result | Required `codex/review-gate` Commit Status |
| --- | --- |
| Carrier-valid, final-stable current-head clean with no applicable open finding or incomplete acquisition, plus canonical Action `success` | `success` (`PASS`) |
| Proved blocking current-head/ancestor finding or unresolved applicable thread | `failure` |
| Carrier-valid ancestor-bound clean without an accepted current-head clean, valid progress, boundedly recoverable unknown ancestry, or transient incomplete acquisition while its existing budget remains | `pending` |
| Deterministic malformed evidence, or an unknown/transient condition after its bounded budget is exhausted | `error` |
| At or after overall max-wait, any still-budgeted unknown/transient/resource/other incomplete acquisition or remaining nonterminal wait | `failure` |

Proved nonancestor evidence is audit-only and is removed before this reduction; it does not create progress, reset a deadline, trigger a retry, or publish its own status. Deterministic malformed evidence likewise does not authorize a new `@codex review`. Preserve the fixed Action clocks: 300 seconds for ACK, exponential ACK retry capped at 1,800 seconds, 3,600 seconds for the result measured from marker creation, and 7,200 seconds overall. `eyes` may only move an admitted attempt from waiting-for-ACK to waiting-for-result and never resets a deadline; `+1` supplies neither `PASS` nor ACK. Exhausted ancestry/acquisition authority maps to `error`, while still-budgeted incomplete acquisition at overall max-wait maps to `failure` before late `PASS`.

Before provider or required-Action evidence acquisition, type-sensitively load the epoch machine's exact configuration and require every `resource_budget` to equal it. One parent-owned composed-operation ledger covers the complete evidence graph: counters, retained UTF-8 bytes, and deadline remain cumulative, while the body ceiling alone is per body. No initial/final capture, candidate/sibling evaluation, caller, release, or test input may reset, split, refund, borrow, override, or reseal the ledger; exhaustion follows the owning plane's canonical reducer and supplies no partial authority.

Read current-head required checks from authenticated PR and branch/ruleset state. Record every required context, its conclusion, and the head SHA it covers. A green check on an older head, a skipped required job, or an incomplete status inventory is not ready.

Read all review conversations and thread resolution state with complete pagination. Unresolved actionable human or provider findings block. Current-head and proved-ancestor provider findings remain applicable; proved nonancestor evidence is excluded from the current-head reduction, while unknown ancestry stays pending during bounded acquisition and becomes an explicit error after exhaustion. Only authoritative thread resolution closes a joined thread finding. A later carrier-valid, stable current-head clean may supersede an older same-head or ancestor threadless finding, but never an unresolved thread, nonancestor exclusion, or unknown ancestry.

Repository compatibility statuses that start no reviewer remain CI-only audit records. They never supply Action-status `PASS`, a named review lane, or provider disposition.

## Fix Loop

When a reviewer, provider, CI job, or conversation produces an actionable finding:

1. bind it to the exact head and evidence source;
2. implement only the scoped repair;
3. run focused validation;
4. freeze the new head;
5. return to discovery or the invalidated review/readiness gate.

A tracked head change invalidates all head-bound lane, secret-admission, CI, and readiness evidence. A same-head transport or evidence-retrieval failure reruns only the affected gate. Do not use repeated reviewer launches to substitute for fixing a finding.

Stop after bounded retries when authentication, permissions, required infrastructure, or external state prevents progress. Report the exact blocker and any retained recovery state instead of looping indefinitely.

## Readiness Outcomes

Use precise outcomes:

- `merge-ready`: required lanes, canonical current-head Action-status `PASS`, local gates, exact-secret admission, all other CI, conversation, branch/base, lifecycle, scope, and authorization are all current and clean.
- `blocked-input`: required authoritative input is missing, ambiguous, or inconsistent.
- `blocked-authorization`: a required mutation is not authorized.
- `blocked-safety` or `blocked-authentication`: the named local lane cannot satisfy its trust or auth contract.
- `triple-inconclusive`: GitHub activity started but current-epoch evidence cannot be accepted.
- `selected-pr-closed`, `already-merged`, or `selected-pr-merged`: lifecycle short-circuit.
- `effective-double`: GitHub is provably unavailable before start while the two local lanes remain fully scoped.

## Merge-Ready Report

Report:

- repository, PR URL, base branch, branch, exact `base_sha..head_sha`, and PR merge base;
- requested and effective review shape;
- each local named lane's terminal status and evidence;
- the six independent GitHub planes `request_policy`, `provider`, `required_action_status`, `named_github_lane`, `reaction_audit`, and `readiness`; nest `evidence_basis` only inside `provider`, and add neither a seventh top-level plane nor a collapsed GitHub-lane summary;
- tests, lint/static gates, exact-secret admission, canonical Action-status evidence including the caller `@v1`, per-candidate `W/(T|C)` resolution, independently verified release-`R`/derived-`v1.minor`/historical-`T` proofs, separate current `T_current/C_current` live-alias proof, provenance-v2 asset, receipt/protocol/schema/policy majors, and trusted signer evidence, all other CI, and conversation status actually observed;
- lifecycle and scope revalidation points;
- authorization evidence consumed by the `readiness` plane;
- remaining risks, exclusions, and any retained artifacts.

Do not claim an unrun gate. Do not merge unless authorized.
