# GitHub Codex Provider-Evidence Authority

## Status And Scope

This reference defines the normative evidence-consumption contract for the
GitHub Codex lane. It separates request-orchestration policy from provider
review results, defines how duplicate requests are reported, and defines the
limited dynamic profile under which a `+1` reaction may act as weak clean
evidence.

This is a policy contract. It does not introduce a GitHub client, a runtime
evaluator, or a new provider API.

## Fixed Authority Baseline

The decision is grounded in these immutable upstream snapshots:

- Source `master`:
  [`JoeyTeng/codex-review-gate@16366aa81270ad2c875d2ceb8ce194f5b2308af6`](https://github.com/JoeyTeng/codex-review-gate/commit/16366aa81270ad2c875d2ceb8ce194f5b2308af6)
- Released action:
  [`JoeyTeng/codex-review-gate-action@2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6`](https://github.com/JoeyTeng/codex-review-gate-action/commit/2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6)

At those commits, the complete 15-file release tree has the same relative
paths and Git blob identities as the source repository's complete
`packages/action/` tree. This includes `action.yml`, `package.json`,
`src/gate.mjs`, its runtime imports `src/core.mjs` and
`src/evidence-budget.mjs`, and all ten shipped documentation, license, support,
and security files. The source decision is therefore checked against the
published Action's complete release tree rather than against an unreleased
design or a partial runtime comparison.

The inherited authority rule is:

- Reconstruct a complete current evidence snapshot.
- Treat controlled requests, sticky state, deadlines, status history, and
  retry markers as orchestration or audit records.
- Let the latest trustworthy terminal artifact determine the provider result.
- Fail closed when identity, schema, pagination, ordering, scope, or final
  stability is incomplete.

### Why Result-Present Acceptance Is Deliberate

“Result-present acceptance” means that a complete, trustworthy current-scope
provider result can establish the outcome without proving which request or run
caused it. This is deliberate for three reasons:

1. A provider-authored terminal payload carries the actual finding/no-findings
   decision and commit scope; a request comment carries only intent to start.
2. GitHub review and issue-comment APIs do not expose a general request/run
   lineage. Requiring one would turn valid results into permanent
   `triple-inconclusive` solely because transport metadata is unavailable.
3. Duplicate or mistimed requests are still actionable orchestration defects,
   but they do not contradict what the provider reported. Keeping them in
   `request_policy` preserves the warning without corrupting the result plane.

The fixed source baseline locks this choice in
`test/gate-runner.test.mjs`. Its named regressions include
`valid current-head clean passes without creating a review marker`,
`current-head clean passes regardless of marker timing or deadline` (including
`clean predates active marker`), and
`marker and audit history cannot reject stable current-head clean` (including
conflicting trusted markers). Because the released Action files are blob-aligned
with that source snapshot, these tests are the comparison baseline for future
playbook changes.

Result-present acceptance is not optimistic acceptance. A newer finding or
malformed terminal artifact, unresolved thread, incomplete page, conflicting
same-time channel evidence, stale scope, or unstable final re-read still blocks.

## Decision

### Requests And Results Are Separate Planes

The request plane controls whether the orchestrator should create another
`@codex review` comment. The result plane determines what GitHub Codex
actually reported.

| Plane | Inputs | Authority |
| --- | --- | --- |
| Request policy | Exact request comments, their server IDs and times, local-lane ordering, and complete request enumeration | Warn, wait, or forbid another request |
| Provider result | Exact-bot terminal issue comments or pull-request reviews, associated inline comments, review-thread resolution, reactions allowed by the selected profile, and current scope | Determine `clean`, `findings`, `pending`, or `inconclusive` |

A request is never itself a review result. Conversely, a producer-side request
policy violation does not erase otherwise complete provider-authored result
evidence. Result consumption does not require request/run attribution when the
complete snapshot, provider identity, terminal grammar, evidence ordering, and
current scope independently establish the result.

The orchestrator must still avoid creating duplicates. Before posting, it
fully enumerates accepted requests for the exact current scope. If an accepted
request already exists, it does not post another one. This producer rule and
the consumer result rule are intentionally distinct.

### Request-Policy Report

Report request policy as a record, not as the provider verdict:

```yaml
request_policy:
  status: compliant | warning | unknown | not-applicable
  warnings:
    - early-request-observed
    - duplicate-observed
```

- `early-request-observed` means a request existed before both required local
  lanes had parent-recorded terminal artifacts.
- `duplicate-observed` means more than one accepted request exists for the
  same immutable whole-PR scope.
- A lone request that was posted under producer policy and is still pending is
  `compliant`, not a warning. If a second same-scope request is pending or
  overlaps another request, record `duplicate-observed`.
- Both codes may appear together.
- `duplicate-observed is warning-only`; it is outcome-neutral after the
  evidence snapshot is otherwise complete.
- `unknown` means request enumeration or identity is incomplete. It forbids a
  new request but does not independently invalidate complete provider-result
  evidence. If the same read failure also makes a required provider-evidence
  page incomplete, that separate provider gate blocks completion.
- `not-applicable` is used only when no eligible request plane exists, such as
  a proved no-PR or unsupported-host/identity path.

Warnings remain visible in the final report even when the provider result is
clean. Never silently normalise duplicate history into `compliant`, and never
post a third request to repair it.

## Terminal Artifact Precedence

Evaluate provider artifacts independently of request count:

1. Re-read exact PR lifecycle, `baseRefOid`, `headRefOid`, and the unique local
   merge base. Require the selected whole-PR range to remain exact.
2. Fully paginate issue comments, reviews, every associated inline review
   comment, reactions needed by the active profile, and review threads.
   Aggregate issue-comment reaction counts do not identify the actor and
   cannot authorize `+1`; consume the fully paginated individual reaction
   records with their IDs, actors, content, and server times.
3. Admit only exact provider identity. Terminal comment/review evidence
   requires REST `user.login == "chatgpt-codex-connector[bot]"` and
   `user.type == "Bot"`. A lookalike, missing field, or differently cased
   identity is inconclusive.
4. Parse terminal-looking issue comments and reviews with a closed grammar and
   an exact commit binding. A terminal-looking malformed artifact is evidence
   conflict, not ignorable prose.
5. Order trustworthy terminal artifacts by trusted semantic server time. For
   a review, use `submitted_at`. For an issue comment whose body has never
   changed, use `created_at`; when `updated_at != created_at`, use
   `updated_at` because that is when the currently observed body became
   authoritative. A missing or contradictory edit time is inconclusive.
   Reactions use `created_at`. Within one source channel, use the stable
   numeric artifact ID as the deterministic tie-breaker. At one equal server
   time, a trustworthy finding takes precedence over clean. Other incompatible
   issue-comment/review cross-channel artifacts are ambiguous unless another
   provider-stable ordering signal resolves them.
6. Select the latest trustworthy terminal artifact. A newer malformed or
   scope-conflicting terminal-looking artifact blocks an older clean result.
   A newer finding blocks an older clean result. A latest explicit clean
   artifact may yield `clean` only after the finding and final-stability gates
   below.
7. If no trustworthy current-scope terminal payload exists, apply the selected
   provider profile. Only `thumbs-up-clean` can reach the weak `+1` fallback;
   `mixed` still requires terminal payload for a clean result.
8. Perform the final re-read. The result counts only if scope, lifecycle,
   request history, profile inputs, provider evidence, and thread state are
   unchanged.

An exact-App check or check run is service-start evidence only. It is not a
terminal provider artifact and never proves clean, even when its conclusion is
`success`.

### Duplicate Scenarios

`R1` and `R2` are accepted requests for the same immutable scope. `clean1` and
`clean2` are trustworthy terminal clean artifacts ordered by trusted provider
time.

| Scenario | Outcome | Evidence decision |
| --- | --- | --- |
| `R1-clean1-R2-pending` | `clean` | `clean1` remains the latest terminal result; report `duplicate-observed` and do not post another request. |
| `R1-clean1-R2-clean2` | `clean` | `clean2` is authoritative; report `duplicate-observed`. |
| `R1-R2-clean1-clean2` | `clean` | `clean2` is authoritative even though the requests overlap and the artifacts expose no request/run mapping; report `duplicate-observed`. |
| `R1-findings1-R2-clean2` | `clean` or blocked by thread state | `clean2` may supersede a top-level finding under the rule below, but it cannot supersede an unresolved review thread. |
| `R1-clean1-R2-findings2` | `findings` | `findings2` is authoritative. |

The scenarios above do not authorise the orchestrator to create `R2`; they
define how to consume provider evidence after a duplicate already exists.

## Finding Authority

### Thread-Backed Findings

An inline finding backed by a GitHub review thread uses the thread's
`isResolved` value. `isOutdated` is not a substitute. Enumeration must join the
fully paginated REST review comment to its parent review and to the fully
paginated GraphQL thread without an orphan or conflicting identity.

An unresolved thread finding is not superseded. A later clean terminal
artifact can establish the provider's latest terminal outcome, but the lane
and PR readiness cannot claim completed-clean while any applicable
thread-backed finding remains unresolved.

### Top-Level Findings

A top-level issue-comment finding has no GitHub resolution bit. It remains
active until trusted provider ordering and commit ancestry show that a later
clean artifact supersedes it.

A top-level finding may be superseded by a later clean artifact on the same or
successor head. “Successor” requires proved commit ancestry; timestamp order
alone is insufficient. A prior-head clean is stale evidence for a newer head
and does not complete the current whole-PR lane.

Associated inline comments are part of a pull-request review's terminal
payload. A clean-looking review body with an associated inline finding is a
finding result, and incomplete associated-comment pagination is inconclusive.

## Dynamic Provider Profiles

`provider_profile` is recomputed from the final complete snapshot and bounded
same-repository history. It is not a sticky provider preference and is not
inferred from one convenient reaction.

| Profile | Meaning |
| --- | --- |
| `terminal-payload` | Default. Clean requires an explicit closed-grammar issue comment or review with exact commit binding. Reactions are not clean evidence. |
| `mixed` | The provider has eligible terminal-payload and reaction-only behaviour. Terminal payload remains the only clean authority; reaction-only evidence cannot independently pass, even when no current-scope payload exists or the reaction is newer. |
| `thumbs-up-clean` | The provider has explicitly defined `+1` as completed-clean and the bounded eligible history proves consistent reaction-only operation with no clean payload. |
| `unknown` | The available evidence cannot establish either terminal-payload or eligible reaction-only semantics. A reaction-only outcome remains pending or inconclusive. |

For dynamic history, first collapse evidence to at most one final eligible
outcome per distinct immutable scope key: repository identity, PR number,
frozen whole-PR `base_sha` equal to `pr_merge_base`, and head OID. Never use
the moving `baseRefOid` as this key: base-branch advancement that leaves
`pr_merge_base` and head unchanged is still one outcome. Apply the
terminal-precedence rules inside that scope before it enters the sample.
Duplicate requests, duplicate reactions, and multiple artifacts for one scope
never increase the sample size.

Enumerate every distinct eligible same-repository outcome from the last 30
days and sort it newest first by trusted semantic server time, then stable
artifact ID. Select exactly the first 10 when 10 or more exist; otherwise
select the complete eligible set. Never cherry-pick a favourable subset. An
eligible outcome has exact provider identity, complete pagination, stable
recorded scope, and a determinable evidence basis.

The three-outcome minimum applies only to selecting reaction-only
`thumbs-up-clean`. It never downgrades observed terminal-payload behaviour:
terminal-payload behaviour alone selects `terminal-payload`, and eligible
terminal-payload plus reaction-only behaviour selects `mixed`, even when
fewer than three total scopes are available. When no terminal-payload
behaviour exists, fewer than 3 distinct reaction-only outcomes yields
`unknown`. `thumbs-up-clean` requires 3 to 10 distinct selected outcomes,
every one reaction-only and none containing a clean terminal payload.
Provider-explicit `+1` semantics must be recorded from an authoritative
provider statement; repeated observation alone is insufficient.

Any terminal payload admitted in a `mixed` snapshot remains subject to the
terminal precedence rules. `+1` cannot independently establish clean in this
profile and cannot override a trustworthy current-scope payload. `mixed` never
accepts reaction-only clean evidence. No profile lets a reaction hide a
finding or a malformed terminal-looking artifact. Classification is
deterministic: terminal-payload behaviour only selects `terminal-payload`;
eligible terminal-payload plus reaction-only behaviour selects `mixed`;
reaction-only behaviour selects `thumbs-up-clean` only when every activation
condition holds; every other case selects `unknown`. A current trustworthy
terminal payload plus selected reaction-only history is therefore `mixed`,
never an implementation choice between profiles.

### +1 Fallback

+1 fallback requires all of the following:

1. `provider_profile is thumbs-up-clean`; `mixed` cannot use this fallback.
2. The parent record captures the provider's explicit semantics that an exact
   `+1` means the review completed cleanly.
3. The bounded 30-day same-repository history contains 3 to 10 eligible
   outcomes and satisfies the profile rule above.
4. The parent recorded the exact accepted request comment for the exact
   current whole-PR scope before consuming any reaction.
5. The reaction has exact provider identity.
6. The `+1` was created after the request according to trusted server times.
7. Complete pagination covers request comments, issue reactions, issue
   comments, reviews, associated inline comments, and review threads.
8. The PR remains open and unmerged, and the final base, head, unique merge
   base, and frozen range prove stable current scope.
9. There is no trustworthy current-scope terminal artifact of any outcome and
   no current-scope terminal-looking malformed artifact. The weaker condition
   “no newer trustworthy terminal artifact” is insufficient: in `mixed`, a
   terminal payload remains authoritative even when the `+1` is later.
10. There is no active top-level finding on the current head or a proved
    ancestor head. Reaction-only clean never supersedes a finding.
11. There is no unresolved thread finding.
12. There is no newer exact-provider `eyes` reaction. `eyes` is liveness-only:
    it can show that work started or restarted, but it never proves clean.
13. The final re-read is unchanged, including the profile sample, exact
    request, reaction identity and time, all evidence pages, thread state,
    lifecycle, and whole-PR scope.

If any condition is absent, `+1` does not complete the lane. Missing or
ambiguous evidence is `pending` while bounded waiting remains meaningful and
otherwise `triple-inconclusive`; it is never upgraded by optimistic inference.
This is the only clean-completion path that deliberately has no terminal
review/comment payload.

## No-Start And Non-Completion States

At the fixed authority baseline, only authenticated structured capability or
installation metadata with a defined schema may prove that the integration or
service is unavailable and reduce requested triple to effective double. The
metadata must identify the selected repository/integration and explicitly
encode the unavailable or not-installed state; absence, timeout, permission
failure, generic transport/HTTP failure, and provider-authored free-form prose
do not satisfy this path.

An authenticated no-start rejection would likewise be availability evidence,
not a clean review result. However, the fixed authority baseline intentionally
defines no accepted provider body grammar for this path: neither fixed upstream
snapshot publishes one. Therefore free-form prose that appears to say
“unavailable” or “did not start” is currently `triple-inconclusive`, even from
the exact bot.

A future policy version may activate this path only by adding an immutable
provider-backed declaration, an exact finite body allowlist or fully anchored
closed grammar, normalization rules, and positive plus near-miss contract
tests. Only then may an exact-bot issue comment reduce requested triple to
effective double, and the comment must also:

- occur after a parent-recorded controlled request for the exact current
  scope;
- unambiguously state that the integration or service is unavailable and
  that no review run started;
- have complete identity, pagination, server-time, lifecycle, and scope
  evidence; and
- not be contradicted by an acknowledgement, `eyes`, exact-App run/check
  start, review activity, terminal review payload, or other start evidence in
  the complete snapshot.

This future path would not require a hidden request/run identifier that GitHub
does not expose. It would require the controlled request and exact current
scope so an unrelated provider comment cannot manufacture unavailability.
Report its actually recomputed `provider_profile` and
`evidence_basis.kind: no-start-rejection`; it never supplies a clean result.
Missing response remains `pending` while bounded waiting is meaningful.
After waiting is exhausted, generic failure, unknown identity, absent grammar,
ambiguous no-start wording, or any contradictory start evidence remains
`triple-inconclusive`.

## Required Report Fields

Every GitHub Codex lane report includes the three independent keys below.
Required keys may be `null` only in the states listed after the example; `null`
is not another provider profile.

```yaml
request_policy:
  status: warning
  warnings:
    - duplicate-observed
provider_profile: mixed
evidence_basis:
  kind: pull-request-review
  source_channel: reviews
  id: "123456789"
  url: https://github.com/OWNER/REPO/pull/123#pullrequestreview-123456789
  server_time: 2026-07-30T00:00:00Z
  server_time_field: submitted_at
  commit: 0123456789abcdef0123456789abcdef01234567
```

| Lane state | `provider_profile` | `evidence_basis` |
| --- | --- | --- |
| Proved pre-provider ineligibility or blocker: no PR, unsupported host/identity, authenticated structured capability/installation metadata proving a missing integration or unavailable service, selected PR closed before start, or scope/lifecycle failure before provider evaluation | `null` | `null`; report the exact effective-double or blocker reason separately |
| Eligible and waiting with no selected provider artifact | Computed profile, or `unknown` when it cannot yet be established | `null` |
| Accepted terminal clean or findings result | `terminal-payload` or `mixed` | Selected issue comment or pull-request review |
| Accepted weak reaction clean | `thumbs-up-clean` | Exact accepted `+1` reaction plus its controlled request and scope |
| Future accepted authenticated no-start rejection after an explicit grammar policy activates it | Actually recomputed profile, normally `terminal-payload` or `mixed` | Exact `no-start-rejection` issue comment plus its controlled request and scope |
| Inconclusive evidence | Computed profile or `unknown` | Stable blocking artifact when one exists; otherwise `null` |

For a pull-request review, `server_time` is the exact REST `submitted_at` and
`server_time_field` is `submitted_at`. For an unedited issue comment, use exact
REST `created_at` and `server_time_field: created_at`; for an edited issue
comment, use exact REST `updated_at` and `server_time_field: updated_at`. A
reaction always uses exact REST `created_at` and
`server_time_field: created_at`. Never rewrite one channel's time into another
channel's field name.

For reaction fallback, `evidence_basis` instead records `kind: reaction`, the
exact reaction ID, URL or API resource, `server_time`,
`server_time_field: created_at`, exact provider identity, content `+1`, and
the bound request ID/time and whole-PR scope. When a terminal artifact is
selected, record it even when its outcome is findings. Do not reduce the basis
to prose such as “Codex completed”.

## Alignment And Intentional Differences From The Fixed Action Baseline

The result-evidence authority is inherited from the fixed Action baseline.
The stricter scope gates and playbook extensions below are deliberate and must
not be “corrected” by copying the Action implementation mechanically:

1. **Whole-PR scope and lifecycle are stricter.** The Action baseline binds a
   clean artifact to the current head and validates a complete evidence
   snapshot. This playbook additionally requires exact selected-PR lifecycle,
   base OID, head OID, one local merge base, and equality with the frozen
   whole-PR range. A base-only retarget on the same head remains
   `base-changed-same-head`.
2. **An empty `APPROVED` review is not clean.** The Action baseline accepts an
   empty or exact `Looks good.` approved-review body under its closed grammar.
   This playbook requires an explicit clean comment/review payload with commit
   binding for `terminal-payload`; an empty state-only approval is
   insufficient.
3. **The `+1` fallback is new playbook policy.** The fixed Action collects
   `plusOne` in its reaction baseline but does not use it as provider-result
   authority; its result selector consumes terminal issue comments and
   reviews. This playbook permits `+1` only under the dynamic-profile and
   thirteen-condition fallback above.
4. **`eyes` remains orchestration-only.** The fixed Action uses a new `eyes`
   transition as acknowledgement/liveness. This playbook preserves that
   boundary and additionally rejects `+1` fallback when a newer `eyes`
   indicates later activity.
5. **Duplicate result consumption aligns with the Action; warning codes are a
   playbook extension.** Stable current-head result evidence is not rejected by
   marker or audit history in the fixed baseline. This playbook inherits that
   consumer rule, while adding `duplicate-observed` and the producer rule that
   the orchestrator must never create another same-scope request.
6. **Early-result consumption aligns with the Action; local-lane sequencing is
   a playbook extension.** The fixed baseline accepts stable clean evidence
   regardless of marker timing. This playbook additionally requires local
   terminal artifacts before it sends a new GitHub request and reports
   `early-request-observed` when that producer order was violated. Do not
   discard a later independently trustworthy provider result solely because of
   that producer-side sequencing defect.

## Non-Goals

- Do not treat checks, status contexts, acknowledgements, progress comments,
  `eyes`, sticky state, deadlines, or request markers as clean results.
- Do not weaken exact bot identity or full pagination to make a profile fit.
- Do not carry a profile across repositories or beyond the bounded 30-day
  evidence window.
- Do not create a duplicate request, empty commit, or synthetic provider
  artifact to escape an inconclusive state.
- Do not claim the policy itself proves provider behaviour; every counted
  outcome still requires the complete evidence and final-stability checks
  above.
