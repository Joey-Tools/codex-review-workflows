# GitHub Codex Evidence Authority

## Scope

This file is the single source of truth for interpreting the GitHub Codex
review lane. It defines provider identity, current-head evidence, finding
precedence, the clean result, and the reaction fallback.

It does not define GitHub Actions, status-check, or ruleset implementation.
Those integrations may publish evidence, but they do not change this consumer
contract. PR lifecycle, base and merge-base validation, CI, all-conversation
resolution, and merge readiness belong to [pr-readiness.md](pr-readiness.md).
Probe and retry mechanics belong to [github-pr-probes.md](github-pr-probes.md).

The GitHub lane proves a result for one exact PR head. It does not prove which
base or merge base the provider inspected. Local readiness owns that proof.

This is an explicit product boundary, not a missing proof obligation for this
lane. A trustworthy latest-head terminal clean result, or another accepted
positive basis below, completes the GitHub lane when no applicable Codex
finding remains unresolved. Do not downgrade that result to `inconclusive`
solely because the provider does not expose its internal input base. The local
Codex lane and PR-readiness gates independently prove the current base,
whole-PR range, CI, conversations, and merge policy before the PR can be ready.

When authenticated selection proves that no supported PR exists, there is no
PR head to freeze and no provider recovery to run. Emit the closed no-PR
`not-applicable` report variant defined below, with null PR and head fields;
never manufacture a selector, head, request, or pending retry state.

## Immutable Scope

Freeze these fields before consuming evidence:

```yaml
repository: owner/name
pull_request: 123
host: github.com
base_sha: 40-lowercase-hex # parent-proved unique merge base for ancestry only
head_sha: 40-lowercase-hex
```

Only exact-host `github.com` is supported by this contract. Read the PR again
immediately before accepting a result and require the same head. A clean result
for an older head is stale. A finding on the current head or a locally proved
ancestor in the current PR range remains applicable until resolved or
superseded under the rules below.

`ancestor_shas` is not provider data. The parent orchestrator owns its closed
local projection and binds it to the exact repository, PR number, locally
proved unique merge base in the frozen scope's `base_sha`, and immutable head.
The projection's `base_sha` and `head_sha` must equal those independent scope
endpoints. The projection records its
owner, `complete | incomplete` status, canonical ancestor count, and SHA-256
digest. The canonical list is the sorted, duplicate-free lowercase full-SHA
set in `base_sha..head_sha`, excluding `head_sha`; its digest covers each ASCII
SHA followed by LF, including the final SHA. Before ancestor membership can
make a finding applicable, the consumer must validate the projection's closed
field set, scope endpoints, count, canonical order, and digest and require
`status: complete`. A valid incomplete projection makes non-head applicability
inconclusive. A mismatched, open, or invalid projection is malformed scope
evidence; raw provider ancestry claims never substitute for this parent proof.

An observed target `baseRefName` change or advance of the target base tip does
not by itself invalidate head-bound provider evidence. If the head and unique
merge base are unchanged, the frozen local range endpoints are unchanged too,
but the new exact target-ref identity or `baseRefOid`
invalidates every prior local PR-wide review, local validation and test result,
CI/status result, conversation/readiness decision, and final reread. Reacquire
all of them before counting readiness again; unchanged range provenance does
not preserve those earlier results. Retain the head-bound provider result only
after a complete final reread confirms its exact head is still current and no
applicable provider finding remains unresolved. Do not claim that a provider
comment, review, reaction, or ordinary check proves the base. The retained
result supplies no base, merge-base, or target-ref coverage.

This observed-change invalidation rule is unchanged by the narrow atomic-window
alternative in [pr-readiness.md](pr-readiness.md): only an unobserved movement
of the same frozen target ref during the direct merge's atomic window may use a
parent-proved monotonic range contraction. Authorized PR-retarget actors belong
to that proof's trusted external control plane, not provider evidence.

After a merge-base change on an unchanged head, the parent may reuse the
head-bound GitHub result after a complete final reread confirms the same head
and no unresolved applicable provider finding. It must rerun every invalidated
local and readiness gate against the new merge base only after the parent-owned
`range_origin` provenance gate in [pr-readiness.md](pr-readiness.md) authorizes
that local PR-wide range. This authority neither selects nor rewrites a local
range: missing or unknown origin may block local readiness while the
trustworthy head-only GitHub result remains reusable. Reconcile any
base-sensitive merge/status check. Do not post another `@codex review` merely
because the base changed, and never describe the reused provider artifact as a
review of the new base.

By contrast, merging the current base branch into the feature branch creates a
new head. Every old-head positive GitHub Codex result is stale; unresolved
findings remain applicable under the rules below. The new head must obtain fresh
provider evidence after its local tests and review lanes are rerun.

## Provider Identity

Terminal comments, reviews, inline findings, and reaction fallback count only
when the raw GitHub REST actor has both exact fields:

```text
user.login == "chatgpt-codex-connector[bot]"
user.type == "Bot"
```

When a non-null App field is used as corroboration, require
`performed_via_github_app.slug == "chatgpt-codex-connector"`. Current-head
check-run service evidence uses exact `app.slug == "chatgpt-codex-connector"`.

Missing fields, different casing, lookalikes, copied provider prose, and human
quotes are not provider evidence. Human and unrelated-bot records stay in the
audit snapshot but cannot create or resolve a GitHub Codex finding.

## Complete Snapshot

Fetch and retain every page needed for the selected PR:

- issue comments;
- pull-request reviews;
- all inline comments associated with every candidate provider review;
- GraphQL review threads and every nested thread-comment page;
- reactions on each candidate exact `@codex review` request; and
- current-head check runs or statuses used as a preferred merge/status basis.

Start each connection at its first page, follow the returned cursor or next
link, and stop only at the provider's typed terminal pagination state. Summary
reaction counts are not actor evidence. Partial pages, broken cursor chains,
ambiguous IDs, or unstable final rereads are inconclusive.

Preserve raw IDs, URLs, actor fields, states, bodies, commit IDs, and server
timestamps. Parse only documented provider carriers with an anchored parser.
Unknown terminal-looking provider prose is malformed evidence, not a clean
result and not silently ignorable.

Before any `pass`, freeze a separate closed parent-owned
`complete_pr_snapshot` from two complete raw observations. Its initial and
final closed selected-PR scopes must be type-preserving equal and bind the
exact report repository, PR, and head. Its initial and final page inventories
must also be type-preserving equal: issue comments, reviews, associated inline
comments, GraphQL review threads, every nested thread-comment page, reactions
on every candidate exact review request, check runs, and
commit statuses each carry an exact `true` completion flag and a typed
non-negative count. The two closed terminal selections must be equal and
bind the unique latest trustworthy terminal result selected under this
authority's precedence. Terminal-clean and merge-status pass require
`classification: clean` plus the complete selected evidence; reaction-clean
requires `classification: absent` plus null evidence. Every pass requires an
exact integer zero unresolved-provider-finding count. The same record also
contains equal initial and final closed pass-basis selections derived from the
complete raw observations: terminal-clean repeats the exact selected terminal
evidence, reaction-clean binds the exact request and provider reaction
kind/command/actor/IDs/URLs/server times, and merge-status binds the exact
check-run ID/URL/name/App/head/status/conclusion/time fields, producer-contract
descriptor, and complete associated provider-clean evidence. The unused union
branches are null.

The snapshot's initial and final lowercase SHA-256 values must be equal digests
of RFC 8785 canonical JSON for the complete raw snapshot: exact scope/head,
raw issue/review/inline/thread, nested thread-comment, and reaction pages,
pagination envelopes and typed counts, derived terminal candidates and
ordering, the selected latest terminal result, selected pass-basis projection,
unresolved applicable findings, and check/status records.
They are not digests of the report summary.
The parent persists this record independently before report validation;
report, association, epoch, or check fields cannot create,
amend, or self-prove it. The consumer requires both basis selections to be
type-preserving equal and to join exactly to the report and its orthogonal
epoch or merge-contract carrier; changing those carriers together while
leaving this frozen selection unchanged fails closed.

## Evidence Strength

Evaluate the following bases in order:

1. A trustworthy repository merge/status check that is demonstrably associated
   with the current head and the GitHub Codex review result.
2. A trustworthy exact-provider terminal clean issue comment or pull-request
   review for the current head.
3. The exact-provider `+1` reaction fallback on the selected current-head
   request.

The first basis is preferred when it exists because repositories commonly
aggregate the review into a merge-oriented check. Association requires both
current-head check-run metadata and an independently parent-verified repository
contract; never guess a workflow, check name, or App identity. The raw check
run must bind its stable ID and exact repository `/runs/<ID>` URL, exact App ID
and slug, `completed` status, `success` conclusion, and full head SHA to that
contract. The same association must name one accepted current-head provider
terminal-clean result. A generic successful check, an App start marker, or a
status from another head does not qualify.

The check association and its separately verified producer contract are
necessary but not sufficient. A merge-status pass also requires the common
`complete_pr_snapshot` above to select that exact associated clean evidence as
the stable latest trustworthy terminal result, and to select the exact check
run and association as its stable merge-status basis, with zero unresolved
applicable findings.

Preference does not silently enlarge what the check proves. Unless its
documented contract explicitly binds the PR base, the related merge/status
check remains head-associated GitHub-lane evidence and the local readiness
plane still owns base assurance.

No positive basis bypasses the complete unresolved-finding scan.

## Closed Consumer Carrier Grammar

[github-codex-terminal-carriers-v1.json](github-codex-terminal-carriers-v1.json)
is the normative version-1 consumer grammar and fixture matrix for provider
terminal comments, pull-request reviews, top-level findings, and joined inline
findings. Consumers must implement that exact version's Unicode and line
normalization, provider identity, terminal-looking and progress detection,
body-effective semantic time, commit binding, closed carrier branches, and
one-to-one thread join. Locally proved ancestor applicability additionally
requires the grammar's closed parent-owned `ancestor_shas_projection`; a raw
SHA list is insufficient. An exact-provider terminal-looking record that does
not match an accepted branch is malformed; it is never generic clean prose.
The same consumer resource's `required_report_schema` and `report_fixtures`
are the executable, closed, basis-discriminated report contract. They reject
cross-variant field combinations rather than relying on YAML examples alone.

The resource is deliberately a consumer contract. It does not define, validate,
or authorize a GitHub Action, status producer, workflow name, check conclusion,
or ruleset. Those producer integrations belong to their separately reviewed
workstream and can supply a preferred basis only through the association rules
above.

## Terminal Results

A terminal provider artifact is a provider-authored issue comment or review
whose carrier is accepted by the normative version-1 grammar and unambiguously
reports either findings or no findings. Every accepted version-1 terminal
branch exposes its artifact commit: a clean issue-comment marker, a finding
URL, a native review `commit_id`, or the joined parent/child commit. Resolve a
known short clean-issue marker through the exact repository API, require a
stable unique current-head match, and otherwise bind the native lowercase full
SHA directly. A hashless issue comment is not a terminal carrier.

`stable-request-epoch` is reserved for the reaction-only fallback below, where
it records the stable current-head request epoch. It does not classify or bind
a terminal payload.

A terminal clean artifact passes only when all of these hold:

- its actor has the exact provider identity;
- its accepted head binding resolves to the exact current head;
- its grammar is a known clean carrier rather than generic praise or review
  state alone;
- every associated inline-comment page and relevant thread page is complete;
- there is no unresolved applicable GitHub Codex finding; and
- scope, lifecycle, raw pages, and selected evidence remain stable on the
  final reread.

A current-head `inline-parent-v1` artifact whose provider-target inline
children are all resolved is a closed non-positive terminal classification,
not a clean artifact. Report it as `pending` with the distinct
`resolved-inline-awaiting-clean` basis. The parent must supply the closed
`resolved_inline_snapshot` input, frozen independently from two complete raw
snapshots before report validation and never derived from report fields:
exact repository, PR,
initial/current/final head and artifact commit; exact artifact ID, URL, review
channel, and branch; a positive provider-target child count; complete child
and GraphQL thread pages; integer zero unresolved provider findings; and equal
initial/final SHA-256 digests of the RFC 8785 canonical closed carrier plus
joined thread snapshot sorted by child ID. A top-level finding, an unresolved
child, a zero-child carrier, an ancestor-head artifact, incomplete pagination,
a malformed join, or an unstable snapshot cannot use this basis.

`resolved-inline-awaiting-clean` never completes the lane and never satisfies
the required latest-current-head terminal-clean conjunction. Because the
terminal artifact also excludes reaction fallback, recovery may reconcile the
same head by idempotently rerunning the repository Action under the retry
policy to obtain a later accepted clean comment or review.

An `APPROVED` review is not clean when an associated provider inline comment
contains a finding. A clean body never overrides an unresolved thread finding.
Parse and join all associated provider children before treating an ancestor
`APPROVED`/`No findings.` parent as stale: a child bound to that locally proved
ancestor is still an applicable inline finding. A top-level finding review must
likewise parse and join every associated provider child; its top-level finding
cannot hide an unresolved inline thread.

A terminal finding blocks immediately only when exact identity, scope, and
carrier are trustworthy and the finding is applicable and unresolved. Missing
positive evidence cannot neutralize such a finding.

## Finding Precedence And Resolution

Classify provider findings independently of human conversation state.

- For an inline finding, only the raw GraphQL thread node's typed `isResolved`
  value resolves that thread. On the same head, typed `isResolved == true`
  removes the finding from `unresolved_provider_findings` after a complete,
  stable reread; it does not require a replacement request or a new head.
  `isOutdated`, a human reply, or a synthesized REST field is not resolution.
- Join an inline REST comment to exactly one GraphQL thread comment by the
  exact child comment ID, URL, and parent review ID. URL plus parent alone is
  not an identity join. Require the URL's frozen repository and PR and its
  `#discussion_r<ID>` suffix to match that exact child ID. An orphan, duplicate
  join, child-ID mismatch, parent mismatch, or incomplete nested page is
  inconclusive or malformed according to the closed grammar.
- A top-level provider finding remains active until a later trustworthy
  provider clean correction on the same head, or a trustworthy clean artifact
  on a locally proved descendant head, supersedes it. A same-head correction
  must have exact provider identity, an accepted terminal-clean carrier and
  current-head binding, later semantic time than the finding, complete pages,
  and a stable final reread; generic correction prose is not enough.
- A later clean never supersedes an unresolved provider thread finding.
- A finding from a non-ancestor old head is audit context, not an applicable
  current-range finding. An inability to prove ancestry is inconclusive.

A resolution-only thread transition or trustworthy same-head correction does
not invalidate otherwise stable current-head tests or local reviews. If
addressing the finding changes repository code, commit that change as a new
head and reacquire every head-bound test, local review, provider result, CI
result, and final reread required by PR readiness. Do not create an empty
commit merely to turn a resolved finding into a fresh review.

When terminal candidates share the latest semantic server time, findings win
over clean or resolved-inline-only within the same GitHub channel. Conflicting
latest candidates from different channels, a latest malformed candidate, or a
contradictory commit binding is inconclusive. Use `submitted_at` for reviews
and the body-effective server time for issue comments (`updated_at` when
edited, otherwise `created_at`). Do not compare IDs across GitHub resource
types.

## Reaction-Only Fallback

Reaction fallback is intentionally small. It requires no historical sampling,
provider declaration digest, or receipt sidecar.

Accept it only when every condition holds:

1. The parent selected the unique latest visible exact `@codex review` request
   for the current head epoch.
2. The PR scope and head were read immediately before and after the request
   and have the same repository, PR, and head when the reaction and final
   snapshot are read.
3. The exact provider actor placed a `+1` reaction on that request after the
   request's server creation time.
4. Request and reaction pagination is complete, and there is no later request,
   conflicting provider reaction, or provider `eyes` at or after the selected
   `+1`.
5. There is no terminal provider artifact, malformed terminal-looking
   provider artifact, or unresolved applicable provider finding.
6. Lifecycle, scope, request, reaction, provider pages, and finding state are
   stable on the final reread.

`eyes` is liveness only. It never proves clean. A terminal artifact takes
precedence over reaction fallback even if the reaction is later.

The report consumer accepts reaction fallback only with a separate closed,
parent-owned `reaction_clean_epoch` input. The parent freezes and persists it
from the raw observations before report validation; the consumer reads it as
an independent trust input and never derives it from report or evidence
fields. Its `pre_request_scope`,
`post_request_scope`, `reaction_read_scope`, and `final_scope` are each closed
selected-PR scope values and must all equal the report scope and exact head.
The epoch also binds the exact request ID/URL/command/server time and reaction
ID/URL/`+1`/provider actor/server time, requires the reaction to be later than
the request, records complete request/reaction/provider/thread pages, and
records the absence of later requests, conflicting reactions, later `eyes`,
terminal artifacts, malformed terminal-looking artifacts, and unresolved
findings. Reusing a head-A request or reaction while reporting head B therefore
fails closed even if the visible IDs and URL are unchanged.

The epoch remains orthogonal to the common `complete_pr_snapshot`: a
reaction-clean pass requires both. The common snapshot must have stable
`classification: absent` / null terminal selection, complete typed page
inventories, a stable exact reaction-clean basis selection, equal canonical
snapshot digests, and integer zero unresolved findings. The basis selection
must repeat the epoch's request and provider-reaction identity/actor/times and
join to the report evidence. An epoch cannot self-prove that final whole-PR
snapshot.

If the POST outcome was ambiguous, first reread the unchanged current head and
its complete visible exact-request set. If delivery still cannot be proved,
the same exact `@codex review` POST may be repeated after backoff as an
idempotent delivery retry under the named lane's authorized ambiguous-delivery
recovery. Before every repetition, the single recovery owner performs that
reread again; never run concurrent POSTs, and stop POSTing as soon as delivery
or another definite outcome is proved. Any visible duplicate remains part of
the same logical review lane, is reported as an audit warning, and never counts
as an additional lane. Prefer the latest visible request for fallback, and
never let duplicate request count erase trustworthy terminal provider
evidence.

## Service And Pending Evidence

An exact-App current-head check/run can prove that the service started. A
successful App check is not by itself a clean review because it may represent
startup or aggregation and can coexist with findings.

Absent evidence, transport failure, a timeout, a cancelled or skipped run,
free-form provider failure prose, or unknown identity is not a pass. Keep the
lane `pending` only while typed GitHub state or a documented repository
contract supplies a machine-decidable retryable pending or infrastructure
reason. A stable malformed snapshot, scope contradiction, unknown
free-form-only failure, or other non-retryable inconclusive state terminates
recovery and is reported immediately as `inconclusive`. Recovery policy is
defined in [github-pr-probes.md](github-pr-probes.md).

## Decision Table

| Complete current-head state | Lane result |
| --- | --- |
| Trusted associated merge/status check is clean and no provider finding is unresolved | `pass` |
| Trusted terminal clean artifact and no provider finding is unresolved | `pass` |
| Valid reaction fallback and no provider finding is unresolved | `pass` |
| Any applicable unresolved provider finding | `findings` |
| Stable current-head inline-only artifact has one or more provider children and all are GraphQL-resolved, but no later terminal clean exists | `pending` with `resolved-inline-awaiting-clean`; reconcile may retry the Action |
| Work is running or failure is retryable | `pending` |
| Pagination, identity, grammar, scope, ordering, or final stability cannot be proved | `inconclusive` |
| Authenticated selection proves no supported PR | `not-applicable` using the closed null-PR/head variant |

Only the first three rows complete the GitHub lane. Other PR conversations and
required checks can still block overall PR readiness.

## Required Report

Record compact, reproducible evidence. The normative executable shape is
`required_report_schema` in the version-1 consumer resource above; the forms
below are its human-readable projection. The PR-bound common envelope is:

```yaml
github_codex_lane:
  status: pass | findings | pending | inconclusive | not-applicable
  repository: owner/name
  pull_request: 123
  head_sha: 40-lowercase-hex
  scope_assurance: latest-head-only
  base_assurance: local-pr-readiness
  basis: merge-status | terminal-clean | resolved-inline-awaiting-clean | reaction-clean | null
  evidence: one-closed-variant-below-or-null
  request_policy:
    status: compliant | warning | unknown | not-applicable
    warnings: []
  unresolved_provider_findings: []
  last_reason: stable-machine-readable-reason
```

When authenticated selection proves no supported PR, use the separate closed
variant rather than inserting invented scope values into the PR-bound
envelope:

```yaml
github_codex_lane:
  status: not-applicable
  repository: owner/name
  pull_request: null
  head_sha: null
  scope_assurance: proved-no-selected-supported-pr
  base_assurance: not-applicable
  basis: null
  evidence: null
  request_policy:
    status: not-applicable
    warnings: []
  unresolved_provider_findings: []
  last_reason: no-selected-supported-pr
```

This no-PR variant is terminal. It never enters retry recovery, and its null
PR/head fields cannot be mixed into a PR-bound `pass`, `findings`, `pending`,
or `inconclusive` report.

`evidence` is a closed, basis-discriminated union; do not merge fields or
alternatives between variants. `basis: terminal-clean` requires this exact
binding shape (with the channel-specific server-time field):

```yaml
evidence:
  kind: terminal-artifact
  id: stable-github-id
  url: https://github.com/...
  channel: issue-comment | review
  grammar: github-codex-terminal-carriers-v1
  grammar_branch: clean-issue-v1 | clean-review-v1
  grammar_status: accepted
  artifact_commit: 40-lowercase-hex
  server_time: RFC3339
  server_time_field: created_at | updated_at | submitted_at
  head_binding: explicit-commit
  request_id: stable-github-id-or-null
```

For `basis: terminal-clean`, `artifact_commit` is required, non-null, and equal
to the envelope `head_sha`; `head_binding` is exactly `explicit-commit`.
`artifact_commit: null` and `head_binding: stable-request-epoch` are
structurally invalid for terminal clean. The clean channel and grammar branch
are a closed pair: `issue-comment` requires `clean-issue-v1`, while `review`
requires `clean-review-v1`; crossing those pairs is malformed evidence.

This evidence object cannot self-prove complete final state: terminal-clean
pass also requires the independent `complete_pr_snapshot` to select this exact
evidence as both its stable latest clean terminal result and its stable
terminal-clean basis selection.

`basis: resolved-inline-awaiting-clean` uses the same closed terminal-artifact
evidence fields, but only with `status: pending`, `channel: review`,
`grammar_branch: inline-parent-v1`, a non-null `artifact_commit` equal to the
report head, and `head_binding: explicit-commit`. It additionally requires the
separate closed parent-owned `resolved_inline_snapshot` described above. Empty
report findings alone are never enough: the snapshot must prove a positive
child count, complete joined pages, typed GraphQL resolution for every
provider child, and stable initial/final canonical snapshot digests. Changing
this report to `status: pass` or `basis: terminal-clean` is structurally
invalid; a later accepted current-head clean artifact is still required.

Reaction fallback uses a separate closed shape:

```yaml
evidence:
  kind: reaction
  id: stable-github-reaction-id
  url: https://github.com/...
  channel: reaction
  grammar: null
  grammar_branch: null
  grammar_status: null
  artifact_commit: null
  server_time: RFC3339
  server_time_field: reaction-time
  head_binding: stable-request-epoch
  request_id: stable-github-request-id
```

`stable-request-epoch` is valid only in that `basis: reaction-clean` reaction
variant, and the evidence is accepted only alongside the closed parent-owned
`reaction_clean_epoch` and common absent-terminal `complete_pr_snapshot`
described above. The snapshot's stable reaction-clean basis selection must
repeat the epoch's exact request and reaction identity, provider actor, and
server times and join exactly to the report evidence. A `basis: merge-status`
report uses
this distinct closed check-run shape; `provider_clean_evidence` is the complete
terminal-clean evidence shape shown above, not an ID-only assertion:

```yaml
evidence:
  kind: merge-status
  id: stable-check-run-id
  url: https://github.com/owner/name/runs/<same-id>
  channel: check-run
  check_name: exact-name-from-verified-contract
  status: completed
  conclusion: success
  artifact_commit: 40-lowercase-hex-equal-to-report-head
  app:
    id: exact-positive-app-id-from-verified-contract
    slug: exact-app-slug-from-verified-contract
  server_time: RFC3339
  server_time_field: completed_at
  head_binding: explicit-commit
  association:
    kind: parent-verified-repository-contract
    owner: parent-orchestrator
    status: complete
    repository: owner/name
    pull_request: 123
    head_sha: 40-lowercase-hex-equal-to-report-head
    check_run_id: stable-check-run-id
    check_run_url: https://github.com/owner/name/runs/<same-id>
    check_name: exact-name-from-verified-contract
    app_id: exact-positive-app-id-from-verified-contract
    app_slug: exact-app-slug-from-verified-contract
    contract:
      source_repository: owner/name
      source_commit: 40-lowercase-hex
      source_path: safe/repository-relative/path
      source_sha256: 64-lowercase-hex
    provider_clean_evidence: exact-terminal-clean-evidence-object
```

Before accepting this shape, the consumer receives a separate closed
parent-owned `merge_status_parent_contract` record; it must not derive that
record from the report being validated. The record carries the four contract
descriptor strings (`source_repository`, `source_commit`, `source_path`, and
`source_sha256`), trusted App ID and slug, exact check name, stable check-run ID
and URL, and stable provider-clean evidence ID and URL. Compare every descriptor
string by exact UTF-8 byte identity with the independently verified record and
compare every remaining field exactly. Coupled edits to the report's contract,
App, check, or stable association identities therefore fail even when the
edited report remains internally self-consistent.

The consumer also receives the independent common `complete_pr_snapshot`.
Its stable latest clean selection must equal `provider_clean_evidence`
type-for-type. Its stable merge-status basis selection must also equal the
outer check's complete identity/App/head/status/conclusion/time projection and
the producer-contract descriptor and associated provider-clean evidence
type-for-type, and must join exactly to the independently supplied parent
contract. Neither the check association nor the parent contract may self-prove
or repair that whole-PR snapshot.

The parent independently verifies the exact contract bytes and digest and
confirms that the contract binds this App identity, check name, check identity,
current-head scope, and provider-clean association. The association fields must
equal the outer raw check-run fields, while the report and association
repository, PR, and head must separately equal the parent's
independently supplied frozen scope inputs. Its accepted clean artifact must
use the closed channel/branch pair above, bind the same head, and have semantic
time no later than `completed_at`.
Thus a successful service-start check cannot become a merge-status pass merely
by copying the App identity or current head.

A findings report backed by an accepted terminal carrier uses
`kind: terminal-artifact`, a non-null full `artifact_commit`,
`head_binding: explicit-commit`, and its finding grammar branch. Pending and
inconclusive PR-bound reports may use `evidence: null` when no stable diagnostic
artifact is selected. The no-PR `not-applicable` variant always uses null
evidence together with its required null PR/head fields.

Use `warning` for observed early or duplicate requests. Warnings do not change
the provider verdict and never authorize another concurrent request. Use
`unknown` when request enumeration or POST outcome cannot yet be proved. Every
finding entry records its stable ID/URL, commit, carrier, and thread resolution
state without copying large bodies into the summary.

## Non-Goals

This contract does not:

- attest the provider's internal input merge base;
- require provider input-base evidence before accepting an otherwise complete
  latest-head positive result;
- infer clean from silence, request count, `eyes`, or a generic successful
  check;
- treat human resolution as provider-lane resolution;
- define repository workflow files, status-check names, or rulesets; or
- turn retries or duplicate requests into additional reviewers.
