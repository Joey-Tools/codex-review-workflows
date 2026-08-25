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

The GitHub lane proves a result for one exact PR head. An ordinary terminal
artifact, reaction, or feature-head producer contract does not prove which
base or merge base the provider inspected; local readiness owns that proof. A
trusted synthetic-merge producer contract may additionally prove only its
closed current-merge-scope assertion when it binds the exact current base and
check subject under this authority. Local readiness still validates that scope
independently.

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
result supplies no base, merge-base, or target-ref coverage. A feature-head
merge/status basis follows that same rule. A synthetic-merge basis is
base-sensitive instead: any change to its frozen base ref, base tip, unique
merge base, feature head, or check-subject SHA invalidates it and requires a
new producer result for the recomputed current scope.

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
review of the new base. The raw provider artifact may remain in the audit
inventory, but old `finding_page_receipt`, `finding_range_receipt`, and
`finding_carrier_snapshot` inputs are not reusable across that scope change.
Freeze all three again, rebuild the ancestor projection over the new
`base_sha..head_sha` full commit DAG, and reclassify the raw carrier before it
may block the refreshed scope. Do not reduce that projection to first-parent,
ancestry-path, or otherwise linear history.

By contrast, merging the current base branch into the feature branch creates a
new head. Every old-head positive GitHub Codex result is stale; unresolved
findings remain applicable under the rules below. The new head must obtain fresh
provider evidence after its local tests and review lanes are rerun. Reevaluate
any retained raw finding carrier against a newly frozen current-scope
`finding_page_receipt`, `finding_range_receipt`, and
`finding_carrier_snapshot`; none of the old parent inputs or their page,
ancestor, or thread projections carries forward to the new head.

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
- feature-head check runs and statuses and, when distinct, the selected
  synthetic-subject check runs and statuses used as a preferred merge/status
  basis.

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
on every candidate exact review request, feature-head check runs/statuses, and
selected-subject check runs/statuses each carry an exact `true` completion flag
and a typed non-negative count. Each check/status inventory also binds the
exact queried subject SHA and a lowercase SHA-256 identity over that subject
plus its raw pagination envelopes and records. The feature-head inventory is
always present and binds the exact current feature head. The selected-subject
inventory is also always present. For a feature-head subject it must identify
the same page set type-for-type; for a GitHub synthetic merge subject it must
bind that distinct subject and a separately fetched, distinct page-set identity.
Missing either subject's check-run or status pages, coupling the synthetic
inventory to the feature-head inventory, or changing both subject labels
together is incomplete evidence. The two closed terminal selections must be
equal and bind the selected positive result under this authority's precedence.
Terminal-clean requires `classification: clean` plus the exact terminal
artifact. Merge-status requires `classification: clean` plus the exact
contract-verified producer check; it does not require a second terminal clean
comment or review. Reaction-clean requires `classification: absent` plus null
evidence. Every pass requires an exact integer zero unresolved-provider-finding
count. The same record also contains equal initial and final closed pass-basis
selections derived from the complete raw observations: terminal-clean repeats
the exact selected terminal evidence, reaction-clean binds the exact request
and provider reaction kind/command/actor/IDs/URLs/server times, and merge-status
binds the exact feature head, current base ref/tip and unique merge base,
check-subject kind/SHA, App/workflow/run/attempt/check-suite/check-run identity,
producer-contract descriptor, and provider-clean assertion. The unused union
branches are null.

For merge-status only, the snapshot also carries equal initial/final closed
`merge_status_scope` values. They bind repository, PR, feature head, exact base
ref, current base tip, unique merge base, check-subject kind, and
`check_subject_sha`, and must equal the independently frozen parent scope. They
are null for the other bases. For a producer contract that names the GitHub
synthetic merge commit as its subject, both observations must read that exact
subject's complete check-run and status pages in addition to the exact feature
head's complete pages. A feature-head-only contract sets the subject to the
feature head, requires exact identity equality between those two inventory
projections, and receives no base-coverage claim.

The snapshot's initial and final lowercase SHA-256 values must be equal digests
of RFC 8785 canonical JSON for the complete raw snapshot: exact scope/head,
raw issue/review/inline/thread, nested thread-comment, and reaction pages,
pagination envelopes and typed counts, derived terminal candidates and
ordering, the selected latest terminal or producer result, selected pass-basis projection,
unresolved applicable findings, check/status records, and the complete
merge-status scope when that basis is selected. Check/status records include
both subject-discriminated page sets and their subject-bound identities.
They are not digests of the report summary.
The parent persists this record independently before report validation;
report, association, epoch, or check fields cannot create,
amend, or self-prove it. The consumer requires both basis selections to be
type-preserving equal and to join exactly to the report and its orthogonal
epoch or merge-contract carrier; changing those carriers together while
leaving this frozen selection unchanged fails closed.

Before any blocking `findings` result, persist three separate closed
parent-owned inputs: a `finding_page_receipt` for acquisition completeness, a
`finding_range_receipt` for the current local range, and a
`finding_carrier_snapshot` containing the consumer replay observation and
selected carrier. All three are created before report validation and are
read-only to the consumer. Report fields and embedded page, carrier, or
ancestry projections cannot create, amend, or self-prove any of them.

The `finding_page_receipt` has exact fields `owner`, `status`, `profile`,
`scope`, `page_inventory`, and `records_sha256`. Require
`owner: parent-orchestrator`, `status: complete`, and exact profile
`github-codex-finding-acquisition-v1`. Its closed
`finding_acquisition_scope` has exact fields `repository`, `pull_request`,
`base_sha`, `head_sha`, and `ancestor_shas_sha256`; each joins the independent
`finding_range_receipt` type-preservingly.

Its closed `finding_acquisition_page_inventory` contains only the five
acquisition completion Booleans and their five typed non-negative counts for
issue comments, reviews, associated inline comments, GraphQL review threads,
and nested thread comments. Every completion flag is exact `true`, and every
field joins the corresponding `complete_observation.page_inventory` field
before candidate selection. The derived `terminal_candidate_count` remains
outside this acquisition receipt.

The parent freezes this receipt from the complete current-scope page
acquisition before constructing the finding snapshot. The consumer recomputes
`records_sha256` as the lowercase SHA-256 digest of RFC 8785 canonical JSON for
the exact closed object `{issue_comments, reviews}` supplied by the observation,
including every ordered parent-enriched record, embedded provider child, and
GraphQL thread join. Deleting or changing a later correction, child, thread
join, page count, or completion flag cannot be repaired by changing the
snapshot observation, its digest, or report summaries while this independent
receipt remains unchanged.

The `finding_range_receipt` has exact fields `owner`, `status`, `repository`,
`pull_request`, `base_sha`, `head_sha`, `history_mode`,
`base_is_unique_merge_base`, `base_is_ancestor_of_head`, `ancestor_shas`,
`ancestor_count`, and `ancestor_shas_sha256`. Require
`owner: parent-orchestrator`, `status: complete`, `history_mode: full-dag`, and
both Boolean properties to be exact `true`. The ancestor list contains full
lowercase SHAs, sorted by ASCII bytes, duplicate-free, and excludes both base
and head; recompute its typed count and its SHA-256 digest over each ASCII SHA
followed by LF. Build it from the complete `base_sha..head_sha` commit DAG,
including merge commits and side history. First-parent, ancestry-path, or any
other linear projection is invalid.

The receipt's repository, PR, and head join the report and observation exactly.
The consumer projects the receipt into every candidate carrier's complete
`scope` and `ancestor_shas_projection` and requires type-preserving equality.
An `owner` string or projection embedded only in the carrier is not independent
ancestry evidence. The selected artifact is applicable only when its commit is
the exact receipt head or a member of the receipt's complete ancestor list.
Changing the base while retaining the same head invalidates the old receipt and
snapshot; coupled edits to a carrier commit, body, report, and embedded
projection cannot repair that mismatch.

The `finding_carrier_snapshot` has exact fields `owner`, `status`,
`complete_observation`, `complete_observation_sha256`, `raw_carrier`,
`raw_carrier_sha256`, `evidence`, and `unresolved_provider_findings`. Require
`owner: parent-orchestrator` and `status: complete`. `complete_observation` is
the supplied closed `finding_complete_observation` object with exact fields
`scope`, `page_inventory`, `issue_comments`, `reviews`,
`selected_carrier_sha256`, and `selection_status`; require the status to be
exactly `selected-findings`. A digest without this canonical object is invalid.
Its scope is the closed repository/PR/head scope. Its `page_inventory` is the
closed `finding_page_inventory`: issue-comment, review,
associated-inline-comment, GraphQL review-thread, and nested thread-comment
completion flags are exact `true`; their counts are typed non-negative
integers. Require `issue_comment_count` and `review_count` to equal the exact
lengths of the supplied channel arrays, `inline_comment_count` to equal the sum
of every supplied review's child count, and `terminal_candidate_count` to be a
typed positive integer equal to the consumer-derived terminal-looking record
count. Before trusting those values or record arrays, require their acquisition
subset and page-record digest to join the independent `finding_page_receipt`
exactly.

The parent supplies the canonical observation object itself, not merely a
summary or claimed digest. The consumer recomputes
`complete_observation_sha256` as the lowercase SHA-256 digest of RFC 8785
canonical JSON for that exact object only after the independent range and page
receipts join its scope, acquisition inventory, and page-record bytes. Validate
every terminal candidate as a closed parent-enriched issue-comment or review
carrier. The supplied channel arrays contain every record frozen by the page
receipt from the complete current-scope pages, including nonterminal records
from which the consumer derives the terminal candidates.
Require unique raw-carrier digests and unique `(kind, id)` identities across
both arrays, exact receipt scope joins, and canonical semantic-time/within-channel
ID order in each array. Raw provider fields remain unchanged; parent-enriched
scope, pagination, commit-resolution, and thread-join companions must all
satisfy the version-1 grammar. A full-SHA issue-comment
finding has `commit_resolution: null`. In this negative-observation selector,
an issue-comment clean candidate with a 40-character marker can supply
supersession authority only when `commit_resolution` is null and the marker
equals the independent range receipt's head. A 10-character marker additionally
requires a grammar-valid closed resolution whose repository and marker join the
receipt and whose initial and final resolved commits both equal the receipt
head, which must start with that marker. A carrier's `commit_resolution` never
supplies finding-selection authority by itself; any range join failure makes
the complete selection fail closed rather than superseding a finding.

Run the normative classifier over every supplied record, derive the complete
terminal-candidate set and its count, and independently
replay this authority's applicability, ordering, cross-channel precedence,
resolution, and supersession rules. Only a strictly later trustworthy clean may
supersede an older top-level finding. `resolved-inline-only` clears only that
carrier's typed resolved inline findings, and no later clean supersedes an
unresolved inline child. A globally latest malformed or inconclusive candidate,
conflicting cross-channel classification or commit result in the globally
latest decision bucket, conflicting latest channels during finding selection,
or an ambiguous same-channel winner prevents a valid selection and cannot be
converted to blocking evidence. Require the independently selected carrier
digest to equal
`complete_observation.selected_carrier_sha256`.

When a selected `top-level-finding-v1` carrier also contains an exact-provider
unresolved inline child, a strictly later trustworthy clean may supersede only
the top-level component. The selected raw carrier and evidence remain that
original carrier, but the unresolved projection must then be non-empty and
inline-only; retaining its superseded top-level entry or dropping its unresolved
inline child fails closed.

`raw_carrier` is the exact selected candidate and must be type-preservingly
equal to one unique observation member. Recompute `raw_carrier_sha256` from its
RFC 8785 canonical JSON and require it to equal the independently selected
digest.
Derive provider identity, channel, grammar branch, evidence identity, commit,
server time, and the exact unresolved top-level or inline-child projection from
that carrier. Derive a parent issue-comment or review URL canonically from the
receipt repository, PR, channel, and carrier ID; bind an inline child's raw
discussion URL through its exact parent review and GraphQL thread join. A
parent-owned `request_id` association may remain in the evidence projection
when the raw carrier has no such field; it cannot replace any carrier,
observation, or range binding. Finally require the snapshot's evidence and
unresolved list to equal those derived projections and the report
type-preservingly.

A single complete observation may prove the presence of a selected applicable
unresolved finding and block immediately; it need not satisfy the
two-observation stability proof used to prove absence for `pass`. This
asymmetry does not remove the final-reread gate: merge readiness must still
reread the complete current scope and may retain the finding only if it remains
the independently selected applicable unresolved result.

A non-ancestor or stale carrier, a fabricated commit or identity, an incomplete
page or range receipt, incomplete observation or pagination, or an orphaned,
ambiguous, or malformed thread join remains in the raw audit inventory. Such
evidence may make the lane inconclusive, but it cannot enter the authoritative
unresolved-finding projection or generate blocking `status: findings`. A new
head or merge base requires a new page receipt, range receipt, and snapshot even
if the raw provider carrier is retained; rebuild the projection over the new
`base_sha..head_sha` full DAG and rerun acquisition and complete-observation
selection.

## Evidence Strength

Evaluate the following bases in order:

1. A trustworthy repository merge/status check whose independently verified
   producer contract defines successful completion as a GitHub Codex clean
   result for its exact declared scope.
2. A trustworthy exact-provider terminal clean issue comment or pull-request
   review for the current head.
3. The exact-provider `+1` reaction fallback on the selected current-head
   request.

The first basis is preferred when it exists because repositories commonly
aggregate the review into a merge-oriented check. Association requires an
independently parent-verified repository contract; never guess a workflow,
check name, App identity, check subject, or producer semantics. The raw evidence
must bind exact App, workflow, run, attempt, check suite, check run, check name,
status, conclusion, feature head, and check-subject identities to that contract.
The contract itself must say that `completed` / `success` means GitHub Codex
provider clean for either `latest-feature-head` or `current-merge-scope` and
must require zero unresolved applicable provider findings. No separate terminal
clean comment or review is required for this basis.

For `latest-feature-head`, require `check_subject_sha == feature_head_sha` and
describe the result only as feature-head coverage; base and merge-base assurance
remain local readiness facts. For `current-merge-scope`, require the contract's
`github-synthetic-merge` subject and independently bind the exact feature head,
base ref, current base tip, unique merge base, and synthetic
`check_subject_sha`. A generic successful check, service-start marker, static
name match, unknown producer contract, or check from another subject does not
qualify.

The check association and producer contract are necessary but not sufficient.
A merge-status pass also requires the common `complete_pr_snapshot` to select
that exact contract-verified check as the stable positive result and stable
merge-status basis, with equal initial/final scope and zero unresolved
applicable findings.

Preference does not silently enlarge what the check proves. The feature-head
branch remains head-only. The synthetic branch may state current-merge-scope
coverage only when every declared base/merge/subject binding above is closed
and stable; the local readiness plane still revalidates those facts
independently before merge.

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

The version-1 finding snapshot and actionable projection bind exactly one raw
finding carrier. If the complete observation contains more than one applicable
carrier with an active finding component, selection fails closed; the consumer
must not choose only the newest carrier and hide an older unresolved finding. A
later clean does not clear an unresolved inline child. Typed thread resolution
or a strictly later trustworthy clean that supersedes only a top-level
component may reduce the active set, after which the remaining unique carrier
can be projected normally.

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

A terminal finding blocks immediately only when the independent parent-owned
`finding_page_receipt` proves acquisition completeness, the separate
`finding_range_receipt` proves current full-DAG applicability, and the separate
`finding_carrier_snapshot` supplies a digest-recomputable observation whose
replay selects that exact unresolved carrier. The consumer then joins its
derived evidence and finding projection type-preservingly to the report. Report
fields, a digest without its object, embedded page state, and a carrier's own
scope never prove those facts to one another. Missing positive evidence cannot
neutralize a finding that passes this negative-evidence contract.

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
- The parent review is part of the inline finding's identity. Its accepted
  carrier is `inline-parent-v1`, its channel is exactly `review`, and its raw
  pull-request-review ID and URL must bind both the child and the report through
  the independent finding snapshot. A child discussion URL or copied parent
  ID alone cannot establish that association.
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

The exact repository, PR, and feature head define one comment-mutation epoch.
That epoch permits at most one possibly delivered create-comment POST, and the
parent must completely enumerate the visible exact-request set before making
it. Once the call could have reached GitHub, it consumes the epoch's
comment-mutation budget even when its result is ambiguous. Never repeat the
comment POST in that epoch.

After an ambiguous outcome, reread the unchanged current head and its complete
visible exact-request set. If closed before/after observations unambiguously
prove which request the one-shot call created, bind that stable request. If
delivery cannot be proved, use `request_policy.status: unknown`; read-only
observation may remain pending while another read is meaningful, but reaction
fallback cannot use an unproved request identity. Without an independently
accepted terminal basis, exhausted observation becomes `inconclusive` with
`last_reason: request-delivery-unproven`. Only an independently authorized
exact Actions tuple may use idempotent reconcile and backoff; that authority
never extends to comment creation.

Any visible duplicate remains part of the same logical review lane and is
reported as an audit warning. An observed duplicate never authorizes another
comment write, never restores the comment-mutation budget, and never counts as
an additional lane. Prefer the latest provably selected visible request for
fallback, and never let duplicate request count erase trustworthy terminal
provider evidence.

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
| Trusted contract-verified merge/status producer is clean for its exact feature-head or synthetic-merge scope and no provider finding is unresolved | `pass` |
| Trusted terminal clean artifact and no provider finding is unresolved | `pass` |
| Valid reaction fallback and no provider finding is unresolved | `pass` |
| Parent-owned page and range receipts plus replayed complete finding snapshot prove an applicable unresolved provider finding and join exactly to the report | `findings` |
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
  scope_assurance: latest-head-only | latest-feature-head | current-merge-scope
  base_assurance: local-pr-readiness | producer-contract-current-scope-plus-local-pr-readiness
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
report uses this distinct closed check-run shape. The producer's clean
assertion is contract semantics, not a copied terminal artifact:

```yaml
evidence:
  kind: merge-status
  id: stable-check-run-id
  url: https://github.com/owner/name/runs/<same-id>
  channel: check-run
  check_name: exact-name-from-verified-contract
  status: completed
  conclusion: success
  feature_head_sha: 40-lowercase-hex-equal-to-report-head
  check_subject_sha: exact-feature-head-or-synthetic-merge-sha
  workflow_id: exact-positive-workflow-id
  run_id: exact-positive-run-id
  run_attempt: exact-positive-attempt
  check_suite_id: exact-positive-check-suite-id
  app:
    id: exact-positive-app-id-from-verified-contract
    slug: exact-app-slug-from-verified-contract
  server_time: RFC3339
  server_time_field: completed_at
  association:
    kind: parent-verified-repository-contract
    owner: parent-orchestrator
    status: complete
    repository: owner/name
    pull_request: 123
    feature_head_sha: 40-lowercase-hex-equal-to-report-head
    base_ref: refs/heads/exact-base
    base_tip_sha: exact-current-base-tip
    merge_base_sha: exact-parent-proved-unique-merge-base
    check_subject_kind: feature-head | github-synthetic-merge
    check_subject_sha: exact-feature-head-or-synthetic-merge-sha
    workflow_id: exact-positive-workflow-id
    run_id: exact-positive-run-id
    run_attempt: exact-positive-attempt
    check_suite_id: exact-positive-check-suite-id
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
    provider_clean_assertion:
      kind: verified-producer-contract
      semantics: github-codex-provider-clean
      scope: latest-feature-head | current-merge-scope
      unresolved_findings_required_zero: true
```

Before accepting this shape, the consumer receives a separate closed
parent-owned `merge_status_parent_contract` record; it must not derive that
record from the report being validated. The record carries the four contract
descriptor strings (`source_repository`, `source_commit`, `source_path`, and
`source_sha256`), trusted App ID and slug, exact workflow/run/attempt, check
suite/name/run ID and URL, and exact closed provider-clean assertion. Compare
every descriptor string by exact UTF-8 byte identity with the independently
verified record and compare every remaining field type-preservingly. Coupled
edits to the report's contract, App, run, check, assertion, or stable
association identities therefore fail even when the edited report remains
internally self-consistent.

The consumer also receives the independent common `complete_pr_snapshot`.
Its stable positive selection must equal the complete outer merge-status
evidence type-for-type. Its stable merge-status basis selection must also equal
the feature-head/base/merge/check-subject scope, complete App/workflow/run/check
identity, status/conclusion/time projection, producer-contract descriptor, and
provider-clean assertion type-for-type, and must join exactly to the
independently supplied parent contract. Neither the check association nor the
parent contract may self-prove or repair that whole-PR snapshot.

The parent independently verifies the exact contract bytes and digest and
confirms that the contract binds this App/workflow/run/check identity, subject
mode, scope, and provider-clean semantics. The association fields must equal
the outer raw check-run fields, while repository, PR, feature head, base ref and
tip, unique merge base, and subject must separately equal the parent's frozen
scope inputs and the initial/final complete snapshot. Thus a generic successful
check or service-start marker cannot become a merge-status pass merely by
copying the App identity, feature head, or check name.

A findings report backed by an accepted terminal carrier uses
`kind: terminal-artifact`, a non-null full `artifact_commit`,
`head_binding: explicit-commit`, and its finding grammar branch. It is accepted
only alongside the independently supplied closed parent-owned
`finding_page_receipt`, `finding_range_receipt`, and
`finding_carrier_snapshot` described above. The consumer validates the current
range first, recomputes the acquisition page-record digest and joins its exact
inventory next, then recomputes the observation and selected-carrier digests,
joins every record to the independent current range, replays the complete
terminal selection, and validates the selected raw carrier before comparing
its exact derived evidence and unresolved list type-preservingly with the report.
Equality among report fields, or even a coupled edit to the carrier, embedded
projection, report evidence, and every finding entry, supplies no authority.
Because version 1 has a single-carrier evidence projection, more than one active
finding carrier fails closed rather than permitting a newest-only report.
Non-ancestor, stale, fabricated, incomplete-projection, incomplete-observation,
or malformed-join carriers remain audit-only and cannot produce
`status: findings`.

The page receipt, range receipt, and snapshot are external parent inputs, not
fields in `github_codex_lane`. A new head or merge base requires all three to be
newly frozen and requires a newly computed complete `base_sha..head_sha`
full-DAG ancestor projection; the consumer cannot rebind old inputs by changing
their page state, carrier, or report scopes. The final readiness reread still
confirms that the current scope and thread state have not cleared or invalidated
the finding. Pending and inconclusive PR-bound reports may use `evidence: null`
when no stable diagnostic artifact is selected. The no-PR `not-applicable`
variant always uses null evidence together with its required null PR/head fields.

Use `warning` for observed early or duplicate requests. Warnings do not change
the provider verdict and never authorize another comment write. Use `unknown`
when request enumeration or the one-shot POST's delivery cannot be proved.
While another read remains meaningful, that delivery uncertainty may be
reported as `pending` with `last_reason: request-delivery-unproven`; when
read-only observation is exhausted and no independently accepted terminal
basis exists, report `inconclusive` with the same reason. Every finding entry
records its stable ID/URL, commit, carrier, and thread resolution state without
copying large bodies into the summary.

## Non-Goals

This contract does not:

- attest the provider's internal input merge base;
- require provider input-base evidence before accepting an otherwise complete
  latest-head positive result;
- infer clean from silence, request count, `eyes`, or a generic successful
  check;
- treat human resolution as provider-lane resolution;
- treat non-idempotent comment creation as an idempotent Actions tuple;
- define repository workflow files, status-check names, or rulesets; or
- turn retries or duplicate requests into additional reviewers.
