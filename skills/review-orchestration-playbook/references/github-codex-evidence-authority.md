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

The source `packages/action/` subtree and released Action root both have exact
Git tree ID `d03de9035d20f285e6a93986d436403b4a30e9bc`. Their complete relative-path
blob manifest is:

| Relative path | Git blob ID |
| --- | --- |
| `COOKBOOK.md` | `70784aed0869504d85cd9b95710b2dea427841e5` |
| `COOKBOOK.zh-CN.md` | `f7dc955b8ebd1673883d38352f37b58099b1227d` |
| `DESIGN.md` | `8de87334a37bd85a6b3f3d1a4362933eeacbab25` |
| `DESIGN.zh-CN.md` | `45026f208847f1385780ffe9904b58b98903fb44` |
| `EULA.md` | `eeaeb240bb31e35e2d7c574c044d3ddcbb64ea30` |
| `LICENSE` | `d9a10c0d8e868ebf8da0b3dc95bb0be634c34bfe` |
| `README.md` | `c43aeded90def8d5876dec6d67e07a7cdcfac038` |
| `README.zh-CN.md` | `c66a93b90a3354269f2f91135103490cc949a81e` |
| `SECURITY.md` | `ae8b45461e2f41350b1e6fc7343504fc4c9dcd8b` |
| `SUPPORT.md` | `4378a1e3377ee0fb58fcaa7a2ad715a4d53e814f` |
| `action.yml` | `2169ca33d1cb8c698805513768e6a5c34887fe35` |
| `package.json` | `b554018df447543590a0f732968892ccc22050f3` |
| `src/core.mjs` | `7270586bced68f0faca15ebe844f0517dc7b1ec3` |
| `src/evidence-budget.mjs` | `b2a07e9a4dd33dc60d138d97a59444b3fc537677` |
| `src/gate.mjs` | `e0b974b27ebd64e412eaef1d069789b5f6bd76ba` |

The inherited authority rule is:

- Reconstruct a complete current evidence snapshot.
- Treat controlled requests, sticky state, deadlines, status history, and
  retry markers as orchestration or audit records.
- Let the latest trustworthy terminal artifact determine the provider result.
- Fail closed when identity, schema, pagination, ordering, scope, or final
  stability is incomplete.

This is an anti-drift baseline, not a floating reference to either repository's
default branch. Future changes must compare against both immutable commits, the
common tree ID, and all 15 path/blob pairs above, then explicitly record whether
the baseline is retained or replaced. A branch name, tag name, partial runtime
diff, or a later release with similar prose is not a substitute.

Treat the source commit, released-Action commit, common tree ID, complete
15-path manifest, and the result-present decision rationale below as one atomic
anti-drift receipt. Matching only the executable files does not preserve the
published release envelope, and matching only the prose does not preserve the
implementation that the named regressions exercise. Any future replacement
must pin a new source/action pair, prove their complete-tree relationship,
publish the complete replacement path/blob manifest, and explain whether each
result-present regression remains authoritative or why the decision changed.
Until that comparison is recorded, this exact baseline and rationale remain
normative.

Only the provider-result authority is inherited: trustworthy provider results
decide the outcome, while requests and run markers remain producer/audit
evidence. The playbook's raw REST/GraphQL review-thread proof, exact whole-PR
scope and lifecycle gates, closed terminal issue-comment carrier and edit-time
rules, independent artifact-time whole-PR scope receipt, and conditional `+1`
fallback are local extensions. They must not be
removed merely because the fixed Action uses a different evidence envelope,
and they must not be attributed to that Action without a new pinned comparison.

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
same-time channel evidence, a missing artifact-time scope receipt on an
artifact claimed as receipt-bound authority, stale scope, or unstable final provider
artifact/thread/selection re-read still blocks. Request-sidecar-only instability
instead closes request/reaction authority without erasing a stable terminal
result. Likewise, request edits, request/reaction relative ordering, selected
reaction IDs, and legal reaction contents remain audited but cannot invalidate
a complete terminal carrier; those constraints become result authority only
for the reaction-only fallback.
An unresolved thread finding is not superseded by a later clean artifact.
A truly absent pre-v1 receipt is the narrow legacy exception: a strictly older,
otherwise well-formed artifact may remain only in the closed
`legacy_unreceipted_audit` partition. It is never positive terminal authority
or the selected completion basis. A later accepted receipt-bound result may
still have a non-null `evidence_basis` that carries the item in
`legacy_unreceipted_artifacts`; the legacy item does not by itself veto that
result when every legacy-migration partition, time, stability,
ordinary-precedence, and thread gate closes.

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
  lanes had parent-recorded terminal artifacts. Emit it only when trusted
  server time and parent-recorded local terminal times prove that order. If
  either side of that comparison is missing or contradictory, set
  `request_policy.status: unknown`, do not infer the warning, and do not post
  another request.
- `duplicate-observed` means more than one accepted request exists for the
  same immutable whole-PR scope.
- A lone request that was posted under producer policy and is still pending is
  `compliant`, not a warning. If a second same-scope request is pending or
  overlaps another request, record `duplicate-observed`.
- Both codes may appear together.
- `duplicate-observed is warning-only`; it is outcome-neutral after the
  evidence snapshot is otherwise complete.
- `unknown` means request enumeration, identity, or the trusted ordering needed
  to classify producer timing is incomplete. It forbids a new request but does
  not independently invalidate complete provider-result evidence. If the same
  read failure also makes a required provider-evidence page incomplete, that
  separate provider gate blocks completion.
- `not-applicable` is used only when no eligible request plane exists, such as
  a proved no-PR or unsupported-host/identity path.

Warnings remain visible in the final report even when the provider result is
clean. Never silently normalise duplicate history into `compliant`, and never
post a third request to repair it.

### Parent-Owned Request-Time Scope Receipt Sidecar

Reaction evidence and request-policy classification require proof of the
immutable whole-PR scope at the time the parent created each controlled
request. The authority for that proof is a parent-owned sidecar captured around
the write, not a scope later attached to an issue-comment record. Its closed
shape is:

```yaml
request_scope_receipts:
  - kind: parent-recorded-request-scope-v1
    request_id: <positive request-comment ID>
    pre_request_scope_receipts:
      pull: <closed raw response receipt>
      compare: <closed raw response receipt>
    request_comment_receipt: <closed raw response receipt>
    post_request_scope_receipts:
      pull: <closed raw response receipt>
      compare: <closed raw response receipt>
```

Every raw response receipt has exactly these fields and no others:
`{method, request_url, status, date_header, body_utf8, body_sha256}`.
`date_header` is the canonical IMF-fixdate from that authenticated GitHub
response, `body_utf8` is the bounded strict-UTF-8 JSON response body, and
`body_sha256` is recomputed over those exact UTF-8 bytes. Self-reported
authentication flags, normalized projections, GraphQL objects, and locally
constructed response bodies are not receipts.

Every `body_utf8` receipt or page is decoded before projection by one strict
JSON decoder. It rejects duplicate object member names at every depth,
`NaN`, `Infinity`, `-Infinity`, any decoded non-finite number, and any string
or member name containing `U+D800` through `U+DFFF`. Endpoint forward
compatibility permits unknown fields only after this syntax and scalar-value
gate succeeds.

For each pre-request and post-request phase:

- `pull` is exact `GET` of
  `https://api.github.com/repos/<owner>/<repo>/pulls/<pr>` with integer status
  `200`. Its raw body supplies the canonical positive PR number plus full
  lowercase `base.sha` and `head.sha`.
- `compare` is exact `GET` of
  `https://api.github.com/repos/<owner>/<repo>/compare/<base.sha>...<head.sha>`
  with integer status `200`. Its raw body must repeat both endpoints as
  `base_commit.sha` and `head_commit.sha` and supplies `pr_merge_base` only
  from `merge_base_commit.sha`. A response for another head is not scope
  evidence even when its base and merge-base fields look plausible.
- The two independently parsed records derive one exact scope tuple
  `(repository, pr, pr_merge_base, head)`. The pre-request and post-request
  tuples must be type-preserving identical. They must also equal the enclosing
  historical or current scope before that request or any child reaction enters
  the enclosing scope's request/reaction authority. A valid tuple with the same
  repository and PR but an older head remains old-epoch audit evidence; the
  dedicated same-head/different-merge-base classification follows the
  base-only-retarget rule below. Preserve the individual response `Date`
  values; do not require the two sequential GETs in one phase to share a
  timestamp. Every pre `Date` is no later than the request semantic time or
  POST response, every post `Date` is no earlier than the POST response, and
  every receipt `Date` is no later than the frozen history as-of bound.

`request_comment_receipt` is the exact authenticated response to parent-owned
`POST` of `https://api.github.com/repos/<owner>/<repo>/issues/<pr>/comments`
with integer status `201` and exact submitted body `@codex review`. Independently
project its raw response body to the controlled request's eight-field record:

```yaml
id: <positive issue-comment ID>
url: https://github.com/OWNER/REPO/pull/<pr>#issuecomment-<id>
created_at: <canonical server time>
updated_at: <same canonical server time as created_at>
request_server_time: <created_at>
request_server_time_field: created_at
normalized_body: "@codex review"
user:
  login: <authenticated parent login>
  type: <exact REST user type>
```

The raw POST body must also bind the canonical REST issue-comment URL, exact
repository/PR, and the authenticated parent actor accepted by the controlled
request rule. Version `parent-recorded-request-scope-v1` accepts only the
unedited creation response (`created_at == updated_at` and
`request_server_time_field: created_at`); authority for a later edit would
require a separately predeclared receipt version. `request_id` must equal the
projected `id`; the projected eight top-level fields—including the closed
`user: {login, type}` actor projection—must type-preservingly equal the
independently fetched request record in the complete issue-comment traversal;
and the request semantic server time must fall between every pre-read `Date`
and the POST response `Date`.

For the request/reaction plane, the mapping is one-to-one and onto: every
observed controlled request has exactly one sidecar and every sidecar names
exactly one such request. Duplicate, extra, cross-PR, or unmatched receipts are
not admitted. A receipt-derived old epoch may remain in the complete audit but
cannot be counted in the enclosing scope. The selected request and every
`same_scope_request_audit` entry repeat their exact sidecar. Reaction
`source_record_sha256` binds the request projection, this sidecar, and the
individual reaction projection together.

This sidecar does **not** change `discovery_endpoint_transcript` schema version
4. The raw transcript remains exactly the bounded discovery sources and per-PR endpoint
fetch envelope defined below; `request_scope_receipts` is separate parent-owned
write-time evidence and is never inserted as a transcript fetch kind, page, or
endpoint response. A future transcript version must not be implied merely by
adding or validating this sidecar.

A missing, malformed, duplicate, extra, or mismatched sidecar closes only the
request/reaction planes. Set `request_policy.status: unknown` with no invented
timing or duplicate warning, forbid another POST for that observed scope, and
do not use the affected request or any child reaction for profile history or
`thumbs-up-clean`. It does not erase a separately complete, trustworthy
current-scope terminal payload: terminal selection continues normally and may
still yield clean or findings while the request-policy report remains
`unknown`, provided that artifact has its own complete
`parent-recorded-terminal-artifact-scope-v1` receipt. A read failure that
independently makes a provider endpoint page
incomplete is still a separate terminal-evidence blocker.

Never reattach an old-epoch request or reaction to the current scope merely
because the PR number or head is familiar. If either receipt-derived tuple
differs from the enclosing tuple, the request and all of its child reactions
remain old-scope audit evidence and cannot become a current or historical
reaction sample for another tuple. In particular, a base-only retarget cannot
relabel an old request as belonging to the new merge-base epoch.

The sidecar proves neither request/run lineage nor continuous scope stability.
It binds one exact parent-created comment to matching authenticated scope
observations immediately before and after the write; GitHub still exposes no
general mapping from that request to a provider run or terminal artifact.
Likewise, equal pre/post tuples are point-in-time observations and do not prove
that an intermediate `A -> B -> A` scope change, close/reopen, or other ABA
transition did not occur. Never describe the sidecar as a transaction,
continuous lifecycle attestation, or run identifier.

## Terminal-Artifact Scope Receipt

Result-present acceptance removes request/run lineage as a consumer gate; it
does not permit the current PR metadata to retroactively assign whole-PR scope
to an older provider artifact. Every terminal-looking exact-provider artifact
that enters the receipt-bound normalized decision member, including the
selected clean or findings artifact and any receipt-bound malformed blocker,
therefore requires exactly one independent parent-owned
`parent-recorded-terminal-artifact-scope-v1` receipt.
Store the unique receipt as that artifact wrapper's singular
`artifact_scope_receipt` beside, never inside, the raw endpoint inventory.
Do not insert it into transcript schema version 4.
An otherwise applicable pre-v1 artifact with a truly absent receipt never
enters that normalized member. Preserve it only through the raw endpoint
inventory and the closed Legacy Receipt Migration partition below; that
audit-only exception cannot select a result or basis.

Each receipt rejects unknown fields and contains exactly:

- `kind: parent-recorded-terminal-artifact-scope-v1`;
- `pre_artifact_scope_receipts.pull` and `.compare`, each an authenticated raw
  `200` response receipt using the same closed method, canonical request URL,
  status, `Date`, UTF-8 body, and SHA-256 fields as request-time scope receipts;
- one `artifact_get_receipt` for the canonical authenticated REST `GET` of the
  exact issue comment or pull-request review, also preserving method, canonical
  URL, integer `200` status, response `Date`, raw UTF-8 body, and body SHA-256;
  and
- `post_artifact_scope_receipts.pull` and `.compare` with the same closed raw
  response contract.

The artifact GET response, rather than redundant receipt metadata, binds the
exact repository/PR, channel, native ID, and provider artifact projection. The
pre/post pull and compare bodies independently bind head and merge base; those
raw projections together form the immutable
`(repository, pr, pr_merge_base, head)` join. No sibling ID or scope assertion
may substitute for projecting the receipt's raw bodies.

Strictly parse and retain the complete raw GitHub response bytes and verify
their digests, but compare the closed authority projection rather than require
the whole REST object to equal a synthetic minimal object. Real pull, compare,
review, and issue-comment resources contain legitimate extra GitHub fields.
Those fields remain covered by the retained-body digest and stability check;
they neither become authority fields nor make an otherwise exact projection
invalid. Mutation, omission, ambiguity, or type drift in any projected
security-relevant field still fails closed.

Both pre and post pull/compare pairs must independently project the same exact
base OID, artifact-time head OID, and unique local merge base. For a clean or
malformed current-head artifact, that tuple must equal the enclosing current
scope. For a finding on a proved ancestor, the receipt's repository, PR, and
merge base still equal the enclosing scope, while its artifact-time head equals
the finding's native or parsed artifact commit; the enclosing normalized
`scope.head` remains current, and the separate local ancestry receipt proves
the ancestor relation. Open lifecycle remains an independent mandatory
snapshot and is not synthesized from this receipt. The artifact GET must
project type-preservingly to the artifact in both complete current raw
inventories: native ID and channel, canonical API/HTML URL, exact bot/App
identity where applicable, raw body and digest, grammar classification, state,
native or parsed artifact commit, and trusted semantic server time. For a
review, the separately complete inline-comment and thread pages remain
mandatory provider evidence; the artifact receipt does not replace their
pagination or joins.

Derive the actual full base and head OIDs from the pull receipt; never
synthesize either OID from a fixture, PR number, branch name, or enclosing
summary. Build the canonical compare URL from those parsed OIDs, then require
the compare body to repeat them as exact `base_commit.sha` and
`head_commit.sha` while supplying the unique `merge_base_commit.sha`. A compare
for another head cannot lend its merge base to this artifact scope.

The time envelope is exact: every pre-scope response `Date` is strictly earlier
than the artifact semantic server time, the artifact semantic server time is no
later than the exact artifact GET response `Date`, and every post-scope
response `Date` is no earlier than that artifact GET response `Date`. An
artifact whose semantic server time does not strictly follow every available
trustworthy pre observation cannot be scoped retroactively. It is
`triple-inconclusive` unless
the parent can reuse a previously persisted, still-valid receipt that already
bracketed that exact artifact and whose body, digest, identity, semantic time,
and scope remain type-preservingly identical on the final reread. A later
current-scope read is never a substitute for the missing earlier boundary.

GitHub's relevant semantic timestamps and HTTP `Date` headers have only
whole-second authority here. Equality between a pre-scope `Date` and the
artifact semantic time therefore cannot prove which event happened first: an
old-scope artifact may have been created earlier in that second, followed by a
same-head base retarget and the pre read. Treat equality as inconclusive rather
than binding the artifact retroactively to the later scope. This strict edge is
specific to the pre-to-artifact causal boundary; the exact artifact GET and
the parent-ordered post reads may share a second with the preceding event.

The frozen reaction-history `as_of_server_time` constrains historical semantic
records, not when the parent is allowed to collect or revalidate an artifact
receipt. Where that cutoff applies, the artifact semantic time must be within
the frozen window, but the exact artifact GET and post-scope response `Date`
values may be later while the bounded decision/final reread is still active.
Rejecting a receipt merely because its collection `Date` is after the history
as-of would conflate evidence time with observation time.

The cutoff also does not cap the semantic time of a current
`terminal-payload` or `mixed` result: such a result may arrive during the
bounded provider wait after declaration discovery and still decide the current
scope. The cutoff applies to historical reaction-profile samples and to the
separately bounded current reaction-only basis used by `thumbs-up-clean`, not
to strong current terminal evidence.

This receipt is artifact/scope provenance, not request provenance. It does not
name a request or run and does not establish request/run/artifact lineage. A
missing or malformed request-time sidecar still closes only request/reaction
authority, while a missing, malformed, unmatched, unstable, or over-budget
artifact-scope receipt makes that terminal artifact unusable for current-scope
precedence. Receipt capture and validation use a bounded, non-borrowing receipt
ledger under the fixed evidence resource profile; no receipt may create an
unbudgeted traversal or fresh deadline inside one decision pass.

The v1 contract deliberately defines **artifact-publication scope**. A
complete receipt authorizes the artifact for the whole-PR tuple observed around
its publication even when request history is unbound or an external narrative
says provider work began under an earlier merge base. It does not attest the
provider's internal input merge base. Only a valid same-head/different-merge-base
request sidecar proves `base-changed-same-head`; a missing or malformed sidecar
is `not-proved`, makes request policy unknown, and cannot veto an independently
trustworthy terminal result. Requiring unavailable launch-time scope would
restore the rejected request/run/artifact binding. A future
provider-authenticated input-base marker governed by a predeclared provider
profile may change this policy explicitly; inference from request timing or
caller narrative may not.

### Legacy Receipt Migration

Legacy receipt migration never adopts an old artifact retroactively. A
same-head request or terminal result observed before the parent captured the
version-1 artifact pre-scope boundary cannot acquire
`parent-recorded-terminal-artifact-scope-v1` authority from a later
current-scope read. Before any migration decision can complete, derive the raw
applicable artifact set from each complete current endpoint inventory, after
the ordinary actor, carrier, grammar, commit-applicability, inline-join, and
thread checks. An exact-provider terminal-looking identity remains in this raw
set when its grammar, role, or required thread state is malformed or unknown;
those defects cannot be filtered away before partitioning. Then prove this
exact disjoint union:

```text
raw_applicable_artifacts
  = receipt_bound_normalized_artifacts ⊎ legacy_unreceipted_audit
```

Here, receipt-bound normalized artifacts (normalized decision records backed
by their own valid version-1 artifact receipt) are the only positive terminal
authority. The legacy unreceipted audit (the closed negative/audit projection
for otherwise-applicable artifacts that lack that receipt) is not another
completion source. Match the three sets one-to-one by exact
`(channel, positive native id)`. Every raw applicable artifact appears exactly
once on the right, no identity appears in both members, and neither duplicate,
overlap, nor omission is allowed. A raw item that cannot be projected into one
of the two closed members makes the partition unproved rather than ignorable.

The selected newly receipted artifact supplies two pre-scope boundaries: the
raw HTTP `Date` from its pre-artifact pull-detail receipt and the raw HTTP
`Date` from its pre-artifact compare receipt. Every item admitted to
`legacy_unreceipted_audit` must have a trustworthy semantic server time
strictly earlier than both boundaries. Recompute this comparison from the raw
records and the selected artifact receipt in both the initial and final
selection passes. Equality at whole-second authority, a later legacy time, an
unknown or malformed semantic time or `Date`, an absent boundary, an invalid
receipt, or an unprojectable/malformed legacy artifact fails closed. A final
current-scope read never supplies the missing earlier boundary.

The legacy list is audit-only for positive authority, but it is not
verdict-neutral:

- An old clean is audit-only and can never establish clean or become the
  selected completion basis.
- An old top-level finding or an old finding whose joined target threads are
  all resolved follows ordinary terminal precedence. A later receipt-bound
  current-head clean may supersede it.
- An old finding with any still-unresolved applicable target thread remains a
  blocker even when the newly receipted artifact is clean. It cannot enter the
  tolerated legacy list, so the partition does not close.

An unreceipted malformed terminal artifact, unknown role, incomplete target
join, or unknown/malformed required item field likewise cannot enter the
tolerated legacy list. Each makes the partition unproved and fails closed; do
not hide it under an audit role.

Every completed terminal clean or findings result must therefore select an
artifact from `receipt_bound_normalized_artifacts` and embed that artifact's
valid receipt. No `legacy_unreceipted_audit` item may become a completion
basis. A legacy unresolved-thread blocker instead leaves the lane
`triple-inconclusive` and is never promoted into a receipt-bound basis. If no
independently validated stable receipt-bound blocker basis exists, report
literal `evidence_basis: null`; do not manufacture a basis merely to display
the rejected legacy artifact.

Preserve both complete initial and final raw endpoint inventories. For
migration completion, their provider decision-authority projections—terminal
artifacts, applicable findings, joined thread state, canonical provider
nonterminal audit records, the receipt-bound normalized member, and the closed
legacy member—must be type-preserving identical, and the disjoint partition
must close independently in both passes. Raw request, reaction, and
request-sidecar bytes remain on their separate plane: preserve and reevaluate
them, but request/reaction-only drift does not overturn an otherwise identical
receipt-bound terminal decision. This is the same result-present boundary used
outside migration.

Every non-null terminal-shaped `evidence_basis` exposes the single stable
closed list `legacy_unreceipted_artifacts`; an ordinary non-migration terminal
basis uses `[]`. The evaluator independently derives the list from the initial
and final raw inventories, requires the two type-preserving projections to be
identical, and emits only that one sorted list. Each item has exactly
`{scope_authority, role, channel, id, server_time, artifact_commit,
source_record_sha256}`. `scope_authority` is the exact literal
`unreceipted-audit-only-v1`; `role` is exactly `clean` or `finding`, where
`finding` covers every non-unresolved finding, whether top-level or
thread-backed with no unresolved applicable target thread. The report does not
claim a finer top-level-versus-resolved distinction. `channel` plus positive
native `id` is the canonical identity; `server_time` is the trusted semantic time;
`artifact_commit` is the preserved lowercase full SHA; and
`source_record_sha256` binds the canonical raw artifact/thread projection.
Sort only for serialization by `(channel, id)`. Unknown fields, an invalid
role, noncanonical identity/commit/digest, or a raw projection mismatch fails
closed. An unresolved thread, malformed terminal artifact, or unknown legacy
record is rejected before list emission rather than represented by another
role.

The agent never POSTs another same-scope request to repair this legacy gap.
There are only two recovery paths:

1. A separately authorized, ordinary substantive change creates a new head;
   the new scope epoch then follows the normal one-request producer policy.
   Never manufacture an empty or anchor commit for this purpose.
2. The caller may explicitly perform one caller-owned manual exact
   `@codex review` trigger on the unchanged head, but only after the parent has
   persisted the standard pre-artifact pull/compare scope pair. The agent
   neither performs nor repeats that POST, does not synthesize a request
   sidecar for it. Request policy therefore remains `unknown`, and reaction-only
   evidence is unavailable. Only a later terminal artifact that strictly
   follows the recorded pre boundary, satisfies the complete version-1 artifact
   receipt and final-stability contract, closes the raw/normalized legacy
   partition above, and wins normal terminal precedence may decide. It need not
   be attributed to the manual request.

A proved `base-changed-same-head` event is not a legacy-receipt gap and cannot
use the manual path; only a real new head can recover that lane.

If neither path produces a newly receipted terminal artifact, or the new
artifact is equal to the pre boundary at whole-second authority, the lane
remains `triple-inconclusive`. This migration rule preserves result-present
authority without weakening whole-PR publication scope or creating a hidden
request/run/artifact join. It also preserves alignment with the fixed Action
rationale: completion still comes from a trustworthy provider result without
request/run attribution; request markers and audit history remain separate;
and an ordinary older top-level or resolved-thread finding may be superseded by
a later current-head clean. Treating an unresolved provider thread as a blocker
is the existing playbook thread-safety extension, not a request-history veto.

Like the request-time sidecar, the receipt consists of point-in-time reads. It
proves the recorded pre/artifact/post observations and detects an observed
scope mismatch, but it does not prove that no intermediate `A -> B -> A`,
close/reopen, or other ABA transition occurred. Equality of the initial/final
raw decision-authority projections and their digests likewise cannot prove
that no intermediate provider-state ABA occurred, and no final digest proves
that GitHub state stayed unchanged after that digest was computed. Preserve
both limitations in reports rather than describing the envelope as continuous
scope or post-read stability attestation; a later observation invalidates the
prior completion decision.

## Terminal Artifact Precedence

Evaluate provider artifacts independently of request count:

1. Re-read exact PR lifecycle, `baseRefOid`, `headRefOid`, and the unique local
   merge base. Require the selected whole-PR range to remain exact.
2. Fully paginate issue comments, reviews, every associated inline review
   comment, every reaction on a current controlled request, all bounded-history
   candidate outcomes needed to compute the profile, and review threads. The
   profile is selected only after these reads; it cannot decide which evidence
   is fetched. When reaction clean is possible, preserve an independently
   fetched raw initial current endpoint inventory before deriving the
   normalized current snapshot or ancestry set.
   Aggregate issue-comment reaction counts do not identify the actor and
   cannot authorize `+1`; consume the fully paginated individual reaction
   records with their IDs, actors, content, and server times.
3. Require the unique matching
   `parent-recorded-terminal-artifact-scope-v1` receipt for every
   terminal-looking exact-provider artifact admitted to the receipt-bound
   normalized decision member. Validate its pre/artifact/post time envelope,
   exact artifact-time scope, and artifact body/digest/identity binding before
   using it as positive authority. Clean and malformed evidence require the
   exact current scope; a finding may use the proved-ancestor head rule above.
   A missing earlier boundary cannot be manufactured by a later fetch. A
   strictly older, otherwise well-formed pre-v1 artifact whose receipt is truly
   absent remains raw and may enter only the Legacy Receipt Migration
   audit-only member; it does not by itself veto a later receipt-bound result
   when that partition and all ordinary gates close.
4. Admit only exact provider identity. Terminal comment/review evidence
   requires REST `user.login == "chatgpt-codex-connector[bot]"` and
   `user.type == "Bot"`. A lookalike, missing field, or differently cased
   identity is inconclusive.
5. Parse terminal-looking issue comments and reviews only with the fixed
   grammar below and an exact commit binding. No other clean or finding syntax
   is active at this baseline. A terminal-looking malformed artifact is
   evidence conflict, not ignorable prose.
6. Before ordinary artifact ordering, fail closed on any exact-provider
   terminal-signal review whose state is `DISMISSED`, missing, or unknown. It is
   a whole-snapshot inconclusive blocker because no trusted transition time is
   available; its original `submitted_at` cannot make it older than, or
   superseded by, another artifact.
7. Order trustworthy terminal artifacts by trusted semantic server time. For
   a review, use `submitted_at`. For an issue comment whose body has never
   changed, use `created_at`; when `updated_at != created_at`, use
   `updated_at` because that is when the currently observed body became
   authoritative. A missing or contradictory edit time is inconclusive.
   Reactions use `created_at`. First take every terminal-looking artifact at
   the greatest semantic server time. If that equal-time set contains more
   than one source channel, fail closed before outcome or ID tie-breaking:
   numeric IDs from issue comments and reviews are different native namespaces,
   and the report contract has no predeclared cross-channel selector or
   multi-artifact basis. This applies even when the channels report the same
   outcome or one reports findings while another reports clean. Within one
   source channel, any malformed or scope-conflicting member blocks; otherwise
   any trustworthy finding in the set takes precedence over every clean. Only
   after semantic outcome and commit scope agree may the greatest positive
   stable numeric artifact ID in that same channel choose the reported basis.
   Incompatible artifacts without another provider-stable ordering signal are
   ambiguous; this baseline conservatively treats every equal-time
   cross-channel set as that case.
8. Select the latest trustworthy terminal artifact. A newer or equal-time
   malformed or scope-conflicting terminal-looking artifact blocks an older
   clean result.
   A newer finding blocks an older clean result. A latest explicit clean
   artifact may yield `clean` only after the finding and final-stability gates
   below.
9. If no trustworthy current-scope terminal payload exists, apply the selected
   provider profile. Only `thumbs-up-clean` can reach the weak `+1` fallback;
   `mixed` still requires terminal payload for a clean result. Any later legal
   exact-provider reaction—including `+1`, `eyes`, `heart`, or `confused`—
   remains audit evidence; it does not demote, replace, or reorder an already
   selected terminal payload. Only the reaction-only fallback restricts
   semantic content to `+1` plus compatible earlier `eyes`; every other
   exact-provider reaction content makes that weaker candidate `unknown`.
10. Perform the final re-read. Terminal clean/findings count only if scope,
   lifecycle, the provider artifact/thread/finding projection, canonical
   nonterminal provider audit records, every applicable artifact-scope receipt,
   and the selected artifact are unchanged, and every raw channel remains
   completely paginated and parseable. An already
   stable duplicate or pending request, an already stable later reaction, or raw
   current request/reaction records that change between the initial and final
   inventories do not veto the terminal result because they are not contrary
   verdicts. Preserve both raw inventories and recompute request policy and any
   reaction-only authority from the final complete evidence. Incomplete,
   ambiguous, or malformed request/reaction pages still fail closed for every
   plane that cannot be proved. Bounded historical profile-input drift or
   request-scope-sidecar-only drift likewise makes request policy and reaction
   authority `unknown`; it does not veto an independently stable terminal
   result. Reaction clean additionally requires stable request history/profile
   inputs, a new independent raw final current endpoint inventory, and repeated
   parent-owned local Git ancestry receipts for every raw-derived finding
   commit; normalized snapshot equality alone is insufficient.

An exact-App check or check run is service-start evidence only. It is not a
terminal provider artifact and never proves clean, even when its conclusion is
`success`.

### Fixed Terminal-Payload Grammar

The accepted grammar is deliberately narrower than arbitrary provider prose.
Treat an API body as a well-formed Unicode scalar-value sequence, then normalize
it in this exact order. `U+D800` through `U+DFFF` are not Unicode scalar values
and are rejected before normalization:

1. Replace CRLF, bare CR, vertical tab (`U+000B`), form feed (`U+000C`), NEL
   (`U+0085`), line separator (`U+2028`), and paragraph separator (`U+2029`)
   with LF (`U+000A`).
2. Reject NUL and every remaining C0/C1 control except HT (`U+0009`) and LF.
3. Remove only HT, LF, and ASCII space (`U+0020`) from both outer edges.
4. Apply no Unicode normalization, case folding, punctuation rewriting,
   Markdown rendering, or other whitespace transformation.

For issue-comment terminal detection, take the first LF-delimited line and its
first exact case-sensitive ASCII occurrence of `Codex Review`. The comment is
terminal-looking when that occurrence starts within the first 64 Unicode scalar
values and every preceding scalar is not an ASCII letter or digit. This
deterministically admits Markdown punctuation, spaces, and emoji-like prefixes
without defining a grapheme algorithm. If no such occurrence exists, the
comment is not a provider terminal candidate.

Starting at that occurrence, a first line is progress-only only when it equals
exactly `Codex Review in progress`, `Codex Review still in progress`, either
exact form plus `.`, or either exact form plus `: ` and 1 to 160 Unicode scalar
values containing no LF or control. A progress-only comment must have no later
nonempty line. Every other terminal-looking issue comment is evaluated by the
closed branches below. Here `control` means a C0/C1 `General_Category=Cc`
value; format characters such as `U+200D` ZERO WIDTH JOINER remain admissible
Unicode scalar values.

For a pull-request review, state admissibility and terminal-looking detection
are separate:

- REST `state == "PENDING"` is nonterminal. Retain it for the final re-read,
  but do not select it as a result.
- `APPROVED`, `COMMENTED`, and `CHANGES_REQUESTED` are terminal-looking states
  and continue to the closed grammar below.
- `DISMISSED` is terminal-looking but inadmissible. It is a whole-snapshot
  inconclusive blocker, not an ignorable review.
- A missing or unknown state is terminal-looking when the normalized review
  body is nonempty or one or more associated inline children exist. Such a
  review is also a whole-snapshot inconclusive blocker. A missing or unknown
  state with an empty body and no associated child supplies no terminal signal
  and cannot complete the lane.

Thus a terminal-looking review cannot disappear merely because its state field
is missing, unknown, or no longer one of the three admitted terminal states.
REST `submitted_at` records the original submission, not a trustworthy time for
a later state transition. Until a provider-stable state-transition timestamp is
defined, do not place these invalid-state blockers in ordinary artifact order
and do not let a later-looking clean supersede them. In a non-current scope,
their presence makes the historical universe inconclusive before window
filtering; original `submitted_at` cannot classify one as an expired
`confirmed-non-candidate`.

When the exact current scope contains exactly one fully validated invalid-state
blocker, that uniquely observed artifact may supply the inconclusive blocking
basis without claiming that `submitted_at` orders the state transition. When it
contains two or more, retain every blocker in `scope_authority_audit` and the
current `applicable_artifacts` projection, but set `candidate_basis`,
`source_ordering_key`, `source_evidence`, and report `evidence_basis` to `null`.
Neither list order, review ID, channel, nor original `submitted_at` may choose
one. A fully validated unresolved target-thread finding remains the explicit
higher-priority exception: it may supply its stable blocker basis while the
overall verdict stays inconclusive.

Only the following terminal payloads are accepted:

1. **Clean issue comment.** Require exact provider REST identity, exact
   `performed_via_github_app.slug == "chatgpt-codex-connector"`, and this
   anchored body:

   ```text
   Codex Review: Didn't find any major issues.[ OPTIONAL_TAGLINE]

   **Reviewed commit:** `<FULL_40_HEX_SHA>`
   ```

   `OPTIONAL_TAGLINE` is absent; exact ASCII `:rocket:`, `:tada:`, or `:+1:`;
   exact Unicode `🚀` (`U+1F680`), `🎉` (`U+1F389`), `👍` (`U+1F44D`), `✨`
   (`U+2728`), or `✅` (`U+2705`); or one exact stem below followed by exactly
   one of `.`, `!`, or `?`:

   ```text
   Nice work
   Chef's kiss
   What shall we delve into next
   Already looking forward to the next diff
   Keep them coming
   Swish
   Another round soon, please
   Breezy
   Can't wait for the next one
   More of your lovely PRs please
   Bravo
   Keep it up
   Delightful
   Hooray
   You're on a roll
   ```

   The reviewed commit marker occurs exactly once, uses lowercase full SHA
   text, and must resolve to the selected current head. The only permitted
   suffix is two LF characters followed by this exact disclosure block:

   ```text
   <details> <summary>ℹ️ About Codex in GitHub</summary>
   <br/>
   Codex has been enabled to automatically review pull requests in this repo. Reviews are triggered when you
   - Open a pull request for review
   - Mark a draft as ready
   - Comment "@codex review".
   If Codex has suggestions, it will comment; otherwise it will react with 👍.
   When you [sign up for Codex through ChatGPT](https://openai.com/codex), Codex can also answer questions or update the PR, like "@codex address that feedback".
   </details>
   ```

2. **Clean pull-request review.** Require REST `state == "APPROVED"`, a native
   lowercase full-SHA `commit_id` equal to the selected current head, and a
   normalized body exactly equal to `No findings.`. The review's associated
   inline-comment endpoint and the raw GraphQL thread/comment connections must
   be fully paginated. The target child set is only the exact-provider REST
   children whose positive canonical `pull_request_review_id` equals this
   selected review ID. Every target must complete the canonical one-to-one
   thread join below. The review is clean only when that target set is empty.
   A valid target child is a finding and therefore takes precedence over the
   clean-looking parent; an unread, incomplete, malformed, orphaned,
   duplicate, or conflicting target join is inconclusive or malformed, never
   clean. This finding classification is independent of `isResolved`;
   resolution is applied only when deciding whether a later clean outcome
   remains blocked. An `APPROVED` / `No findings.` review with zero children
   is the only clean review shape in this branch. Fully fetched human or
   unrelated-bot comments, null-parent replies,
   and threads containing no target child remain audit context. They neither
   create a selected-review finding nor supply resolution for one. Empty
   bodies, `Looks good.`, coverage summaries, alternative punctuation,
   additional prose, links, HTML, comments, and code fences are malformed
   under this stricter playbook grammar.
3. **Top-level finding.** Require a normalized body with the exact first line
   `### 💡 Codex Review` followed by one or more nonempty LF-delimited finding
   lines. The body either ends after the final finding line or appends exactly
   two LF characters plus the exact disclosure block above; no other suffix or
   intervening line is accepted. Each finding line has this exact grammar:

   ```text
   - [P<SEVERITY>] <TITLE> — <BLOB_URL>
   ```

   `SEVERITY` is one ASCII digit in `0` through `3`. `TITLE` is 1 to 240
   Unicode scalar values, has no control, LF, or exact substring ` — `, and
   begins and ends with neither HT nor ASCII space. `BLOB_URL` is an ASCII RFC
   3986 absolute URI with no userinfo, port, query, or trailing punctuation and
   this exact shape:

   ```text
   https://github.com/<EXACT_OWNER>/<EXACT_REPO>/blob/<FULL_40_HEX_SHA>/<PATH>#L<POSITIVE_LINE>[-L<POSITIVE_LINE>]
   ```

   The scheme and host are lowercase as shown. Owner and repository are the
   exact selected ASCII GitHub path segments. `PATH` is nonempty and consists
   only of RFC 3986 `pchar`, `/`, and uppercase `%HH` escapes; after strict
   UTF-8 percent decoding it has no empty, `.`, or `..` segment. A line number
   is ASCII `[1-9][0-9]*`. Every finding line in one artifact uses the same
   lowercase full SHA. For a pull-request review, require native full-SHA
   `commit_id` to equal that SHA and REST state `COMMENTED` or
   `CHANGES_REQUESTED`; an `APPROVED` finding body is malformed. The selection
   and ancestry rules then decide whether the extracted SHA is current, an
   eligible ancestor, or stale.
4. **Inline-parent review container.** Let `P` be the parent review's native
   lowercase full-SHA `commit_id`. Require `P` to equal the selected current
   head or a locally proved ancestor of it. A `COMMENTED` review is an
   inline-parent container only in one of two forms:

   - **Empty form:** the normalized parent body is empty and at least one fully
     joined exact-provider inline child exists. No reviewed-commit marker is
     present or required.
   - **Nonempty form:** at least one fully joined exact-provider inline child
     exists and the normalized body is exactly the three lines below followed
     immediately, with two LF characters, by the exact disclosure block above:

   ```text
   ### 💡 Codex Review
   Here are some automated review suggestions for this pull request.
   **Reviewed commit:** `<FULL_40_HEX_SHA>`
   ```

   In the nonempty form, the marker SHA must equal `P`. In both forms, every
   child must have exact provider REST identity, positive canonical
   `pull_request_review_id` equal to the parent review ID, lowercase full-SHA
   `commit_id == P`, lowercase full-SHA `original_commit_id == P`, and a
   nonempty normalized body. The fully paginated child list and review-thread
   join supply the findings. A missing child, missing or conflicting parent
   join, missing/mismatched child SHA, incomplete page, or any other parent
   body is inconclusive or malformed, never clean.

The enclosing current scope and the artifact commit are distinct fields. In
every normalized current record, `scope.head` is the exact current PR head and
never changes to match an older artifact. A clean issue comment's
`parsed_commit` and a clean review's native `commit_id` must equal that current
`scope.head`; a clean bound only to an ancestor cannot complete the current
lane. A finding issue comment's `parsed_commit`, finding review's native
`commit_id`, or inline-parent/child commit may instead be the current head or a
locally proved ancestor. Preserve that SHA as the artifact commit while keeping
`scope.head` current, and admit it to the applicable projection only through
the matching parent-owned local Git object/ancestry receipt. A missing or
unreadable ancestry result is inconclusive; a proved non-ancestor remains
audit-only and cannot block or complete the current scope. It must not appear
in normalized `active_top_level_findings` or `unresolved_thread_findings`; such
an injection is a raw/normalized projection mismatch and selects `unknown`.

This separation is required for the ordinary fix sequence `H1 finding -> H2
clean`: the raw and normalized current projections must retain the H1 ancestor
finding so the later H2 clean can supersede a top-level finding under the
ordering rule. A resolved H1 target-thread finding may likewise cease blocking,
but an unresolved applicable target thread still blocks H2 clean. Never make
the projections agree by rewriting the finding commit to H2 or by dropping the
ancestor finding.

Every terminal issue-comment candidate uses this closed snapshot schema before
its body enters any clean, finding, malformed, current, historical, or report
path:

```yaml
complete: true
artifact_kind: terminal-payload | active-top-level-finding | malformed-terminal-artifact
outcome: clean | findings | malformed
channel: issue-comment
id: <canonical positive issue-comment ID>
stable_artifact_id: <same canonical positive issue-comment ID>
api_url: https://api.github.com/repos/OWNER/REPO/issues/comments/<id>
url: https://github.com/OWNER/REPO/pull/<pr>#issuecomment-<id>
user_login: chatgpt-codex-connector[bot]
user_type: Bot
app_slug: chatgpt-codex-connector
body: <raw REST body>
normalized_body: <body after the fixed normalization above>
grammar_status: accepted | malformed
terminal_looking: true
created_at: <trusted REST server time>
updated_at: <trusted REST server time>
server_time: <created_at when unedited, otherwise updated_at>
server_time_field: created_at | updated_at
parsed_commit: <lowercase full SHA parsed from the accepted body>
scope:
  repository: OWNER/REPO
  pr: <positive PR number>
  pr_merge_base: <lowercase full SHA>
  head: <lowercase full SHA>
```

The object rejects unknown fields and review-only fields such as `state`,
`submitted_at`, `commit_id`, and inline-thread joins. Require
`updated_at >= created_at`. When the two times are equal, require
`server_time == created_at` and `server_time_field == created_at`; when they
differ, require `server_time == updated_at` and
`server_time_field == updated_at`. `api_url`, `url`, actor, App, body,
normalization, grammar result, parsed commit, and scope all participate in the
type-preserving initial/final equality check. The issue-comment ID shares its
native namespace with request and provider-declaration comments, so one ID
cannot describe conflicting records in those roles.

For a clean issue comment, `parsed_commit == scope.head` is mandatory. For a
finding issue comment, `parsed_commit` is the artifact commit and may differ
from `scope.head` only when current raw authority proves it is an ancestor;
the enclosing scope remains current. Apply the same distinction to a review's
native `commit_id` and to its joined inline children.

Before actor or parent classification, validate every associated inline record
against the same closed nine-field schema: `id`, `url`, `user_login`,
`user_type`, `pull_request_review_id`, `commit_id`, `original_commit_id`,
`body`, and `normalized_body`. Reject unknown or missing fields, non-full-SHA
commit IDs, invalid parent IDs, and body-normalization mismatches. Only after
that validation may a complete human, unrelated-bot, or exact-provider
null-parent record remain audit context rather than target finding evidence.
Audit-only status never permits malformed evidence to disappear.

All other terminal-looking exact-provider comments or reviews are malformed.
In particular, these near misses never complete clean: a missing or duplicate
reviewed-commit marker, a 10-character SHA, a mixed-case or mismatched SHA,
`No findings!`, an empty `APPROVED` review, `Looks good.`, an unlisted tagline,
an extra footer, a short-SHA or cross-repository finding URL, conflicting
finding SHAs, a malformed percent escape or line anchor, a clean body
containing a finding line, an empty inline parent, or an inline child whose
parent ID, `commit_id`, or `original_commit_id` differs. A `PENDING` review
remains nonterminal; `DISMISSED`, missing, or unknown state with a terminal
signal is malformed. Tests must lock at least one positive example for each
active grammar branch and every named near-miss class before the grammar
changes.

The following records are normative positive examples, with `OWNER` and `REPO`
replaced by the exact selected repository:

```text
Codex Review: Didn't find any major issues.

**Reviewed commit:** `0123456789abcdef0123456789abcdef01234567`
```

```yaml
id: 123456789
state: APPROVED
commit_id: 0123456789abcdef0123456789abcdef01234567
body: No findings.
children: []
```

```text
### 💡 Codex Review
- [P1] Example finding — https://github.com/OWNER/REPO/blob/0123456789abcdef0123456789abcdef01234567/path/to/file.py#L10
```

```yaml
parent:
  id: 123456789
  state: COMMENTED
  commit_id: 0123456789abcdef0123456789abcdef01234567
  body: ""
children:
  - pull_request_review_id: 123456789
    commit_id: 0123456789abcdef0123456789abcdef01234567
    original_commit_id: 0123456789abcdef0123456789abcdef01234567
    body: "[P1] Example inline finding"
```

The first record is accepted only as an exact-App issue comment, the second
only as a pull-request review, and the third only after repository substitution
and the applicable issue-comment or review binding checks. The fourth requires
exact provider identity on parent and child and the full join contract above.

The contract fixture matrix is normative:

| Fixture | Branch | Mutation from positive record | Classification |
| --- | --- | --- | --- |
| `clean-issue-positive` | clean issue comment | none | `clean` |
| `clean-review-positive` | clean pull-request review | none | `clean` |
| `clean-review-with-inline-finding` | clean pull-request review | associated inline finding | `findings` |
| `clean-review-unread-children` | clean pull-request review | associated inline set unavailable | `malformed` |
| `clean-review-wrong-parent-child` | clean pull-request review | exact-provider child bound to a different review | `malformed` |
| `clean-review-malformed-human-audit-child` | clean pull-request review | human audit child missing `commit_id` | `malformed` |
| `clean-review-malformed-unrelated-bot-audit-child` | clean pull-request review | unrelated-bot audit child with an unknown field | `malformed` |
| `clean-review-malformed-null-parent-audit-child` | clean pull-request review | null-parent audit child with mismatched normalization | `malformed` |
| `finding-positive` | top-level finding | none | `findings` |
| `finding-with-disclosure-positive` | top-level finding | exact provider disclosure suffix | `findings` |
| `inline-parent-positive` | inline-parent review | none | `findings` |
| `inline-parent-nonempty-positive` | inline-parent review | exact container body and disclosure | `findings` |
| `clean-issue-short-sha` | clean issue comment | 10-character marker | `malformed` |
| `clean-issue-missing-marker` | clean issue comment | missing marker | `malformed` |
| `clean-issue-duplicate-marker` | clean issue comment | duplicate marker | `malformed` |
| `clean-issue-mixed-case-sha` | clean issue comment | uppercase SHA text | `malformed` |
| `clean-issue-mismatched-sha` | clean issue comment | different full SHA | `malformed` |
| `clean-issue-unlisted-tagline` | clean issue comment | unlisted tagline | `malformed` |
| `clean-issue-extra-footer` | clean issue comment | unlisted footer | `malformed` |
| `clean-issue-containing-finding` | clean issue comment | appended finding line | `malformed` |
| `clean-review-empty` | clean pull-request review | empty body | `malformed` |
| `clean-review-punctuation` | clean pull-request review | `No findings!` | `malformed` |
| `clean-review-looks-good` | clean pull-request review | `Looks good.` | `malformed` |
| `review-pending-terminal-body` | pull-request review state | `PENDING` with clean-shaped body | `nonterminal` |
| `review-dismissed-terminal-body` | pull-request review state | `DISMISSED` with clean-shaped body | `malformed` |
| `review-missing-state-terminal-body` | pull-request review state | missing state with clean-shaped body | `malformed` |
| `review-unknown-state-terminal-body` | pull-request review state | unknown state with clean-shaped body | `malformed` |
| `inline-parent-missing-state` | pull-request review state | missing state with associated inline child | `malformed` |
| `finding-cross-repository` | top-level finding | different repository | `malformed` |
| `finding-short-sha` | top-level finding | 10-character URL SHA | `malformed` |
| `finding-mixed-sha` | top-level finding | two finding lines with different SHAs | `malformed` |
| `finding-bad-percent-escape` | top-level finding | `%2f` in path | `malformed` |
| `finding-bad-line-anchor` | top-level finding | zero line anchor | `malformed` |
| `inline-parent-empty-children` | inline-parent review | no child | `malformed` |
| `inline-parent-wrong-parent` | inline-parent review | different `pull_request_review_id` | `malformed` |
| `inline-parent-wrong-child-commit` | inline-parent review | mismatched child `commit_id` | `malformed` |
| `inline-parent-wrong-original-commit` | inline-parent review | mismatched child `original_commit_id` | `malformed` |

Contract tests must encode this table as data, exercise every row against a
closed reference classifier, and assert the four active positive branches are
all represented. Adding or changing a grammar branch requires changing both
the table and classifier in the same reviewed range.

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

The frozen historical `as_of_server_time` bounds reaction-profile sampling; it
does not erase later live current-scope request-policy evidence. If the final
current reread first observes a fully validated, receipt-bound R2 after that
cutoff, retain it in the final request audit and report the resulting duplicate
warning. Terminal selection compares the complete provider artifact/thread/
finding projection while isolating this request-plane delta, so stable `clean1`
can still pass. An absent, malformed, or over-budget R2 sidecar instead makes
request policy unknown. Neither case admits R2 into historical samples or the
weak reaction fallback, and neither exception applies to a newer finding,
malformed terminal artifact, unresolved thread, or scope/lifecycle change.

## Finding Authority

### Thread-Backed Findings

An inline finding backed by a GitHub review thread uses only the raw GraphQL
thread node's `isResolved` value. `isOutdated` is retained as audit context but
is not a substitute for resolution.

The evidence basis stores the fully paginated raw REST inline-comment records
and the fully paginated raw GraphQL `reviewThreads` pages, including each
thread's stable `id`, typed `isResolved`, typed `isOutdated`, outer
`pageInfo`, every nested thread-comment page and its `pageInfo`, and each
comment's GraphQL `id`, `fullDatabaseId`, `url`, and
`pullRequestReview { id fullDatabaseId }`. Both connections start at a null
cursor, follow an opaque non-empty `endCursor` exactly only when typed
`hasNextPage == true`, and terminate at typed `hasNextPage == false` even when
that terminal page retains a non-empty cursor. The raw audit retains all
fetched comments and threads; target selection happens only after complete
pagination.

Normalize each non-null GraphQL `BigInt` to canonical positive decimal text.
Normalize a REST JSON numeric ID only when it is a positive integer; booleans,
floats, zero, negatives, signs, leading zeros, and other text forms are
invalid. For one selected review, derive the target set only from raw REST
records with exact provider identity and a positive canonical
`pull_request_review_id` equal to the selected review ID. Join every target
REST child to exactly one raw GraphQL comment by normalized REST
`id == fullDatabaseId`, then require
`pullRequestReview.fullDatabaseId` to equal the selected review ID and require
the canonical URLs to agree. Every target child participates in one and only
one join. A target orphan, duplicate mapping, parent-review conflict, URL
conflict, missing page, broken cursor chain, or wrong JSON type makes the
snapshot incomplete and fails closed.

Fully fetched REST records from confirmed humans or unrelated bots, replies
whose `pull_request_review_id` is null, GraphQL comments that are not the
unique target match, and threads that contain no target remain audit context.
They do not have to be promoted into the target join, cannot create or resolve
a selected-review finding, and cannot make an otherwise malformed target join
valid. A missing or ambiguous actor is not a confirmed non-target; apply the
provider-identity fail-closed rule before excluding it. Likewise, an
exact-provider REST record with a positive selected-review parent is always a
target and cannot be relabelled as a reply or unrelated audit context to avoid
the join.

Fields such as `thread_id`, `thread_resolved`, or `is_resolved` attached to a
REST inline record are synthesized assertions, not raw GitHub authority. Do
not accept them in place of the raw pages and canonical one-to-one join, and do
not copy them into the raw record schema. A derived reader-facing
`thread_findings` summary is allowed only after the raw join succeeds and must
be recomputable field for field from those pages.

An unresolved target-thread finding is not superseded. A later clean terminal
artifact can establish the provider's latest terminal outcome, but the lane
and PR readiness cannot claim completed-clean while any applicable
target-thread finding remains unresolved. Resolution on a human-only,
unrelated-bot-only, null-parent-only, or otherwise unrelated thread is audit
context and cannot resolve a target finding.

### Top-Level Findings

A top-level issue-comment finding has no GitHub resolution bit. It remains
active until trusted provider ordering and commit ancestry show that a later
clean artifact supersedes it.

A top-level finding may be superseded by a later clean artifact on the same or
successor head. “Successor” requires proved commit ancestry; timestamp order
alone is insufficient. A prior-head clean is stale evidence for a newer head
and does not complete the current whole-PR lane.

The complete current projection therefore includes applicable findings whose
artifact commit is the current head or a proved ancestor, while every clean
candidate must bind the exact current head. The enclosing `scope.head` remains
the current head for both cases. A later current-head clean may supersede the
older top-level ancestor finding only after it remains present in that
projection and wins the strong ordering rule; an unresolved applicable thread
finding is never removed or superseded by that clean.

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

The bounded history is mandatory before reaction-only clean can pass and before
reaction behaviour can upgrade a profile to `mixed`. It is not a veto over an
independently complete current-scope terminal artifact. If historical
provider declaration is missing, a historical traversal or pagination chain is
incomplete, a historical endpoint or artifact ledger exceeds its budget, or
historical request-scope sidecars are missing, malformed, or unstable, but the
independent initial/final **current** endpoint traversals and current artifact
receipts still prove a trustworthy stable terminal clean or findings payload,
select `terminal-payload`, set affected request policy to `unknown` where
applicable, and reject only `mixed` plus reaction-derived authority. Do not
report `mixed` from unverifiable reaction history, and do not turn a strong
current terminal result into `unknown` merely because the weaker adaptation
plane failed. This exception is plane-scoped: a failed current endpoint
traversal or current artifact ledger/receipt, or any current identity, scope,
lifecycle, thread, ancestry, grammar, selection, or final-stability failure,
still blocks that terminal result.

Evaluate optional historical adaptation before the final current-evidence
reread. Allocate fresh current endpoint/sidecar/artifact trackers after that
history attempt, even if an earlier current probe already exists. Each
inventory deadline bounds that inventory's active validation and is sealed
when the phase completes; elapsed time spent in another inventory must not age
out an already completed phase. Immediately before report success, recheck the
fresh final-current deadline and require every retained phase tracker to have
completed without failure. This ordering keeps a historical timeout from
leaking into current authority while preserving the current final-reread gate.

For dynamic history, first collapse evidence to at most one final candidate
outcome per distinct immutable scope key: repository identity, PR number,
frozen whole-PR `base_sha` equal to `pr_merge_base`, and head OID. Never use
the moving `baseRefOid` as this key: base-branch advancement that leaves
`pr_merge_base` and head unchanged is still one outcome. Apply the
terminal-precedence rules inside that scope before it enters the candidate set.
Duplicate requests, duplicate reactions, and multiple artifacts for one scope
never increase the sample size.

Enumerate the complete same-repository historical candidate universe for the
last 30 days before deciding eligibility. The one canonical as-of receipt is
the exact response receipt from the first direct authenticated REST GET of the
provider-declaration issue comment:
`https://api.github.com/repos/<owner>/<repo>/issues/comments/<declaration_id>`.
The closed receipt is exactly
`{method, request_url, status, date_header, body_utf8, body_sha256}`. Require
`GET`, the canonical declaration URL, exact integer `200`, canonical
IMF-fixdate, strict UTF-8 JSON, and a recomputed digest. Project the declaration
snapshot independently from the raw body and require type-preserving equality
with the recorded initial snapshot. Repeat the same receipt validation for the
final GET, require its projected snapshot to be identical and its Date not
earlier, but use only the initial receipt as the window anchor. Require
`as_of_receipt` to equal that initial receipt, `as_of_api_url` to equal its
`request_url`, and `as_of_server_time` to equal the parsed initial `Date`.
Freeze those values before discovery starts. A current-PR endpoint, local
clock, final-read response time, caller timestamp, or literal
`window_days: 30` label is not evidence. Set
`window_seconds: 2592000` and derive the exact half-open interval
`(window_start_exclusive = as_of_server_time - 2592000,
window_end_inclusive = as_of_server_time]`. Record the source URL, all four
values, and the initial receipt. Self-reported `authenticated` or
`tls_attested` booleans are not receipt fields and add no authority.

This frozen as-of bounds semantic historical outcomes; it is not a claim that
the later raw discovery traversals observed an immutable repository snapshot at
that instant. Raw updated-desc pull rows may therefore carry an `updated_at`
later than `as_of_server_time`. Those rows are discovery observations, not
eligible historical outcomes merely because the live endpoint returned them.

The raw `discovery_endpoint_transcript`, not the candidate array, inventory
entries, or count, is the historical-universe authority. Store it in both the
initial and final inventory, with each inventory produced by its own
independent fetch traversal. Its closed top-level shape is exactly
`{schema_version: 4, repository, scope_discovery, scopes}`.
It has no `request_scope_receipts` member. Request-time scope receipts remain
the independent parent-owned sidecar above and are supplied beside the
transcript to the fixed projector; adding them neither changes this envelope
nor authorizes another fetch kind.

Each historical inventory and each current raw endpoint inventory carries a
parent-owned `resource_budget` sibling beside, never inside, the unchanged
version-4 transcript. It must type-preservingly equal this closed profile:

```yaml
profile: github-codex-evidence-resource-budget-v1
schema_version: 1
max_seeded_pull_requests: 512
max_controlled_requests: 512
max_fetch_attempts: 8192
max_retained_pages: 4096
max_records: 20000
max_page_body_bytes: 8388608
max_retained_utf8_bytes: 67108864
deadline_seconds: 900
```

These are fixed maxima; evidence may not raise or lower them. Apply the profile
to three non-borrowing ledgers for one inventory: the endpoint
transcript/current detail fetch set, the request-scope-sidecar validation
plane, and the terminal-artifact-scope-receipt validation plane. All three
share the inventory's same monotonic start and 900-second deadline. Count each
sidecar and artifact-wrapper array before iteration. Each controlled request
charges one sidecar record plus its five retained raw responses (pre
pull/compare, POST, and post pull/compare) as five attempts, pages, and records.
Each terminal artifact charges one wrapper plus its five retained raw
responses (pre pull/compare, exact artifact GET, and post pull/compare) under
the same caps. Every response applies the body cap and counts the UTF-8 bytes
of its request URL, `Date`, and body.

Create the artifact-receipt ledger exactly once per inventory decision pass.
Validate each type-preservingly immutable wrapper once and memoize that closed
result for candidate ordering, complete audit, profile, outcome, and report
projection. Those consumers must not refetch, reparse, recharge, or create a
fresh tracker or deadline per candidate, scope, or recomputation. Aggregate
artifact-ledger overflow invalidates the complete terminal-artifact projection
and selects `unknown`; accepting a validated prefix is forbidden. A missing,
malformed, or over-budget request sidecar instead makes request policy unknown
and disables reaction authority, but its isolated bounded validation work
cannot consume or invalidate an independently complete terminal-artifact
ledger. No ledger may borrow unused capacity from another.

Memoization has its own fixed admission envelope because the memo key is not
authority evidence and therefore must never become an unmetered copy of the
untrusted evidence tree. `github-codex-memo-fingerprint-guard-v1` accepts only
strict JSON values with string object keys and finite floats. It permits at
most 64 container levels, 20,000 entries in one container, 2,000,000 value/key
occurrences (each object key and each value counts once), 128 bits in one
integer, 8,388,608 UTF-8 bytes in one scalar, and 67,108,864 aggregate scalar
UTF-8 bytes. The integer cap keeps conversion to a small fixed operation;
GitHub native IDs and server times are far below it. It processes strings in 4,096-character chunks and checks
the owning plane's shared deadline at entry, exit, every 1,024 occurrences,
and every 1,048,576 scalar bytes. Cycles, unsupported values, or any exceeded
bound fail closed in that endpoint, sidecar, or artifact plane.

The order is normative. First perform the iterative, no-hash structural
preflight. Apply it to the bounded policy-binding envelope too, including the
provider declaration and local ancestry map, before deriving that envelope's
streaming namespace digest; never derive a namespace with canonical JSON. On a
cache miss, immediately compute a bounded, sorted-key, type-tagged,
length-framed SHA-256 baseline after admission; never call `json.dumps` or build
a complete canonical body for the memo key. This first digest is a
non-authoritative content-stability observation, not authority evidence or
cache admission. Then run the owning plane's uncached evidence validator so
its record, page, and retained-byte charges succeed. A failed ledger discards
the baseline, and a truthy partial result cannot override that failure. After a
healthy validator return, compute a second bounded confirmation fingerprint.
The no-hash, baseline, and confirmation summaries must match, and the baseline
and confirmation digests must match, before either a result is returned or a
cache entry is written. A mismatch does neither. Healthy positive and negative
results retain only the confirmed digest. A cache hit remains the bounded
no-hash preflight followed by one content digest: summary drift rejects before
hashing, and an unchanged summary is rehashed against the cached digest. Thus
an equal-size nested content edit cannot reuse either result. The protected
property is exact memo-subject content stability across cold validation, not
merely object identity or container shape. These point observations cannot
exclude an `A -> B -> A` change between the two cold digests or a mutation
after the final confirmation hash, so immutable snapshots and a fresh
reread/context remain required. A mutation after a cached negative remains
fail-closed rather than being upgraded in place. Transient fingerprint bytes
are not retained evidence and are not charged again; zero-charge deadline
observations still advance. This sequencing preserves immutable-result
memoization without letting the bounded baseline become authority, survive a
failed evidence ledger, or let a sidecar failure consume the independent
terminal-artifact ledger.

Memo subjects and cache identity are plane-specific. Endpoint memoization sees
only the retained transcript or the exact single-scope `fetches` list;
sidecar memoization sees only `request_scope_receipts`; artifact memoization
sees each artifact wrapper. Composite normalized inventory records are checked
afresh from those memoized plane results and are never fingerprinted against a
single plane tracker. Therefore a deep or oversized unused sidecar cannot mark
the endpoint or artifact tracker failed, and the same namespace/object pair
cannot reuse a cache entry created under another plane tracker. The root
deadline coordinator is never an owning memo ledger. Artifact wrapper and
wrapper-array cache entries bind the exact artifact tracker, while lookup also
validates exact scope types before key construction, so Python equality such as
`True == 1` cannot alias a previously validated PR scope. The narrowed current
single-scope subject is permitted only when the excluded transcript scaffold
has the exact schema, repository, scope, pull number, and field set; its root,
scope array, scope record, fetch array, and repository text must all be exact
built-in JSON types rather than equality-compatible subclasses. Complete,
sidecar-blind, ancestry-filtering, and candidate-ordering paths share one
tracker-bound wrapper-array precharge before any wrapper iteration; only exact
built-in list/dict scaffolds enter that path. A filtered projection proves that
each retained wrapper is an identity-preserving subsequence of the charged
source arrays before it reuses that ledger: cloned entries, reordering, and
multiplicity beyond the source are rejected, while an accepted projection is
seeded without charging the same wrapper array again. The wrapper plus its five
responses therefore always costs six records exactly once. The outer current
raw inventory likewise requires an exact built-in object/fetch list, exact
built-in repository and head strings, and an exact positive integer PR number
before rebuilding the narrow transcript; subclass, boolean, or floating-point
equality aliases cannot be normalized into current authority.

For endpoint evidence, charge a fetch attempt before every REST or GraphQL
request, including retries. Charge known page and record counts before cloning
or serialization, then charge retained UTF-8 bytes and the body cap before
hashing, JSON decoding, or appending. The per-page byte cap applies to
`body_utf8`; the aggregate counts UTF-8 bytes for `request_url`, `link_header`
when present, `request_after` when present, and `body_utf8`. Each REST array
element or direct-object response is one record, and each GraphQL review-thread
node and nested comment node is one record. Every accepted REST status is an
exact integer `200`, never a boolean or float alias. Pull-detail and compare are
direct-object endpoints: each has exactly one retained page, a null `Link`
header, and a JSON object root. Every REST collection page has an array root;
its unique Link relations preserve the fixed HTTPS host, path, and decoded
non-page query map, use one literal canonical `page=N` token, treat an omitted
page and `page=1` as the same first page, and advance by following the exact raw
`rel=next` URL through consecutive page numbers. For updated-desc pull
discovery, `last` is stable across retained pages and cannot claim a page after
a no-`next` natural end or before the current `next`. A later page or an array
wrapper can never supply a direct-object scope response. Check the monotonic deadline at
every boundary and once again before success. Initial and final inventories
receive independent starts; provider waiting between them is not charged. Any
endpoint-ledger overflow discards that traversal and selects `unknown`; it never
authorizes truncation, newest-N sampling, or a caller-selected envelope. The
offline transcript can be recounted against page, record, and byte limits, but
does not itself attest the parent's monotonic clock or unretained retry attempts,
so the trusted fetcher must enforce those controls while collecting.

`scope_discovery` is exactly
`{recent_pull_requests, recent_request_comments, anchors}`. The first source
starts at
`GET /repos/<owner>/<repo>/pulls?state=all&sort=updated&direction=desc&per_page=100`.
Its dedicated parser retains complete pages through the first page containing
an exact RFC3339 `updated_at <= window_start_exclusive`, requires every earlier
row to be newer than the cutoff, requires all rows globally non-increasing by
typed timestamp, and permits at most 100 rows per page. A final retained page
with a canonical unique `Link rel="next"` is complete only after that boundary
(`window-boundary-complete`); without `rel="next"`, the traversal is
`natural-end-complete`. A next link without a boundary is incomplete. Other
unique canonical GitHub pagination relations may coexist with `next`;
duplicate, unknown, malformed, or inconsistent relations fail closed. Only
rows newer than the cutoff seed raw detail scopes; boundary and older rows are
witnesses. Because ordering is descending, every row with
`updated_at > as_of_server_time` must form one contiguous validated future
prefix before every row at or before as-of. Future-prefix rows remain in the
budget-charged raw pages and seed the same complete detail traversal as any
other newer row. They are never accepted as historical semantic evidence from
the pull row alone.

Each raw-derived and stored per-traversal projection retains its exact complete
stop reason. After both traversals independently prove complete, the joint
stable comparison treats `window-boundary-complete` and
`natural-end-complete` as equivalent complete termination forms. It removes
only that transport-level stop label from the derived comparison view; raw and
stored evidence keep it, and an incomplete, malformed, or unproved traversal
can never be normalized into either complete form.

The second source fully paginates
`GET /repos/<owner>/<repo>/issues/comments?sort=updated&direction=desc&since=<RFC3339-cutoff>&per_page=100`.
It validates every record whose body is the exact `@codex review` string,
regardless of actor type or `performed_via_github_app`. Discovery is a scope
completeness step, not an identity verdict: a comment whose canonical
`issue_url` and `html_url` jointly route to a PR seeds that PR before the full
detail traversal and request-sidecar plane later accept a valid controlled
request or select `unknown`; an untrusted, App-authored, or ambiguous strict
request may not make its PR disappear from the union. Canonical ordinary-issue
`@codex review` comments are validated, retained, and budget-charged as raw-only
non-seeds; mismatched or ambiguous PR-like routing fails closed. Each seeded raw
record must occur one-to-one, type-preserving raw-equal in that PR's detail
issue comments. Controlled-comment IDs remain unique across PR and ordinary
issue routes. Canonical decimal page and native-ID tokens are limited to 39
digits and 128 bits before integer conversion; overlong values fail closed
without raising.
This source is necessary because a reaction does not imply that GitHub advances
the PR's `updated_at`; a recent historical request can seed an otherwise
old-updated PR. It proves neither request/run lineage nor request-time scope. A
historical reaction-only outcome is eligible only when its parent appears in
this feed and both request and response fall inside the frozen interval. The
explicitly anchored current PR retains the independent single-scope current raw
path and is never a historical sample.

`anchors` binds the exact current PR and authenticated declaration PR. The raw
detail seed is the union of newer pull rows, controlled-request PRs, and both
anchors. `max_seeded_pull_requests: 512` counts that pre-filter union and all of
its detail traversals, including future-prefix-only pull seeds, never boundary
witnesses or cumulative repository PR count. A 513th raw union member, an
incomplete source, or a budget overflow selects `unknown`; no prefix or
truncation is allowed. Each scope is exactly
`{pull_number, fetches}`, where `pull_number` is a canonical positive integer
from that union.
A version-3 transcript lacks this bounded dual-source completeness proof and
cannot prove reaction fallback.
Each fetch is exactly
`{kind, transport, parent_comment_id, pages}`. The only fetch kinds are
`pull_requests`, `compare`, `issue_comments`, `reviews`, `inline_comments`,
`review_threads`, and `request_reactions`.

Every pull number in that union seeds exactly one complete PR-detail traversal.
There may be no missing union member, duplicate scope, caller-injected scope,
or scope silently removed before detail parsing. The scope's `pull_requests`
fetch is the canonical detail GET for that exact number. The fixed parser takes
`base.sha` and `head.sha` from that raw detail record, binds those exact values
into the canonical compare request, and takes `pr_merge_base` only from
`compare.merge_base_commit.sha`; neither `base.sha` nor
`merge_commit_sha` substitutes for the merge base. When updated-desc discovery
also supplied the PR, its typed list-row `state` must equal the pull-detail
lifecycle state.

After every raw scope is completely parsed, the fixed projection records one
closed `retained_pull_scope_audit` item for every PR that remains in the
semantic union. Each item contains exactly `pull_number`, pull-detail
`base_oid` and `head_oid`, compare-derived `merge_base`, and normalized closed
`lifecycle`, sorted by unique positive pull number. This audit covers
request-feed and anchor-only seeds plus record-free confirmed non-candidates;
for a PR present in both local unions, the corresponding initial/final audit
items must be type-preserving identical. The complete arrays may differ only by
a fully validated item that appears in exactly one local union and also appears
identically in that side's `future_prefix_omission_eligibility_audit`; the joint
coordinator handles that difference below. This prevents a shared scope with no
separate authority record from hiding base, head, merge-base, or lifecycle
drift without rejecting an eligible one-sided future-prefix scope before joint
coordination.

Only after that raw seed/detail closure succeeds may one traversal classify a
future-prefix-only pull seed as locally eligible for coordinated omission.
Eligibility requires all of the following: neither the since-cutoff request
feed nor either anchor also seeds the PR; the complete detail traversal proves
no semantic record in `(window_start_exclusive, as_of_server_time]`; it proves
no controlled request, exact-provider, ambiguous/provider-like, exact-child,
ambiguous-child, or other provider/policy-bearing semantic record at any time;
and every observed post-as-of record, if any, is one of the already defined
fully validated removable confirmed-different suffix forms. An otherwise empty
future-prefix scope can therefore be eligible. The per-traversal parser does
not omit that scope: it remains in the local stable pull list, union,
`retained_pull_scope_audit`, `scope_classifications`, and applicable authority
projections until both traversals have been validated. The raw pull row, every
raw detail page, and all attempts/pages/records/bytes remain charged and
retained. A request-feed or anchor co-seed is never eligible. An incomplete
page or join, cross-cutoff edit, unclassifiable record, or observed
base/head/lifecycle drift fails closed instead of granting eligibility.

Each traversal records local eligibility in a closed
`future_prefix_omission_eligibility_audit`. Every item contains exactly
`pull_number`, pull-detail `base_oid` and `head_oid`, compare-derived
`merge_base`, and normalized closed `lifecycle`, sorted by unique positive pull
number. The stored projection must type-preservingly equal the raw-derived
projection for that traversal. The eligibility audit is a closed subset of
that traversal's retained audit identities. Only the initial/final joint coordinator may
make omission effective: the PR must occur in exactly one complete local union
and in that same traversal's eligibility audit. It then removes that one-sided
scope only from the derived stable comparison view; it never rewrites or drops
raw evidence. A PR observed in both traversals is always retained in the stable
comparison even if either or both traversals mark it eligible, so unrelated
post-as-of activity cannot turn an already retained record-free scope into an
omission. Compare the remaining coordinated views exactly. Eligibility items
for the same pull number in both traversals must also be type-preserving
identical. Thus a newly observed one-sided irrelevant or empty scope can
converge without letting a repeatedly observed scope hide base, head,
merge-base, or lifecycle drift. Live `updated_at`, pull-row digest, and endpoint
order remain deliberately outside this audit. The two independently validated
complete stop reasons are likewise transport observations rather than fixed
semantic drift; their raw values remain audited under the rule above.

The seed/detail closure includes the authenticated declaration PR. Its PR
number must occur as an explicit anchor in the discovery union, drive the same
complete pull/compare/comments/reviews/inline/thread traversal as every other
seeded PR, and expose exactly one issue-comment record type-preservingly equal
to the canonical declaration resource projected from both stable direct GET
receipts. The direct declaration GET remains declaration authority; discovery
proves only that the authenticated artifact also exists in its repository/PR
context.

Declaration authority and terminal classification are orthogonal roles. The
same raw issue-comment artifact may prove the exact provider declaration and,
independently, classify under the ordinary terminal grammar as clean, findings,
or malformed. Matching the declaration line never suppresses terminal-looking
classification. Only a declaration record independently classified as
nonterminal is audit-only; if its seeded PR contains no other provider
behaviour, that declaration-only scope is `confirmed-non-candidate`, the record
does not enter `entries`, and it does not increase `candidate_universe_count`.
A comment accepted by the exact closed progress-only grammar is likewise
retained in `nonterminal_records` and is audit-only. No other exact-provider
free-form issue-comment prose may be downgraded to a confirmed non-candidate:
prose that is neither an authenticated declaration-role match nor closed
progress-only syntax fails the projection and selects `unknown`. A
terminal-looking exact-provider record that misses every accepted terminal
branch remains a `malformed` historical candidate under ordinary terminal
precedence when its final basis is inside the frozen interval; it is never
hidden by its simultaneous declaration role or by the progress exception. A
fully parsed malformed terminal record at or before the exclusive lower
boundary remains visible audit evidence under the temporal classification rule
below, but does not become an in-window candidate.

A schema-version-4 `review_threads` response stores the real GraphQL
`comments { nodes pageInfo }` connection inside each raw thread node; it never
stores the report's normalized `comments.pagination_complete/pages` shape in
the response body. Version 4 accepts that nested connection only when its
first response is already complete (`hasNextPage == false`). A terminal
`endCursor` may be null or a non-empty string and never requests another page.
A nested `hasNextPage == true` requires a separately
bound child-cursor fetch shape that this schema does not define, so the profile
is `unknown`; an implementation must introduce a new transcript schema version
rather than folding multiple normalized pages into a fabricated raw response.
`parent_comment_id` is non-null only for the corresponding controlled-request
reaction fetch. A scope with no controlled request has no reaction fetch; a
scope with requests has exactly one complete reaction traversal per request.

Every page is exactly
`{request_url, status, link_header, request_after, body_utf8, body_sha256}`.
A REST page records the exact request URL, integer status, raw `Link` header or
null, `request_after: null`, bounded raw body, and recomputed lowercase body
SHA-256. Raw GitHub REST timestamps remain canonical whole-second RFC3339
`YYYY-MM-DDTHH:MM:SSZ` text. Before ordering, window checks, or policy-projection
hashing, the fixed projector converts them to positive integer Unix seconds by
strict round trip; JSON numbers, booleans, offsets, fractional seconds, and
noncanonical or invalid dates are rejected. A GraphQL page records exact
request URL `https://api.github.com/graphql`, integer status,
`link_header: null`, the exact requested `request_after` cursor or null, and
the same bounded raw body/digest. Every response page also carries raw
`repository.nameWithOwner` and `pullRequest.number`; the fixed parser requires
them to equal the transcript repository and positive pull number before it
reads raw `pageInfo.hasNextPage` and `pageInfo.endCursor`. This response-side
scope binding is mandatory even for an empty `reviewThreads.nodes` result, so
a complete response from another owner, repository, or PR cannot substitute
for the selected scope. REST Link page relations are validated semantically
against the fixed HTTPS host, path, and non-page query map; omitted page and a
literal canonical `page=1` are equivalent, while each raw `rel=next` URL is
followed exactly.
GraphQL traversal starts at null, requires each next `request_after` to equal
the prior raw `endCursor`, and terminates only at typed
`hasNextPage == false`. A terminal GraphQL page requires typed
`hasNextPage == false`; `endCursor` may be null or a non-empty string, and a
retained terminal cursor never triggers another fetch. A top-level GraphQL
`errors` member, when present,
must be an array. An empty array is admissible; `null`, a non-array value, or a
nonempty array fails closed. A nonempty array is partial evidence even when the
same response also contains apparently usable `data`; this rule applies
independently to every outer pagination page.

The transcript envelope is closed, but endpoint JSON objects are forward
compatible: the versioned fixed projector reads and type-checks every field
used by policy while ignoring unrelated GitHub response additions. The raw page
digest still binds all response bytes. A versioned fixed parser independently
derives the fixed semantic seed list from stable closed
`{pull_number, base_oid, head_oid}` identities in positive pull-number order;
pull-list `updated_at`, raw pull-row digest, and endpoint row order are not part
of that fixed semantic identity. The parser independently derives the complete
set of candidate scope keys and scope-final bases from the retained semantic
records. It also derives the closed `scope_classifications` list in positive
pull-number order, with exactly one
`{pull_number, scope_key, classification}` item for every PR in that
traversal's complete local semantic union. A fully traversed future-prefix-only
seed that satisfies the narrow eligibility rule remains in this local
projection; only the joint coordinator may remove a proved one-sided scope
from the derived stable comparison view.
The classification is exact `current`, `historical-candidate`, or
`confirmed-non-candidate`; a pending controlled request, ambiguous identity,
incomplete traversal, or unparseable record cannot be downgraded to
`confirmed-non-candidate`. A receipt-bound request whose sidecar proves the
same repository/PR but an older head is not pending for the parsed epoch: when
no current-epoch provider result or terminal artifact exists, an
old-epoch-only scope remains audit-only, produces no entry, and is classified
`current` for the exact current scope or `confirmed-non-candidate` otherwise.
Missing or unmatched sidecars and a same-head/different-merge-base tuple remain
fail-closed; the exception is only for a fully proved older head. The parser
then derives `entries` in the closed
shape `{scope_key, source_ordering_key, source_evidence}` and
`candidate_universe_count`. `source_evidence` is exactly
`{carrier, channel, semantic, native_identity, source_record_sha256}`. It binds
reaction versus terminal-artifact carrier, request-reaction versus review or
issue-comment channel, `+1` / `eyes` / clean / findings / malformed semantics,
the native parent-and-ID or channel-and-ID identity, and the digest of the
canonical policy projection. A review result digest includes the review, its
exact-provider target inline records, and their joined target thread nodes.
It does not promote human, unrelated-bot, null-parent, or unrelated-only
threads into provider result authority. An independent scope-level
`review-thread-audit` bundle hashes every non-excluded semantic GraphQL thread
projection and enters `nonterminal_records`, so changes to those audit-only
threads still fail initial/final convergence. Issue-comment digests bind the
projected comment; reaction digests bind the eight-field parent request, its
exact request-time scope sidecar, and the projected child reaction. Same time
and numeric ID alone therefore cannot substitute one carrier, channel, scope
epoch, or semantic result for another.

The only nullable-selection entry is the exact current scope with two or more
fully validated invalid-state blockers and no selected unresolved-thread basis:
both `source_ordering_key` and `source_evidence` are `null`, while the complete
scope audit and applicable-artifact projection retain every blocker. Such an
entry can support only an inconclusive result and can never enter historical
window ordering or reaction fallback.

Window filtering happens only after a seeded scope has been completely
traversed, parsed, and reduced by terminal precedence. A fully valid
provider-bearing non-current scope whose final `source_ordering_key.server_time`
is at or before `window_start_exclusive` remains in the raw transcript and
`scope_classifications` as `confirmed-non-candidate` for this frozen interval,
but it is omitted from `entries` and `candidate_universe_count`. A scope is a
`historical-candidate` for this interval only when its final basis satisfies
`window_start_exclusive < server_time <= window_end_inclusive`. This audit-only
classification never permits an incomplete traversal, ambiguous identity,
malformed projection, or post-`as_of_server_time` policy-bearing record to be
hidden as an expired non-candidate; those cases still fail closed. Only the
fully validated confirmed-different suffix records defined below are raw-only
and excludable from the fixed semantic projection.

The fixed semantic projection also derives `scope_authority_audit`, sorted by
positive pull number, for every retained semantic scope that contains policy-relevant
request, reaction, provider artifact, or provider nonterminal evidence. Each
item is exactly
`{scope_key, lifecycle, requests, reactions, applicable_artifacts,
nonterminal_records}`. `requests` retains every controlled request plus its
derived scope and exact sidecar when valid; `reactions` retains every individual
in-cutoff reaction, including confirmed-different actors. Raw-only post-cutoff
confirmed-different suffix records remain in the transcript but do not enter
this fixed semantic projection. `applicable_artifacts` retains
every provider terminal/finding/malformed source with channel, semantic time,
native ID, outcome, native or parsed artifact commit, and canonical source
digest rather than only the selected one; and `nonterminal_records` retains
exact-provider pending/progress plus
in-cutoff confirmed-different and fully fetched null-parent/unrelated audit
context. Because version 4 has no inline timestamp, such inline context remains
semantic unless it belongs to a fully validated post-cutoff
confirmed-different review bundle. This list is derived from the raw transcript
and is not an inventory entry or sample-count input. It keeps current and
temporally excluded provider scopes auditable and makes any policy-relevant
node, semantic, lifecycle, or source-evidence drift visible across the two
traversals.

For an in-window reaction candidate, the closed candidate evaluator requires
its complete request/sidecar and reaction audit plus lifecycle and every
provider artifact to equal the matching raw scope-authority projection. This
includes earlier `eyes`, confirmed-different reactions, duplicate parents, and
unselected terminal artifacts. When a terminal artifact determines a
candidate, request/reaction-plane defects remain isolated and do not veto that
stronger carrier; lifecycle and the complete provider artifact projection must
still match. Raw-only nonterminal records are compared between traversals even
though they do not enter the normalized candidate array.

The closed candidate evaluator independently validates each complete candidate
array element and requires its full authority projection to equal the
raw-derived entry. Initial/final candidate arrays must also be type-preserving
identical. Audit-only normalized fields that do not originate in one endpoint
are not falsely described as raw-derived. These checks never prove the
transcript complete merely by agreeing with one another. In particular,
deleting an in-window candidate, deleting its inventory entry, and decrementing
the count while leaving its raw fetch record present must fail closed. Missing
required child fetches, an unreadable page, a repository-list or detail traversal that
exceeds any predeclared page/count/byte/time evidence budget, a broken
Link/cursor chain, a body-digest mismatch, initial/final semantic drift, or any
projection mismatch selects `unknown`; no completeness flag can override it.
Never truncate the discovery union, skip a seeded PR, or keep an older
in-budget subset after overflow. A version-3 transcript has no bounded
dual-source discovery closure and therefore cannot prove `thumbs-up-clean`, even when
its derived candidates, entries, and counts are internally consistent.

The parent GitHub fetch path that captured each response is a trusted workflow
boundary. The stored offline transcript and hashes preserve the bytes supplied
to the decision, but do not themselves provide a cryptographic proof of GitHub
TLS origin. Do not describe the record as a TLS attestation.

A candidate basis at the lower boundary is outside the window; one at the upper
boundary is inside. The fixed projector first validates complete pagination,
closed syntax, native ID, canonical URL/parent joins, timestamp grammar, and
the exact/confirmed-different/ambiguous actor classification. Controlled
`@codex review` requests, exact-provider records, and ambiguous/provider-like
records must be no later than `as_of_server_time`; a later one makes the
profile `unknown`. A non-request issue comment proved to have been created
entirely after the cutoff, a confirmed-different submitted review after the
cutoff, or a confirmed-different reaction created after the cutoff is retained
in the raw transcript but excluded as an irrelevant suffix from the fixed
semantic projection. This lets two independent traversals converge when
ordinary humans or unrelated bots write after the frozen observation; it does
not move the cutoff. An issue comment created at or before the cutoff but
edited after it remains fail-closed because its cutoff body cannot be
reconstructed. A future confirmed-different review may carry only the fully
validated unrelated child/thread bundle allowed by the closed join; an exact
or ambiguous child is not hidden with that parent. Version 4 has no
inline-child timestamp, so a later human reply on an in-cutoff provider review
cannot be inferred to be a removable suffix and remains semantic drift. A
`PENDING` review retains its required null `submitted_at` and follows the
existing identity/nonterminal rules. Normalized candidate/current arrays may
not inject any raw-only suffix record.

Issue-comment provider identity is a joint actor/App classification. Only the
exact Bot actor together with exact
`performed_via_github_app.slug == "chatgpt-codex-connector"` is exact. If
either half claims the provider while the other half is absent or conflicts,
the record is ambiguous/provider-like and fails closed; it is never a
confirmed-different suffix that may be ignored.

Raw discovery includes the exact current scope and every confirmed
non-candidate PR, including the PR that carries the authenticated declaration.
The fixed parser first completes and validates every seeded detail traversal,
derives the full classified scope inventory, and only then excludes the exact
current scope from the historical candidate set. The current outcome is
validated separately and never counts toward the three-outcome history
minimum. A historical scope is a candidate when it contains a terminal-looking
provider record (including a malformed one), an exact-bot reaction on a
receipt-bound controlled request, or a provider-like record whose identity is
missing or ambiguous. Historical candidates exclude the exact current scope.
Only the independently nonterminal role of the one authenticated declaration
and independently nonterminal closed progress-only records remain audit-only
exceptions. A declaration-bearing record that also matches clean, findings,
or malformed terminal grammar retains and is ranked by that terminal role. Any
other exact-provider free-form prose fails closed rather than silently
confirming a non-candidate. A scope containing only confirmed different actors
is not provider behaviour and becomes a confirmed non-candidate only after full
parsing; its raw scope and bounded records remain in discovery audit evidence.
They cannot cause ordinary human comments, reviews, inline threads, or
reactions to masquerade as provider behaviour. A confirmed different actor is
not provider behaviour. A provider terminal artifact may form a candidate even
when no controlled request was observed. Reaction-only evidence still requires
the exact controlled parent and its matching request-time scope sidecar.
Complete pagination and scope inventory must prove that universe and its
recorded count by derivation from the raw transcript. The initial and final
enumerations must be semantically identical for the same frozen interval. A PR
already retained in that fixed semantic inventory may acquire unrelated
post-as-of human or unrelated-bot activity between traversals and still
converge when its stable pull/base/head identity, lifecycle, cutoff-in evidence,
provider/policy evidence, classification, and authority projection are
unchanged. A new raw future-prefix-only seed may likewise appear in only one
traversal and be omitted from the coordinated stable view only under the
narrow fully traversed eligibility rule above.
Validate each traversal's page digests, REST links, GraphQL cursor chain, and
seed-to-detail closure independently. The two raw transcript envelopes, page
bodies, body digests, and opaque cursor tokens need not be byte-identical.
Opaque GraphQL cursor bytes need only form a valid chain within their own
traversal; type-preserving equality of the fixed semantic projection core,
`scope_classifications`, candidate `entries`, candidate arrays, and recorded
count, together with the complete `scope_authority_audit`, establishes final
equivalence. The core includes exact equality of
`retained_pull_scope_audit`, even for request/anchor-only or record-free
confirmed non-candidates. The joint coordinator derives one-sided effective
omissions from the two complete local unions plus their
`future_prefix_omission_eligibility_audit` arrays. A PR present in both unions
is never omitted. Exact audit equality is required for every eligibility pull
number present in both arrays. Raw pull-row timestamps/digests/order and fully
validated one-sided eligible future-only seeds are not fixed-semantic drift.
Repeatedly observed scope base/head/merge-base/lifecycle drift,
controlled-request or provider/policy-bearing evidence, cross-cutoff edits,
incomplete pages, or any other semantic or candidate-set drift still fails
closed. For
`thumbs-up-clean`, the separately evaluated current reaction-only outcome's
selected basis must not be later than the same `as_of_server_time`; its
reaction-fallback raw evidence snapshot is subject to that bound as well. This
sentence does not constrain a strong current `terminal-payload` or `mixed`
artifact.

After applying terminal precedence inside each scope, record that final
candidate outcome's ordering basis as `candidate_basis.kind`,
`candidate_basis.server_time`, and
`candidate_basis.stable_artifact_id`. A reaction supplies this basis only when
the scope's final candidate outcome is reaction-only. If a terminal payload,
malformed terminal artifact, active top-level finding, or unresolved thread
finding determines the scope outcome, that artifact supplies the basis; an
older reaction cannot hide it. Validate the basis against the complete scope
evidence for every candidate before sorting, including candidates that will
fall outside the selected 10-outcome window. This pre-sort validation includes
the candidate's stable initial/final scope snapshot, every required pagination
flag, all provider-like reactions across every controlled request parent, and
terminal precedence. When a terminal or finding artifact determines the scope
outcome, later `+1` and `eyes` reactions remain in the audit but cannot replace
or reorder that artifact's basis. When the scope outcome is reaction-only, a
later `eyes` or another provider-like reaction must change or invalidate the
reaction basis. A later terminal artifact or an incomplete evidence page
always changes or invalidates the recorded basis, even when that candidate
would otherwise rank eleventh.

The exact-current multiple-invalid-state exception above instead records
`candidate_basis: null`: those blockers prove inconclusiveness but cannot supply
a single authorized ordering basis. It is not a historical candidate and does
not relax the complete-snapshot audit.

Sort candidates newest first by the validated candidate-basis server time,
then stable artifact ID. If any candidate lacks a trustworthy or correctly
bound ordering basis, the profile is `unknown` and reaction-only clean is
disabled. Select exactly the first 10 candidates when 10 or more exist;
otherwise select the complete candidate set. Never skip an incomplete,
conflicting, or unfavourable candidate and continue to an older one. Every
selected candidate must have exact provider identity, complete pagination,
stable recorded scope, and a determinable evidence basis. If any selected
candidate cannot prove those properties, the profile is `unknown` and the
current `+1` cannot pass.

Every reaction-only outcome also requires at least one exact parent-recorded
issue comment whose normalized body is exactly `@codex review` for that
immutable scope, plus an individual exact-bot `+1` reaction fetched from that
request comment's fully paginated reactions endpoint. Enumerate every accepted
same-scope controlled request parent, not just the parent selected as the
`+1` basis, and fully paginate each parent's individual reactions. Record each
request's closed eight-field projection and its exact one-to-one
`parent-recorded-request-scope-v1` sidecar. Both pre/post raw scope projections
must equal this candidate's immutable scope, and the POST response must project
type-preservingly to those eight request fields, including exact
`user.login`/`user.type`. This sidecar version accepts
only the unedited creation response: require `updated_at == created_at`, use
that value as the request semantic time, and record
`request_server_time_field: created_at`. A later edited request remains audit
evidence but cannot enter reaction authority without a future predeclared
edit-receipt version. Record every reaction's
positive ID, `parent_request_id`, the exact
`issues/comments/<parent_request_id>/reactions?per_page=100` fetch URL,
`created_at`, content, login, and type. GitHub's
[issue-comment reaction list endpoint](https://docs.github.com/en/rest/reactions/reactions#list-reactions-for-an-issue-comment)
does not return a reaction self URL, so never synthesize one. The stable native
identity is the tuple of the exact canonical fully paginated parent endpoint
and the returned positive reaction ID. The parent ID and fetch URL must equal
the enclosing audited request and selected request when applicable; nesting a
reaction under a request in local data is not parent evidence by itself. Prove
strict trusted-server ordering against that fetched parent:
`reaction.created_at > request.request_server_time`.
Missing/contradictory edit time, a reaction that predates an edit into
`@codex review`, a missing/malformed scope sidecar, a receipt-derived old-epoch
scope, or a reaction without that direct parent makes the selected candidate
unclassifiable and the reaction profile `unknown`, even when the reaction actor
is the exact bot. None of those request-plane failures invalidates an otherwise
independent trustworthy terminal artifact.

For reaction-profile classification, retain confirmed different actors in the
complete audit but exclude them from provider semantic ordering. A confirmed
different actor has a nonempty login other than the exact provider login and
either REST `type == "User"` or REST `type == "Bot"` with no ASCII
case-insensitive substring `codex` in that login. A missing login/type, the
exact login with a non-`Bot` type, or a differently cased or other
`codex`-containing bot login is provider-like identity ambiguity, not a
confirmed different actor; it makes the candidate unclassifiable and the
profile `unknown`.

Across all accepted same-scope request parents, de-duplicate only repeated API
records with the same positive reaction ID. Order the remaining exact-provider
reactions globally by `(created_at, positive numeric ID)`. One or more `+1`
records may collapse to the latest `+1` outcome. That selected `+1` must also
belong to the unique accepted request with the greatest request semantic time
and be strictly later than the semantic time of every accepted same-scope
request. Equal-time latest requests are ambiguous. A duplicate request later
than the selected parent, with no qualifying `+1` of its own selected as the
basis, leaves the weak fallback pending or `unknown`. Exact-provider `eyes`
records are compatible only when they are strictly earlier than the selected
`+1` in the global order. Any exact-provider reaction on any same-scope parent
with other content, an `eyes` at or after the selected `+1`, a reaction at or
before its own request semantic time, or a record whose positive ordering ID
is missing makes the candidate unclassifiable and the profile `unknown`.
Aggregate reaction counts and a single selected parent's reaction page cannot
prove the absence of a cross-parent conflict.

The three-outcome minimum applies only to selecting reaction-only
`thumbs-up-clean`. Here, “observed behaviour” means behaviour in the
deterministic selected outcome window—exactly the newest 10 eligible
historical outcomes when at least 10 exist, otherwise the complete eligible
set—plus the separately evaluated current scope. All candidates in the
complete 30-day universe are still validated before sorting. A valid candidate
that ranks outside the selected 10 remains a completeness, ordering, and audit
input, but its payload kind does not itself select the provider profile.
Within the selected window, the minimum never downgrades terminal-payload
behaviour: terminal-payload behaviour alone selects `terminal-payload`, and
eligible terminal-payload plus reaction-only behaviour selects `mixed`, even
when fewer than three selected scopes are available. When no selected
terminal-payload behaviour exists, fewer than 3 distinct selected
reaction-only outcomes yields `unknown`. `thumbs-up-clean` requires 3 to 10
distinct selected outcomes, every one reaction-only and none containing a
clean terminal payload.
Provider-explicit `+1` semantics must be recorded from an authoritative
provider statement; repeated observation alone is insufficient. At this
baseline, the only active declaration authority is an exact provider-authored
GitHub issue-comment artifact fetched directly from its canonical REST resource
and re-read unchanged. Require exact
`user.login == "chatgpt-codex-connector[bot]"`,
`user.type == "Bot"`, and
`performed_via_github_app.slug == "chatgpt-codex-connector"`; a positive
numeric artifact ID; exact repository, PR, API URL, and HTML URL binding; and
consistent `created_at`, `updated_at`, selected semantic server time, and field
name. Its body must contain exactly once, as one LF-delimited line, the exact
provider text:

```text
If Codex has suggestions, it will comment; otherwise it will react with 👍.
```

Record `github_reaction_glyph: "👍"` and its GitHub REST reaction content
`github_reaction_content: "+1"`. This is the active provider-authored
declaration that an exact `+1` is the reaction-only clean outcome. Record the
exact asserted line and SHA-256 of its normalized content. Normalize that field
as a well-formed Unicode
scalar-value sequence by replacing CRLF and bare CR with LF, making no other
change, encoding the result as UTF-8 without a byte-order mark, and hashing
those exact bytes. Record this algorithm as
`normalization: crlf-and-cr-to-lf+utf8`; trimming, Unicode normalization,
Markdown rendering, case folding, and local paraphrase are forbidden.

Generic `issuer`/`source` strings, an arbitrary documentation URL, a local
paraphrase with a self-consistent hash, a copied disclosure without exact REST
actor/App identity, or a synthesized provider record are not authority.
Parent-owned code must fetch the declaration through the trusted GitHub API;
caller-supplied fields alone never authenticate it. The declaration envelope
and both identical snapshots use the closed, predeclared field set above;
unknown fields and JSON type aliases are not forward-compatible authority.
Both independent bounded dual-source discovery traversals must also include the
declaration's bound PR as an explicit anchor, fully traverse it, and find
exactly that raw issue-comment record once. Declaration matching does not consume or suppress terminal
classification: the same artifact remains eligible for ordinary
clean/findings/malformed classification. Only when that record is independently
nonterminal is it audit-only and, by itself, leaves that PR
`confirmed-non-candidate`; this contextual check does not replace either direct
declaration GET receipt or manufacture a provider result.
Expanding the declaration
authority set later requires a predeclared source kind, authentication and
issuer binding, closed schema, exact accepted text/digest, final re-read, and
positive plus near-miss contract fixtures. Until then, other declaration forms
select `unknown`.

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

### Current Raw Provider-Evidence Authority

A normalized `current.initial_snapshot` / `current.final_snapshot` pair is a
derived reader-facing view. Even when those two objects agree, it cannot prove
that the current endpoint universe was fetched or that every current/ancestor
finding commit was checked locally. It is insufficient for terminal clean,
terminal findings, or `+1` clean.

Before accepting any current terminal clean/findings result or current
reaction-only clean, the parent independently fetches two complete raw current
endpoint inventories: one initial traversal and a new final traversal
immediately before acceptance. Each inventory has the closed endpoint shape
`{repository, pull_number, head, resource_budget, fetches}` and may additionally
carry the separate `request_scope_receipts` sibling used by request/reaction
authority; no other root field is accepted. `resource_budget` is mandatory and
must type-preservingly equal the fixed profile above. Its `fetches` use the same
closed fetch/page records, pagination rules, raw bodies, and digests as
discovery schema version 4 and cover the current pull detail, compare, issue
comments, reviews, associated inline comments, raw GraphQL review
threads/comments, and every controlled-request reaction endpoint.
`request_scope_receipts` is parent-owned sidecar evidence, not a member of or
new kind inside those fetches. The two inventories are independent API
traversals, not aliases, copies of one body, normalized snapshots, or
projections supplied by the caller. Both must independently derive the same
complete provider-artifact, target-thread, and finding-commit sets.
Request/reaction set equivalence and sidecar stability are additionally
mandatory only when classifying request policy or reaction evidence. Missing
pages, over-budget traversal, provider artifact/thread drift, or finding-commit
drift still blocks terminal authority; a missing, malformed, or sidecar-only
drift instead makes request policy and the affected reaction authority
`unknown` without erasing an independently stable terminal payload.

From each raw inventory, before applying ancestry or resolution filtering, the
fixed projector derives every distinct lowercase full finding commit exposed
by a top-level finding or an exact-provider selected-review target child. A
missing or malformed commit binding remains a malformed/blocking artifact; it
cannot be omitted from the derivation. For every derived full commit, the
parent—not a reviewer, caller, normalized snapshot, or GitHub payload—records
one local Git ancestry receipt against the exact current head in both the
initial and final phases. The receipt's closed fields are exactly
`{finding_commit, head, object_check_return_code,
ancestry_return_code}`. With lazy fetching and credential prompting disabled,
`object_check_return_code` is the exact return code from locally resolving
`<finding_commit>^{commit}` and must be `0`.
`ancestry_return_code` is the exact return code from
`git merge-base --is-ancestor <finding_commit> <head>` and must be exactly:

- `0`: the finding commit equals or is an ancestor of the current head, so the
  finding is applicable to reaction clean;
- `1`: local Git proves that the finding commit is not an ancestor of the
  current head, so it remains audit evidence but is not a current/ancestor
  blocker.

A missing ancestry receipt, missing local object, duplicate or extra ancestry
receipt, a return code other than the exact values above, a raw-derived
commit-set mismatch, provider-artifact/thread drift, or ancestry-receipt drift
makes the current terminal and reaction classification `unknown`. The initial
and final ancestry-receipt arrays must be type-preserving identical and must
each cover exactly the full commit set derived from its corresponding raw
inventory. Request-scope sidecars remain a separate plane: their absence,
malformation, or reread drift cannot veto a stable terminal payload, but it
makes request policy and reaction authority `unknown`.

For ordinary terminal completion, the complete raw projection must equal the
normalized current record before terminal precedence is applied. Legacy
receipt migration instead proves the explicit raw-to-receipt-qualified join
`raw_applicable_artifacts = receipt_bound_normalized_artifacts ⊎
legacy_unreceipted_audit`; the normalized current record contains only the
receipt-bound wrappers, while the closed audit-only member remains derived
from both raw inventories. A raw-only artifact or thread that is neither in
the receipt-bound normalized member nor admissible under that exact legacy
partition makes the profile `unknown`. An
unresolved applicable target-thread finding still blocks terminal clean; an
older top-level finding may be superseded only under the documented strong
terminal-precedence rule and must remain present in the compared projection.
For reaction completion, any applicable top-level finding blocks clean, and
any applicable target-thread finding whose raw GraphQL thread has typed
`isResolved == false` also blocks clean. Human, unrelated-bot, null-parent,
and unrelated-only thread state cannot contribute resolution, while a
malformed target join still fails closed. Every accepted terminal or reaction
`evidence_basis` embeds both independent raw current endpoint inventories and
both parent-owned local Git ancestry-receipt arrays; external ledgers or
normalized current snapshots do not replace them.

A raw current endpoint inventory is already selected to one exact PR and
contains exactly one retained detail fetch set. It does not contain a
repository-wide `scope_discovery` seed. Its parser charges and parses the real
pull-detail page exactly once, derives the scope from that page plus compare,
and validates the outer PR/head selector against the result. It must not create
or charge a synthetic seed, pre-parse the pull under another tracker, grant a
second deadline, or mutate retained bytes after budget validation.

### +1 Fallback

+1 fallback requires all of the following:

1. `provider_profile is thumbs-up-clean`; `mixed` cannot use this fallback.
2. The parent directly fetched, authenticated, and twice matched the active
   exact-provider GitHub declaration artifact above. Generic issuer/source
   labels, copied prose, and self-hashed paraphrases do not satisfy it.
3. The complete bounded 30-day same-repository historical candidate universe,
   derived from a schema-version-4 bounded dual-source discovery union,
   excludes the exact current scope only after every raw-union-seeded PR was fully
   traversed and parsed, and has type-preserving stable initial/final discovery
   projections. It selects 3 to 10 outcomes
   and every selected candidate is eligible under the profile rule above. No
   incomplete, conflicting, ambiguous, over-budget, or unfavourable candidate
   was skipped. A version-3 transcript cannot satisfy this condition. Every
   selected history entry records its immutable scope, exact selected
   controlled request, exact child `+1` reaction, every accepted same-scope
   request/reaction audit, the scope-final `candidate_basis`, and strict
   request-semantic-time-before-reaction ordering. The trusted GitHub
   `as_of_server_time`, exact half-open interval, complete classified seed
   inventory/count, and every pre-sort candidate basis also satisfy the window
   contract above.
4. The parent recorded the exact accepted request comment for the exact
   current whole-PR scope, including its closed eight-field projection and
   one-to-one `parent-recorded-request-scope-v1` sidecar. The sidecar contains
   complete pre/post pull-detail and compare raw receipts plus the exact POST
   response, and both scope projections equal the current immutable tuple,
   before any reaction is consumed.
5. The reaction has exact provider identity.
6. The `+1` was created strictly after the unedited request's `created_at`;
   this sidecar version admits no edited request into reaction authority.
7. Complete pagination covers request comments, issue reactions, issue
   comments, reviews, associated inline comments, and review threads. The
   independently fetched initial and final raw current endpoint inventories
   are complete, stable, and embedded in the basis; normalized current
   snapshots are not a substitute.
8. The PR remains open and unmerged, and the final base, head, unique merge
   base, and frozen range prove stable current scope.
9. There is no trustworthy current-scope terminal artifact of any outcome and
   no current-scope terminal-looking malformed artifact. The weaker condition
   “no newer trustworthy terminal artifact” is insufficient: in `mixed`, a
   terminal payload remains authoritative even when the `+1` is later.
10. Parent-owned initial and final local Git ancestry receipts cover every
    finding commit independently derived from the corresponding raw current
    inventory. Every object check returns exact `0`, every ancestry check
    returns exact `0` or `1`, and both receipt sets are stable. There is no
    active top-level finding whose receipt returns `0` for the current head:
    no active top-level finding on the current head or a proved ancestor head.
    Reaction-only clean never supersedes a finding, including a current or
    ancestor finding. No unresolved thread finding may remain. Missing,
    other-return-code, or drifting ancestry evidence selects `unknown`.
11. There is no unresolved exact-provider selected-review target-thread
    finding whose commit has ancestry return code `0`. Human,
    unrelated-bot, null-parent, and unrelated-only threads are audit context
    and cannot contribute resolution; malformed target joins fail closed.
12. Every accepted current-scope controlled request and its reactions are
    fully paginated and have no cross-parent conflict under the rule above.
    Its parent is the unique latest request by semantic time, and the selected
    `+1` is later than every such request. In particular, there is no `-1`,
    `confused`, or other non-`+1`/`eyes` content on any parent and no `eyes` at
    or after the selected `+1` in the global
    `(created_at, positive numeric ID)` order. `eyes` is liveness-only: it can
    show that work started or restarted, but it never proves clean.
13. The final re-read is unchanged, including the canonical declaration REST
    artifact and recomputed digest, trusted history-window anchor/count, the
    complete dual-source discovery projection and every retained-semantic PR classification, every
    candidate before sorting, every ordered historical request/reaction sample,
    every request-time scope sidecar, the exact current request and reaction,
    the independently fetched raw
    current endpoint inventories, both parent-owned ancestry-receipt arrays,
    all evidence pages, target-thread state, lifecycle, and whole-PR scope.

If any condition is absent, `+1` does not complete the lane. Missing or
ambiguous evidence is `pending` while bounded waiting remains meaningful and
otherwise `triple-inconclusive`; it is never upgraded by optimistic inference.
This is the only clean-completion path that deliberately has no terminal
review/comment payload.

## No-Start And Non-Completion States

At the fixed authority baseline, the accepted structured
capability/installation schema set is empty. Therefore no current metadata
document may prove that the integration or service is unavailable or reduce
requested triple to effective double. Absence, timeout, permission failure,
generic transport/HTTP failure, and provider-authored free-form prose likewise
do not satisfy this path.

A future policy may activate structured availability evidence only by pinning
the authoritative API/issuer, schema identifier and version, required fields,
repository/installation binding, exact unavailable/not-installed enum values,
authentication requirements, normalization, and positive plus near-miss
contract tests. Until all of those are present, integration/service state is
unknown rather than unavailable.

An authenticated no-start rejection would likewise be availability evidence,
not a clean review result. However, the fixed authority baseline intentionally
defines no accepted no-start body grammar for this path: neither fixed upstream
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

For reaction-history evidence, each inventory reports its complete local union.
The eligibility audit is a closed identity subset of the retained audit. The
joint initial-final coordinator removes a scope from the stable comparison only
when it is present in exactly one union and eligible there; a PR observed in
both unions is retained and compared exactly.

For every accepted terminal basis and stable terminal blocking basis, include
the exact nested field
`evidence_basis.scope_assurance: artifact-publication-only`. The artifact is
independently trustworthy for the selected publication-time evidence scope,
but the report must not claim that GitHub Codex reviewed the current whole-PR
range or that its internal input merge base was attested. `Result present`
never turns an unreceipted historical artifact into current-scope evidence.
This closed field records the accepted trust boundary without adding
request/run/artifact lineage. Reaction bases omit `scope_assurance`, and a
`null` basis remains literal `null` rather than an object carrying assurance.

```yaml
request_policy:
  status: warning
  warnings:
    - duplicate-observed
provider_profile: mixed
evidence_basis:
  kind: pull-request-review
  scope_assurance: artifact-publication-only
  legacy_unreceipted_artifacts: []
  selection_snapshots:
    initial: <complete lifecycle/scope/pagination/candidate/thread snapshot>
    final: <repeat the complete identical selection snapshot>
  artifact: {
    "initial_snapshot": {
      "complete": true,
      "artifact_kind": "terminal-payload",
      "outcome": "clean",
      "channel": "pull-request-review",
      "id": 80100,
      "stable_artifact_id": 80100,
      "url": "https://github.com/OWNER/REPO/pull/1#pullrequestreview-80100",
      "user_login": "chatgpt-codex-connector[bot]",
      "user_type": "Bot",
      "state": "APPROVED",
      "body": "No findings.",
      "normalized_body": "No findings.",
      "grammar_status": "accepted",
      "terminal_looking": true,
      "submitted_at": 21,
      "server_time": 21,
      "server_time_field": "submitted_at",
      "commit_id": "0123456789abcdef0123456789abcdef01234567",
      "scope": {
        "repository": "OWNER/REPO",
        "pr": 1,
        "pr_merge_base": "1111111111111111111111111111111111111111",
        "head": "0123456789abcdef0123456789abcdef01234567"
      },
      "associated_inline_comments": {
        "pagination_complete": true,
        "records": []
      },
      "review_thread_pages": {
        "endpoint": "https://api.github.com/graphql",
        "pagination_complete": true,
        "pages": [
          {
            "after": null,
            "nodes": [],
            "pageInfo": {
              "hasNextPage": false,
              "endCursor": null
            }
          }
        ]
      }
    },
    "final_snapshot": "__TYPE_PRESERVING_EXACT_COPY_OF_INITIAL_SNAPSHOT__",
    "artifact_scope_receipt": {
      "kind": "parent-recorded-terminal-artifact-scope-v1",
      "pre_artifact_scope_receipts": {
        "pull": "__CLOSED_RAW_PRE_PULL_DETAIL_RESPONSE_RECEIPT__",
        "compare": "__CLOSED_RAW_PRE_COMPARE_RESPONSE_RECEIPT__"
      },
      "artifact_get_receipt": "__CLOSED_EXACT_REVIEW_GET_RESPONSE_RECEIPT__",
      "post_artifact_scope_receipts": {
        "pull": "__CLOSED_RAW_POST_PULL_DETAIL_RESPONSE_RECEIPT__",
        "compare": "__CLOSED_RAW_POST_COMPARE_RESPONSE_RECEIPT__"
      }
    }
  }
  current_raw_authority:
    raw_endpoint_inventories:
      initial: <complete independently fetched raw current endpoint inventory>
      final: <new complete raw current endpoint inventory>
    finding_commits:
      initial: <complete raw-derived full-SHA set>
      final: <repeat the complete identical full-SHA set>
    local_git_ancestry_receipts:
      initial: <complete parent-owned object/ancestry receipt array>
      final: <repeat the complete type-preserving identical receipt array>
```

Angle-bracket leaves in the surrounding YAML and `__...__` sentinel-string
leaves inside the JSON `artifact` value abbreviate complete closed subobjects;
they do not permit omitted or additional fields. In particular, `artifact` is
closed to exactly `initial_snapshot`, `final_snapshot`, and
`artifact_scope_receipt`. The executable contract fixture parses this JSON
fragment, replaces only the named sentinel leaves with the exact copy and raw
response receipts, requires type-preserving equality with the generated closed
artifact, and round-trips the complete report through the closed validator.

| Lane state | `provider_profile` | `evidence_basis` |
| --- | --- | --- |
| Proved pre-provider ineligibility or blocker: no PR, unsupported host/identity, selected PR closed before start, or scope/lifecycle failure before provider evaluation | `null` | `null`; report the exact effective-double or blocker reason separately |
| Eligible and waiting with no selected provider artifact | Computed profile, or `unknown` when it cannot yet be established | `null` |
| Accepted terminal clean or findings result | `terminal-payload` or `mixed` | Selected issue comment or pull-request review plus complete initial/final raw current authority |
| Accepted weak reaction clean | `thumbs-up-clean` | Exact accepted `+1` reaction plus its controlled request and scope; provider declaration identity/digest and every ordered historical request/reaction sample |
| Future accepted authenticated no-start rejection after an explicit grammar policy activates it | Actually recomputed profile, normally `terminal-payload` or `mixed` | Exact `no-start-rejection` issue comment plus its controlled request and scope |
| Inconclusive evidence | Computed profile or `unknown` | Stable blocking artifact when one exists; otherwise `null` |

An inconclusive blocking basis reuses the terminal basis shape above: `kind`
is the carrier channel, `scope_assurance` is exactly
`artifact-publication-only`, and the complete selected artifact, identical
selection snapshots, and current raw authority remain embedded. An unresolved
exact-provider target-thread finding has blocking-basis priority regardless of
an otherwise newer clean or malformed artifact; choose the greatest
`(server_time, stable_artifact_id)` only among fully validated unresolved
target-thread artifacts. When no such thread blocker exists, a malformed
artifact supplies a basis only when it is the selected terminal blocker under
the ordinary channel/time/precedence rules. Input list order never selects a
blocker, and an unstable, incomplete, or ambiguous blocker has no stable basis
and therefore reports `null` rather than a guessed summary.
An unreceipted legacy unresolved thread or malformed/unknown terminal artifact
is not a fully validated blocker basis under this paragraph. It fails the
legacy partition and blocks completion, but `evidence_basis` remains `null`
unless a separate receipt-bound blocker independently satisfies the complete
basis contract.
Selecting an unresolved blocker uses a blocker-specific projection of the same
fully validated raw endpoint inventories: it chooses the greatest validated
unresolved target-thread `(server_time, stable_artifact_id)` before ordinary
terminal channel arbitration. Therefore an equal-time clean or malformed
artifact on another channel can keep the overall verdict inconclusive without
erasing the independently stable unresolved blocker basis. This exception
changes only the reported blocker selection; ordinary terminal acceptance
continues to fail closed on equal-time cross-channel ambiguity.

For a pull-request review, `server_time` is the exact REST `submitted_at` and
use `server_time_field: submitted_at`. For an unedited issue comment, use exact
REST `created_at` and `server_time_field: created_at`; for an edited issue
comment, use exact REST `updated_at` and `server_time_field: updated_at`. A
reaction always uses exact REST `created_at` and
`server_time_field: created_at`. Never rewrite one channel's time into another
channel's field name.

Every terminal-payload basis embeds identical `selection_snapshots.initial` and
`.final` records containing lifecycle, immutable whole-PR scope, all required
pagination results, every terminal candidate's stable ID/channel/time/outcome,
malformed blockers, and relevant thread state. It also embeds identical
`artifact.initial_snapshot` and `.final_snapshot` records plus
`current_raw_authority` with independent initial/final raw endpoint
inventories, raw-derived finding-commit sets, and matching parent-owned local
Git ancestry receipts. Outside migration, the raw projection must
type-preservingly equal the normalized current selection input. During legacy
migration, equality is replaced only by the closed raw-to-receipt-qualified
partition above; a selected-artifact summary or normalized snapshot without
that authority is not auditable evidence.

Every non-null terminal-shaped basis includes
`legacy_unreceipted_artifacts`. An ordinary terminal basis uses the empty list.
For a legacy-receipt migration decision, independently derive the closed list
from each raw inventory, require the two projections to be type-preserving
identical, and emit only their common canonical `(channel, id)`-sorted value.
Prove that the raw applicable artifact set is exactly the disjoint union of the
receipt-bound normalized decision projection and this list. The selected
completion artifact must be in the receipt-bound member. Revalidate that every
legacy semantic time is strictly earlier than both of the selected artifact
receipt's pre-scope `Date` values; equality, later/unknown time, malformed
projection, overlap, omission, or drift selects `triple-inconclusive`. Legacy
clean remains audit-only, ordinary old top-level/all-resolved findings remain
visible to normal precedence, and an old any-unresolved target thread fails
the partition and still blocks. Request/reaction-only raw drift remains
excluded from this decision-authority comparison under the independent-plane
rule. A rejected legacy blocker is never promoted merely so the report can
carry a non-null basis.

Each receipt-bound terminal-looking artifact wrapper in those snapshots also
embeds its unique closed `artifact_scope_receipt`. The object contains exactly `kind`,
`pre_artifact_scope_receipts`, `artifact_get_receipt`, and
`post_artifact_scope_receipts`; its kind is
`parent-recorded-terminal-artifact-scope-v1`. Initial/final equality includes
the complete receipt. The exact artifact GET projection—not a sibling summary—
binds repository/PR, channel, native ID, body/digest, exact provider identity,
semantic time, and artifact commit; the pre/post pull and compare projections
bind artifact-time head and merge base. Clean and malformed artifacts bind the
enclosing current scope exactly. An ancestor finding instead preserves its
older artifact-time head while the enclosing normalized `scope.head` remains
current and local ancestry proves applicability. A missing earlier pre-scope
boundary cannot be supplied by final current metadata, so an unreceipted old
artifact is not trustworthy current-scope terminal authority.
Do not copy a truly unreceipted legacy wrapper into those normalized snapshots:
it remains visible only in the complete raw inventories and the derived closed
`legacy_unreceipted_artifacts` list. That audit-only omission from normalized
receipt-bound wrappers is the migration join, not a raw/normalized mismatch.

For terminal authority, initial/final equality covers scope, lifecycle,
provider artifacts, thread/finding state, and canonical nonterminal provider
audit records. In legacy migration it also covers the closed
raw-applicable/receipt-bound/legacy partition and the complete legacy item
projection. Raw request records, provider reactions, and request-scope sidecar
metadata belong to the separate request/reaction plane. Preserve the exact
initial and final raw inventories in the report even when those records differ,
a sidecar is absent, or the sidecar-only projection drifts. Their complete pages
must remain parseable, but their differences do not veto an identical terminal
selection and artifact snapshot. Recompute
`request_policy.status` and reaction authority from the available final
evidence; use `unknown` whenever their own stability or binding cannot be
proved.

Request-sidecar independence does not extend to artifact-scope provenance. A
missing request receipt affects only request/reaction authority; a missing,
malformed, unmatched, or unstable `artifact_scope_receipt` blocks the wrapped
terminal artifact itself. Neither receipt kind supplies request/run/artifact
lineage, and neither point-read envelope proves an ABA-free interval.

These evidence records use closed object schemas and JSON type identity.
Unknown fields are rejected until a future policy version explicitly admits
them. In particular, a JSON boolean is never a numeric ID, timestamp, or
count, and numeric `0` / `1` are never boolean pagination or resolution
values. Initial/final equality is type-preserving rather than Python-style
value equality.

For a pull-request review, each artifact snapshot contains exact REST
`id`/URL, `user.login`, `user.type`, `state`, raw body, normalized body,
`submitted_at`, native `commit_id`, and the complete associated inline-comment
pages. Every raw REST child record includes its stable ID/URL, exact actor,
`pull_request_review_id`, `commit_id`, `original_commit_id`, raw/normalized
body, but no synthesized thread or resolution field. The snapshot separately
stores the complete raw GraphQL thread/comment pages. The canonical BigInt
one-to-one join targets only exact-provider REST children whose canonical
parent is the selected review and derives `thread_findings`; only the joined
target thread's raw GraphQL `isResolved` value supplies resolution authority.
The pagination and raw join inputs must prove the complete target set even when
it is empty. Human, unrelated-bot, null-parent, and unrelated-only records stay
in the raw audit and cannot supply resolution. Thus an `APPROVED` /
`No findings.` review with zero targets, one with a valid target finding child,
one with only unrelated audit children, and one whose target page/join is
unread or malformed produce distinguishable reports.
This raw page set plus its canonical derivation is the associated inline-comment
page/join evidence; the legacy phrase does not authorize synthesized fields.

For a terminal issue comment, each artifact snapshot contains exact REST
`id`/API URL/HTML URL, `user.login`, `user.type`,
`performed_via_github_app.slug`, raw body, normalized body, `created_at`,
`updated_at`, selected semantic server time/field, and the parsed exact
full-head marker or finding SHA. The initial/final records must be identical
after re-fetch. Missing actor/App/body/time/commit fields, a changed body, or a
sparse summary cannot prove the closed grammar. Use the complete closed
issue-comment schema defined above in current, historical, selected-artifact,
and blocking-artifact records; no review-only evaluator may silently drop this
carrier.

For reaction fallback, `evidence_basis` uses this field-level shape. The
`samples` array has 3 to 10 entries in the deterministic selected order and
repeats the full request/reaction provenance for every historical outcome:

```yaml
evidence_basis:
  kind: reaction
  provider_declaration:
    initial_snapshot: <complete authenticated declaration record using the fields below>
    final_snapshot: <repeat the complete identical declaration record>
    initial_fetch_receipt:
      method: GET
      request_url: https://api.github.com/repos/OWNER/REPO/issues/comments/<artifact_id>
      status: 200
      date_header: <canonical IMF-fixdate from the first GET>
      body_utf8: <bounded raw declaration JSON response>
      body_sha256: <recomputed lowercase SHA-256>
    final_fetch_receipt:
      method: GET
      request_url: <same canonical declaration URL>
      status: 200
      date_header: <canonical IMF-fixdate not earlier than the initial Date>
      body_utf8: <bounded raw declaration JSON response projecting to the same snapshot>
      body_sha256: <recomputed lowercase SHA-256>
    authority_kind: exact-provider-github-artifact
    repository: OWNER/REPO
    pull_request: <positive PR number>
    artifact_id: <positive issue-comment ID>
    api_url: https://api.github.com/repos/OWNER/REPO/issues/comments/<artifact_id>
    html_url: https://github.com/OWNER/REPO/pull/<pull_request>#issuecomment-<artifact_id>
    channel: issue-comment
    user_login: chatgpt-codex-connector[bot]
    user_type: Bot
    app_slug: chatgpt-codex-connector
    created_at: <server time>
    updated_at: <same server time for this baseline>
    server_time: <created_at>
    server_time_field: created_at
    body: <direct REST body containing the exact asserted line once>
    asserted_text: "If Codex has suggestions, it will comment; otherwise it will react with 👍."
    github_reaction_content: "+1"
    github_reaction_glyph: "👍"
    normalization: crlf-and-cr-to-lf+utf8
    normalized_sha256: <64 lowercase hex>
  history_window:
    as_of_source: github-response-date-header
    as_of_api_url: https://api.github.com/repos/OWNER/REPO/issues/comments/<artifact_id>
    as_of_server_time: <Date from the first direct provider-declaration REST GET>
    as_of_receipt: <exact initial_fetch_receipt above>
    window_seconds: 2592000
    window_start_exclusive: <as_of_server_time minus 2592000>
    window_end_inclusive: <same as as_of_server_time>
    candidate_universe_count: <distinct-scope count derived from the raw transcript>
  historical_universe:
    initial_inventory:
      complete: true
      repository: OWNER/REPO
      resource_budget: <exact github-codex-evidence-resource-budget-v1 profile above>
      pagination: <all nine source/detail fetch-kind flags, each exact true>
      discovery_endpoint_transcript:
        schema_version: 4
        repository: OWNER/REPO
        scope_discovery:
          recent_pull_requests: <closed updated-desc boundary-aware raw REST fetch>
          recent_request_comments: <closed fully paginated since-cutoff raw REST fetch>
          anchors:
            current_pull_number: <positive current PR number>
            declaration_pull_number: <positive declaration PR number>
        scopes:
          - pull_number: <positive PR number in the discovery union>
            fetches:
              - kind: pull_requests | compare | issue_comments | reviews | inline_comments | review_threads | request_reactions
                transport: rest | graphql
                parent_comment_id: <positive request-comment ID or null>
                pages:
                  - request_url: <exact REST URL or https://api.github.com/graphql>
                    status: 200
                    link_header: <raw REST Link header or null for GraphQL>
                    request_after: <null for REST/first GraphQL page or prior raw endCursor>
                    body_utf8: <bounded raw JSON response body; GraphQL pages include exact repository.nameWithOwner and pullRequest.number>
                    body_sha256: <recomputed lowercase SHA-256>
      request_scope_receipts:
        - <one closed parent-owned request-time scope sidecar for every controlled request in the seeded scopes>
      scope_discovery_projection:
        cutoff_rfc3339: <canonical window_start_exclusive>
        stop_reason: window-boundary-complete | natural-end-complete
        recent_pull_requests:
          - pull_number: <positive PR number retained after complete detail validation>
            base_oid: <full lowercase pull-detail base OID>
            head_oid: <full lowercase pull-detail head OID>
        recent_request_comments:
          - request_id: <positive controlled-request comment ID>
            pull_number: <positive joined PR number>
            updated_at: <canonical in-window server time>
            source_record_sha256: <canonical raw issue-comment SHA-256>
        anchors:
          current_pull_number: <positive current PR number>
          declaration_pull_number: <positive declaration PR number>
        union_pull_numbers: [<every sorted fixed-semantic-union PR number>]
        retained_pull_scope_audit:
          - pull_number: <every unique positive fixed-semantic-union PR number>
            base_oid: <full lowercase pull-detail base OID>
            head_oid: <full lowercase pull-detail head OID>
            merge_base: <full lowercase compare-derived merge-base OID>
            lifecycle: <closed normalized PR lifecycle object>
        future_prefix_omission_eligibility_audit:
          - pull_number: <unique positive locally eligible future-prefix-only PR number retained in this local union>
            base_oid: <full lowercase pull-detail base OID>
            head_oid: <full lowercase pull-detail head OID>
            merge_base: <full lowercase compare-derived merge-base OID>
            lifecycle: <closed normalized PR lifecycle object>
      scope_classifications:
        - pull_number: <every fixed-semantic-union PR, including current, declaration, and confirmed non-candidates>
          scope_key: [OWNER/REPO, <pr>, <pr_merge_base>, <head>]
          classification: current | historical-candidate | confirmed-non-candidate
      entries:
        - scope_key: [OWNER/REPO, <pr>, <pr_merge_base>, <head>]
          source_ordering_key: [<server_time>, <stable_artifact_id>]
          source_evidence:
            carrier: reaction | terminal-artifact
            channel: request-reaction | issue-comment | pull-request-review
            semantic: "+1" | eyes | clean | findings | malformed
            native_identity: [<parent reactions URL or channel>, <positive native ID>]
            source_record_sha256: <canonical policy-projection SHA-256>
    final_inventory: <independently fetched complete inventory whose joint coordinated stable view equals the initial view, with exact overlap equality for future_prefix_omission_eligibility_audit, identical retained semantic projection, and stable request_scope_receipts; raw future prefixes and proved one-sided eligible seeds may differ only under the validated coordination rule>
    initial_candidates:
      - <complete candidate snapshot defined below>
    final_candidates:
      - <repeat every complete initial candidate snapshot in the same order>
  current:
    raw_endpoint_inventories:
      initial: {
        "repository": "OWNER/REPO",
        "pull_number": 1,
        "head": "__FULL_LOWERCASE_CURRENT_HEAD_SHA__",
        "resource_budget": "__EXACT_GITHUB_CODEX_EVIDENCE_RESOURCE_BUDGET_V1__",
        "fetches": "__COMPLETE_CLOSED_CURRENT_FETCHES__",
        "request_scope_receipts": "__COMPLETE_CLOSED_REQUEST_SCOPE_RECEIPTS__"
      }
      final: <independently re-fetched complete current inventory with identical authority projection>
    finding_commits:
      initial:
        - <every distinct full commit derived from the raw initial inventory>
      final: <repeat the independently derived type-preserving identical list>
    local_git_ancestry_receipts:
      initial:
        - finding_commit: <full lowercase SHA>
          head: <same current head>
          object_check_return_code: 0
          ancestry_return_code: 0 | 1
      final: <repeat the complete type-preserving identical parent-owned receipt array>
    initial_snapshot: <complete current snapshot using the fields below>
    final_snapshot: <repeat the complete identical current snapshot>
    complete: true
    pagination:
      request_comments: true
      request_reactions: true
      issue_comments: true
      reviews: true
      inline_comments: true
      review_threads: true
    evidence_state:
      terminal_payloads: []
      malformed_terminal_artifacts: []
      active_top_level_findings: []
      unresolved_thread_findings: []
    lifecycle:
      state: open
      merged: false
      merged_at: null
    scope:
      repository: OWNER/REPO
      pr: 123
      pr_merge_base: <full lowercase SHA>
      head: <full lowercase SHA>
    request_scope_receipts:
      - <closed sidecar for each request below>
    request:
      id: 123456
      url: <exact issue-comment URL>
      created_at: <server time>
      updated_at: <same server time as created_at>
      request_server_time: <created_at>
      request_server_time_field: created_at
      normalized_body: "@codex review"
      user:
        login: <authenticated parent login>
        type: <exact REST user type>
    request_scope_receipt: <the unique matching sidecar for request.id>
    reaction:
      id: 789012
      parent_request_id: 123456
      parent_reactions_api_url: https://api.github.com/repos/OWNER/REPO/issues/comments/123456/reactions?per_page=100
      created_at: <server time after request.request_server_time>
      content: "+1"
      user_login: chatgpt-codex-connector[bot]
      user_type: Bot
    selected_request_id: 123456
    selected_reaction_id: 789012
    same_scope_request_audit:
      - request: <same eight request fields>
        request_scope_receipt: <the unique matching sidecar>
        reactions:
          - <same seven reaction fields>
    candidate_basis:
      kind: reaction
      server_time: <trusted scope-final reaction time>
      stable_artifact_id: <positive reaction ID>
  samples:
    - scope: <same four immutable scope fields>
      candidate_basis:
        kind: reaction | terminal-payload | malformed-terminal-artifact | active-top-level-finding | unresolved-thread-finding
        server_time: <trusted semantic server time after scope-local precedence>
        stable_artifact_id: <positive native numeric ID>
      request: <same eight request fields>
      request_scope_receipt: <the unique matching sidecar>
      reaction: <same seven reaction fields>
      same_scope_request_audit:
        - request: <same eight request fields>
          request_scope_receipt: <the unique matching sidecar>
          reactions:
            - <same seven reaction fields>
```

Within the reaction report example, `__...__` sentinel-string leaves in the
JSON `current.raw_endpoint_inventories.initial` value abbreviate the complete
closed budget, fetch, and sidecar objects. The executable contract parses that
exact heading-bounded JSON fragment with duplicate-key rejection, substitutes
only those named leaves, and requires type-preserving equality with the fixed
current-inventory producer and parser schema.

Every REST request ID, reaction ID, reaction parent ID, and selected
request/reaction ID in this report is an exact positive JSON integer, never a
quoted decimal string, boolean, or float. Canonical positive decimal text is
reserved for GraphQL BigInt-to-REST join comparison and does not change the
REST/report JSON type.

The report embeds both independently fetched schema-version-4 raw historical
discovery endpoint transcripts, including each bounded pull/request source,
both anchors, every raw-union-seeded PR traversal, and every retained-semantic
current/candidate/non-candidate classification. The union/detail closure includes the authenticated declaration
PR and retains its exact declaration record in its declaration role. That role
does not suppress terminal classification; only an independently nonterminal
declaration record is audit-only evidence.
Each historical inventory stores the parent-owned request-time scope sidecar
array beside—not inside—its unchanged version-4 transcript. It also embeds both
raw-derived source-authority inventories and both independently validated
complete candidate arrays, including
candidates outside `samples`; a count, version-3 transcript, or external ledger
reference is insufficient. Each complete candidate snapshot repeats these
fields: `complete`, all six pagination results, the four
`evidence_state` artifact arrays with stable IDs/times, lifecycle, immutable
scope, every controlled request, its one-to-one `request_scope_receipts`, every
in-cutoff individual reaction (including confirmed-different-actor reactions), selected
request/reaction IDs when present, `same_scope_request_audit`, and
`candidate_basis`. The initial and final candidate arrays, parent-owned
`request_scope_receipts`, derived `scope_classifications`, and derived `entries`
must be type-preserving identical. The fixed `scope_discovery_projection`
records the cutoff, while the enclosing history window separately records the
frozen as-of. It also records the stop reason, deterministic positive-number
list of stable retained pull/base/head seed identities, ordered request
IDs/PRs/digests, anchors, sorted fixed semantic union, and the closed
`retained_pull_scope_audit`, whose item set exactly covers that traversal's
local union. Each traversal also records a closed
`future_prefix_omission_eligibility_audit`; its items are unique and ordered by
positive pull number and form a subset of the retained audit. The joint
coordinator first excludes the independently validated complete stop-reason
label from both derived views, removes only a locally eligible PR present in
exactly one complete local union, then requires every projection field and
retained audit item remaining after those two operations to be type-preserving
identical. A PR present in both unions remains in the comparison. Every pull
number in both eligibility audits must bind identical
pull/base/head/merge-base/lifecycle values. The projection
deliberately excludes pull-list
`updated_at`, raw pull-row digests, and endpoint row order. The
independently fetched raw transcript records need not be structurally or
byte-identical when each traversal is complete and their fixed semantic
projection cores are identical; opaque cursor and raw page-byte differences,
unrelated activity on an already retained seed, and a fully traversed one-sided
eligible future-prefix-only seed are raw observation differences, not candidate
drift.
Every such raw row and detail traversal still consumes the ordinary endpoint
budget. A request-feed/anchor co-seed, controlled request, exact or ambiguous
provider/policy evidence, cross-cutoff edit, repeatedly observed scope
base/head/merge-base/lifecycle drift, or incomplete source/detail page remains
fixed-semantic drift or incomplete
authority and fails closed.

`current.raw_endpoint_inventories.initial` and `.final` are independent,
complete endpoint traversals and each is the authority for its corresponding
raw finding-commit set. Their `request_scope_receipts` siblings bind each
controlled request to its parent-created POST and matching pre/post whole-PR
scope without changing transcript schema version 4. The parent-owned
`current.local_git_ancestry_receipts.initial` and `.final` cover exactly those
sets and accept only local object-check return code `0` plus ancestry return
code `0` or `1`. The two receipt arrays and raw authority projections must be
type-preserving identical for reaction completion. For terminal completion,
the two ancestry-receipt arrays and terminal-decision projections must be
identical, while request-scope-sidecar metadata is excluded and reported on
the request/reaction plane. `current.initial_snapshot` and `.final_snapshot`
likewise embed the complete reader-facing field set for the exact current scope
and must be structurally identical, but neither normalized snapshot substitutes
for the raw inventories or ancestry receipts. Every policy-bearing time and
every non-excludable raw record in historical and current inventories is
checked against the recorded as-of bound after strict actor classification and
before candidate selection. Fully validated post-cutoff confirmed-different
suffix records stay visible only in the raw transcript under the rule above.
This lets a reader distinguish a valid
11-candidate universe from one whose unselected candidate was truncated,
incompletely paginated, changed on final reread, or contained a future
provider/provider-like record rather than an irrelevant human suffix.

The current raw authority projection retains every exact-provider
`PENDING` review and progress-only issue comment in a canonical
`nonterminal_records` audit list. Each item binds its channel, positive native
ID, and canonical source digest. A progress comment also binds its semantic
server time. A `PENDING` review requires the REST `submitted_at` value to be
absent or null, records exact `server_time: null`, and binds its exact-provider
inline and thread bundle instead of inventing a local or receipt timestamp.
The same list carries at most one scope-level `review-thread-audit` item,
identified by the positive pull number with `server_time: null`; its source
digest binds every fully parsed semantic GraphQL thread after the allowed
post-cutoff confirmed-different suffix exclusion. This item is audit-only and
cannot complete, block, or resolve a provider result by itself.
These records never enter terminal ordering or create a result, but the
complete initial/final projection must keep them type-preserving identical.
When comparing the raw terminal decision to the normalized current snapshot,
exclude this audit-only list plus the complete raw request and provider-reaction
collections, including request-scope metadata and receipts. Preserve those
excluded collections in the raw initial/final inventories and evaluate them on
the request/reaction plane. Preserve and compare lifecycle, scope, provider
artifact, thread, and finding fields. Any difference in that terminal-decision
projection fails closed; a difference confined to the excluded request/reaction
collections instead changes or closes only their own authority.

`provider_declaration.asserted_text` stores the exact authenticated line, not a
summary. `normalized_sha256` is recomputed with the recorded normalization
algorithm after projecting each canonical REST receipt body. The history
window is derived arithmetically from the initial receipt's canonical `Date`;
its label, URL alone, or arbitrary integer cannot substitute for that receipt.
The final declaration receipt proves a stable re-read but does not move
`as_of_server_time`, replace `as_of_receipt`, or replace `as_of_api_url`. Every
historical reaction-profile candidate basis must satisfy
`window_start_exclusive < candidate_basis.server_time <=
window_end_inclusive`, and the separately evaluated current reaction-only
basis for `thumbs-up-clean` cannot be later than the same as-of time. A strong
current `terminal-payload` or `mixed` basis is outside this reaction-history
cutoff.

Each `samples[]` entry independently proves exact request/sidecar/reaction
identity, both receipt-derived scope tuples, the eight-field POST projection,
and `reaction.created_at > request.request_server_time`, and its
`same_scope_request_audit` enumerates every accepted request parent plus every
fully paginated reaction for that scope. The selected request and its exact
sidecar must appear in that audit with the same fields. Each reaction's
`parent_request_id` and
`parent_reactions_api_url` must match the request whose fully paginated endpoint
actually returned it; relocating an R1 reaction under R2 is a parent-binding
conflict even when its actor and timestamp remain plausible.
`candidate_basis` is recomputed from the final scope outcome after terminal
precedence; a reaction basis is invalid when a terminal or finding artifact
actually determines that scope, when a later provider-like reaction exists, or
when any required candidate page/snapshot is incomplete. A terminal basis
remains the basis when a later `+1` or `eyes` exists; those reactions remain
visible in the complete audit and may prevent only reaction-only fallback.
References to an external ledger do not replace these fields.
Immediately before success, re-fetch and revalidate the authenticated
declaration artifact without moving the frozen window, re-read every raw
discovery endpoint transcript, independently rederive the bounded dual-source
raw-union coverage, every retained-semantic PR classification, the historical inventory/count,
and every universe candidate before sorting, and revalidate every ordered
`samples[]`. Independently re-fetch the final raw current endpoint inventory,
rederive its complete finding-commit set, repeat every parent-owned local Git
ancestry receipt, and revalidate every `current` field and cross-parent audit.
Missing provider data, non-`0` object resolution, ancestry return codes outside
exact `0`/`1`, budget overflow, or provider-artifact/thread/finding drift
selects `unknown` for the provider result. Missing, malformed, or drifting
request-scope sidecars select `unknown` only for request/reaction authority and
do not erase an independently stable terminal result.
When a terminal artifact is selected, record it even when its outcome is
findings. Do not reduce the basis to prose such as “Codex completed”.

## Alignment And Intentional Differences From The Fixed Action Baseline

Only the provider-result authority is inherited from the fixed Action
baseline. The stricter evidence carriers and scope gates below are deliberate
playbook extensions and must not be “corrected” by copying the Action
implementation mechanically:

1. **Whole-PR scope and lifecycle are stricter.** The Action baseline binds a
   clean artifact to the current head and validates a complete evidence
   snapshot. This playbook additionally requires exact selected-PR lifecycle,
   base OID, head OID, one local merge base, and equality with the frozen
   whole-PR range, plus the independent artifact-time scope receipt described
   below. A base-only retarget on the same head remains
   `base-changed-same-head`.
2. **Raw thread resolution is a playbook extension.** This playbook requires
   complete raw REST inline-comment records, complete raw GraphQL thread and
   nested-comment pages, canonical BigInt normalization, and a one-to-one join
   for every exact-provider selected-review target child. Fully fetched human,
   unrelated-bot, null-parent, and unrelated-only records remain audit context
   and cannot contribute resolution. It never treats synthesized REST
   `thread_id` / `thread_resolved` fields or `isOutdated` as resolution
   authority, and a malformed target join still fails closed.
3. **The closed terminal issue-comment carrier is a playbook extension.** The
   inheritance does not make the fixed Action's internal carrier schema this
   playbook's schema. The exact Bot/App/API/HTML/body/scope record, parsed
   commit, edited-comment `updated_at` ordering, final reread, and
   cross-channel equal-time fail-closed rule remain locally normative.
4. **An empty `APPROVED` review is not clean.** The Action baseline accepts an
   empty or exact `Looks good.` approved-review body under its closed grammar.
   This playbook requires an explicit clean comment/review payload with commit
   binding for `terminal-payload`; an empty state-only approval is
   insufficient.
5. **The `+1` fallback is new playbook policy.** The fixed Action collects
   `plusOne` in its reaction baseline but does not use it as provider-result
   authority; its result selector consumes terminal issue comments and
   reviews. This playbook permits `+1` only under the dynamic-profile and
   thirteen-condition fallback above, including independent initial/final raw
   current inventories and parent-owned local Git ancestry receipts. A
   normalized current snapshot is not that authority.
6. **`eyes` remains orchestration-only.** The fixed Action uses a new `eyes`
   transition as acknowledgement/liveness. This playbook preserves that
   boundary and additionally rejects `+1` fallback when a newer `eyes`
   indicates later activity.
7. **Duplicate result consumption aligns with the Action; warning codes are a
   playbook extension.** Stable current-head result evidence is not rejected by
   marker or audit history in the fixed baseline. This playbook inherits that
   consumer rule, while adding `duplicate-observed` and the producer rule that
   the orchestrator must never create another same-scope request.
8. **Early-result consumption aligns with the Action; local-lane sequencing is
   a playbook extension.** The fixed baseline accepts stable clean evidence
   regardless of marker timing. This playbook additionally requires local
   terminal artifacts before it sends a new GitHub request and reports
   `early-request-observed` when that producer order was violated. Do not
   discard a later independently trustworthy provider result solely because of
   that producer-side sequencing defect.
9. **Bounded dual-source discovery schema version 4 is a playbook extension.**
   This playbook combines an updated-desc boundary traversal, a since-cutoff
   repository issue-comment feed, and current/declaration anchors; it traverses
   every raw-union-seeded PR and excludes current only after full parsing. Its
   fixed semantic projection compares stable PR/base/head seed identities rather
   than live pull-row timestamps, digests, or endpoint order, and may omit a
   fully traversed future-prefix-only seed only under the narrow
   confirmed-different rule above. Version 3
   cannot prove the fallback, and evidence-budget overflow selects `unknown`.
   The versioned playbook budget deliberately reuses the fixed Action
   baseline's 20000-item, 8 MiB per-response, and 64 MiB per-work bounds. Its
   512 raw-union-seeded PRs, 512 controlled requests, 8192 attempts, 4096 retained pages,
   and 900-second per-traversal deadline are playbook extensions needed for
   the two fresh historical traversals; they are not attributed to the Action.
10. **Request-time scope sidecars are a playbook extension.** The fixed Action
    comparison does not establish the exact scope of a parent-created request.
    This playbook separately captures closed pre/post pull-and-compare receipts
    and the exact POST response, binds every reaction parent one-to-one to that
    scope, and fails the request/reaction planes closed when the sidecar is
    absent. It neither changes raw transcript schema version 4 nor creates
    request/run lineage, and it does not veto an independently trustworthy
    terminal payload with its own complete artifact-time scope receipt.
11. **Artifact-time whole-PR receipts are a playbook extension.** Result-present
    acceptance is inherited, but the fixed Action comparison does not prove an
    artifact's merge base at its semantic server time. This playbook requires
    the singular closed `parent-recorded-terminal-artifact-scope-v1` receipt
    with pre pull/compare, exact artifact GET, and post pull/compare responses.
    The envelope binds the artifact body/digest/identity and artifact-time
    whole-PR scope without naming a request or run. Clean and malformed
    evidence require the current tuple; a proved-ancestor finding preserves its
    artifact-time head while normalized `scope.head` remains current. An
    artifact that does not strictly follow every trustworthy pre observation
    cannot be retroactively scoped. Equal point reads still do not exclude an
    intermediate ABA transition.
12. **Declaration discovery is a playbook extension.** The authenticated
    declaration PR participates in the complete discovery union/detail
    traversal. Only the independently nonterminal declaration role and closed
    progress-only grammar are audit-only. A declaration-bearing record that
    also matches clean, findings, or malformed terminal grammar retains its
    terminal classification; other exact-provider free-form prose fails closed,
    and in-window terminal-looking malformed artifacts remain candidates. This
    classification is not behaviour attributed to either fixed upstream commit.

## Non-Goals

- Do not treat checks, status contexts, acknowledgements, progress comments,
  `eyes`, sticky state, deadlines, or request markers as clean results.
- Do not weaken exact bot identity or full pagination to make a profile fit.
- Do not use a version-3 transcript, truncated discovery union, normalized
  current snapshot, or external ancestry ledger as reaction-clean authority.
- Do not insert request-time scope receipts into raw transcript schema version
  4, infer request/run lineage from them, or claim matching pre/post scope
  snapshots exclude an intermediate ABA transition.
- Do not reconstruct an artifact-time receipt from later current metadata,
  omit the exact artifact GET, add unversioned fields to its closed object, or
  claim its pre/artifact/post point reads prove continuous or ABA-free scope.
- Do not conflate `scope.head` with a finding's artifact commit. Clean must bind
  current head; applicable ancestor findings remain projected through local
  ancestry receipts until strong supersession or thread resolution applies.
- Do not reattach a request/reaction from one receipt-derived scope epoch to
  another, even when the repository, PR number, or head matches.
- Do not carry a profile across repositories or beyond the bounded 30-day
  evidence window.
- Do not create a duplicate request, empty commit, or synthetic provider
  artifact to escape an inconclusive state.
- Do not claim the policy itself proves provider behaviour; every counted
  outcome still requires the complete evidence and final-stability checks
  above.
